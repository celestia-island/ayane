//! The lifecycle commands that do not touch a message: `LIST`, `STATUS`,
//! `SELECT`/`EXAMINE` — with the CONDSTORE/QRESYNC parameters RFC 7162 §3.1.8
//! and §3.2.5 hang off them — `UNSELECT`, `ENABLE`, and the re-scan a
//! `NOOP`/`CHECK` performs. `EXPUNGE`, `UID EXPUNGE` and the `CLOSE` sweep
//! live in [`super::expunge`].

use imap_codec::imap_types::{
    extensions::enable::CapabilityEnable,
    flag::FlagPerm,
    mailbox::{ListMailbox, Mailbox},
    response::Code,
    response::{Data, Response, Status},
    status::StatusDataItemName,
};
use std::borrow::Cow;

use crate::maildir_reader::INBOX;

use super::ext_wire::{self, ExtParams};
use super::modseq;
use super::qresync::QresyncParam;
use super::session::{Folder, ImapSession, Selected, State, Transport};
use super::uidlist::UidMap;
use super::wire::{bad, capabilities, encode, glob, line, non_zero, status_value, system_flags};
use super::{answer, Kind, Outcome, BAD_MAILBOX, NO_MAILBOX, UIDLIST};

impl ImapSession<'_> {
    pub(crate) fn untagged(&self, data: &Data<'_>) -> Vec<u8> {
        encode(&Response::Data(data.clone()))
    }

    pub(crate) fn contained(&self, status: &Status<'_>) -> Vec<u8> {
        encode(&Response::Status(status.clone()))
    }

    /// An untagged `OK [<code>] …` line.
    pub(crate) fn notice(&self, code: Code<'_>, text: &str) -> Vec<u8> {
        self.contained(&Status::ok(None, Some(code), text).expect("a short code"))
    }

    pub(crate) fn ok(&self, tag: &str, text: &str) -> Vec<u8> {
        line(tag, Kind::Ok, None, text, true)
    }

    pub(crate) fn no(&self, tag: &str, text: &str) -> Outcome {
        Outcome {
            out: line(tag, Kind::No, None, text, true),
            ..Outcome::default()
        }
    }

    pub(crate) fn bad(&self, tag: &str, text: &str) -> Outcome {
        Outcome {
            out: line(tag, Kind::Bad, None, text, true),
            ..Outcome::default()
        }
    }

    /// An untagged line followed by the tagged `OK` that completes a command.
    pub(crate) fn reply(&self, tag: &str, name: &str, data: Data<'_>) -> Outcome {
        let mut out = self.untagged(&data);
        out.extend(self.ok(tag, &format!("{name} completed")));
        Outcome {
            out,
            ..Outcome::default()
        }
    }

    pub(crate) async fn authenticate(&mut self, tag: &str, user: &str, pass: &str) -> Outcome {
        if self.transport == Transport::Clear {
            return self.no(
                tag,
                "[PRIVACYREQUIRED] TLS is required before authenticating",
            );
        }
        // The mailbox is the destination, not a claim: another account's
        // password must not open this mailbox, however valid it is.
        let same = user.trim().eq_ignore_ascii_case(self.mailbox.as_str());
        if !same || !self.passwords.verify(user.trim(), pass).await {
            return self.no(tag, "[AUTHENTICATIONFAILED] invalid credentials");
        }
        self.state = State::Authenticated;
        Outcome {
            out: line(
                tag,
                Kind::Ok,
                Some(Code::Capability(capabilities(
                    self.transport,
                    self.starttls,
                ))),
                "Logged in",
                true,
            ),
            ..Outcome::default()
        }
    }

    /// A command's mailbox argument, resolved to its folder and read.
    pub(crate) fn census_of(
        &self,
        tag: &str,
        mailbox: &Mailbox<'_>,
    ) -> Result<(String, Folder), Outcome> {
        let folder = Self::folder(tag, mailbox)?;
        let census = self.census(&folder).map_err(|err| self.no(tag, &err))?;
        Ok((folder, census))
    }

    /// The folder a command's mailbox argument names, or the `BAD` that
    /// answers a name this layout cannot hold.
    pub(crate) fn folder(tag: &str, mailbox: &Mailbox<'_>) -> Result<String, Outcome> {
        Self::folder_of(mailbox).ok_or_else(|| bad(tag, BAD_MAILBOX))
    }

    /// The selection, re-read, or the `BAD`/`NO` that answers it.
    pub(crate) fn current(&self, tag: &str) -> Result<Selected, Outcome> {
        let selected = self.selected.clone().ok_or_else(|| bad(tag, NO_MAILBOX))?;
        self.rescan(&selected)
            .map(|messages| selected.with(messages))
            .map_err(|err| self.no(tag, &format!("cannot rescan: {err}")))
    }

    /// The folder name a mailbox argument names, if this layout holds it.
    /// `INBOX` is case-insensitive (§5.1); `*`/`%` are wildcards, never names.
    pub(crate) fn folder_of(mailbox: &Mailbox<'_>) -> Option<String> {
        let name = match mailbox {
            Mailbox::Inbox => return Some(INBOX.to_owned()),
            Mailbox::Other(other) => String::from_utf8_lossy(other.inner().as_ref()).into_owned(),
        };
        (!name.contains(['*', '%']) && name.len() <= 200).then(|| {
            if name.eq_ignore_ascii_case(INBOX) {
                INBOX.to_owned()
            } else {
                name
            }
        })
    }

    pub(crate) fn list(&mut self, tag: &str, wildcard: &ListMailbox<'_>) -> Outcome {
        let pattern = match wildcard {
            ListMailbox::Token(token) => String::from_utf8_lossy(token.as_ref()).into_owned(),
            ListMailbox::String(string) => String::from_utf8_lossy(string.as_ref()).into_owned(),
        };
        let mut out = Vec::new();
        match self.reader.folders(&self.mailbox) {
            Err(err) => return self.no(tag, &format!("cannot list mailboxes: {err}")),
            Ok(folders) => {
                for mailbox in folders
                    .into_iter()
                    .filter(|f| glob(&pattern, f))
                    .filter_map(|f| Mailbox::try_from(f).ok())
                {
                    out.extend(self.untagged(&Data::List {
                        items: Vec::new(),
                        delimiter: None,
                        mailbox,
                    }));
                }
            }
        }
        out.extend(self.ok(tag, "LIST completed"));
        Outcome {
            out,
            ..Outcome::default()
        }
    }

    /// The folder's directory, its UID table, and its messages.
    pub(crate) fn census(&self, folder: &str) -> Result<Folder, String> {
        let dir = self
            .reader
            .folder_dir(&self.mailbox, folder, false)
            .map_err(|err| err.to_string())?;
        let mut map = UidMap::load(&dir).map_err(|err| format!("cannot read {UIDLIST}: {err}"))?;
        let messages = self
            .scan(&dir, &mut map)
            .map_err(|err| format!("cannot read mailbox: {err}"))?;
        Ok(Folder { dir, map, messages })
    }

    pub(crate) fn status(
        &mut self,
        tag: &str,
        mailbox: &Mailbox<'_>,
        items: &[StatusDataItemName],
    ) -> Outcome {
        let (folder, Folder { dir, map, messages }) = answer!(self.census_of(tag, mailbox));
        // RFC 7162 §3.1.2: `STATUS … (HIGHESTMODSEQ)` is a CONDSTORE enabling
        // command, so the one-time notice rides in front of the answer.
        let want_highest = items
            .iter()
            .any(|item| matches!(item, StatusDataItemName::HighestModSeq));
        let notice = if want_highest {
            self.enable_condstore()
        } else {
            Vec::new()
        };
        let Some(mapped) = items
            .iter()
            // The codec 1.0 status item list has no HIGHESTMODSEQ member —
            // the value is appended to the rendered line below.
            .filter(|item| !matches!(item, StatusDataItemName::HighestModSeq))
            .map(|item| status_value(item, &map, &messages))
            .collect::<Option<Vec<_>>>()
        else {
            return self.bad(tag, "that status item is not supported here");
        };
        let Ok(name) = Mailbox::try_from(folder) else {
            return self.bad(tag, BAD_MAILBOX);
        };
        let mut line = self.untagged(&Data::Status {
            mailbox: name,
            items: Cow::Owned(mapped),
        });
        if want_highest {
            let highest = modseq::table(&dir).map_or(0, |table| table.highest());
            // RFC 7162 §3.1.7: a mailbox with persistent mod-sequences
            // answers its true value (never `0`, never `NOMODSEQ`).
            ext_wire::insert_before_close(&mut line, &format!(" HIGHESTMODSEQ {highest}"));
        }
        let mut out = notice;
        out.extend(line);
        out.extend(self.ok(tag, "STATUS completed"));
        Outcome {
            out,
            ..Outcome::default()
        }
    }

    /// `SELECT`/`EXAMINE`, with the RFC 7162 §3.1.8 / §3.2.5 parameters when
    /// the client sent them.
    ///
    /// The order of what comes back is load-bearing: `[CLOSED]` first (RFC
    /// 7162 §3.2.11 — once CONDSTORE or QRESYNC is advertised, a change of
    /// mailbox announces the old one is closed), then RFC 3501 §6.3.2's own
    /// untagged run, then `[HIGHESTMODSEQ]`, then — for a QRESYNC parameter
    /// whose UIDVALIDITY matches — the `VANISHED (EARLIER)` line **before**
    /// the changed-message FETCH lines it summarizes (RFC 7162 §3.2.5).
    pub(crate) fn select(
        &mut self,
        tag: &str,
        mailbox: &Mailbox<'_>,
        read_only: bool,
        ext: &ExtParams,
    ) -> Outcome {
        // RFC 7162 §3.2.2: the parameter is refused until `ENABLE QRESYNC`
        // was answered positively — and refused *before* any mailbox is
        // opened (§3.2.5.1: a syntax problem never selects).
        if ext.select_qresync.is_some() && !self.qresync_enabled {
            return self.bad(tag, "QRESYNC parameter is only valid after ENABLE QRESYNC");
        }
        let (folder, Folder { dir, map, messages }) = answer!(self.census_of(tag, mailbox));
        let recent: Vec<u32> = messages
            .iter()
            .filter(|(_, _, in_cur)| !in_cur)
            .map(|(uid, _, _)| *uid)
            .collect();
        let first_unseen = messages
            .iter()
            .position(|(_, _, in_cur)| !in_cur)
            .and_then(|i| u32::try_from(i + 1).ok());
        let selected = Selected {
            folder: folder.clone(),
            dir: dir.clone(),
            read_only,
            messages: messages.clone(),
            recent: recent.clone(),
            highest_modseq: modseq::table(&dir).map_or(1, |table| table.highest()),
        };
        let mut out = Vec::new();
        if self.selected.is_some() {
            out.extend(ext_wire::closed_line());
        }
        // `(CONDSTORE)` and `(QRESYNC …)` are enabling commands (§3.1.2,
        // §3.2.2) — flipped before the responses that carry mod-sequences.
        if ext.select_condstore || ext.select_qresync.is_some() {
            self.condstore_enabled = true;
        }
        self.selected = Some(selected.clone());
        self.state = State::Selected;
        out.extend(self.untagged(&Data::Flags(system_flags())));
        let mut permanent: Vec<FlagPerm<'static>> =
            system_flags().into_iter().map(FlagPerm::Flag).collect();
        permanent.push(FlagPerm::Asterisk);
        out.extend(self.notice(Code::PermanentFlags(permanent), "Flags permitted"));
        out.extend(self.untagged(&Data::Exists(messages.len() as u32)));
        out.extend(self.untagged(&Data::Recent(recent.len() as u32)));
        if let Some(first) = first_unseen {
            out.extend(self.notice(Code::Unseen(non_zero(first)), "First unseen"));
        }
        out.extend(self.notice(Code::UidValidity(non_zero(map.validity)), "UIDs valid"));
        out.extend(self.notice(Code::UidNext(non_zero(map.next)), "Predicted next UID"));
        // RFC 7162 §3.1.2.1: the code rides every SELECT/EXAMINE once
        // CONDSTORE is active on the connection — via the parameter here, or
        // because an earlier enabling command already woke it.
        if self.condstore_enabled {
            out.extend(ext_wire::highestmodseq_line(selected.highest_modseq));
        }
        if let Some(qresync) = &ext.select_qresync {
            out.extend(self.qresync_initial_sync(&selected, &map, qresync));
        }
        out.extend(line(
            tag,
            Kind::Ok,
            Some(if read_only {
                Code::ReadOnly
            } else {
                Code::ReadWrite
            }),
            &format!("{folder} selected"),
            true,
        ));
        Outcome {
            out,
            ..Outcome::default()
        }
    }

    /// `ENABLE` (RFC 5161): acknowledges the extensions this server really
    /// switched on, ignores the rest (RFC 5161 §3.1: unknown parameters are
    /// answered, never refused).
    ///
    /// `QRESYNC` implies CONDSTORE (RFC 7162 §3.2.2); until the untagged
    /// `ENABLED` below goes out, the `(QRESYNC …)` SELECT parameter and the
    /// `VANISHED` fetch modifier must answer `BAD`.
    pub(crate) fn enable(&mut self, tag: &str, requested: &[CapabilityEnable<'_>]) -> Outcome {
        let mut enabled: Vec<CapabilityEnable<'static>> = Vec::new();
        let mut notice = Vec::new();
        for item in requested {
            // The codec spells `QRESYNC` as an unknown-capability atom at
            // 1.0 (it has no QRESYNC variant); its `Display` is the text the
            // client sent, so the name is read off that.
            let name = match item {
                CapabilityEnable::CondStore => "CONDSTORE".to_owned(),
                CapabilityEnable::Other(_) => item.to_string(),
                CapabilityEnable::Utf8(_) => continue,
                // `#[non_exhaustive]` upstream: a future variant is ignored,
                // exactly as RFC 5161 §3.1 asks of unknown parameters.
                _ => continue,
            };
            match name.to_ascii_uppercase().as_str() {
                "CONDSTORE" => {
                    if !self.condstore_enabled {
                        notice = self.enable_condstore();
                    }
                    enabled.push(CapabilityEnable::CondStore);
                }
                "QRESYNC" => {
                    // RFC 7162 §3.2.2: QRESYNC turns CONDSTORE on with it.
                    self.qresync_enabled = true;
                    notice = self.enable_condstore();
                    enabled.push(CapabilityEnable::try_from("QRESYNC").expect("an atom"));
                }
                // RFC 5161 §3.1: an unknown parameter is ignored, and the
                // `ENABLED` answer lists only what was really enabled.
                _ => {}
            }
        }
        let mut out = self.untagged(&Data::Enabled {
            capabilities: enabled,
        });
        out.extend(notice);
        out.extend(self.ok(tag, "ENABLE completed"));
        Outcome {
            out,
            ..Outcome::default()
        }
    }

    /// Marks CONDSTORE active and answers RFC 7162 §3.1.2.1's one-time
    /// notice — an untagged `* OK [HIGHESTMODSEQ n]` for the client that
    /// enabled late and was not there for its `SELECT`'s own code. Empty
    /// bytes when the connection is already enabled or has no mailbox open.
    pub(crate) fn enable_condstore(&mut self) -> Vec<u8> {
        if self.condstore_enabled {
            return Vec::new();
        }
        self.condstore_enabled = true;
        match &self.selected {
            Some(selected) => match modseq::table(&selected.dir) {
                Ok(table) => ext_wire::highestmodseq_line(table.highest()),
                Err(_) => Vec::new(),
            },
            None => Vec::new(),
        }
    }

    /// RFC 7162 §3.2.5's initial synchronization for a matching QRESYNC
    /// parameter: the `VANISHED (EARLIER)` line first, then one FETCH line
    /// per message that changed since the client's mod-sequence. A
    /// UIDVALIDITY mismatch ignores the parameters whole (§3.2.5.1) — the
    /// client is answered by the plain SELECT run above.
    fn qresync_initial_sync(
        &self,
        selected: &Selected,
        map: &UidMap,
        qresync: &QresyncParam,
    ) -> Vec<u8> {
        if map.validity != qresync.uidvalidity {
            return Vec::new();
        }
        let known = qresync
            .known_uids
            .clone()
            .unwrap_or_else(|| vec![(1, map.next.saturating_sub(1).max(1))]);
        let mut out = Vec::new();
        let vanished = self.vanished_earlier_uids(
            selected,
            map,
            qresync.modseq,
            Some(&known),
            qresync.seq_match.as_ref(),
        );
        if !vanished.is_empty() {
            out.extend(ext_wire::vanished_line(&vanished, true));
        }
        out.extend(self.changed_fetch_lines(selected, qresync.modseq, Some(&known)));
        out
    }
}
