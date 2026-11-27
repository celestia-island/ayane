//! The lifecycle commands that do not touch a message: `LIST`, `STATUS`,
//! `SELECT`/`EXAMINE`, `UNSELECT`, `CLOSE`, `EXPUNGE` and the re-scan a
//! `NOOP`/`CHECK` performs.

use std::borrow::Cow;

use imap_codec::imap_types::{
    flag::FlagPerm,
    mailbox::{ListMailbox, Mailbox},
    response::Code,
    response::{Data, Response, Status},
    status::StatusDataItemName,
};

use crate::maildir_reader::{MessageId, INBOX};

use super::session::{Folder, ImapSession, Selected, State, Transport};
use super::uidlist::{uid_validity, UidMap};
use super::wire::{
    bad, capabilities, encode, glob, is_deleted, line, non_zero, status_value, system_flags,
};
use super::{answer, Kind, Outcome, Row, BAD_MAILBOX, NO_MAILBOX, READ_ONLY, UIDLIST};

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
        let Some(mapped) = items
            .iter()
            .map(|item| status_value(item, &dir, &map, &messages))
            .collect::<Option<Vec<_>>>()
        else {
            return self.bad(tag, "that status item is not supported here");
        };
        let Ok(name) = Mailbox::try_from(folder) else {
            return self.bad(tag, BAD_MAILBOX);
        };
        self.reply(
            tag,
            "STATUS",
            Data::Status {
                mailbox: name,
                items: Cow::Owned(mapped),
            },
        )
    }

    pub(crate) fn select(&mut self, tag: &str, mailbox: &Mailbox<'_>, read_only: bool) -> Outcome {
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
        let validity = non_zero(uid_validity(&dir));
        self.selected = Some(Selected {
            folder: folder.clone(),
            dir,
            read_only,
            messages: messages.clone(),
            recent: recent.clone(),
        });
        self.state = State::Selected;
        let mut out = self.untagged(&Data::Flags(system_flags()));
        let mut permanent: Vec<FlagPerm<'static>> =
            system_flags().into_iter().map(FlagPerm::Flag).collect();
        permanent.push(FlagPerm::Asterisk);
        out.extend(self.notice(Code::PermanentFlags(permanent), "Flags permitted"));
        out.extend(self.untagged(&Data::Exists(messages.len() as u32)));
        out.extend(self.untagged(&Data::Recent(recent.len() as u32)));
        if let Some(first) = first_unseen {
            out.extend(self.notice(Code::Unseen(non_zero(first)), "First unseen"));
        }
        out.extend(self.notice(Code::UidValidity(validity), "UIDs valid"));
        out.extend(self.notice(Code::UidNext(non_zero(map.next)), "Predicted next UID"));
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

    pub(crate) fn close(&mut self, tag: &str) -> Outcome {
        let mut out = Vec::new();
        if let Some(selected) = self.selected.take().filter(|selected| !selected.read_only) {
            out.extend(self.expunge_now(&selected));
        }
        self.state = State::Authenticated;
        out.extend(self.ok(tag, "CLOSE completed"));
        Outcome {
            out,
            ..Outcome::default()
        }
    }

    pub(crate) fn expunge(&mut self, tag: &str) -> Outcome {
        let Some(selected) = self.selected.clone() else {
            return self.bad(tag, NO_MAILBOX);
        };
        if selected.read_only {
            return self.no(tag, READ_ONLY);
        }
        let Ok(messages) = self.rescan(&selected) else {
            return self.no(tag, "cannot rescan");
        };
        let selected = selected.with(messages);
        let mut out = self.expunge_now(&selected);
        let kept: Vec<Row> = selected
            .messages
            .iter()
            .filter(|(_, name, _)| !is_deleted(name))
            .cloned()
            .collect();
        let recent = selected
            .recent
            .iter()
            .copied()
            .filter(|uid| kept.iter().any(|(it, _, _)| it == uid))
            .collect();
        self.selected = Some(Selected {
            messages: kept,
            recent,
            ..selected
        });
        out.extend(self.ok(tag, "EXPUNGE completed"));
        Outcome {
            out,
            ..Outcome::default()
        }
    }

    /// Remove every `\Deleted` message, lowest number first — the order that
    /// makes each untagged `EXPUNGE` describe the list as the client now holds
    /// it (a message's number when it goes is its original position minus the
    /// ones already gone, counting itself).
    fn expunge_now(&self, selected: &Selected) -> Vec<u8> {
        let mut out = Vec::new();
        let mut removed = 0u32;
        for (index, (_, name, _)) in selected.messages.iter().enumerate() {
            let Some(id) = MessageId::parse(name).ok().filter(|id| id.flags().trashed) else {
                continue;
            };
            if self
                .reader
                .purge(&self.mailbox, &selected.folder, &id.file_name())
                .is_err()
            {
                continue;
            }
            removed += 1;
            if let Ok(original) = u32::try_from(index + 1) {
                out.extend(self.untagged(&Data::Expunge(non_zero(
                    original.saturating_sub(removed - 1),
                ))));
            }
        }
        out
    }

    /// Rescan the selection, announce mail another process wrote, and answer.
    pub(crate) fn refresh(&mut self, tag: &str) -> Outcome {
        let mut out = Vec::new();
        if let Some(selected) = self.selected.clone() {
            if let Ok(messages) = self.rescan(&selected) {
                let grew = messages.len() > selected.messages.len();
                let mut recent = selected.recent.clone();
                recent.extend(
                    messages
                        .iter()
                        .map(|(uid, _, _)| *uid)
                        .filter(|uid| !selected.is_recent(*uid)),
                );
                self.selected = Some(Selected {
                    messages: messages.clone(),
                    recent: recent.clone(),
                    ..selected
                });
                if grew {
                    out.extend(self.untagged(&Data::Exists(messages.len() as u32)));
                    out.extend(self.untagged(&Data::Recent(recent.len() as u32)));
                }
            }
        }
        out.extend(self.ok(tag, "NOOP completed"));
        Outcome {
            out,
            ..Outcome::default()
        }
    }
}
