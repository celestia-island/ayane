//! The IMAP4rev1 session: the RFC 3501 §3 state machine, the command set a
//! mail client actually uses, and the maildir backend behind both.
//!
//! The module opens no socket. The greeting and every reply are bytes a caller
//! writes; a client's literal is framed by [`read_command`] and handed to the
//! codec. The driver lives with the other listeners (`crate::server`), so the
//! state machine is drivable as a table in a test.
//!
//! # The state machine
//!
//! `NotAuthenticated → Authenticated → Selected → Logout`, with two gates:
//! `LOGIN`/`AUTHENTICATE PLAIN` are refused in the clear (RFC 3501 §11's
//! `LOGINDISABLED`, enforced rather than advertised alone — `STARTTLS` is the
//! only way in), and a read-only selection (`EXAMINE`) refuses every mutation.
//!
//! # Identifiers
//!
//! Sequence numbers are positions in the selected list, ordered by UID
//! (§2.3.1.2) — so `EXPUNGE`'s renumbering rule (§7.4.1) follows from the list
//! rather than from remembered state. A **UID lives in `ayane-uidlist`**, one
//! `uid name` line per message in the folder, because a maildir name is not a
//! stable identity: a flag change renames the file (`:2,S`) and so does a move
//! from `new/` into `cur/`. The table records the name's `unique` half, which
//! neither touches. It never reassigns a UID (`next` only grows), gives an
//! unknown message the next free UID in name order (so two sessions agree), and
//! is replaced atomically (`tmp` → `fsync` → `rename` → `fsync(dir)`), skipping
//! a line it cannot parse rather than making the folder unreadable.
//! `UIDVALIDITY` is a digest of the folder directory's inode and creation
//! stamp, so it is stable for the maildir's life and changes with the maildir.
//!
//! # Literals
//!
//! A literal is **not a line**: `{n}` plus CRLF is answered with a `+` line,
//! then exactly `n` octets are read as they come (they may hold CRLF, `{0}`, a
//! whole message).
//! [`read_command`] stops at the announcement, because a reader that reads past
//! it has swallowed the octets the client is still waiting to be asked for.
//!
//! # Not here
//!
//! `CONDSTORE`/`QRESYNC`, ACLs, quotas, `IMAP4rev2`, `UIDPLUS` and binary
//! literals are not advertised and not implemented (a client asking is answered
//! `NO`/`BAD`, never mis-served). `LITERAL+` and `MOVE` are advertised: a client
//! only uses a non-sync literal when offered it, and moving is what a mail
//! client does to every message it files.

use std::borrow::Cow;
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use ayane_proto::Address;
use imap_codec::{
    decode::{CommandDecodeError, Decoder},
    encode::{Encoder, Fragment},
    imap_types::{
        auth::AuthMechanism,
        body::{BasicFields, Body, BodyStructure, SpecificFields},
        command::{Command as Wire, CommandBody},
        core::{AString, IString, Literal, LiteralMode, NString, NonEmptyVec, Tag, Text},
        datetime::DateTime,
        envelope::{Address as EnvAddress, Envelope},
        fetch::{MacroOrMessageDataItemNames, MessageDataItem, MessageDataItemName, Section},
        flag::{Flag, FlagFetch, FlagPerm, StoreResponse, StoreType},
        mailbox::{ListMailbox, Mailbox},
        response::{Capability, Code, Data, Response, Status},
        search::SearchKey,
        sequence::{SequenceSet, Strategy},
        status::{StatusDataItem, StatusDataItemName},
    },
    CommandCodec, ResponseCodec,
};
use sha2::{Digest, Sha256};

use crate::authn::{decode_plain, PasswordVerifier};
use crate::maildir_reader::{
    FlagChange, Flags, MaildirReader, MessageId, ReaderError, Renamed, INBOX,
};

/// Unwrap a `Result` that carries an `Outcome` refusal: the operation's answer
/// is the refusal itself, so the caller returns it.
macro_rules! answer {
    ($e:expr) => {
        match $e {
            Ok(value) => value,
            Err(out) => return out,
        }
    };
}

/// The mapping file's name, inside the folder it describes.
pub const UIDLIST: &str = "ayane-uidlist";

/// The most a client's command may occupy, literals included.
pub const MAX_COMMAND_BYTES: usize = 32 * 1024 * 1024;

/// The most a command *line* (before its literal) may occupy.
pub const MAX_LINE_BYTES: usize = 8 * 1024;

/// One message as the selection holds it: its UID, its file name, and whether
/// it is in `cur/` (`new/` otherwise).
type Row = (u32, String, bool);

/// The `BAD` a command gets when no mailbox is selected.
const NO_MAILBOX: &str = "no mailbox is selected";
/// The `NO` a mutation gets on a read-only selection.
const READ_ONLY: &str = "[READ-ONLY] mailbox is read-only";
/// The `BAD` a command gets for a mailbox name this layout cannot hold.
const BAD_MAILBOX: &str = "mailbox name is not one this layout holds";

/// The system flags this mailbox reports, in RFC 3501 §2.3.2's order.
fn system_flags() -> Vec<Flag<'static>> {
    vec![
        Flag::Answered,
        Flag::Flagged,
        Flag::Deleted,
        Flag::Seen,
        Flag::Draft,
    ]
}

// ── the folder's identity table ──────────────────────────────────────────

/// A folder's UID table: the mapping from UID to maildir name, plus the
/// watermark the next UID comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UidMap {
    /// The next UID to hand out. Never decreases.
    pub next: u32,
    /// `(uid, unique name)`, ascending by UID.
    pub lines: Vec<(u32, String)>,
}

impl Default for UidMap {
    /// An empty table: the first UID is `1`.
    fn default() -> Self {
        Self {
            next: 1,
            lines: Vec::new(),
        }
    }
}

impl UidMap {
    /// Where the table lives inside `dir`.
    #[must_use]
    pub fn path(dir: &Path) -> PathBuf {
        dir.join(UIDLIST)
    }

    /// Read the table, or an empty one when the folder has never had a
    /// session (a folder only SMTP has written to, or a fresh one). A line
    /// that does not parse is skipped, not fatal.
    ///
    /// # Errors
    ///
    /// Returns [`io::Error`] when the file exists and cannot be read.
    pub fn load(dir: &Path) -> io::Result<Self> {
        let raw = match fs::read_to_string(Self::path(dir)) {
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(Self::default()),
            other => other?,
        };
        let mut map = Self::default();
        for line in raw.lines() {
            let Some((Ok(uid), Some(name))) = line
                .split_once(' ')
                .map(|(uid, name)| (uid.parse::<u32>(), Some(name)))
            else {
                continue;
            };
            if uid > 0 && MessageId::parse(name).is_ok() {
                map.next = map.next.max(uid.saturating_add(1));
                map.lines.push((uid, unique_of(name)));
            }
        }
        map.lines.sort_unstable();
        map.lines.dedup_by_key(|(uid, _)| *uid);
        Ok(map)
    }

    /// The UID `name` (with or without its flag suffix) is mapped to.
    #[must_use]
    pub fn uid_of(&self, name: &str) -> Option<u32> {
        let unique = unique_of(name);
        self.lines
            .iter()
            .find(|(_, it)| *it == unique)
            .map(|(uid, _)| *uid)
    }

    /// The `unique` half a UID was issued for.
    #[must_use]
    pub fn name_of(&self, uid: u32) -> Option<&str> {
        self.lines
            .iter()
            .find(|(it, _)| *it == uid)
            .map(|(_, name)| name.as_str())
    }

    /// Bring the table into step with what the folder holds now and answer
    /// `(uid, file name, in_cur)` sorted by UID.
    ///
    /// A name the table does not hold gets a fresh UID in `unique` order; a
    /// table line whose name is not live is **kept** — the file may be
    /// mid-rename in another process, and handing its UID to a later message
    /// is the one mistake a client can detect and never recover from.
    #[must_use]
    pub fn sync(&mut self, live: &[(String, String, bool)]) -> Vec<Row> {
        let mut out: Vec<Row> = self
            .lines
            .iter()
            .filter_map(|(uid, unique)| {
                live.iter()
                    .find(|(u, _, _)| u == unique)
                    .map(|(_, name, in_cur)| (*uid, name.clone(), *in_cur))
            })
            .collect();
        let mut fresh: Vec<&(String, String, bool)> = live
            .iter()
            .filter(|(u, _, _)| self.lines.iter().all(|(_, m)| m != u))
            .collect();
        fresh.sort_by(|a, b| a.0.cmp(&b.0));
        for (unique, name, in_cur) in fresh {
            let uid = self.next;
            self.next = self.next.saturating_add(1);
            self.lines.push((uid, unique.clone()));
            out.push((uid, name.clone(), *in_cur));
        }
        out.sort_unstable_by_key(|(uid, _, _)| *uid);
        out
    }

    /// Write the table durably and atomically. # Errors # Errors
    ///
    /// # Errors
    ///
    /// Returns [`io::Error`] when the temporary file, the `fsync` or the
    /// rename fails — a caller that swallows it has answered `OK` for
    /// something it did not record.
    pub fn store(&self, dir: &Path) -> io::Result<()> {
        fs::create_dir_all(dir)?;
        let text: String = self
            .lines
            .iter()
            .map(|(uid, name)| format!("{uid} {name}\n"))
            .collect();
        let tmp = dir.join(format!("{UIDLIST}.tmp"));
        let mut file = fs::File::create(&tmp)?;
        io::Write::write_all(&mut file, text.as_bytes())?;
        file.sync_all()?;
        drop(file);
        fs::rename(&tmp, Self::path(dir))?;
        crate::queue::fsync_dir(dir)
    }
}

/// The part of a maildir name a flag change does not touch.
fn unique_of(name: &str) -> String {
    MessageId::parse(name).map_or_else(|_| name.to_owned(), |id| id.unique().to_owned())
}

/// The folder's `UIDVALIDITY`: a digest of the directory's identity and
/// creation stamp — stable for the life of the maildir, different for a new
/// one at the same path, and `1` for a folder that does not exist yet.
#[must_use]
pub fn uid_validity(dir: &Path) -> u32 {
    let Ok(meta) = fs::metadata(dir) else {
        return 1;
    };
    let mut hasher = Sha256::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        hasher.update(meta.ino().to_be_bytes());
        hasher.update(meta.dev().to_be_bytes());
        hasher.update(meta.ctime().to_be_bytes());
    }
    #[cfg(not(unix))]
    hasher.update(meta.len().to_be_bytes());
    let digest = hasher.finalize();
    u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]).max(1)
}

// ── the session ──────────────────────────────────────────────────────────

/// The four RFC 3501 §3 states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// Before the client proved who it is.
    NotAuthenticated,
    /// The client is known; no mailbox is open.
    Authenticated,
    /// A mailbox is open, read-write (`SELECT`) or read-only (`EXAMINE`).
    Selected,
    /// `LOGOUT` arrived; the caller writes the bye and closes.
    Logout,
}

/// How the connection is reached — the one fact the state machine cannot see.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    /// Plaintext: `STARTTLS` is offered, a password is refused.
    Clear,
    /// Already inside TLS (implicit TLS, or after `STARTTLS`).
    Tls,
}

/// What one command produced.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Outcome {
    /// Bytes to write to the client, in order.
    pub out: Vec<u8>,
    /// The caller must now write this line (no CRLF: the handshake, not more
    /// text, follows it) and start TLS. Only `STARTTLS` sets it.
    pub start_tls: Option<Vec<u8>>,
    /// The caller must close the connection after writing `out`.
    pub close: bool,
}

/// A folder as one command sees it: where it is, its UID table, and its
/// messages.
struct Folder {
    dir: PathBuf,
    map: UidMap,
    messages: Vec<Row>,
}

/// A client's selection of a mailbox — the state `Selected` carries.
#[derive(Debug, Clone)]
struct Selected {
    /// `INBOX` or the folder name, in [`MaildirReader`]'s spelling.
    folder: String,
    /// The folder's directory.
    dir: PathBuf,
    /// `EXAMINE`: every mutation is refused.
    read_only: bool,
    /// `(uid, file name, in_cur)` at the last rescan; sequence number = index+1.
    messages: Vec<Row>,
    /// The UIDs this session announced as `\Recent`.
    recent: Vec<u32>,
}

impl Selected {
    /// Whether `uid` is recent *for this session*.
    fn is_recent(&self, uid: u32) -> bool {
        self.recent.contains(&uid)
    }

    /// The sequence number of `uid` (1 when it is no longer in the list).
    fn seq_of(&self, uid: u32) -> u32 {
        self.messages
            .iter()
            .position(|(it, _, _)| *it == uid)
            .and_then(|i| u32::try_from(i + 1).ok())
            .unwrap_or(1)
    }

    /// The `(uid, file name)` pair a UID or a 1-based sequence number names.
    fn row(&self, n: u32, by: By) -> Option<(u32, String)> {
        let row = match by {
            By::Seq => self.messages.get(usize::try_from(n).ok()?.checked_sub(1)?),
            By::Uid => self.messages.iter().find(|(uid, _, _)| *uid == n),
        }?;
        Some((row.0, row.1.clone()))
    }

    /// The largest value `*` means for this selector (`1` when empty: a
    /// mailbox with no messages has no valid `*`).
    fn largest(&self, by: By) -> u32 {
        match by {
            By::Seq => u32::try_from(self.messages.len())
                .unwrap_or(u32::MAX)
                .max(1),
            By::Uid => self
                .messages
                .iter()
                .map(|(uid, _, _)| *uid)
                .max()
                .unwrap_or(1),
        }
    }

    /// The same selection with a new message list.
    fn with(&self, messages: Vec<Row>) -> Self {
        Self {
            messages,
            ..self.clone()
        }
    }
}

/// How a sequence set selects messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum By {
    /// `1..=n` over the selection's current list.
    Seq,
    /// The UIDs themselves.
    Uid,
}

/// One IMAP session: the state, the selection, and the credentials check.
pub struct ImapSession<'a> {
    hostname: String,
    mailbox: Address,
    reader: MaildirReader,
    transport: Transport,
    state: State,
    selected: Option<Selected>,
    passwords: &'a dyn PasswordVerifier,
}

impl std::fmt::Debug for ImapSession<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ImapSession")
            .field("mailbox", &"<redacted>")
            .field("transport", &self.transport)
            .field("state", &self.state)
            .field("folder", &self.selected.as_ref().map(|s| s.folder.as_str()))
            .finish_non_exhaustive()
    }
}

impl<'a> ImapSession<'a> {
    /// A session for `mailbox`, reached over `transport`.
    #[must_use]
    pub fn new(
        hostname: impl Into<String>,
        mailbox: Address,
        reader: MaildirReader,
        transport: Transport,
        passwords: &'a dyn PasswordVerifier,
    ) -> Self {
        Self {
            hostname: hostname.into(),
            mailbox,
            reader,
            transport,
            state: State::NotAuthenticated,
            selected: None,
            passwords,
        }
    }

    /// The state the session is in.
    #[must_use]
    pub fn state(&self) -> State {
        self.state
    }

    /// The greeting the caller writes first (RFC 3501 §7.1).
    #[must_use]
    pub fn greeting(&self) -> Vec<u8> {
        let mut out = self.notice(
            Code::Capability(capabilities(self.transport)),
            &self.hostname,
        );
        trim_crlf(&mut out);
        out.extend_from_slice(b" IMAP4rev1 ready\r\n");
        out
    }

    /// What this connection advertises, as text.
    #[must_use]
    pub fn capabilities(&self) -> &'static str {
        match self.transport {
            Transport::Clear => "IMAP4rev1 STARTTLS LOGINDISABLED MOVE LITERAL+",
            Transport::Tls => "IMAP4rev1 AUTH=PLAIN MOVE LITERAL+",
        }
    }

    /// Handle one parsed command and answer with what to write.
    pub async fn handle(&mut self, command: &Wire<'_>) -> Outcome {
        let tag = command.tag.as_ref().to_owned();
        if self.state == State::Logout {
            return self.bad(&tag, "no commands after LOGOUT");
        }
        if let Some(refusal) = state_refusal(self.state, &command.body) {
            return self.bad(&tag, refusal);
        }
        use CommandBody as B;
        match &command.body {
            B::Capability => self.reply(
                &tag,
                "CAPABILITY",
                Data::Capability(capabilities(self.transport)),
            ),
            B::Noop | B::Check => self.refresh(&tag),
            B::Logout => {
                let mut out = self.contained(&Status::bye(None, "Logging out").expect("bye"));
                out.extend(self.ok(&tag, "LOGOUT completed"));
                self.state = State::Logout;
                Outcome {
                    out,
                    close: true,
                    ..Outcome::default()
                }
            }
            // The line carries no CRLF: the handshake, not more text, follows.
            B::StartTLS => Outcome {
                start_tls: Some(line(
                    &tag,
                    Kind::Ok,
                    None,
                    "Begin TLS negotiation now",
                    false,
                )),
                ..Outcome::default()
            },
            B::Login { username, password } => {
                self.authenticate(
                    &tag,
                    &astring_text(username),
                    &astring_text(password.declassify()),
                )
                .await
            }
            B::Authenticate {
                initial_response, ..
            } => match initial_response {
                None => self.no(&tag, "SASL initial response required"),
                Some(initial) => match decode_plain(&String::from_utf8_lossy(initial.declassify()))
                {
                    Ok((user, pass)) => self.authenticate(&tag, &user, &pass).await,
                    Err(_) => self.no(&tag, "[AUTHENTICATIONFAILED] malformed PLAIN response"),
                },
            },
            B::List {
                mailbox_wildcard, ..
            } => self.list(&tag, mailbox_wildcard),
            B::Lsub { .. } => Outcome {
                out: self.ok(&tag, "LSUB completed"),
                ..Outcome::default()
            },
            B::Status {
                mailbox,
                item_names,
            } => self.status(&tag, mailbox, item_names),
            B::Select { mailbox } => self.select(&tag, mailbox, false),
            B::Examine { mailbox } => self.select(&tag, mailbox, true),
            B::Unselect => {
                self.selected = None;
                self.state = State::Authenticated;
                Outcome {
                    out: self.ok(&tag, "UNSELECT completed"),
                    ..Outcome::default()
                }
            }
            B::Close => self.close(&tag),
            B::Expunge => self.expunge(&tag),
            B::Append {
                mailbox,
                flags,
                message,
                ..
            } => self.append(&tag, mailbox, flags, message.data()),
            B::Fetch {
                sequence_set,
                macro_or_item_names,
                uid,
            } => self.fetch(&tag, sequence_set, macro_or_item_names, *uid),
            B::Store {
                sequence_set,
                kind,
                response,
                flags,
                uid,
            } => self.store(&tag, sequence_set, *kind, *response, flags, *uid),
            B::Search { criteria, uid, .. } => self.search(&tag, criteria, *uid),
            B::Copy {
                sequence_set,
                mailbox,
                uid,
            } => self.copy(&tag, sequence_set, mailbox, *uid, false),
            B::Move {
                sequence_set,
                mailbox,
                uid,
            } => self.copy(&tag, sequence_set, mailbox, *uid, true),
            other => self.bad(&tag, &format!("{} is not implemented here", name_of(other))),
        }
    }
}

impl ImapSession<'_> {
    fn untagged(&self, data: &Data<'_>) -> Vec<u8> {
        encode(&Response::Data(data.clone()))
    }

    fn contained(&self, status: &Status<'_>) -> Vec<u8> {
        encode(&Response::Status(status.clone()))
    }

    /// An untagged `OK [<code>] …` line.
    fn notice(&self, code: Code<'_>, text: &str) -> Vec<u8> {
        self.contained(&Status::ok(None, Some(code), text).expect("a short code"))
    }

    fn ok(&self, tag: &str, text: &str) -> Vec<u8> {
        line(tag, Kind::Ok, None, text, true)
    }

    fn no(&self, tag: &str, text: &str) -> Outcome {
        Outcome {
            out: line(tag, Kind::No, None, text, true),
            ..Outcome::default()
        }
    }

    fn bad(&self, tag: &str, text: &str) -> Outcome {
        Outcome {
            out: line(tag, Kind::Bad, None, text, true),
            ..Outcome::default()
        }
    }

    /// An untagged line followed by the tagged `OK` that completes a command.
    fn reply(&self, tag: &str, name: &str, data: Data<'_>) -> Outcome {
        let mut out = self.untagged(&data);
        out.extend(self.ok(tag, &format!("{name} completed")));
        Outcome {
            out,
            ..Outcome::default()
        }
    }

    async fn authenticate(&mut self, tag: &str, user: &str, pass: &str) -> Outcome {
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
                Some(Code::Capability(capabilities(self.transport))),
                "Logged in",
                true,
            ),
            ..Outcome::default()
        }
    }

    /// A command's mailbox argument, resolved to its folder and read.
    fn census_of(&self, tag: &str, mailbox: &Mailbox<'_>) -> Result<(String, Folder), Outcome> {
        let folder = Self::folder(tag, mailbox)?;
        let census = self.census(&folder).map_err(|err| self.no(tag, &err))?;
        Ok((folder, census))
    }

    /// The folder a command's mailbox argument names, or the `BAD` that
    /// answers a name this layout cannot hold.
    fn folder(tag: &str, mailbox: &Mailbox<'_>) -> Result<String, Outcome> {
        Self::folder_of(mailbox).ok_or_else(|| bad(tag, BAD_MAILBOX))
    }

    /// The selection, re-read, or the `BAD`/`NO` that answers it.
    fn current(&self, tag: &str) -> Result<Selected, Outcome> {
        let selected = self.selected.clone().ok_or_else(|| bad(tag, NO_MAILBOX))?;
        self.rescan(&selected)
            .map(|messages| selected.with(messages))
            .map_err(|err| self.no(tag, &format!("cannot rescan: {err}")))
    }

    /// The folder name a mailbox argument names, if this layout holds it.
    /// `INBOX` is case-insensitive (§5.1); `*`/`%` are wildcards, never names.
    fn folder_of(mailbox: &Mailbox<'_>) -> Option<String> {
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

    fn list(&mut self, tag: &str, wildcard: &ListMailbox<'_>) -> Outcome {
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
    fn census(&self, folder: &str) -> Result<Folder, String> {
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

    fn status(
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

    fn select(&mut self, tag: &str, mailbox: &Mailbox<'_>, read_only: bool) -> Outcome {
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

    fn close(&mut self, tag: &str) -> Outcome {
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

    fn expunge(&mut self, tag: &str) -> Outcome {
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
    fn refresh(&mut self, tag: &str) -> Outcome {
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

    // ── the maildir side ─────────────────────────────────────────────────

    /// The folder's messages as `(unique, file name, in_cur)`. `new/` first.
    fn live(dir: &Path) -> io::Result<Vec<(String, String, bool)>> {
        let mut live = Vec::new();
        for (sub, in_cur) in [("new", false), ("cur", true)] {
            let Ok(entries) = fs::read_dir(dir.join(sub)) else {
                continue;
            };
            for entry in entries.flatten() {
                let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                    continue;
                };
                if let (false, true, Ok(id)) = (
                    name.starts_with('.'),
                    entry.path().is_file(),
                    MessageId::parse(&name),
                ) {
                    live.push((id.unique().to_owned(), name, in_cur));
                }
            }
        }
        Ok(live)
    }

    /// Rescan a folder through its table, storing the table if it grew.
    fn scan(&self, dir: &Path, map: &mut UidMap) -> io::Result<Vec<Row>> {
        let before = map.clone();
        let list = map.sync(&Self::live(dir)?);
        if *map != before {
            map.store(dir)?;
        }
        Ok(list)
    }

    /// Re-derive a selection's list.
    fn rescan(&self, selected: &Selected) -> io::Result<Vec<Row>> {
        self.scan(&selected.dir, &mut UidMap::load(&selected.dir)?)
    }

    /// One untagged `FETCH` line for a message, if every item can be built.
    fn fetch_line(
        &self,
        selected: &Selected,
        uid: u32,
        items: Vec<MessageDataItem<'_>>,
    ) -> Option<Vec<u8>> {
        NonEmptyVec::try_from(items).ok().map(|items| {
            self.untagged(&Data::Fetch {
                seq: non_zero(selected.seq_of(uid)),
                items,
            })
        })
    }

    /// The `(uid, file name)` pairs a sequence set names.
    fn resolve(selected: &Selected, set: &SequenceSet, by: By) -> Vec<(u32, String)> {
        set.iter(Strategy::Naive {
            largest: non_zero(selected.largest(by)),
        })
        .filter_map(|n| selected.row(n.get(), by))
        .collect()
    }

    fn append(
        &mut self,
        tag: &str,
        mailbox: &Mailbox<'_>,
        flags: &[Flag<'_>],
        bytes: &[u8],
    ) -> Outcome {
        let folder = match Self::folder(tag, mailbox) {
            Ok(folder) => folder,
            Err(out) => return out,
        };
        let wanted = Flags {
            seen: flags.contains(&Flag::Seen),
            flagged: flags.contains(&Flag::Flagged),
            trashed: flags.contains(&Flag::Deleted),
            draft: flags.contains(&Flag::Draft),
        };
        // RFC 3501 §6.3.11 lets APPEND carry a message with no header at all,
        // so the bytes are stored as they arrived.
        let Some(uid) = self
            .reader
            .append(&self.mailbox, &folder, bytes, wanted)
            .ok()
            .and_then(|name| self.census(&folder).ok()?.map.uid_of(&name))
        else {
            return self.no(tag, "cannot append");
        };
        let mut out = Vec::new();
        if let Some(selected) = self
            .selected
            .clone()
            .filter(|selected| selected.folder == folder)
        {
            let messages = self
                .census(&folder)
                .map(|folder| folder.messages)
                .unwrap_or_default();
            let mut recent = selected.recent.clone();
            recent.push(uid);
            self.selected = Some(Selected {
                messages: messages.clone(),
                recent,
                ..selected
            });
            out.extend(self.untagged(&Data::Exists(messages.len() as u32)));
        }
        out.extend(line(
            tag,
            Kind::Ok,
            None,
            &format!("APPEND completed (UID {uid})"),
            true,
        ));
        Outcome {
            out,
            ..Outcome::default()
        }
    }

    fn fetch(
        &mut self,
        tag: &str,
        set: &SequenceSet,
        names: &MacroOrMessageDataItemNames<'_>,
        uid: bool,
    ) -> Outcome {
        let selected = answer!(self.current(tag));
        let wanted: Vec<MessageDataItemName<'_>> = match names {
            MacroOrMessageDataItemNames::Macro(macro_item) => macro_item.expand(),
            MacroOrMessageDataItemNames::MessageDataItemNames(names) => names.clone(),
        };
        let mut out = Vec::new();
        for (message_uid, name) in
            Self::resolve(&selected, set, if uid { By::Uid } else { By::Seq })
        {
            let Ok(id) = MessageId::parse(&name) else {
                continue;
            };
            let Ok(raw) = self
                .reader
                .read_raw(&self.mailbox, &selected.folder, &id.file_name())
            else {
                continue;
            };
            let Some(rendered) = wanted
                .iter()
                .map(|item| render_item(item, &raw, &id, message_uid, &selected))
                .collect::<Option<Vec<_>>>()
            else {
                return self.bad(tag, "that data item is not supported here");
            };
            // `BODY[…]` (not `BODY.PEEK[…]`) sets `\Seen` — RFC 3501 §6.4.5.
            if wanted
                .iter()
                .any(|item| matches!(item, MessageDataItemName::BodyExt { peek: false, .. }))
                && !selected.read_only
                && !id.flags().seen
            {
                let _ = self.reader.set_flags(
                    &self.mailbox,
                    &selected.folder,
                    &id.file_name(),
                    FlagChange {
                        seen: Some(true),
                        flagged: None,
                    },
                );
            }
            if let Some(line) = self.fetch_line(&selected, message_uid, rendered) {
                out.extend(line);
            }
        }
        out.extend(self.ok(tag, "FETCH completed"));
        Outcome {
            out,
            ..Outcome::default()
        }
    }

    fn store(
        &mut self,
        tag: &str,
        set: &SequenceSet,
        kind: StoreType,
        response: StoreResponse,
        flags: &[Flag<'_>],
        uid: bool,
    ) -> Outcome {
        let selected = answer!(self.current(tag));
        if selected.read_only {
            return self.no(tag, READ_ONLY);
        }
        let wanted = Flags {
            seen: flags.contains(&Flag::Seen),
            flagged: flags.contains(&Flag::Flagged),
            trashed: flags.contains(&Flag::Deleted),
            draft: flags.contains(&Flag::Draft),
        };
        let mut out = Vec::new();
        for (message_uid, name) in
            Self::resolve(&selected, set, if uid { By::Uid } else { By::Seq })
        {
            let Ok(id) = MessageId::parse(&name) else {
                continue;
            };
            let Ok(renamed) = self.apply_flags(&selected.folder, &id, kind, wanted) else {
                continue;
            };
            if response == StoreResponse::Answer {
                let items = vec![
                    MessageDataItem::Uid(non_zero(message_uid)),
                    MessageDataItem::Flags(flags_of(&renamed.to)),
                ];
                if let Some(line) = self.fetch_line(&selected, message_uid, items) {
                    out.extend(line);
                }
            }
        }
        out.extend(self.ok(tag, "STORE completed"));
        Outcome {
            out,
            ..Outcome::default()
        }
    }

    /// Apply one `STORE` to one message: two renames, because the flags live
    /// in the name and `\Deleted` is its `T`.
    fn apply_flags(
        &self,
        folder: &str,
        id: &MessageId,
        kind: StoreType,
        wanted: Flags,
    ) -> Result<Renamed, ReaderError> {
        let now = id.flags();
        let (seen, flagged, trashed) = match kind {
            StoreType::Replace => (wanted.seen, wanted.flagged, wanted.trashed),
            StoreType::Add => (
                now.seen || wanted.seen,
                now.flagged || wanted.flagged,
                now.trashed || wanted.trashed,
            ),
            StoreType::Remove => (
                now.seen && !wanted.seen,
                now.flagged && !wanted.flagged,
                now.trashed && !wanted.trashed,
            ),
        };
        let first = self.reader.set_flags(
            &self.mailbox,
            folder,
            &id.file_name(),
            FlagChange {
                seen: Some(seen),
                flagged: Some(flagged),
            },
        )?;
        if first.flags.trashed == trashed {
            return Ok(first);
        }
        let cur = reader_dir(&self.reader, &self.mailbox, folder).join("cur");
        let parsed = MessageId::parse(&first.to)?;
        let target = parsed.with_flags(Flags {
            trashed,
            ..parsed.flags()
        });
        let (from, to) = (cur.join(&first.to), cur.join(target.file_name()));
        if from != to {
            fs::rename(&from, &to).map_err(|err| ReaderError::Io {
                path: from.display().to_string(),
                source: err,
            })?;
            let _ = crate::queue::fsync_dir(&cur);
        }
        Ok(Renamed {
            from: first.from,
            to: target.file_name(),
            flags: target.flags(),
        })
    }

    fn search(&mut self, tag: &str, criteria: &SearchKey<'_>, uid: bool) -> Outcome {
        let selected = answer!(self.current(tag));
        let mut hits = Vec::new();
        for (index, (message_uid, name, in_cur)) in selected.messages.iter().enumerate() {
            let Ok(id) = MessageId::parse(name) else {
                continue;
            };
            let (Ok(seq), Ok(size)) = (
                u32::try_from(index + 1),
                fs::metadata(
                    selected
                        .dir
                        .join(if *in_cur { "cur" } else { "new" })
                        .join(name),
                )
                .map(|meta| meta.len()),
            ) else {
                continue;
            };
            let flags = id.flags();
            let raw = self
                .reader
                .read_raw(&self.mailbox, &selected.folder, &id.file_name())
                .unwrap_or_default();
            let ctx = SearchContext {
                seq,
                uid: *message_uid,
                flags,
                unseen: !in_cur && !flags.seen,
                recent: selected.is_recent(*message_uid),
                size,
            };
            if matches_key(criteria, &ctx, &raw) {
                hits.push(non_zero(if uid { *message_uid } else { seq }));
            }
        }
        self.reply(tag, "SEARCH", Data::Search(hits))
    }

    fn copy(
        &mut self,
        tag: &str,
        set: &SequenceSet,
        mailbox: &Mailbox<'_>,
        uid: bool,
        remove: bool,
    ) -> Outcome {
        let folder = match Self::folder(tag, mailbox) {
            Ok(folder) => folder,
            Err(out) => return out,
        };
        let selected = answer!(self.current(tag));
        if selected.read_only {
            return self.no(tag, READ_ONLY);
        }
        let mut out = Vec::new();
        for (message_uid, name) in
            Self::resolve(&selected, set, if uid { By::Uid } else { By::Seq })
        {
            let Ok(id) = MessageId::parse(&name) else {
                continue;
            };
            let written = if remove {
                self.reader
                    .move_to(&self.mailbox, &selected.folder, &id.file_name(), &folder)
            } else {
                self.reader
                    .read_raw(&self.mailbox, &selected.folder, &id.file_name())
                    .and_then(|raw| {
                        self.reader
                            .append(&self.mailbox, &folder, &raw, id.flags())
                            .map(|to| Renamed {
                                from: id.file_name(),
                                to,
                                flags: id.flags(),
                            })
                    })
            };
            if written.is_err() {
                continue;
            }
            // The copy needs a UID in its new folder before a client can name
            // it; `UIDPLUS` is not advertised, so nothing claims one.
            let dir = reader_dir(&self.reader, &self.mailbox, &folder);
            let _ = self.scan(&dir, &mut UidMap::load(&dir).unwrap_or_default());
            if remove {
                out.extend(self.untagged(&Data::Expunge(non_zero(selected.seq_of(message_uid)))));
            }
        }
        out.extend(self.ok(
            tag,
            &format!("{} completed", if remove { "MOVE" } else { "COPY" }),
        ));
        Outcome {
            out,
            ..Outcome::default()
        }
    }
}

// ── helpers ──────────────────────────────────────────────────────────────

/// One of the three status kinds a reply line can carry.
#[derive(Debug, Clone, Copy)]
enum Kind {
    Ok,
    No,
    Bad,
}

/// One tagged reply line. `terminated` appends the CRLF that ends a command;
/// `STARTTLS` answers with the same line unterminated, because the handshake
/// follows it.
fn line(tag: &str, kind: Kind, code: Option<Code<'_>>, text: &str, terminated: bool) -> Vec<u8> {
    let Ok(tag) = Tag::try_from(tag.to_owned()) else {
        return Vec::new();
    };
    let text: Text<'_> = text
        .try_into()
        .unwrap_or_else(|_| "error".try_into().expect("a literal text"));
    let tag = Some(tag);
    let status = match kind {
        Kind::Ok => Status::Ok { tag, code, text },
        Kind::No => Status::No { tag, code, text },
        Kind::Bad => Status::Bad { tag, code, text },
    };
    let mut out = encode(&Response::Status(status));
    trim_crlf(&mut out);
    if terminated {
        out.extend_from_slice(b"\r\n");
    }
    out
}

/// A tagged `BAD` without a session (for the helpers that have no `self`).
fn bad(tag: &str, text: &str) -> Outcome {
    Outcome {
        out: line(tag, Kind::Bad, None, text, true),
        ..Outcome::default()
    }
}

/// Why `body` may not run in `state`, if it may not.
fn state_refusal(state: State, body: &CommandBody<'_>) -> Option<&'static str> {
    use CommandBody as B;
    let proof = matches!(body, B::Login { .. } | B::Authenticate { .. } | B::StartTLS);
    if proof {
        return (state != State::NotAuthenticated)
            .then_some("command is not permitted after authentication");
    }
    let any_state = matches!(body, B::Capability | B::Noop | B::Check | B::Logout);
    (state == State::NotAuthenticated && !any_state).then_some("must authenticate first")
}

/// This connection's capabilities.
fn capabilities(transport: Transport) -> NonEmptyVec<Capability<'static>> {
    let mut caps = vec![Capability::Imap4Rev1];
    caps.extend(match transport {
        Transport::Clear => vec![Capability::StartTls, Capability::LoginDisabled],
        Transport::Tls => vec![Capability::Auth(AuthMechanism::Plain)],
    });
    caps.extend([Capability::Move, Capability::LiteralPlus]);
    NonEmptyVec::try_from(caps).expect("capabilities are never empty")
}

/// The folder's directory, in [`MaildirReader`]'s spelling.
fn reader_dir(reader: &MaildirReader, mailbox: &Address, folder: &str) -> PathBuf {
    reader
        .folder_dir(mailbox, folder, false)
        .unwrap_or_default()
}

/// A `u32` as the non-zero number the protocol wants (0 becomes 1).
pub(crate) fn non_zero(value: u32) -> std::num::NonZeroU32 {
    std::num::NonZeroU32::new(value).unwrap_or(std::num::NonZeroU32::MIN)
}

/// Drop a trailing CRLF the encoder appended.
fn trim_crlf(bytes: &mut Vec<u8>) {
    if bytes.ends_with(b"\r\n") {
        bytes.truncate(bytes.len() - 2);
    }
}

/// A `StatusDataItem` for one requested name, or `None` when this server does
/// not answer it.
fn status_value(
    item: &StatusDataItemName,
    dir: &Path,
    map: &UidMap,
    messages: &[(u32, String, bool)],
) -> Option<StatusDataItem> {
    Some(match item {
        StatusDataItemName::Messages => StatusDataItem::Messages(messages.len() as u32),
        StatusDataItemName::Recent => {
            StatusDataItem::Recent(messages.iter().filter(|(_, _, in_cur)| !in_cur).count() as u32)
        }
        StatusDataItemName::UidNext => StatusDataItem::UidNext(non_zero(map.next)),
        StatusDataItemName::UidValidity => StatusDataItem::UidValidity(non_zero(uid_validity(dir))),
        StatusDataItemName::Unseen => StatusDataItem::Unseen(
            messages.iter().filter(|(_, n, _)| !flag_of(n, 'S')).count() as u32,
        ),
        _ => return None,
    })
}

/// Whether the name carries a maildir flag suffix.
fn flag_of(name: &str, flag: char) -> bool {
    MessageId::parse(name).is_ok_and(|id| id.suffix().contains(flag))
}

/// Whether the name carries the maildir `T` suffix (`\Deleted`).
fn is_deleted(name: &str) -> bool {
    flag_of(name, 'T')
}

/// The flags a maildir name carries, as the protocol spells them.
fn flags_of(name: &str) -> Vec<FlagFetch<'static>> {
    [
        ('S', Flag::Seen),
        ('F', Flag::Flagged),
        ('T', Flag::Deleted),
        ('D', Flag::Draft),
    ]
    .into_iter()
    .filter(|(suffix, _)| flag_of(name, *suffix))
    .map(|(_, flag)| FlagFetch::Flag(flag))
    .collect()
}

/// `LIST` wildcards (RFC 3501 §6.3.8). The layout is flat, so `%` and `*`
/// select the same folders.
fn glob(pattern: &str, name: &str) -> bool {
    fn go(p: &[u8], n: &[u8]) -> bool {
        match (p.first(), n.first()) {
            (None, None) => true,
            (Some(b'*' | b'%'), _) => go(&p[1..], n) || (!n.is_empty() && go(p, &n[1..])),
            (Some(c), Some(d)) if c.eq_ignore_ascii_case(d) => go(&p[1..], &n[1..]),
            _ => false,
        }
    }
    go(pattern.as_bytes(), name.as_bytes())
}

/// The text of an `AString` as the protocol carried it.
fn astring_text(value: &AString<'_>) -> String {
    match value {
        AString::Atom(atom) => atom.as_ref().to_owned(),
        AString::String(string) => String::from_utf8_lossy(string.as_ref()).into_owned(),
    }
}

/// Encode one server response.
fn encode(response: &Response<'_>) -> Vec<u8> {
    let mut out = Vec::new();
    for fragment in ResponseCodec::default().encode(response) {
        match fragment {
            Fragment::Line { data } => out.extend_from_slice(&data),
            // A response literal is announced the same way a client's is; the
            // client is already reading, so nothing is negotiated.
            Fragment::Literal { data, .. } => {
                out.extend_from_slice(format!("{{{}}}\r\n", data.len()).as_bytes());
                out.extend_from_slice(&data);
            }
        }
    }
    out
}

/// The name of a command, for a `BAD` that names what it refused.
fn name_of(body: &CommandBody<'_>) -> &'static str {
    match body {
        CommandBody::Create { .. } => "CREATE",
        CommandBody::Delete { .. } => "DELETE",
        CommandBody::Rename { .. } => "RENAME",
        CommandBody::Subscribe { .. } | CommandBody::Unsubscribe { .. } => "SUBSCRIBE",
        CommandBody::Idle => "IDLE",
        _ => "command",
    }
}

// ── literal framing ──────────────────────────────────────────────────────

/// What [`read_command`] produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Framed {
    /// A complete command, plus the continuation lines the caller must write
    /// *before* the client will send the rest.
    Complete {
        /// The command's bytes, exactly as the codec wants them.
        bytes: Vec<u8>,
        /// `+ …` lines, in arrival order.
        continuations: Vec<Vec<u8>>,
    },
    /// The peer closed cleanly between commands.
    Eof,
    /// The command cannot be served; the caller writes `<tag> BAD …`.
    Refused(String),
}

/// Read one client command, literals included, from `stream`.
///
/// A literal is **not a line**: `{n}\r\n` is answered with a continuation
/// (unless the client wrote `{n+}`, which needs no permission), and then
/// exactly `n` octets are taken as they come — the `\r\n` inside them are data,
/// not framing.
///
/// # Errors
///
/// Returns [`io::Error`] when the stream fails.
pub fn read_command<R: Read>(stream: &mut R) -> io::Result<Framed> {
    let mut pending: Vec<u8> = Vec::new();
    let mut continuations: Vec<Vec<u8>> = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        // A literal's announcement is what the reader must *stop at*: the
        // client is waiting for `+` and will not send the octets until it
        // arrives. So bytes are taken one at a time, and the announcement is
        // looked for the moment a CRLF completes a line — never after octets
        // that belong to the literal have already been read.
        if let Some((tag, length, mode)) = announcement(&pending) {
            if pending.len() + length as usize > MAX_COMMAND_BYTES {
                return Ok(Framed::Refused(tag));
            }
            if mode == LiteralMode::Sync {
                continuations.push(format!("+ Ready for {length} octets\r\n").into_bytes());
            }
            let mut literal = vec![0u8; length as usize];
            stream.read_exact(&mut literal)?;
            pending.extend_from_slice(&literal);
            continue;
        }
        match CommandCodec::default().decode(&pending) {
            Ok(_) => {
                return Ok(Framed::Complete {
                    bytes: pending,
                    continuations,
                })
            }
            Err(CommandDecodeError::Incomplete | CommandDecodeError::LiteralFound { .. }) => {}
            Err(CommandDecodeError::Failed) => {
                // A malformed line is skipped to its CRLF, so the next command
                // starts where the client believes a command starts.
                if let Some(end) = pending.windows(2).position(|window| window == b"\r\n") {
                    return Ok(Framed::Refused(tag_of(&pending[..end])));
                }
            }
        }
        if pending.len() > MAX_LINE_BYTES {
            return Ok(Framed::Refused(tag_of(&pending)));
        }
        if stream.read(&mut byte)? == 0 {
            return Ok(Framed::Eof);
        }
        pending.push(byte[0]);
    }
}

/// The literal announcement a client is waiting on, if `pending` ends with
/// one.
///
/// An announcement is the one part of an IMAP command an **unfinished** buffer
/// can hold: the client stops there and will not send the octets until it
/// hears `+`. So the check is on the last line's end — `…{123}` or `…{123+}`,
/// with or without the announcing CRLF. A `{5}` inside literal octets is never
/// there, and `{}` with nothing in the braces is an empty flag list.
fn announcement(pending: &[u8]) -> Option<(String, u32, LiteralMode)> {
    let body = pending.strip_suffix(b"\r\n").unwrap_or(pending);
    let line = match body.iter().rposition(|byte| *byte == b'\n') {
        Some(at) => &body[at + 1..],
        None => body,
    };
    if !line.ends_with(b"}") {
        return None;
    }
    let open = line[..line.len() - 1]
        .iter()
        .rposition(|byte| *byte == b'{')?;
    // A literal follows a separator: `{}` is an empty flag list.
    if open == 0 || line[open - 1] != b' ' {
        return None;
    }
    let (digits, mode) = match line[open + 1..line.len() - 1].strip_suffix(b"+") {
        Some(digits) => (digits, LiteralMode::NonSync),
        None => (&line[open + 1..line.len() - 1], LiteralMode::Sync),
    };
    if digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) {
        return None;
    }
    Some((
        tag_of(pending),
        std::str::from_utf8(digits).ok()?.parse().ok()?,
        mode,
    ))
}

/// The announcement [`read_command`] made for these bytes, as `(tag, octets,
/// whether it is non-sync)` — exposed so a test can assert the framing
/// without a socket.
#[must_use]
pub fn announcement_of(pending: &[u8]) -> Option<(String, u32, bool)> {
    announcement(pending).map(|(tag, length, mode)| (tag, length, mode == LiteralMode::NonSync))
}

/// The tag at the front of a partial command.
fn tag_of(bytes: &[u8]) -> String {
    let end = bytes
        .iter()
        .position(|byte| *byte == b' ')
        .unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

// ── one message's data items ─────────────────────────────────────────────

/// One data item as the protocol spells it, or `None` when this server does
/// not answer it.
fn render_item(
    item: &MessageDataItemName<'_>,
    raw: &[u8],
    id: &MessageId,
    uid: u32,
    selected: &Selected,
) -> Option<MessageDataItem<'static>> {
    Some(match item {
        MessageDataItemName::Uid => MessageDataItem::Uid(non_zero(uid)),
        MessageDataItemName::Rfc822Size => {
            MessageDataItem::Rfc822Size(u32::try_from(raw.len()).unwrap_or(u32::MAX))
        }
        MessageDataItemName::Flags => {
            let mut flags = flags_of(&id.file_name());
            if selected.is_recent(uid) {
                flags.push(FlagFetch::Recent);
            }
            MessageDataItem::Flags(flags)
        }
        MessageDataItemName::InternalDate => MessageDataItem::InternalDate(internal_date(raw)),
        MessageDataItemName::Envelope => MessageDataItem::Envelope(envelope(raw)),
        MessageDataItemName::Rfc822 => MessageDataItem::Rfc822(literal_string(raw)),
        MessageDataItemName::Rfc822Text => {
            MessageDataItem::Rfc822Text(literal_string(body_of(raw)))
        }
        MessageDataItemName::Rfc822Header => {
            MessageDataItem::Rfc822Header(literal_string(head_of(raw)))
        }
        MessageDataItemName::Body | MessageDataItemName::BodyStructure => {
            MessageDataItem::BodyStructure(text_structure(body_of(raw)))
        }
        MessageDataItemName::BodyExt {
            section, partial, ..
        } => {
            // A part number or a field subset needs a MIME walk this server
            // does not do (it stores bytes, it does not reparse them).
            let bytes = match section {
                None => raw.to_vec(),
                Some(Section::Text(None)) => body_of(raw).to_vec(),
                Some(Section::Header(None)) => head_of(raw).to_vec(),
                _ => return None,
            };
            let (bytes, origin) = match partial {
                Some((origin, length)) => {
                    let start = usize::try_from(*origin)
                        .unwrap_or(usize::MAX)
                        .min(bytes.len());
                    let end = start
                        .saturating_add(usize::try_from(length.get()).unwrap_or(usize::MAX))
                        .min(bytes.len());
                    (bytes[start..end].to_vec(), Some(*origin))
                }
                None => (bytes, None),
            };
            let section = section.as_ref().map(|section| match section {
                Section::Text(None) => Section::Text(None),
                _ => Section::Header(None),
            });
            MessageDataItem::BodyExt {
                section,
                origin,
                data: literal_string(&bytes),
            }
        }
    })
}

/// Everything up to and including the blank line that ends the header.
fn head_of(raw: &[u8]) -> &[u8] {
    match raw.windows(4).position(|w| w == b"\r\n\r\n") {
        Some(at) => &raw[..at + 4],
        None => raw,
    }
}

/// Everything after it.
fn body_of(raw: &[u8]) -> &[u8] {
    match raw.windows(4).position(|w| w == b"\r\n\r\n") {
        Some(at) => &raw[at + 4..],
        None => &[],
    }
}

/// An `IString` that is always a literal, so a CRLF inside it is data.
fn literal_istring(bytes: &[u8]) -> IString<'static> {
    IString::Literal(Literal::unvalidated(bytes.to_vec()))
}

/// The same as an `NString`, which is never `NIL` here.
fn literal_string(bytes: &[u8]) -> NString<'static> {
    NString(Some(literal_istring(bytes)))
}

/// The one structure this server can prove: `TEXT/PLAIN` with as many lines
/// as the body has newlines.
fn text_structure(body: &[u8]) -> BodyStructure<'static> {
    BodyStructure::Single {
        body: Body {
            basic: BasicFields {
                parameter_list: Vec::new(),
                id: NString(None),
                description: NString(None),
                content_transfer_encoding: literal_istring(b"8BIT"),
                size: u32::try_from(body.len()).unwrap_or(u32::MAX),
            },
            specific: SpecificFields::Text {
                subtype: literal_istring(b"PLAIN"),
                number_of_lines: u32::try_from(body.iter().filter(|byte| **byte == b'\n').count())
                    .unwrap_or(u32::MAX),
            },
        },
        extension_data: None,
    }
}

/// The `ENVELOPE` (RFC 3501 §7.4.2) from the head's fields.
fn envelope(raw: &[u8]) -> Envelope<'static> {
    let field = |name: &str| {
        header(raw, name).map_or_else(|| NString(None), |value| literal_string(value.as_bytes()))
    };
    let from = addresses(&header(raw, "from").unwrap_or_default());
    Envelope {
        date: field("date"),
        subject: field("subject"),
        sender: from.clone(),
        from,
        reply_to: addresses(&header(raw, "reply-to").unwrap_or_default()),
        to: addresses(&header(raw, "to").unwrap_or_default()),
        cc: addresses(&header(raw, "cc").unwrap_or_default()),
        bcc: addresses(&header(raw, "bcc").unwrap_or_default()),
        in_reply_to: field("in-reply-to"),
        message_id: field("message-id"),
    }
}

/// The bare addresses of a header; a display name is dropped rather than
/// mis-parsed, because the envelope's structure is what the protocol needs.
fn addresses(value: &str) -> Vec<EnvAddress<'static>> {
    value
        .split(',')
        .filter_map(|part| {
            let inside = part
                .trim()
                .split_once('<')
                .and_then(|(_, rest)| rest.split_once('>'))
                .map_or(part.trim(), |(addr, _)| addr.trim());
            let (local, host) = inside.rsplit_once('@')?;
            (!local.is_empty() && !host.is_empty()).then(|| EnvAddress {
                name: NString(None),
                adl: NString(None),
                mailbox: literal_string(local.trim_matches('"').as_bytes()),
                host: literal_string(host.trim().as_bytes()),
            })
        })
        .collect()
}

/// The message's internal date: its `Date:` header when the protocol can
/// carry it, else the epoch (`INTERNALDATE` is mandatory, and a maildir keeps
/// no arrival stamp a rename would preserve).
fn internal_date(raw: &[u8]) -> DateTime {
    let epoch = || {
        let at = chrono::DateTime::from_timestamp(0, 0).expect("epoch is representable");
        DateTime::try_from(at.fixed_offset()).expect("the epoch is a legal IMAP date")
    };
    header(raw, "date")
        .and_then(|value| {
            chrono::DateTime::parse_from_str(value.trim(), "%a, %d %b %Y %H:%M:%S %z").ok()
        })
        .and_then(|at| DateTime::try_from(at).ok())
        .unwrap_or_else(epoch)
}

/// One header field's value from the message head, unfolded.
fn header(head: &[u8], field: &str) -> Option<String> {
    let mut value: Option<String> = None;
    for line in String::from_utf8_lossy(head).split_inclusive('\n') {
        let line = line.trim_end_matches(['\r', '\n']);
        if line.is_empty() {
            break;
        }
        match line.strip_prefix([' ', '\t']) {
            Some(rest) => {
                if let Some(value) = value.as_mut() {
                    value.push(' ');
                    value.push_str(rest.trim());
                }
            }
            None => {
                if let Some((name, rest)) = line.split_once(':') {
                    if name.trim().eq_ignore_ascii_case(field) {
                        value = Some(rest.trim().to_owned());
                    }
                }
            }
        }
    }
    value
}

/// What a `SEARCH` key is answered from.
struct SearchContext {
    seq: u32,
    uid: u32,
    flags: Flags,
    unseen: bool,
    recent: bool,
    size: u64,
}

/// Whether one `SEARCH` key matches. A key this server cannot answer is *not
/// matching* rather than an error: a client asking for a date search gets an
/// empty answer it can retry differently, not a closed connection.
fn matches_key(key: &SearchKey<'_>, ctx: &SearchContext, raw: &[u8]) -> bool {
    let flag = |wanted: bool, set: bool| if wanted { set } else { !set };
    match key {
        SearchKey::And(keys) => keys
            .clone()
            .into_inner()
            .iter()
            .all(|key| matches_key(key, ctx, raw)),
        SearchKey::Or(a, b) => matches_key(a, ctx, raw) || matches_key(b, ctx, raw),
        SearchKey::Not(key) => !matches_key(key, ctx, raw),
        SearchKey::All => true,
        SearchKey::Seen => ctx.flags.seen,
        SearchKey::Unseen => ctx.unseen,
        SearchKey::Flagged => ctx.flags.flagged,
        SearchKey::Unflagged => !ctx.flags.flagged,
        SearchKey::Deleted => ctx.flags.trashed,
        SearchKey::Undeleted => !ctx.flags.trashed,
        SearchKey::Draft => ctx.flags.draft,
        SearchKey::Undraft => !ctx.flags.draft,
        SearchKey::Recent => ctx.recent,
        SearchKey::Old => !ctx.recent,
        SearchKey::New => ctx.recent && ctx.unseen,
        // The layout keeps no \Answered state, so "none" and its negation
        // "all" are the only honest answers.
        SearchKey::Answered => false,
        SearchKey::Unanswered => true,
        SearchKey::Keyword(atom) => keyword(atom.as_ref(), ctx.flags),
        SearchKey::Unkeyword(atom) => !keyword(atom.as_ref(), ctx.flags),
        SearchKey::SequenceSet(set) => set
            .iter(Strategy::Naive {
                largest: non_zero(ctx.seq),
            })
            .any(|n| n.get() == ctx.seq),
        SearchKey::Uid(set) => set
            .iter(Strategy::Naive {
                largest: non_zero(ctx.uid),
            })
            .any(|n| n.get() == ctx.uid),
        SearchKey::Larger(bytes) => ctx.size > u64::from(*bytes),
        SearchKey::Smaller(bytes) => ctx.size < u64::from(*bytes),
        SearchKey::Header(field, value) => {
            let field = String::from_utf8_lossy(field.as_ref()).to_ascii_lowercase();
            header(raw, &field).is_some_and(|text| contains(text.as_bytes(), value.as_ref()))
        }
        SearchKey::From(value) => header_contains(raw, "from", value.as_ref()),
        SearchKey::To(value) => header_contains(raw, "to", value.as_ref()),
        SearchKey::Cc(value) => header_contains(raw, "cc", value.as_ref()),
        SearchKey::Bcc(value) => header_contains(raw, "bcc", value.as_ref()),
        SearchKey::Subject(value) => header_contains(raw, "subject", value.as_ref()),
        SearchKey::Body(value) => contains(body_of(raw), value.as_ref()),
        SearchKey::Text(value) => contains(raw, value.as_ref()),
        _ => flag(false, false) && false,
    }
}

/// Whether a header field's value contains `needle` (ASCII case-insensitive).
fn header_contains(raw: &[u8], field: &str, needle: &[u8]) -> bool {
    header(raw, field).is_some_and(|text| contains(text.as_bytes(), needle))
}

/// ASCII case-insensitive substring test over bytes.
fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    let (haystack, needle) = (haystack.to_ascii_lowercase(), needle.to_ascii_lowercase());
    needle.is_empty()
        || haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

/// Whether a keyword names a flag this mailbox can hold.
fn keyword(name: &str, flags: Flags) -> bool {
    match name.trim_start_matches('\\').to_ascii_lowercase().as_str() {
        "seen" => flags.seen,
        "flagged" => flags.flagged,
        "deleted" => flags.trashed,
        "draft" => flags.draft,
        _ => false,
    }
}

#[cfg(test)]
mod tests;
