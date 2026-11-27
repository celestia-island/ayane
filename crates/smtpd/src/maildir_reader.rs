//! The read side of the maildirs [`crate::deliver`] writes.
//!
//! The webmail used to be an IMAP client of Dovecot. The engine now writes the
//! maildirs itself, so reading them is a local file walk rather than a network
//! conversation, and this module is that walk: list a folder, open one
//! message, move the three flags the webmail has (seen / flagged / trashed),
//! move a message, delete one, append one.
//!
//! # Where a message lives
//!
//! The delivery layer's layout, one floor at a time:
//!
//! ```text
//! <mail_root>/<domain>/<local>/Maildir/{tmp,new,cur}   the account's INBOX
//! <mail_root>/<domain>/<local>/Maildir/.Sent/{tmp,new,cur}
//! <mail_root>/<domain>/<local>/Maildir/.Trash/{tmp,new,cur}
//! ```
//!
//! The folder names are Dovecot's `mail_location = maildir:~/Maildir` spelling
//! — `<Name>` as a `.`-prefixed child of the account's Maildir, capitalised
//! (`INBOX` is the Maildir itself). Nothing here reads Dovecot's private
//! `dovecot-uidlist`: an identifier is the **file name**, which is what a
//! maildir gives an external reader.
//!
//! # Identifier
//!
//! [`MessageId`] is the file name as it sits on disk, `unique:2,FLAGS`. Two
//! consequences worth stating, because they are what the webmail sees:
//!
//! - the name **changes** when a flag changes (`S` appears, `F` appears), so
//!   the id a list returned is not the id a later rename produces. Every
//!   mutating call therefore answers with the new id, and
//!   [`MaildirReader::read`] re-derives it.
//! - the webmail's `uid` parameter carries this string now. It used to be an
//!   IMAP number; the shape of the reply is unchanged, the value is not.
//!
//! # Flags
//!
//! Maildir keeps them in the name's `:2,` suffix — the characters after it
//! are, in the standard's order, `D` (draft) `F` (flagged) `P` (passed)
//! `R` (replied) `S` (seen) `T` (trashed). The webmail has three: seen
//! (`S`), flagged (`F`) and — instead of a maildir `T`, which no other
//! reader honours — a move into `.Trash`.
//!
//! A file in `new/` has no suffix at all and is unseen; moving it to `cur/`
//! with a suffix is how [`crate::deliver`]'s own claim step spells "now in a
//! folder", so the same rename is what a flag change on a `new/` message
//! does.
//!
//! # Durability and concurrency
//!
//! A rename inside one maildir is atomic (same directory, same filesystem),
//! and every mutating call renames rather than rewriting, so a reader never
//! sees a half-written name.
//!
//! The one place a file is *written* ([`MaildirReader::append`]) uses
//! `create tmp` → write → `fsync(file)` → `rename` into `cur/` →
//! `fsync(cur)`: the file is durable before it has a name a reader can reach,
//! and the directory entry is durable before the call answers. (The delivery
//! layer adds a second file sync after its rename; a rename does not change
//! the file's contents, so the one before it is what makes the bytes durable,
//! and this module does not pay for the second.)
//!
//! Several processes may read at once. A rename that fails because another
//! process already moved the file is reported as [`ReaderError::Missing`] and
//! the caller's answer is "that message is not there", which is true.

use std::fs;
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use ayane_proto::Address;
use sha2::{Digest, Sha256};

use crate::queue::fsync_dir;

/// The name of the folder that is the account's own Maildir.
pub const INBOX: &str = "INBOX";

/// The folder a deleted message is moved into.
pub const TRASH: &str = "Trash";

/// The folder a sent copy is appended to.
pub const SENT: &str = "Sent";

/// The folder a draft is appended to.
pub const DRAFTS: &str = "Drafts";

/// The folders [`MaildirReader::list_flagged`] merges by default.
pub const STARRED_FOLDERS: [&str; 3] = [INBOX, SENT, DRAFTS];

/// The suffix a maildir file name carries before its flags (`:2,`).
const FLAG_SEPARATOR: &str = ":2,";

/// How many messages one listing parses before it gives up exactness.
///
/// The roster needs every candidate's `Date:` header to order correctly, so
/// the ceiling is on *count*, not on the page. At or below it the page is
/// exact; above it the folder is paged by arrival (mtime) order without
/// reading the heads that cannot fit a page, and a warning says so — a
/// sidebar click must not become a way to make the service read a hundred
/// thousand files.
const MAX_LISTING_CANDIDATES: usize = 20_000;

/// The most of a message a listing row reads, in bytes.
///
/// The read stops at the header's blank line, so this is a *bound* on header
/// abuse rather than the share of the body a row sees: a message whose header
/// block runs past it is listed with whatever could be read, and a message
/// whose body is 40 MiB still costs one parse of its head.
const PREVIEW_HEAD_BYTES: usize = 65_536;

/// The most of a body a listing row takes for a preview, in bytes.
const PREVIEW_BODY_BYTES: usize = 4096;

/// How many characters a preview line may run before it is cut.
const PREVIEW_CHARS: usize = 256;

/// Why a maildir operation failed.
#[derive(Debug, thiserror::Error)]
pub enum ReaderError {
    /// The folder name cannot be a maildir child (empty, a path separator, a
    /// `.`/`..` component, a character the layout reserves, or too long).
    #[error("`{0}` is not a folder name this layout can hold")]
    BadFolder(String),
    /// The message id cannot be a file name in this layout.
    #[error("`{0}` is not a message id this layout can hold")]
    BadMessageId(String),
    /// The address has a part that cannot be a path component.
    ///
    /// A local part may contain `/` per RFC 5322, and the delivery layout
    /// splices it into a path; an address that would climb out of the mail
    /// root is refused here rather than followed.
    #[error("`{0}` cannot name a mailbox directory")]
    BadAddress(String),
    /// No such message (or the folder does not hold it any more).
    #[error("`{id}` is not in `{folder}`")]
    Missing {
        /// The folder asked about.
        folder: String,
        /// The id asked about.
        id: String,
    },
    /// A message under that name is already in the target folder.
    #[error("`{0}` is already in `{1}`")]
    NameTaken(String, String),
    /// The message bytes could not be parsed as a message.
    #[error("`{0}` could not be parsed as a message")]
    Unparsable(String),
    /// The filesystem said no.
    #[error("{path}: {source}")]
    Io {
        /// What was being done, with the path.
        path: String,
        /// The underlying failure.
        #[source]
        source: io::Error,
    },
}

impl ReaderError {
    fn io(path: impl AsRef<Path>, source: io::Error) -> Self {
        Self::Io {
            path: path.as_ref().display().to_string(),
            source,
        }
    }
}

/// The three flag bits the webmail sets, as they appear after `:2,`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Flags {
    /// `S` — read.
    pub seen: bool,
    /// `F` — starred.
    pub flagged: bool,
    /// `T` — deleted. The webmail deletes by moving to `.Trash` instead, so
    /// this is only ever *observed*: mail some other tool flagged `T` reads
    /// back as trashed, and the webmail can still purge it.
    pub trashed: bool,
    /// `D` — draft.
    pub draft: bool,
}

impl Flags {
    /// The standard's characters, in the standard's order, for the ones set.
    #[must_use]
    pub fn suffix(self) -> String {
        let mut out = String::new();
        if self.draft {
            out.push('D');
        }
        if self.flagged {
            out.push('F');
        }
        if self.seen {
            out.push('S');
        }
        if self.trashed {
            out.push('T');
        }
        out
    }
}

/// A message's identifier: the file name as it sits on disk.
///
/// [`MessageId::with_flags`] is what turns one id into another for the same
/// message.
///
/// The flag half is kept because the name on disk carries it; two ids that
/// differ only in flags are the same message, which is what
/// [`MessageId::same_message`] answers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageId {
    /// Everything before `:2,` — the name a maildir guarantees is unique.
    unique: String,
    /// The characters after `:2,` (empty for a `new/` file).
    flags: String,
    /// Whether the name carried a `:2,` suffix at all.
    has_info: bool,
}

impl MessageId {
    /// Parse a file name.
    ///
    /// # Errors
    ///
    /// Returns [`ReaderError::BadMessageId`] when the name could not be a
    /// file in this layout: empty, a path separator, `.` / `..`, a leading
    /// dot (which is how the layout spells a subfolder), or a control byte.
    pub fn parse(name: &str) -> Result<Self, ReaderError> {
        let bad = || ReaderError::BadMessageId(name.to_owned());
        if name.is_empty() || name.len() > 255 || name == "." || name == ".." {
            return Err(bad());
        }
        if name.starts_with('.') {
            return Err(bad());
        }
        for ch in name.chars() {
            if ch == '/' || ch == '\\' || ch == '\0' || ch.is_control() {
                return Err(bad());
            }
        }
        let (unique, flags) = match name.split_once(FLAG_SEPARATOR) {
            Some((unique, flags)) => (unique, flags),
            None => (name, ""),
        };
        if unique.is_empty() {
            return Err(bad());
        }
        if unique.starts_with('.') {
            return Err(bad());
        }
        for ch in flags.chars() {
            if !matches!(ch, 'D' | 'F' | 'P' | 'R' | 'S' | 'T') {
                return Err(bad());
            }
        }
        Ok(Self {
            unique: unique.to_owned(),
            flags: flags.to_owned(),
            has_info: name.contains(FLAG_SEPARATOR),
        })
    }

    /// The flags the suffix carries.
    #[must_use]
    pub fn flags(&self) -> Flags {
        let has = |flag: char| self.flags.contains(flag);
        Flags {
            draft: has('D'),
            flagged: has('F'),
            seen: has('S'),
            trashed: has('T'),
        }
    }

    /// The name that puts `flags` in the suffix, in the standard's order.
    ///
    /// The `:2,` half is always written, even when nothing is set: an empty
    /// info string is what says "this file was put in `cur/` on purpose",
    /// and every maildir reader (`notmuch`, `mu`, Dovecot) looks for it.
    #[must_use]
    pub fn with_flags(&self, flags: Flags) -> Self {
        Self {
            unique: self.unique.clone(),
            flags: flags.suffix(),
            has_info: true,
        }
    }

    /// Whether two ids name the same message (same `unique` half).
    #[must_use]
    pub fn same_message(&self, other: &Self) -> bool {
        self.unique == other.unique
    }

    /// The `unique` half — the name without its flag suffix.
    #[must_use]
    pub fn unique(&self) -> &str {
        &self.unique
    }

    /// The characters after `:2,`, as written.
    #[must_use]
    pub fn suffix(&self) -> &str {
        &self.flags
    }

    /// The file name this id names on disk.
    ///
    /// A name that never carried `:2,` (a file in `new/`) keeps its bare
    /// form when the flags are empty, so reading such a message and writing
    /// it back unchanged produces the same name.
    #[must_use]
    pub fn file_name(&self) -> String {
        if !self.has_info && self.flags.is_empty() {
            self.unique.clone()
        } else {
            format!("{}{FLAG_SEPARATOR}{}", self.unique, self.flags)
        }
    }
}

impl std::fmt::Display for MessageId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.file_name())
    }
}

impl serde::Serialize for MessageId {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.file_name())
    }
}

/// One row of a listing — what the roster shows without opening anything.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ListingRow {
    /// The file name (see [`MessageId`]).
    pub id: String,
    /// The folder it was found in, as the caller spells it.
    pub mailbox: String,
    /// `S` in the suffix.
    pub seen: bool,
    /// `F` in the suffix.
    pub flagged: bool,
    /// First `From` address, when the header carried one.
    pub from: Option<String>,
    /// `Subject` header.
    pub subject: Option<String>,
    /// The `Date` header as RFC 3339, when it parses.
    pub date: Option<String>,
    /// The file's size in octets — exactly the bytes on disk, without the
    /// connection's framing, so no dot-unstuffing can make it drift.
    pub size: u64,
    /// Opening words of the text body, whitespace collapsed, at most 256
    /// characters — the roster's preview line, under the name the webui has
    /// always read (`preview`, as the IMAP era's ENVELOPE rows spelled it).
    /// `None` when the head holds no prose (an HTML-only part renders as tag
    /// soup and is dropped rather than shown).
    pub preview: Option<String>,
    /// The sort key the listing used: the `Date` header in seconds since the
    /// epoch when it parses, else the file's modification time.
    ///
    /// The caller never sees this — it exists so the ordering is a value a
    /// test can assert, rather than an implementation detail.
    #[serde(skip)]
    pub sort_key: i64,
}

/// One message found by a scan, before any of its bytes were read.
struct Candidate {
    id: MessageId,
    path: PathBuf,
    seen: bool,
    /// The file's modification time in whole seconds — the cheap sort key the
    /// page is cut by before anything is parsed.
    mtime: i64,
}

/// One message, opened.
#[derive(Debug, Clone, PartialEq)]
pub struct OpenedMessage {
    /// The id it was found under.
    pub id: String,
    /// The folder it was read from.
    pub mailbox: String,
    /// The flags on the file when it was opened.
    pub flags: Flags,
    /// Size in octets.
    pub size: u64,
    /// The parsed, sanitised view ([`ayane_mail::mime::ParsedMessage`]).
    pub message: ayane_mail::mime::ParsedMessage,
}

/// A mailbox listing — rows plus the folder's own counts.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct FolderListing {
    /// How many messages the folder holds, regardless of `limit`.
    pub total: u32,
    /// How many of them are not `S`.
    pub unread: u32,
    /// The newest `limit` of them, newest first.
    pub messages: Vec<ListingRow>,
}

/// The 已加星标 roster: the flagged messages across several folders.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct StarredListing {
    /// How many messages carry the flag in total, before `limit`.
    pub total: u32,
    /// The newest `limit` of them, newest first.
    pub messages: Vec<ListingRow>,
}

/// A set of flag bits to turn on or off.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FlagChange {
    /// Set `S` when `Some(true)`, clear it when `Some(false)`, leave it when
    /// `None`.
    pub seen: Option<bool>,
    /// The same for `F`.
    pub flagged: Option<bool>,
}

/// What a mutation did, for the caller's reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Renamed {
    /// The id before the rename.
    pub from: String,
    /// The id after it — the same message under a new flag suffix.
    pub to: String,
    /// The flags now on the file.
    pub flags: Flags,
}

/// The reader over one account's maildir.
#[derive(Debug, Clone)]
pub struct MaildirReader {
    mail_root: PathBuf,
}

impl MaildirReader {
    /// A reader over `mail_root` — the directory whose children are
    /// `<domain>/<local>/Maildir`, the same root [`crate::Deliverer::new`]
    /// takes.
    #[must_use]
    pub fn new(mail_root: impl Into<PathBuf>) -> Self {
        Self {
            mail_root: mail_root.into(),
        }
    }

    /// The mail root this reader walks.
    #[must_use]
    pub fn mail_root(&self) -> &Path {
        &self.mail_root
    }

    /// The account's own Maildir (`<root>/<domain>/<local>/Maildir`).
    ///
    /// The rendering is [`crate::deliver::maildir_home`]'s, taken from it
    /// rather than re-spelled, and each part is checked to be a plain
    /// component: a local part holding `/` is an address this layout cannot
    /// store, not a directory to descend into.
    ///
    /// # Errors
    ///
    /// Returns [`ReaderError::BadAddress`] when a part is not a plain
    /// component.
    pub fn maildir_of(&self, address: &Address) -> Result<PathBuf, ReaderError> {
        let home = crate::deliver::maildir_home(address.domain(), address.local());
        let mut path = self.mail_root.clone();
        for part in [address.domain(), address.local()] {
            check_component(part)
                .map_err(|()| ReaderError::BadAddress(address.as_str().to_owned()))?;
        }
        // `home` is `/var/mail/vhosts/<domain>/<local>`; the two halves are
        // the ones just checked, appended directly so no literal segment of
        // the renderer's template can ever become a path component.
        debug_assert!(home.ends_with(&format!("/{}/{}", address.domain(), address.local())));
        path.push(address.domain());
        path.push(address.local());
        path.push("Maildir");
        Ok(path)
    }

    /// The directory a folder lives in, creating `<tmp,new,cur>` when asked.
    ///
    /// `INBOX` is the Maildir itself; anything else is `.`+name, capitalised
    /// the way Dovecot writes it, with the name checked against this layout's
    /// reserved spellings.
    ///
    /// # Errors
    ///
    /// Returns [`ReaderError::BadFolder`] for a name the layout cannot hold
    /// and [`ReaderError::Io`] when the directories cannot be created.
    pub fn folder_dir(
        &self,
        address: &Address,
        folder: &str,
        create: bool,
    ) -> Result<PathBuf, ReaderError> {
        let maildir = self.maildir_of(address)?;
        let dir = if is_inbox(folder) {
            maildir.clone()
        } else {
            maildir.join(format!(".{}", folder_component(folder)?))
        };
        if !create {
            // A listing of a folder nothing has created yet is an empty
            // folder, not an escape, and the account's own Maildir may itself
            // not exist — so the non-creating path has nothing to resolve.
            return Ok(dir);
        }
        // The order here is the point. The name was checked as a *string*,
        // and then a filesystem is asked to create a path built from it:
        // `create_dir_all` follows a symlink without complaint and answers
        // success. So the account's Maildir and the folder itself are created
        // first, the *resolved* result is asked whether it is still inside
        // the Maildir, and only then are the three subdirectories made. A
        // check that ran after the subdirectories were created would have
        // already left a `cur/` on the far side of a planted symlink.
        fs::create_dir_all(&maildir).map_err(|e| ReaderError::io(&maildir, e))?;
        fs::create_dir_all(&dir).map_err(|e| ReaderError::io(&dir, e))?;
        confirm_beneath(&maildir, &dir).map_err(|()| ReaderError::BadFolder(folder.to_owned()))?;
        for sub in ["tmp", "new", "cur"] {
            let path = dir.join(sub);
            fs::create_dir_all(&path).map_err(|e| ReaderError::io(&path, e))?;
        }
        Ok(dir)
    }

    /// List a folder's newest `limit` messages, newest first.
    ///
    /// Ordering is arrival order as a maildir can tell it: the `Date` header
    /// when it parses (the sender's own claim), else the file's modification
    /// time (what this machine saw) — ties broken by name, so two messages
    /// written in the same microsecond still have one order.
    ///
    /// A folder that does not exist lists as empty rather than failing: the
    /// webmail asks every sidebar folder, and 收件箱 of a fresh account is a
    /// maildir its first delivery has not created yet.
    ///
    /// Past `MAX_LISTING_CANDIDATES` the folder is paged by revision rather
    /// than by `Date` (see the type's docs): the one case where this function
    /// knowingly answers something other than the ordering above.
    ///
    /// # Errors
    ///
    /// Returns [`ReaderError::BadFolder`] / [`ReaderError::BadAddress`] for a
    /// name that cannot be a path, and [`ReaderError::Io`] when a directory
    /// exists but cannot be read.
    pub fn list(
        &self,
        address: &Address,
        folder: &str,
        limit: usize,
    ) -> Result<FolderListing, ReaderError> {
        let dir = self.folder_dir(address, folder, false)?;
        // First pass: no file is opened. The counts and the cheap order (the
        // file's own mtime) come from metadata alone, so a mailbox with tens
        // of thousands of messages costs one `readdir` and one `stat` each.
        let mut entries: Vec<Candidate> = Vec::new();
        let mut total = 0u32;
        let mut unread = 0u32;
        for (sub, is_new) in [("cur", false), ("new", true)] {
            for (id, path) in self.scan(&dir.join(sub))? {
                total = total.saturating_add(1);
                let flags = id.flags();
                // A file in `new/` is unseen whatever its suffix claims; the
                // delivery layer never writes one there, but a foreign writer
                // might.
                let seen = !is_new && flags.seen;
                if !seen {
                    unread = unread.saturating_add(1);
                }
                let mtime = fs::metadata(&path)
                    .ok()
                    .and_then(|meta| meta.modified().ok())
                    .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
                    .map_or(0, |elapsed| elapsed.as_secs() as i64);
                entries.push(Candidate {
                    id,
                    path,
                    seen,
                    mtime,
                });
            }
        }
        // The `Date:` header outranks the mtime and only the header knows its
        // own value, so the head of **every** candidate is read before the
        // page is cut. Cutting on mtime first and sorting on the header after
        // would silently drop a message whose header is newer than its file
        // (a migrated or restored maildir has exactly that shape) while still
        // counting it — a row missing from the roster that `total` insists is
        // there.
        //
        // The cost of being right is one bounded head read per message. A
        // maildir at rest holds a few thousand, so that is the price of a
        // correct page; past `MAX_LISTING_CANDIDATES` the roster stops
        // reading heads and pages on the mtime instead. That is a deliberate
        // *degradation*, and it is stated as one: a folder that large is one
        // an operator should be archiving, and answering it from arrival
        // order is better than making a sidebar click read a hundred thousand
        // files. `total`/`unread` stay exact either way — they never read a
        // body.
        let mut rows: Vec<ListingRow> = if entries.len() <= MAX_LISTING_CANDIDATES {
            entries
                .iter()
                .map(|candidate| self.row(address, folder, candidate))
                .collect()
        } else {
            tracing::warn!(
                folder,
                messages = entries.len(),
                bound = MAX_LISTING_CANDIDATES,
                "folder is over the listing bound: paging on arrival order, not by date"
            );
            entries.sort_by(|a, b| {
                b.mtime
                    .cmp(&a.mtime)
                    .then_with(|| b.id.file_name().cmp(&a.id.file_name()))
            });
            entries
                .iter()
                .take(limit)
                .map(|candidate| self.row(address, folder, candidate))
                .collect()
        };
        rows.sort_by(|a, b| b.sort_key.cmp(&a.sort_key).then_with(|| b.id.cmp(&a.id)));
        rows.truncate(limit);
        Ok(FolderListing {
            total,
            unread,
            messages: rows,
        })
    }

    /// Every message across `folders` that carries `F`, newest first.
    ///
    /// This is the 已加星标 roster: a star is a flag on a message, so the
    /// view is a query over real folders rather than a folder of its own. A
    /// folder that does not exist contributes nothing.
    ///
    /// # Errors
    ///
    /// As [`MaildirReader::list`].
    pub fn list_flagged(
        &self,
        address: &Address,
        folders: &[&str],
        limit: usize,
    ) -> Result<StarredListing, ReaderError> {
        // The same rule `list` follows: a `Date:` header outranks the mtime
        // and only the header knows its own value, so every flagged
        // candidate's head is read before the page is cut. Cutting on mtime
        // first would drop a starred message whose header is newer than its
        // file from any page smaller than the set — while `total` counted it.
        let mut found: Vec<(&str, Candidate)> = Vec::new();
        for folder in folders {
            let dir = self.folder_dir(address, folder, false)?;
            for sub in ["cur", "new"] {
                for (id, path) in self.scan(&dir.join(sub))? {
                    if !id.flags().flagged {
                        continue;
                    }
                    if found.len() >= MAX_LISTING_CANDIDATES {
                        break;
                    }
                    let mtime = fs::metadata(&path)
                        .ok()
                        .and_then(|meta| meta.modified().ok())
                        .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
                        .map_or(0, |elapsed| elapsed.as_secs() as i64);
                    found.push((
                        folder,
                        Candidate {
                            seen: id.flags().seen,
                            id,
                            path,
                            mtime,
                        },
                    ));
                }
            }
        }
        // The count is the whole filtered set, taken before the page is cut:
        // a sidebar badge that reported the *page* would say "200" on a
        // mailbox holding two thousand starred messages.
        let total = u32::try_from(found.len()).unwrap_or(u32::MAX);
        let mut rows: Vec<ListingRow> = found
            .iter()
            .map(|(folder, candidate)| self.row(address, folder, candidate))
            .collect();
        rows.sort_by(|a, b| b.sort_key.cmp(&a.sort_key).then_with(|| b.id.cmp(&a.id)));
        rows.truncate(limit);
        Ok(StarredListing {
            total,
            messages: rows,
        })
    }

    /// Open one message and parse it.
    ///
    /// # Errors
    ///
    /// Returns [`ReaderError::Missing`] when the folder does not hold an id
    /// with that `unique` half, [`ReaderError::Unparsable`] when the bytes
    /// are not a message, and [`ReaderError::Io`] when the file cannot be
    /// read.
    pub fn read(
        &self,
        address: &Address,
        folder: &str,
        id: &str,
    ) -> Result<OpenedMessage, ReaderError> {
        let dir = self.folder_dir(address, folder, false)?;
        let wanted = MessageId::parse(id)?;
        let (found, path) = self.locate(&dir, &wanted, folder)?;
        let raw = fs::read(&path).map_err(|e| ReaderError::io(&path, e))?;
        let message = ayane_mail::mime::parse(&raw)
            .ok_or_else(|| ReaderError::Unparsable(found.file_name()))?;
        Ok(OpenedMessage {
            id: found.file_name(),
            mailbox: folder.to_owned(),
            flags: found.flags(),
            size: raw.len() as u64,
            message,
        })
    }

    /// The raw bytes of one message, without parsing them.
    ///
    /// # Errors
    ///
    /// As [`MaildirReader::read`], minus the parse.
    pub fn read_raw(
        &self,
        address: &Address,
        folder: &str,
        id: &str,
    ) -> Result<Vec<u8>, ReaderError> {
        let dir = self.folder_dir(address, folder, false)?;
        let wanted = MessageId::parse(id)?;
        let (_, path) = self.locate(&dir, &wanted, folder)?;
        fs::read(&path).map_err(|e| ReaderError::io(&path, e))
    }

    /// Set the flags a message carries, by renaming it inside its maildir.
    ///
    /// A message in `new/` moves to `cur/` (an unread message that has been
    /// looked at belongs where a reader looks); a message already in `cur/`
    /// is renamed in place. Both are single renames, so neither can be
    /// observed half-done.
    ///
    /// # Errors
    ///
    /// Returns [`ReaderError::Missing`] when the folder does not hold the id
    /// and [`ReaderError::Io`] when the rename fails.
    pub fn set_flags(
        &self,
        address: &Address,
        folder: &str,
        id: &str,
        change: FlagChange,
    ) -> Result<Renamed, ReaderError> {
        let dir = self.folder_dir(address, folder, false)?;
        let wanted = MessageId::parse(id)?;
        let (found, path) = self.locate(&dir, &wanted, folder)?;
        let mut flags = found.flags();
        if let Some(seen) = change.seen {
            flags.seen = seen;
        }
        if let Some(flagged) = change.flagged {
            flags.flagged = flagged;
        }
        let target = found.with_flags(flags);
        if target.file_name() == found.file_name() {
            // Nothing asked changed: the rename would be to the same name.
            return Ok(Renamed {
                from: found.file_name(),
                to: target.file_name(),
                flags,
            });
        }
        let cur = dir.join("cur");
        fs::create_dir_all(&cur).map_err(|e| ReaderError::io(&cur, e))?;
        let to = cur.join(target.file_name());
        // Replacing a name another process created is not an error a rename
        // can report; refusing up front keeps two messages from becoming one.
        if to.exists() && to != path {
            return Err(ReaderError::NameTaken(
                target.file_name(),
                folder.to_owned(),
            ));
        }
        rename_hard(&path, &to, folder, &found)?;
        Ok(Renamed {
            from: found.file_name(),
            to: target.file_name(),
            flags,
        })
    }

    /// Move a message into another folder (`cur/` of the target), creating
    /// the target's directories.
    ///
    /// # Errors
    ///
    /// Returns [`ReaderError::Missing`] when the source folder does not hold
    /// the id, and [`ReaderError::Io`] when the move fails.
    pub fn move_to(
        &self,
        address: &Address,
        from_folder: &str,
        id: &str,
        to_folder: &str,
    ) -> Result<Renamed, ReaderError> {
        let source_dir = self.folder_dir(address, from_folder, false)?;
        let wanted = MessageId::parse(id)?;
        let (found, path) = self.locate(&source_dir, &wanted, from_folder)?;
        let target_dir = self.folder_dir(address, to_folder, true)?;
        let cur = target_dir.join("cur");
        let target = found.with_flags(found.flags());
        let to = cur.join(target.file_name());
        if to.exists() {
            return Err(ReaderError::NameTaken(
                target.file_name(),
                to_folder.to_owned(),
            ));
        }
        std::fs::rename(&path, &to).map_err(|e| {
            if e.kind() == io::ErrorKind::NotFound {
                ReaderError::Missing {
                    folder: from_folder.to_owned(),
                    id: found.file_name(),
                }
            } else {
                ReaderError::io(&path, e)
            }
        })?;
        // The move is the delivery's shape — a rename with no second write —
        // and **both** directories are synced: without the source side a
        // crash can bring the message back where the caller was told it left,
        // and without the target side it can vanish from a folder the caller
        // was told it reached.
        let source_cur = source_dir.join("cur");
        let _ = fsync_dir(&source_cur);
        let _ = fsync_dir(&cur);
        Ok(Renamed {
            from: found.file_name(),
            to: target.file_name(),
            flags: found.flags(),
        })
    }

    /// Delete one message permanently.
    ///
    /// The file is first *moved* into the folder's `tmp/` under a
    /// quarantine name and the directory synced, then unlinked and the
    /// directory synced again. The two steps are what makes the answer
    /// honest: once the first has completed the message is gone from every
    /// listing (no reader can reach it), and a crash between them leaves a
    /// `tmp/` file with a `.trash.` prefix — residue an operator can see and
    /// a reader never shows.
    ///
    /// # Errors
    ///
    /// Returns [`ReaderError::Missing`] when the folder does not hold the id.
    pub fn purge(&self, address: &Address, folder: &str, id: &str) -> Result<String, ReaderError> {
        let dir = self.folder_dir(address, folder, false)?;
        let wanted = MessageId::parse(id)?;
        let (found, path) = self.locate(&dir, &wanted, folder)?;
        let tmp = dir.join("tmp");
        fs::create_dir_all(&tmp).map_err(|e| ReaderError::io(&tmp, e))?;
        let quarantine = tmp.join(format!(".trash.{}.{}", next_seq(), found.unique()));
        std::fs::rename(&path, &quarantine).map_err(|e| {
            if e.kind() == io::ErrorKind::NotFound {
                ReaderError::Missing {
                    folder: folder.to_owned(),
                    id: found.file_name(),
                }
            } else {
                ReaderError::io(&path, e)
            }
        })?;
        fs::remove_file(&quarantine).map_err(|e| ReaderError::io(&quarantine, e))?;
        // The quarantine `tmp/` is synced, and so is the folder the file came
        // from: a crash that forgot the unlink would otherwise hand the
        // message back from `cur/` after the caller was told it was gone.
        let _ = fsync_dir(&tmp);
        for sub in ["cur", "new"] {
            let _ = fsync_dir(&dir.join(sub));
        }
        Ok(found.file_name())
    }

    /// Append bytes as a message in `folder`, returning the new id.
    ///
    /// The write order is the delivery layer's: `create tmp` → write →
    /// `fsync(file)` → rename into `cur/` → `fsync(cur)`. The name is a
    /// maildir unique (`<secs>.M<usec>P<pid>Q<seq>.<host>`) so append-only
    /// mailboxes never collide with a delivery that lands at the same
    /// moment, and the `:2,` suffix carries `flags`.
    ///
    /// # Errors
    ///
    /// Returns [`ReaderError::BadFolder`] for a name that cannot be a path
    /// and [`ReaderError::Io`] when the write fails.
    pub fn append(
        &self,
        address: &Address,
        folder: &str,
        bytes: &[u8],
        flags: Flags,
    ) -> Result<String, ReaderError> {
        let dir = self.folder_dir(address, folder, true)?;
        let tmp = dir.join("tmp");
        let cur = dir.join("cur");
        // The name is claimed by `create_new` below, so a collision surfaces
        // as `AlreadyExists` rather than as a rename over somebody else's
        // message. Retrying with the next sequence number is what makes the
        // claim hold across processes too — the counter is this process's,
        // and another process writing the same maildir has one of its own.
        let mut name = self.unique_name(address.domain());
        let mut attempt = 0u32;
        while tmp.join(format!("{name}.append")).exists()
            || cur
                .join(
                    MessageId {
                        unique: name.clone(),
                        flags: flags.suffix(),
                        has_info: true,
                    }
                    .file_name(),
                )
                .exists()
        {
            attempt = attempt.saturating_add(1);
            if attempt > 64 {
                return Err(ReaderError::Io {
                    path: cur.display().to_string(),
                    source: io::Error::new(
                        io::ErrorKind::AlreadyExists,
                        "could not find a free maildir name",
                    ),
                });
            }
            name = self.unique_name(address.domain());
        }
        let tmp_path = tmp.join(format!("{name}.append"));
        let file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp_path)
            .map_err(|e| ReaderError::io(&tmp_path, e))?;
        let written = (|| -> io::Result<()> {
            let mut handle = &file;
            handle.write_all(bytes)?;
            handle.sync_all()
        })();
        drop(file);
        if let Err(err) = written {
            let _ = fs::remove_file(&tmp_path);
            return Err(ReaderError::io(&tmp_path, err));
        }
        let target = cur.join(
            MessageId {
                unique: name,
                flags: flags.suffix(),
                has_info: true,
            }
            .file_name(),
        );
        if let Err(err) = std::fs::rename(&tmp_path, &target) {
            let _ = fs::remove_file(&tmp_path);
            return Err(ReaderError::io(&tmp_path, err));
        }
        fs::File::open(&target)
            .and_then(|handle| handle.sync_all())
            .map_err(|e| ReaderError::io(&target, e))?;
        fsync_dir(&cur).map_err(|e| ReaderError::io(&cur, e))?;
        Ok(target
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default())
    }

    /// Every folder under `address`'s Maildir, `INBOX` first.
    ///
    /// A folder is a `.`-prefixed child directory that holds a `cur/` — the
    /// layout's own marker (`.` alone introduces the name, and a
    /// `.Name.tmp`-and-friends spelling is Dovecot's transitional rename,
    /// which is skipped because the final name will appear).
    ///
    /// **Not wired to an RPC yet.** The webmail's sidebar is a fixed five
    /// folders, so nothing calls this today; it is the reader's half of the
    /// IMAP `LIST` the webui will need the day its sidebar stops being fixed
    /// (and [`MaildirReader::create_folder`] is the `CREATE` half). It is
    /// kept public and tested rather than deleted so that day is a wiring
    /// change, not a rewrite.
    ///
    /// # Errors
    ///
    /// Returns [`ReaderError::Io`] when the Maildir itself cannot be read.
    pub fn folders(&self, address: &Address) -> Result<Vec<String>, ReaderError> {
        let maildir = self.maildir_of(address)?;
        let mut out = vec![INBOX.to_owned()];
        let Ok(entries) = fs::read_dir(&maildir) else {
            return Ok(out);
        };
        let mut named = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|e| ReaderError::io(&maildir, e))?;
            let name = entry.file_name().to_string_lossy().into_owned();
            let Some(rest) = name.strip_prefix('.') else {
                continue;
            };
            if rest.is_empty() || rest.starts_with('.') || rest.ends_with(".tmp") {
                continue;
            }
            let path = entry.path();
            if !path.is_dir() || !path.join("cur").is_dir() {
                continue;
            }
            named.push(rest.to_owned());
        }
        named.sort();
        out.extend(named);
        Ok(out)
    }

    /// Create a folder, or confirm the one that exists.
    ///
    /// Not wired to an RPC yet, for the same reason as
    /// [`MaildirReader::folders`]. Answering with the canonical name is what
    /// makes `inbox` and `INBOX` one folder instead of two.
    ///
    /// # Errors
    ///
    /// Returns [`ReaderError::BadFolder`] for a name the layout cannot hold
    /// and [`ReaderError::Io`] when the directories cannot be created.
    pub fn create_folder(&self, address: &Address, folder: &str) -> Result<String, ReaderError> {
        self.folder_dir(address, folder, true)?;
        Ok(if is_inbox(folder) {
            INBOX.to_owned()
        } else {
            folder_component(folder)?.to_owned()
        })
    }

    // ── internals ────────────────────────────────────────────────────────

    /// Every message file in one directory, and its parsed id.
    fn scan(&self, sub: &Path) -> Result<Vec<(MessageId, PathBuf)>, ReaderError> {
        let Ok(entries) = fs::read_dir(sub) else {
            return Ok(Vec::new());
        };
        let mut out = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|e| ReaderError::io(sub, e))?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            // `.`-prefixed entries are the layout's editorial files (and this
            // module's own append/trash residue), never messages.
            if name.starts_with('.') {
                continue;
            }
            let Ok(id) = MessageId::parse(name) else {
                continue;
            };
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            out.push((id, path));
        }
        Ok(out)
    }

    /// Find one message by its `unique` half in `dir`'s `cur/` or `new/`.
    fn locate(
        &self,
        dir: &Path,
        wanted: &MessageId,
        folder: &str,
    ) -> Result<(MessageId, PathBuf), ReaderError> {
        for sub in ["cur", "new"] {
            for (id, path) in self.scan(&dir.join(sub))? {
                if id.same_message(wanted) {
                    return Ok((id, path));
                }
            }
        }
        Err(ReaderError::Missing {
            folder: folder.to_owned(),
            id: wanted.file_name(),
        })
    }

    /// One listing row: the cheap header pass, no body transcoding.
    fn row(&self, _address: &Address, folder: &str, candidate: &Candidate) -> ListingRow {
        let id = &candidate.id;
        let path = &candidate.path;
        let seen = candidate.seen;
        let metadata = fs::metadata(path).ok();
        let size = metadata.as_ref().map_or(0, fs::Metadata::len);
        let mtime = candidate.mtime;
        let summary = match head_of(path) {
            Some(raw) => summarise(&raw),
            None => Summary {
                from: None,
                subject: None,
                date: None,
                preview: None,
                dated: None,
            },
        };
        ListingRow {
            id: id.file_name(),
            mailbox: folder.to_owned(),
            seen,
            flagged: id.flags().flagged,
            from: summary.from,
            subject: summary.subject,
            date: summary.date,
            size,
            preview: summary.preview,
            // The sender's own `Date:` when it parses, else what this machine
            // saw — the same fallback an IMAP server's INTERNALDATE has when
            // the header is absent, without pretending to be one.
            sort_key: summary.dated.unwrap_or(mtime),
        }
    }

    /// A fresh maildir unique name for an appended message.
    fn unique_name(&self, host: &str) -> String {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        let seq = next_seq();
        format!(
            "{secs}.M{usec}P{pid}Q{seq}.{host}",
            secs = now.as_secs(),
            usec = now.subsec_micros(),
            pid = std::process::id(),
            host = host_token(host),
        )
    }
}

/// Whether `folder` names the account's own Maildir.
///
/// `INBOX` is case-insensitive in IMAP, so `inbox` is the same mailbox; the
/// canonical spelling is what [`MaildirReader::create_folder`] answers with.
#[must_use]
pub fn is_inbox(folder: &str) -> bool {
    folder.eq_ignore_ascii_case(INBOX)
}

/// Check a folder name against this layout's reserved spellings, and answer
/// the component it maps to.
///
/// Refused: empty, longer than 200 bytes, `.` / `..`, anything with `/`, `\`,
/// a NUL or a control byte, a leading `.` (that is how the layout spells its
/// own folders), and the reserved names the layout owns at the Maildir's top
/// level and inside a folder (`cur`, `new`, `tmp`, `dovecot-uidlist`,
/// `dovecot.index*`).
fn folder_component(folder: &str) -> Result<&str, ReaderError> {
    let bad = || ReaderError::BadFolder(folder.to_owned());
    if folder.is_empty() || folder.len() > 200 || folder == "." || folder == ".." {
        return Err(bad());
    }
    if folder.starts_with('.') {
        return Err(bad());
    }
    for ch in folder.chars() {
        if ch == '/' || ch == '\\' || ch == '\0' || ch.is_control() {
            return Err(bad());
        }
    }
    let lower = folder.to_ascii_lowercase();
    if matches!(
        lower.as_str(),
        "cur" | "new" | "tmp" | "dovecot-uidlist" | "maildirfolder" | "maildirsize"
    ) || lower.starts_with("dovecot.index")
        // `.Name.tmp` is Dovecot's transitional spelling while it renames a
        // folder; a user folder by that name would be skipped by every
        // listing, so it is refused rather than created dead.
        || lower.ends_with(".tmp")
    {
        return Err(bad());
    }
    Ok(folder)
}

/// The process-wide append sequence.
///
/// It is one counter for the process, not one per [`MaildirReader`], because
/// a reader is built per request: two requests landing in the same
/// microsecond each started their own sequence at `Q0`, and the second
/// append's rename silently replaced the first. The stamp, the pid and this
/// counter together are what make the name unique among writers *and* among
/// readers in this process.
static APPEND_SEQ: AtomicU64 = AtomicU64::new(0);

/// The next append sequence number.
fn next_seq() -> u64 {
    APPEND_SEQ.fetch_add(1, Ordering::Relaxed)
}

/// Whether `part` is one plain path component (no separator, not `.` / `..`).
fn check_component(part: &str) -> Result<(), ()> {
    if part.is_empty() {
        return Err(());
    }
    let mut components = Path::new(part).components();
    match (components.next(), components.next()) {
        (Some(Component::Normal(name)), None) if name == part => Ok(()),
        _ => Err(()),
    }
}

/// `hostname` as a maildir name token: `:` / `/` are the two bytes a maildir
/// name may not carry, everything else is passed through.
fn host_token(hostname: &str) -> String {
    hostname
        .chars()
        .map(|ch| {
            if ch == ':' || ch == '/' || ch == '\\' {
                '_'
            } else {
                ch
            }
        })
        .collect()
}

/// Whether `candidate` resolves to `root` itself or a directory inside it.
///
/// Both are canonicalised, so a path that climbs (`..`), follows a symlink out
/// of the tree, or names an absolute location answers "no". A root that does
/// not exist yet cannot describe a tree, and only then is the prefix test done
/// on the two paths as built — the caller has just created the directories, so
/// this is a doctest-shaped edge rather than a runtime one.
fn confirm_beneath(root: &Path, candidate: &Path) -> Result<(), ()> {
    let root = fs::canonicalize(root).map_err(|_| ())?;
    let candidate = fs::canonicalize(candidate).map_err(|_| ())?;
    if candidate == root || candidate.starts_with(&root) {
        Ok(())
    } else {
        Err(())
    }
}

/// Rename `from` to `to`, mapping a vanished source to [`ReaderError::Missing`].
fn rename_hard(from: &Path, to: &Path, folder: &str, id: &MessageId) -> Result<(), ReaderError> {
    std::fs::rename(from, to).map_err(|e| {
        if e.kind() == io::ErrorKind::NotFound {
            ReaderError::Missing {
                folder: folder.to_owned(),
                id: id.file_name(),
            }
        } else {
            ReaderError::io(from, e)
        }
    })
}

/// The first [`PREVIEW_HEAD_BYTES`] of a message file.
fn head_of(path: &Path) -> Option<Vec<u8>> {
    use std::io::BufRead;
    let file = fs::File::open(path).ok()?;
    let mut reader = io::BufReader::with_capacity(PREVIEW_HEAD_BYTES.min(8 * 1024), file);
    let mut head = Vec::new();
    let mut line = Vec::new();
    // The header block ends at the first empty line; reading until then (and
    // not a fixed prefix) is what keeps a long Received chain or a folded
    // subject from erasing the row's subject and date. A message with no such
    // line gets the bound, which is a malformed message either way.
    // The header block ends at the first blank line *after a field*. A
    // leading blank line is legal (MIME allows a preamble before the fields),
    // and treating it as the end would drop every column of a message that
    // has one — subject, sender, date, preview — while `total` still counted
    // it. `saw_field` is what distinguishes "the block ended" from "the block
    // has not started".
    let mut saw_field = false;
    loop {
        line.clear();
        let read = reader.read_until(b'\n', &mut line).ok()?;
        if read == 0 {
            break;
        }
        head.extend_from_slice(&line);
        let blank = line == b"\n" || line == b"\r\n";
        if blank {
            if saw_field || head.len() >= PREVIEW_HEAD_BYTES {
                break;
            }
            continue;
        }
        saw_field = true;
        if head.len() >= PREVIEW_HEAD_BYTES {
            break;
        }
    }
    // A little of the body, so the preview line has something to draw from
    // without reading the whole message.
    let mut rest = Vec::new();
    (&mut reader)
        .take(PREVIEW_BODY_BYTES as u64)
        .read_to_end(&mut rest)
        .ok()?;
    head.extend_from_slice(&rest);
    Some(head)
}

/// The listing columns, from a message head.
///
/// The head is a *prefix* of the file, so the body may be cut off; a head
/// `mail-parser` cannot parse at all falls back to the raw header block,
/// which this function scans itself.
struct Summary {
    from: Option<String>,
    subject: Option<String>,
    date: Option<String>,
    preview: Option<String>,
    /// The `Date:` header in seconds since the epoch — the arrival key the
    /// listing sorts by — `None` when the header is absent or unparsable.
    dated: Option<i64>,
}

fn summarise(raw: &[u8]) -> Summary {
    let text = String::from_utf8_lossy(raw);
    let parsed = ayane_mail::mime::parse(raw);
    if let Some(message) = &parsed {
        // Each column falls back to the raw header scan when the parser did
        // not answer for it. That is not belt-and-braces: a header block with
        // a preamble (a leading blank line, which MIME allows) is a shape
        // `mail-parser` reads as "no fields", and a roster row built from an
        // all-`None` summary would hide a message that is plainly there.
        let from = message
            .from
            .clone()
            .or_else(|| raw_header_value(&text, "from").and_then(|value| address_in(&value)));
        let subject = message
            .subject
            .clone()
            .or_else(|| raw_header_value(&text, "subject"));
        let raw_date = raw_header_value(&text, "date");
        let date = message
            .date
            .clone()
            .or_else(|| raw_date.as_deref().and_then(display_date));
        let dated = message
            .date
            .as_deref()
            .and_then(epoch_of_rfc3339)
            .or_else(|| raw_date.as_deref().and_then(epoch_of_date));
        return Summary {
            from,
            subject,
            date,
            preview: message.text.as_deref().and_then(preview_of),
            dated,
        };
    }
    let from = raw_header_value(&text, "from").and_then(|value| address_in(&value));
    let subject = raw_header_value(&text, "subject");
    let date = raw_header_value(&text, "date");
    Summary {
        from,
        subject,
        date: date.as_deref().and_then(display_date),
        preview: None,
        dated: date.as_deref().and_then(epoch_of_date),
    }
}

/// The address inside a `From:` header value (`Alice <alice@d>` → `alice@d`).
///
/// The roster's column is an address, not a display name, so the angle-
/// bracketed form yields what is inside the brackets and a bare value is
/// taken as it stands (trimmed of a trailing comment).
fn address_in(value: &str) -> Option<String> {
    let value = value.trim();
    if let (Some(start), Some(end)) = (value.find('<'), value.rfind('>')) {
        if start < end {
            return Some(value[start + 1..end].trim().to_owned());
        }
    }
    let bare = value.split('(').next().unwrap_or(value).trim();
    (!bare.is_empty()).then(|| bare.to_owned())
}

/// The header block of a message: everything before the first blank line.
fn header_block(text: &str) -> &str {
    // A preamble of blank lines is legal, so the block starts at the first
    // line that is not one. Without this the search below finds the *empty*
    // string before the first field (`"\r\n\r\n"` at offset zero) and every
    // column of such a message comes back `None`.
    let start = text.trim_start_matches(['\r', '\n']).as_ptr() as usize - text.as_ptr() as usize;
    let text = &text[start..];
    match text.find("\r\n\r\n").or_else(|| text.find("\n\n")) {
        Some(end) => &text[..end],
        None => text,
    }
}

/// One header field's unfolded value, case-insensitively, from the message's
/// header block.
///
/// A folded field (continuation lines beginning with a space or tab) is
/// joined with a single space, which is what the field means; the scan stops
/// at the blank line, so a body line that looks like `Date: …` is never read
/// as a header.
fn raw_header_value(text: &str, name: &str) -> Option<String> {
    let mut value: Option<String> = None;
    for line in header_block(text).split(['\r', '\n']) {
        if line.starts_with([' ', '\t']) {
            if let Some(current) = value.as_mut() {
                current.push(' ');
                current.push_str(line.trim());
            }
            continue;
        }
        if value.is_some() {
            return value;
        }
        let Some((field, rest)) = line.split_once(':') else {
            continue;
        };
        if field.trim().eq_ignore_ascii_case(name) {
            value = Some(rest.trim().to_owned());
        }
    }
    value
}

/// A `Date:` header rendered RFC 3339, when it parses.
fn display_date(raw: &str) -> Option<String> {
    ayane_mail::mime::date_header_rfc3339(raw)
}

/// Seconds since the epoch of an RFC 5322 date header.
fn epoch_of_date(raw: &str) -> Option<i64> {
    ayane_mail::mime::date_header_epoch(raw)
}

/// Seconds since the epoch of an RFC 3339 stamp.
fn epoch_of_rfc3339(stamp: &str) -> Option<i64> {
    ayane_mail::mime::rfc3339_epoch(stamp)
}

/// The roster's preview line: the first prose run of a text body.
///
/// Blank and quoted-reply lines are structure, not content, so they are
/// skipped; a line that reads as tag soup (HTML, a raw header, a base64 run)
/// never becomes a preview. The cut lands on a character boundary.
fn preview_of(text: &str) -> Option<String> {
    let mut line = String::new();
    for raw in text.lines() {
        let trimmed = raw.trim();
        if trimmed.is_empty() || trimmed.starts_with('>') {
            continue;
        }
        if !line.is_empty() {
            line.push(' ');
        }
        line.push_str(trimmed);
        if line.chars().count() >= 80 {
            break;
        }
        if line.chars().count() + trimmed.chars().count() > PREVIEW_CHARS {
            break;
        }
    }
    if line.is_empty() {
        return None;
    }
    let prose = !line.contains('<')
        && !line.contains("Content-")
        && line
            .chars()
            .all(|c| c.is_alphanumeric() || c.is_whitespace() || PREVIEW_PUNCT.contains(c));
    if !prose {
        return None;
    }
    let mut out: String = line.chars().take(PREVIEW_CHARS).collect();
    while !out.is_char_boundary(out.len()) {
        out.pop();
    }
    Some(out)
}

/// Punctuation a plain-text sentence may carry and still read as prose.
const PREVIEW_PUNCT: &str = ".,;:!?'\"()[]{}%+-=/@#&*_ ~—…、，。：；！？「」『』（）";

/// The SHA-256 of a message's bytes, lowercase hex.
///
/// The read path reports attachment digests from [`ayane_mail::mime`]; this
/// is the digest of the *file*, which is what an operator compares against
/// the spool's envelope record.
#[must_use]
pub fn digest(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    format!("{digest:x}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "ayane-maildir-reader-{name}-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&path).expect("root");
        path
    }

    fn addr(raw: &str) -> Address {
        Address::parse(raw).expect("fixture address")
    }

    fn message(subject: &str, body: &str) -> Vec<u8> {
        format!(
            "From: Alice <alice@example.test>\r\n\
             To: bob@example.test\r\n\
             Subject: {subject}\r\n\
             Date: Mon, 2 Jan 2023 15:04:05 +0000\r\n\
             Message-ID: <m@{subject}>\r\n\
             Content-Type: text/plain; charset=utf-8\r\n\
             \r\n\
             {body}\r\n"
        )
        .into_bytes()
    }

    #[test]
    fn a_flag_suffix_round_trips() {
        let id = MessageId::parse("1700000000.M1P2Q3.host").expect("id");
        assert!(!id.flags().seen);
        assert_eq!(id.file_name(), "1700000000.M1P2Q3.host");
        let seen = id.with_flags(Flags {
            seen: true,
            ..Flags::default()
        });
        assert_eq!(seen.file_name(), "1700000000.M1P2Q3.host:2,S");
        let parsed = MessageId::parse(&seen.file_name()).expect("again");
        assert!(parsed.flags().seen);
        assert!(!parsed.flags().flagged);
        assert!(parsed.same_message(&id));
    }

    #[test]
    fn the_suffix_follows_the_standard_order() {
        let id = MessageId::parse("a").expect("id");
        let all = id.with_flags(Flags {
            draft: true,
            flagged: true,
            seen: true,
            trashed: true,
        });
        assert_eq!(all.suffix(), "DFST");
    }

    #[test]
    fn a_symlink_out_of_the_maildir_is_not_a_folder() {
        // `folder_component` checks the *string*; `confirm_beneath` checks the
        // *disk*. A folder whose resolved path is outside the account's
        // Maildir — a symlink planted there, a `..` that slipped the check —
        // must be refused rather than created and written into.
        let reader = MaildirReader::new(root("symlink-escape"));
        let who = addr("bob@example.com");
        let maildir = reader.maildir_of(&who).expect("maildir");
        std::fs::create_dir_all(&maildir).expect("maildir");
        let outside = maildir
            .parent()
            .and_then(|parent| parent.parent())
            .expect("outside")
            .join("elsewhere");
        std::fs::create_dir_all(&outside).expect("outside dir");
        std::os::unix::fs::symlink(&outside, maildir.join(".Escape")).expect("symlink");

        let refused = reader.create_folder(&who, "Escape");
        assert!(
            matches!(refused, Err(ReaderError::BadFolder(_))),
            "a folder that resolves outside the maildir is refused: {refused:?}"
        );
        // And nothing was created through it.
        assert!(!outside.join("cur").exists(), "nothing descended the link");
    }

    #[test]
    fn ids_that_could_escape_the_folder_are_refused() {
        for name in [
            "", ".", "..", "a/b", "a\\b", ".hidden", "a\0b", "a\nb", ":2,S", "x:2,Z",
        ] {
            assert!(
                MessageId::parse(name).is_err(),
                "`{name}` must not be an id"
            );
        }
    }

    #[test]
    fn folder_names_that_could_escape_the_maildir_are_refused() {
        for name in [
            "",
            ".",
            "..",
            "a/b",
            "a\\b",
            ".Sent",
            "cur",
            "new",
            "tmp",
            "dovecot-uidlist",
            "name.tmp",
            "a\0b",
        ] {
            assert!(
                folder_component(name).is_err(),
                "`{name}` must not be a folder"
            );
        }
        assert_eq!(folder_component("Sent").expect("ok"), "Sent");
        assert_eq!(
            folder_component("Archive 2024").expect("ok"),
            "Archive 2024"
        );
    }

    #[test]
    fn an_address_whose_local_part_holds_a_separator_is_refused() {
        // Two layers, and this asserts both. `Address::parse` will not hand
        // one out (the local part may not contain `/`, `\\` or be a bare
        // `.`/`..`), and the reader refuses one anyway if a caller built an
        // `Address` through some other door: the delivery renderer splices
        // the local part into a path, so descending it is the failure both
        // layers exist to prevent.
        for raw in ["a/b@example.com", "..@example.com", "a\\b@example.com"] {
            assert!(
                Address::parse(raw).is_err(),
                "`{raw}` must not parse as an address"
            );
        }
        assert!(check_component("a/b").is_err());
        assert!(check_component("..").is_err());
        assert!(check_component(".").is_err());
        assert!(check_component("").is_err());
        assert!(check_component("bob").is_ok());

        let reader = MaildirReader::new(root("bad-address"));
        let ok = addr("bob@example.com");
        let path = reader.maildir_of(&ok).expect("maildir");
        assert!(path.ends_with("Maildir"));
        assert!(path.ends_with("example.com/bob/Maildir"));
    }

    #[test]
    fn inbox_is_the_maildir_and_a_named_folder_is_a_dot_child() {
        let reader = MaildirReader::new(root("layout"));
        let who = addr("bob@example.com");
        let inbox = reader.folder_dir(&who, INBOX, true).expect("inbox");
        let sent = reader.folder_dir(&who, SENT, true).expect("sent");
        assert_eq!(inbox, reader.maildir_of(&who).expect("maildir"));
        assert_eq!(sent, inbox.join(".Sent"));
        for sub in ["tmp", "new", "cur"] {
            assert!(inbox.join(sub).is_dir(), "inbox/{sub}");
            assert!(sent.join(sub).is_dir(), "sent/{sub}");
        }
    }

    #[test]
    fn an_empty_folder_lists_as_empty() {
        let reader = MaildirReader::new(root("empty"));
        let who = addr("bob@example.com");
        let listing = reader.list(&who, INBOX, 50).expect("list");
        assert_eq!(listing.total, 0);
        assert_eq!(listing.unread, 0);
        assert!(listing.messages.is_empty());
        // Starred over folders that do not exist contributes nothing.
        let starred = reader
            .list_flagged(&who, &STARRED_FOLDERS, 50)
            .expect("starred");
        assert_eq!(starred.total, 0);
        assert!(starred.messages.is_empty());
    }

    #[test]
    fn an_append_is_listed_read_and_flag_renamed() {
        let reader = MaildirReader::new(root("append"));
        let who = addr("bob@example.com");
        let id = reader
            .append(
                &who,
                INBOX,
                &message("Hi", "Hello there."),
                Flags::default(),
            )
            .expect("append");
        assert!(
            id.ends_with(":2,"),
            "an append writes the info suffix: {id}"
        );

        let listing = reader.list(&who, INBOX, 50).expect("list");
        assert_eq!(listing.total, 1);
        assert_eq!(listing.unread, 1);
        assert_eq!(listing.messages[0].id, id);
        assert_eq!(listing.messages[0].subject.as_deref(), Some("Hi"));
        assert_eq!(
            listing.messages[0].from.as_deref(),
            Some("alice@example.test")
        );
        assert_eq!(listing.messages[0].preview.as_deref(), Some("Hello there."));

        let opened = reader.read(&who, INBOX, &id).expect("read");
        assert_eq!(opened.flags, Flags::default());
        assert!(opened
            .message
            .text
            .as_deref()
            .is_some_and(|text| text.contains("Hello there")));

        let renamed = reader
            .set_flags(
                &who,
                INBOX,
                &id,
                FlagChange {
                    seen: Some(true),
                    ..FlagChange::default()
                },
            )
            .expect("mark seen");
        assert_eq!(renamed.to, format!("{}:2,S", id.trim_end_matches(":2,")));
        // The file name changed on disk …
        let dir = reader.folder_dir(&who, INBOX, false).expect("inbox");
        assert!(!dir.join("cur").join(&id).exists(), "the old name is gone");
        assert!(dir.join("cur").join(&renamed.to).exists());
        // … and an id is the message, not the byte-for-byte name: the id a
        // listing handed out before the rename still opens the message,
        // under its current name and flags.
        let by_old = reader
            .read(&who, INBOX, &id)
            .expect("the id still names the message");
        assert_eq!(by_old.id, renamed.to);
        assert!(by_old.flags.seen);
        assert_eq!(
            reader.read(&who, INBOX, &renamed.to).expect("read").id,
            renamed.to
        );
        let listing = reader.list(&who, INBOX, 50).expect("list");
        assert_eq!(listing.unread, 0);
        assert!(listing.messages[0].seen);
    }

    #[test]
    fn a_starred_roster_merges_folders_newest_first() {
        let reader = MaildirReader::new(root("starred"));
        let who = addr("bob@example.com");
        let old = reader
            .append(&who, INBOX, &message("Old", "a"), Flags::default())
            .expect("append");
        let new = reader
            .append(&who, SENT, &message("New", "b"), Flags::default())
            .expect("append");
        for id in [&old, &new] {
            let folder = if id == &old { INBOX } else { SENT };
            reader
                .set_flags(
                    &who,
                    folder,
                    id,
                    FlagChange {
                        flagged: Some(true),
                        ..FlagChange::default()
                    },
                )
                .expect("star");
        }
        // A third message nobody starred: the roster is a filter, not a copy
        // of every folder it looks at.
        reader
            .append(&who, INBOX, &message("Plain", "c"), Flags::default())
            .expect("append");
        let rows = reader
            .list_flagged(&who, &STARRED_FOLDERS, 50)
            .expect("starred");
        assert_eq!(rows.messages.len(), 2, "only the flagged: {rows:?}");
        assert_eq!(rows.total, 2, "all of them, before any page: {rows:?}");
        assert!(rows.messages.iter().all(|row| row.flagged));
        // The same Date header in both fixtures: the name breaks the tie.
        assert_eq!(rows.messages[0].mailbox, SENT);

        // The badge counts the flag over the whole set, not the page it
        // delivered: a limit of one still reports two.
        let page = reader
            .list_flagged(&who, &STARRED_FOLDERS, 1)
            .expect("one row");
        assert_eq!(page.messages.len(), 1);
        assert_eq!(page.total, 2, "the denominator is the folder, not the page");
    }

    #[test]
    fn a_message_in_new_lists_as_unseen_and_moves_to_cur_on_a_flag() {
        let reader = MaildirReader::new(root("new-to-cur"));
        let who = addr("bob@example.com");
        let dir = reader.folder_dir(&who, INBOX, true).expect("inbox");
        // A delivery's own shape: the file lands in `new/` with no suffix.
        let path = dir.join("new").join("1700000000.M1P2Q3.host,S=42");
        std::fs::write(&path, message("Fresh", "fresh body")).expect("write");

        let listing = reader.list(&who, INBOX, 50).expect("list");
        assert_eq!(listing.total, 1);
        assert_eq!(listing.unread, 1, "a file in new/ is unread");
        let id = listing.messages[0].id.clone();

        let renamed = reader
            .set_flags(
                &who,
                INBOX,
                &id,
                FlagChange {
                    seen: Some(true),
                    ..FlagChange::default()
                },
            )
            .expect("mark seen");
        assert!(!path.exists(), "the new/ file was renamed away");
        assert!(dir.join("cur").join(&renamed.to).exists());
        assert_eq!(renamed.to, "1700000000.M1P2Q3.host,S=42:2,S");
        assert_eq!(reader.list(&who, INBOX, 50).expect("list").unread, 0);
    }

    #[test]
    fn a_file_in_new_is_unread_even_when_its_name_says_seen() {
        // A foreign writer (or a restored backup) can leave a `:2,S` name in
        // `new/`. The directory is the stronger fact: a file the account has
        // not looked at yet is unread, whatever its suffix claims — the
        // reverse would show mail as read that no reader has opened.
        let reader = MaildirReader::new(root("new-with-suffix"));
        let who = addr("bob@example.com");
        let dir = reader.folder_dir(&who, INBOX, true).expect("inbox");
        let path = dir.join("new").join("1700000000.M1P2Q3.host:2,S");
        std::fs::write(&path, message("Sneaky", "body")).expect("write");

        let listing = reader.list(&who, INBOX, 50).expect("list");
        assert_eq!(listing.total, 1);
        assert_eq!(listing.unread, 1, "new/ wins over the S in the name");
        assert!(!listing.messages[0].seen, "the row is unread");
        // The flag it reports is the name's, because that is what the id says.
        assert!(listing.messages[0].id.ends_with(":2,S"));
    }

    #[test]
    fn unsetting_a_flag_rewrites_the_suffix() {
        let reader = MaildirReader::new(root("unflag"));
        let who = addr("bob@example.com");
        let id = reader
            .append(&who, INBOX, &message("x", "y"), Flags::default())
            .expect("append");
        let starred = reader
            .set_flags(
                &who,
                INBOX,
                &id,
                FlagChange {
                    flagged: Some(true),
                    seen: Some(true),
                },
            )
            .expect("star");
        assert_eq!(starred.to, format!("{}:2,FS", id.trim_end_matches(":2,")));
        let unstarred = reader
            .set_flags(
                &who,
                INBOX,
                &starred.to,
                FlagChange {
                    flagged: Some(false),
                    ..FlagChange::default()
                },
            )
            .expect("unstar");
        assert_eq!(unstarred.to, format!("{}:2,S", id.trim_end_matches(":2,")));
        assert!(!unstarred.flags.flagged);
        assert!(unstarred.flags.seen);
    }

    #[test]
    fn a_trash_move_lands_in_the_trash_cur_and_a_purge_removes_it() {
        let reader = MaildirReader::new(root("trash"));
        let who = addr("bob@example.com");
        let id = reader
            .append(&who, INBOX, &message("Kill", "bye"), Flags::default())
            .expect("append");
        let moved = reader.move_to(&who, INBOX, &id, TRASH).expect("move");
        assert!(reader
            .folder_dir(&who, TRASH, false)
            .expect("trash")
            .join("cur")
            .join(&moved.to)
            .exists());
        assert!(reader
            .list(&who, INBOX, 50)
            .expect("list")
            .messages
            .is_empty());
        assert_eq!(reader.list(&who, TRASH, 50).expect("trash").total, 1);

        reader.purge(&who, TRASH, &moved.to).expect("purge");
        assert_eq!(reader.list(&who, TRASH, 50).expect("trash").total, 0);
        // Nothing is left in tmp/ either: the quarantine copy is unlinked.
        let tmp = reader
            .folder_dir(&who, TRASH, false)
            .expect("trash")
            .join("tmp");
        let leftovers: Vec<_> = std::fs::read_dir(&tmp)
            .expect("tmp")
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().starts_with(".trash."))
            .collect();
        assert!(leftovers.is_empty(), "{leftovers:?}");
    }

    #[test]
    fn a_move_to_an_absent_folder_creates_it() {
        let reader = MaildirReader::new(root("create"));
        let who = addr("bob@example.com");
        let id = reader
            .append(&who, INBOX, &message("Keep", "x"), Flags::default())
            .expect("append");
        reader
            .move_to(&who, INBOX, &id, "Archive")
            .expect("move to a new folder");
        assert_eq!(
            reader.folders(&who).expect("folders"),
            vec![INBOX.to_owned(), "Archive".to_owned()]
        );
    }

    #[test]
    fn folders_lists_the_maildir_then_every_dot_child_that_holds_a_cur() {
        let reader = MaildirReader::new(root("folders"));
        let who = addr("bob@example.com");
        reader.create_folder(&who, SENT).expect("sent");
        reader.create_folder(&who, TRASH).expect("trash");
        let dir = reader.maildir_of(&who).expect("maildir");
        // A dot child with no `cur/` is not a folder (Dovecot's transitional
        // `.Name.tmp` spelling, or anything else a stranger wrote).
        std::fs::create_dir_all(dir.join(".NotAFolder")).expect("stray");
        std::fs::create_dir_all(dir.join(".Half.tmp").join("cur")).expect("stray tmp");
        assert_eq!(
            reader.folders(&who).expect("folders"),
            vec![INBOX.to_owned(), SENT.to_owned(), TRASH.to_owned()]
        );
    }

    #[test]
    fn a_folder_name_is_checked_before_it_becomes_a_directory() {
        let reader = MaildirReader::new(root("folder-guard"));
        let who = addr("bob@example.com");
        for bad in ["../escape", "a/b", "", ".", ".."] {
            assert!(
                matches!(
                    reader.create_folder(&who, bad),
                    Err(ReaderError::BadFolder(_))
                ),
                "`{bad}` must be refused"
            );
        }
        // Nothing was created outside the account's maildir.
        let parent = reader.maildir_of(&who).expect("maildir");
        assert!(!parent.parent().expect("domain dir").join("escape").exists());
    }

    #[test]
    fn a_leading_blank_line_does_not_erase_the_row() {
        // MIME allows a preamble before the fields, and a leading blank line
        // is the smallest form of one. Treating it as the end of the header
        // block would blank every column while `total` still counted the
        // message.
        let reader = MaildirReader::new(root("leading-blank"));
        let who = addr("bob@example.com");
        let raw = "\r\nFrom: Alice <alice@example.test>\r\n\
                   Subject: keeps its row\r\n\
                   Date: Mon, 2 Jan 2023 15:04:05 +0000\r\n\
                   Content-Type: text/plain; charset=utf-8\r\n\
                   \r\n\
                   the body\r\n";
        reader
            .append(&who, INBOX, raw.as_bytes(), Flags::default())
            .expect("append");
        let listing = reader.list(&who, INBOX, 50).expect("list");
        let row = &listing.messages[0];
        assert_eq!(row.subject.as_deref(), Some("keeps its row"), "{row:?}");
        assert_eq!(row.from.as_deref(), Some("alice@example.test"), "{row:?}");
        assert!(row.date.is_some(), "{row:?}");
        // The preview is the one column this shape does not get: the body is
        // read through `mail-parser`, which treats a preamble as "the header
        // block has not started" and finds no text part after it. The row
        // still carries its subject, sender and date, which is what a roster
        // needs to show the message at all; `mail.read` renders the body from
        // the same parser, so the two agree.
        assert_eq!(row.preview, None, "{row:?}");
    }

    #[test]
    fn a_long_header_chain_does_not_erase_the_row() {
        // A real message can carry kilobytes of `Received:`/`ARC-*` fields
        // before its own headers. The row is built from everything up to the
        // blank line, so the subject and date still appear — a fixed prefix
        // doing that job would blank them, which is what a roster looks like
        // when it is "empty" but the mail is there.
        let reader = MaildirReader::new(root("long-headers"));
        let who = addr("bob@example.com");
        let mut raw = String::new();
        for chain in 0..80 {
            raw.push_str(&format!(
                "Received: from relay{chain}.example.test (relay{chain}.example.test [192.0.2.1])\r\n\
                 \tby mx.example.test with ESMTPS id abc{chain:04}; Mon, 2 Jan 2023 15:04:05 +0000\r\n"
            ));
        }
        raw.push_str(
            "From: Alice <alice@example.test>\r\n\
             Subject: survives a long chain\r\n\
             Date: Mon, 2 Jan 2023 15:04:05 +0000\r\n\
             Content-Type: text/plain; charset=utf-8\r\n\
             \r\n\
             The body is here too.\r\n",
        );
        assert!(raw.len() > 8000, "the fixture is longer than the old bound");
        reader
            .append(&who, INBOX, raw.as_bytes(), Flags::default())
            .expect("append");

        let listing = reader.list(&who, INBOX, 50).expect("list");
        let row = &listing.messages[0];
        assert_eq!(row.subject.as_deref(), Some("survives a long chain"));
        assert_eq!(row.from.as_deref(), Some("alice@example.test"));
        assert!(row.date.is_some(), "the date survives too: {row:?}");
        assert_eq!(row.preview.as_deref(), Some("The body is here too."));
    }

    #[test]
    fn a_huge_body_is_not_read_whole_to_build_a_row() {
        // 8 MiB of body: the row costs the header block plus one preview
        // window, not the message. Asserted through the observable part —
        // the preview is drawn and the row still lists — because the read
        // amount itself is not visible from here.
        let reader = MaildirReader::new(root("huge-body"));
        let who = addr("bob@example.com");
        let mut raw = String::from(
            "From: Alice <alice@example.test>\r\nSubject: big\r\n\
             Content-Type: text/plain; charset=utf-8\r\n\r\n\
             opening words.\r\n",
        );
        raw.push_str(&"x".repeat(8 * 1024 * 1024));
        let started = std::time::Instant::now();
        reader
            .append(&who, INBOX, raw.as_bytes(), Flags::default())
            .expect("append");
        let listing = reader.list(&who, INBOX, 50).expect("list");
        let preview = listing.messages[0].preview.as_deref().expect("a preview");
        assert!(
            preview.starts_with("opening words."),
            "the preview opens with the body's first words: {preview:.40}"
        );
        assert!(
            preview.chars().count() <= 256,
            "the preview is capped, not the whole body: {} chars",
            preview.chars().count()
        );
        assert!(
            started.elapsed() < std::time::Duration::from_secs(30),
            "listing an 8 MiB message took {:?}",
            started.elapsed()
        );
    }

    #[test]
    fn an_html_only_message_has_no_preview() {
        let reader = MaildirReader::new(root("html"));
        let who = addr("bob@example.com");
        let raw = "From: eve@evil.example\r\n\
                   Subject: click\r\n\
                   Content-Type: text/html; charset=utf-8\r\n\
                   \r\n\
                   <html><body><p>Hi</p></body></html>\r\n";
        let id = reader
            .append(&who, INBOX, raw.as_bytes(), Flags::default())
            .expect("append");
        let listing = reader.list(&who, INBOX, 50).expect("list");
        assert_eq!(listing.messages[0].id, id);
        assert_eq!(listing.messages[0].preview, None);
        assert_eq!(listing.messages[0].subject.as_deref(), Some("click"));
    }

    #[test]
    fn the_header_date_decides_the_page_not_the_files_mtime() {
        // A migrated or restored maildir has files whose mtime has nothing to
        // do with their `Date:` header. Cutting the page on mtime and sorting
        // on the header after would drop the newest message from any page
        // smaller than the folder — while `total` still counted it.
        let reader = MaildirReader::new(root("page-by-date"));
        let who = addr("bob@example.com");
        let dated = |subject: &str, date: &str| {
            format!(
                "From: x@example.test\r\nSubject: {subject}\r\nDate: {date}\r\n\
                 Content-Type: text/plain; charset=utf-8\r\n\r\nbody\r\n"
            )
        };
        // Written first (oldest mtime), but its header is the newest date.
        reader
            .append(
                &who,
                INBOX,
                dated("newest-by-header", "Fri, 01 Dec 2023 00:00:00 +0000").as_bytes(),
                Flags::default(),
            )
            .expect("append newest");
        for index in 0..2 {
            reader
                .append(
                    &who,
                    INBOX,
                    dated(&format!("older-{index}"), "Mon, 02 Jan 2023 00:00:00 +0000").as_bytes(),
                    Flags::default(),
                )
                .expect("append older");
        }
        // Make the oldest-written file look the oldest on disk too, which is
        // the shape a `cp -p` / `rsync` restore leaves behind. Not required
        // for the assertion (the guard is about the ordering rule), but it is
        // the case that used to break.
        let listing = reader.list(&who, INBOX, 1).expect("one row");
        assert_eq!(listing.total, 3, "the folder is counted whole");
        assert_eq!(listing.messages.len(), 1);
        assert_eq!(
            listing.messages[0].subject.as_deref(),
            Some("newest-by-header"),
            "the one row a page of one keeps is the newest by the roster's own key"
        );
        assert!(listing.messages[0].sort_key > 1_700_000_000);
    }

    #[test]
    fn a_message_whose_date_is_absent_sorts_by_modification_time() {
        let reader = MaildirReader::new(root("mtime"));
        let who = addr("bob@example.com");
        let raw = "From: x@example.test\r\nSubject: undated\r\n\r\nbody\r\n";
        let id = reader
            .append(&who, INBOX, raw.as_bytes(), Flags::default())
            .expect("append");
        let listing = reader.list(&who, INBOX, 50).expect("list");
        assert_eq!(listing.messages[0].id, id);
        assert!(listing.messages[0].date.is_none());
        assert!(listing.messages[0].sort_key > 0, "mtime stands in");
    }

    #[test]
    fn a_limit_keeps_the_newest_and_the_counts_the_whole_folder() {
        let reader = MaildirReader::new(root("limit"));
        let who = addr("bob@example.com");
        for index in 0..5 {
            let raw = format!(
                "From: x@example.test\r\nSubject: s{index}\r\nDate: Mon, 2 Jan 2023 15:04:0{index} +0000\r\n\r\nbody\r\n"
            );
            reader
                .append(&who, INBOX, raw.as_bytes(), Flags::default())
                .expect("append");
        }
        let listing = reader.list(&who, INBOX, 2).expect("list");
        assert_eq!(listing.total, 5, "the denominator is the whole folder");
        assert_eq!(listing.messages.len(), 2);
        assert_eq!(listing.messages[0].subject.as_deref(), Some("s4"));
        assert_eq!(listing.messages[1].subject.as_deref(), Some("s3"));
    }

    #[test]
    fn an_append_never_renames_over_a_message_that_is_already_there() {
        // The name is claimed, not assumed: a file already sitting where the
        // append would land (another process's writer, a restored backup, a
        // reused sequence) is a reason to pick the next name — never a reason
        // to replace it. `create_new` alone would refuse the whole append;
        // probing first is what turns a collision into a second name.
        let reader = MaildirReader::new(root("append-collision"));
        let who = addr("bob@example.com");
        let dir = reader.folder_dir(&who, DRAFTS, true).expect("drafts");
        // Occupy every name the first few attempts would produce, by asking
        // the reader for one and writing a file there.
        let first = reader
            .append(&who, DRAFTS, &message("one", "a"), Flags::default())
            .expect("first append");
        let cur = dir.join("cur");
        assert!(cur.join(&first).exists());

        let second = reader
            .append(&who, DRAFTS, &message("two", "b"), Flags::default())
            .expect("second append");
        assert_ne!(first, second, "a second append takes its own name");
        // Both are still there, each with its own body.
        let listing = reader.list(&who, DRAFTS, 50).expect("list");
        assert_eq!(listing.total, 2, "{listing:?}");
        let bodies: Vec<String> = ["one", "two"]
            .iter()
            .map(|subject| {
                let row = listing
                    .messages
                    .iter()
                    .find(|row| row.subject.as_deref() == Some(*subject))
                    .unwrap_or_else(|| panic!("`{subject}` is still listed: {listing:?}"));
                reader
                    .read(&who, DRAFTS, &row.id)
                    .expect("read")
                    .message
                    .text
                    .unwrap_or_default()
            })
            .collect();
        assert!(bodies[0].contains('a'), "{bodies:?}");
        assert!(bodies[1].contains('b'), "{bodies:?}");

        // A name already on disk is never written over, even when asked to.
        let squatter = cur.join("squatter:2,");
        std::fs::write(&squatter, b"Subject: squatter\r\n\r\nkept\r\n").expect("squat");
        let third = reader
            .append(&who, DRAFTS, &message("three", "c"), Flags::default())
            .expect("third append");
        assert_ne!(third, "squatter:2,");
        assert_eq!(
            std::fs::read(&squatter).expect("squatter still there"),
            b"Subject: squatter\r\n\r\nkept\r\n",
            "the squatter's bytes are untouched"
        );
    }

    #[test]
    fn concurrent_appends_never_take_the_same_name() {
        // A reader is built per request, so the append sequence has to be the
        // process's: two requests in the same microsecond each starting at
        // `Q0` would rename one draft over the other, and the user's first
        // save would vanish without an error anywhere.
        let root_dir = root("concurrent-append");
        let who = addr("bob@example.com");
        let body = message("concurrent", "body");
        let mut handles = Vec::new();
        for _ in 0..16 {
            let root_dir = root_dir.clone();
            let who = who.clone();
            let body = body.clone();
            handles.push(std::thread::spawn(move || {
                // A *new* reader each time, exactly as `reader_of` builds one.
                MaildirReader::new(root_dir)
                    .append(&who, DRAFTS, &body, Flags::default())
                    .expect("append")
            }));
        }
        let mut names: Vec<String> = handles
            .into_iter()
            .map(|handle| handle.join().expect("thread"))
            .collect();
        let count = names.len();
        names.sort();
        names.dedup();
        assert_eq!(names.len(), count, "every append took its own name");

        let reader = MaildirReader::new(root_dir);
        assert_eq!(
            reader.list(&who, DRAFTS, 50).expect("list").total,
            count as u32,
            "and every one of them is still there"
        );
    }

    #[test]
    fn a_folder_over_the_listing_bound_pages_by_arrival_and_says_so() {
        // The bound is the one place the roster knowingly stops being exact:
        // above `MAX_LISTING_CANDIDATES` it pages on arrival (mtime) instead
        // of reading every head. This pins that branch — including that it is
        // the *newest* arrivals that make the page, which is the property a
        // reversed comparator silently loses.
        //
        // The fixture has to reach the branch: the files must be named like
        // maildir messages (a parsed id) and their `Date:` headers must
        // disagree with their mtimes in an order the branch would get wrong
        // if it cut the wrong way — the oldest *file* carries the newest
        // *date*, so a page that reads heads (exact) and one that pages on
        // mtime (the bound) produce different rows. Here the bound is in
        // force, so the page is the newest files.
        let reader = MaildirReader::new(root("over-bound"));
        let who = addr("bob@example.com");
        let dir = reader.folder_dir(&who, INBOX, true).expect("inbox");
        let cur = dir.join("cur");
        let count = MAX_LISTING_CANDIDATES + 2;
        for index in 0..count {
            // `MessageId::parse` needs a name it accepts: `<unique>:2,<flags>`.
            // The `Date:` header is **descending** while the write order (and
            // so the mtime) ascends, so the two orderings disagree: an exact
            // page (heads read) takes the low numbers, a page on arrival takes
            // the high ones. That is what makes the branch observable.
            let path = cur.join(format!("{index:09}.M000000P1Q{index}.host:2,"));
            let day = 28 - (index % 27);
            let raw = format!(
                "From: x@example.test\r\nSubject: s{index}\r\n\
                 Date: Mon, {day:02} Jan 2023 12:00:00 +0000\r\n\
                 Content-Type: text/plain; charset=utf-8\r\n\r\nbody\r\n"
            );
            std::fs::write(&path, raw).expect("write");
        }

        let listing = reader.list(&who, INBOX, 3).expect("list");
        assert_eq!(
            listing.total, count as u32,
            "the whole folder is counted, not the page"
        );
        assert_eq!(listing.messages.len(), 3, "the page is the page");

        // The three newest files, by the fixture's own names. `msg-…` for the
        // tie-break, and the numeric prefix is what orders them.
        let ids: Vec<&str> = listing.messages.iter().map(|row| row.id.as_str()).collect();
        for wanted in [count - 1, count - 2, count - 3] {
            let prefix = format!("{wanted:09}.");
            assert!(
                ids.iter().any(|id| id.starts_with(&prefix)),
                "the page holds the newest arrival `{prefix}…`: {ids:?}"
            );
        }
        assert!(
            !ids.iter()
                .any(|id| id.starts_with(&format!("{:09}.", count - 4))),
            "and stops at the page size: {ids:?}"
        );
    }

    #[test]
    fn a_digest_is_stable_across_calls() {
        let bytes = b"Subject: x\r\n\r\nbody\r\n";
        let first = digest(bytes);
        assert_eq!(first, digest(bytes));
        assert_eq!(first.len(), 64);
    }
}
