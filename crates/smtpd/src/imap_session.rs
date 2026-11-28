//! The IMAP4rev1 session: the RFC 3501 §3 state machine, the command set a
//! mail client actually uses, and the maildir backend behind both.
//!
//! The module opens no socket. The greeting and every reply are bytes a caller
//! writes; a client's literal is framed by [`read_command`] and handed to the
//! codec. The driver lives with the other listeners (`crate::imap_server`), so
//! the state machine is drivable as a table in a test.
//!
//! # The split
//!
//! One file per question the protocol asks:
//!
//! | file | what it holds |
//! | --- | --- |
//! | `imap_session.rs` | the shared vocabulary: constants, `Row`, `Kind` |
//! | [`session`] | §3's states, the selection, and [`ImapSession`] |
//! | `heading` | the greeting and the connection half of §3 |
//! | `lifecycle` | `LIST`, `STATUS`, `SELECT`, and the re-scan |
//! | `expunge` | `EXPUNGE`, `UID EXPUNGE`, the `CLOSE` sweep, and how a
//!   removal is reported (`* n EXPUNGE` or `* VANISHED`) |
//! | `commands` | the dispatcher: one command in, one answer out |
//! | `store` | `STORE`, and the `UNCHANGEDSINCE` conditions on it |
//! | `maildir_ops` | the maildir side: the UID table in step, `APPEND` |
//! | `query` | `FETCH`, `STORE`, `SEARCH`, `COPY`/`MOVE` |
//! | `render` | one message's data items, and the `SEARCH` keys |
//! | [`framing`] | the literal reader a client's command arrives through |
//! | `wire` | reply lines, capabilities, and the octet helpers |
//! | `uidlist` | a folder's UID table and its `UIDVALIDITY` |
//! | `qresync` | the RFC 7162 §3.2 SELECT parameter and the initial sync |
//! | `ext_scan` | the byte-level scanner the parameter parsers run on |
//! | `ext_lines` | the extension lines the codec cannot encode |
//! | [`modseq`] | a folder's mod-sequence sidecar (`ayane-modseq`) |
//! | `ext_wire` | the extension parameters the codec cannot parse, and the
//!   extension lines it cannot encode (see its module documentation) |
//! | `uidplus` | the UIDPLUS answers: `APPENDUID`, `COPYUID`, `UID EXPUNGE` |
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
//! ACLs, quotas, `IMAP4rev2` and binary literals are not advertised and not
//! implemented (a client asking is answered `NO`/`BAD`, never mis-served).
//! `LITERAL+` and `MOVE` are advertised: a client only uses a non-sync
//! literal when offered it, and moving is what a mail client does to every
//! message it files. `UIDPLUS`, `CONDSTORE` and `QRESYNC` are advertised
//! and implemented — CONDSTORE/QRESYNC by the enabling commands of RFC
//! 7162 §3.1.2/§3.2.2, UIDPLUS unconditionally (`APPENDUID`, `COPYUID`,
//! `UID EXPUNGE`); `IMAP4REV2` is deliberately not declared: RFC 9051
//! Appendix E's mandatory items are a project of their own.

use ayane_proto::Address;

mod commands;
pub(crate) mod expunge;
pub(crate) mod ext_lines;
pub(crate) mod ext_scan;
pub(crate) mod ext_wire;
pub mod framing;
mod heading;
mod lifecycle;
mod maildir_ops;
pub(crate) mod modseq;
mod qresync;
mod query;
mod render;
pub mod session;
mod store;
mod uidlist;
pub(crate) mod uidplus;
mod wire;

pub use framing::{announcement_of, read_command, Framed};
pub use session::{ImapSession, Outcome, State, Transport};
pub use uidlist::{uid_validity, UidMap};
pub use wire::command_name;

/// One of the three status kinds a reply line can carry — shared with the
/// files that render lines.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Kind {
    /// `OK`.
    Ok,
    /// `NO`.
    No,
    /// `BAD`.
    Bad,
}

/// Unwrap a `Result` that carries an `Outcome` refusal: the operation's answer
/// is the refusal itself, so the caller returns it.
///
// `macro_rules!` is scoped to its module by default; a child module reaches it
// through `super::answer` only if it is exported, which must come after the
// definition.
macro_rules! answer {
    ($e:expr) => {
        match $e {
            Ok(value) => value,
            Err(out) => return out,
        }
    };
}

pub(crate) use answer;

/// The address a session is built over before it has a mailbox.
///
/// An [`ImapSession`] is scoped to one account, and a connection has none until
/// its client has logged in — but the greeting and the unauthenticated commands
/// still have to be rendered by *something*. A session built over this address
/// answers exactly those ([`ImapSession::greeting`],
/// [`ImapSession::capabilities`], and the `not authenticated` refusals
/// [`ImapSession::handle`] returns for everything else); it can read no
/// mailbox, because no credential ever opens one.
///
/// `ayane.invalid` is under the RFC 2606 §2 reserved TLD: it can never be
/// delivered to and never belongs to anyone.
#[must_use]
pub fn unassigned() -> Address {
    Address::parse("ayane-unassigned@ayane.invalid")
        .expect("a reserved-TLD address is a valid mailbox address")
}

/// The mapping file's name, inside the folder it describes.
pub const UIDLIST: &str = "ayane-uidlist";

/// The most a client's command may occupy, literals included.
pub const MAX_COMMAND_BYTES: usize = 32 * 1024 * 1024;

/// The most a command *line* (before its literal) may occupy.
pub const MAX_LINE_BYTES: usize = 8 * 1024;

/// One message as the selection holds it: its UID, its file name, and whether
/// it is in `cur/` (`new/` otherwise).
pub(crate) type Row = (u32, String, bool);

/// The `BAD` a command gets when no mailbox is selected.
pub(crate) const NO_MAILBOX: &str = "no mailbox is selected";
/// The `NO` a mutation gets on a read-only selection.
pub(crate) const READ_ONLY: &str = "[READ-ONLY] mailbox is read-only";
/// The `BAD` a command gets for a mailbox name this layout cannot hold.
pub(crate) const BAD_MAILBOX: &str = "mailbox name is not one this layout holds";

#[cfg(test)]
mod tests;
