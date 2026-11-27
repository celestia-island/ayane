//! The session's own state: RFC 3501 §3's four states, the selection a selected
//! session carries, and the object that holds them.

use std::path::PathBuf;

use ayane_proto::Address;

use crate::authn::PasswordVerifier;
use crate::maildir_reader::MaildirReader;

use super::uidlist::UidMap;
use super::Row;

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

impl Outcome {
    /// An answer: bytes to write, nothing else.
    #[must_use]
    pub fn out(out: Vec<u8>) -> Self {
        Self {
            out,
            ..Self::default()
        }
    }

    /// The line that precedes the TLS handshake, and nothing else.
    #[must_use]
    pub fn start_tls(line: Vec<u8>) -> Self {
        Self {
            start_tls: Some(line),
            ..Self::default()
        }
    }
}

/// A folder as one command sees it: where it is, its UID table, and its
/// messages.
pub(crate) struct Folder {
    pub(crate) dir: PathBuf,
    pub(crate) map: UidMap,
    pub(crate) messages: Vec<Row>,
}

/// A client's selection of a mailbox — the state `Selected` carries.
#[derive(Debug, Clone)]
pub(crate) struct Selected {
    /// `INBOX` or the folder name, in [`MaildirReader`]'s spelling.
    pub(crate) folder: String,
    /// The folder's directory.
    pub(crate) dir: PathBuf,
    /// `EXAMINE`: every mutation is refused.
    pub(crate) read_only: bool,
    /// `(uid, file name, in_cur)` at the last rescan; sequence number = index+1.
    pub(crate) messages: Vec<Row>,
    /// The UIDs this session announced as `\Recent`.
    pub(crate) recent: Vec<u32>,
}

impl Selected {
    /// Whether `uid` is recent *for this session*.
    pub(crate) fn is_recent(&self, uid: u32) -> bool {
        self.recent.contains(&uid)
    }

    /// The sequence number of `uid` (1 when it is no longer in the list).
    pub(crate) fn seq_of(&self, uid: u32) -> u32 {
        self.messages
            .iter()
            .position(|(it, _, _)| *it == uid)
            .and_then(|i| u32::try_from(i + 1).ok())
            .unwrap_or(1)
    }

    /// The `(uid, file name)` pair a UID or a 1-based sequence number names.
    pub(crate) fn row(&self, n: u32, by: By) -> Option<(u32, String)> {
        let row = match by {
            By::Seq => self.messages.get(usize::try_from(n).ok()?.checked_sub(1)?),
            By::Uid => self.messages.iter().find(|(uid, _, _)| *uid == n),
        }?;
        Some((row.0, row.1.clone()))
    }

    /// The largest value `*` means for this selector (`1` when empty: a
    /// mailbox with no messages has no valid `*`).
    pub(crate) fn largest(&self, by: By) -> u32 {
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
    pub(crate) fn with(&self, messages: Vec<Row>) -> Self {
        Self {
            messages,
            ..self.clone()
        }
    }
}

/// How a sequence set selects messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum By {
    /// `1..=n` over the selection's current list.
    Seq,
    /// The UIDs themselves.
    Uid,
}

/// One IMAP session: the state, the selection, and the credentials check.
pub struct ImapSession<'a> {
    pub(crate) hostname: String,
    pub(crate) mailbox: Address,
    pub(crate) reader: MaildirReader,
    pub(crate) transport: Transport,
    pub(crate) state: State,
    pub(crate) selected: Option<Selected>,
    pub(crate) passwords: &'a dyn PasswordVerifier,
    /// Whether this listener can actually accept a `STARTTLS`.
    ///
    /// The transport says what a command arrived over; this says what the
    /// listener *can do*, and the two differ on a port with no certificate at
    /// all: a command there still arrived in the clear, but there is nothing to
    /// upgrade to, so `STARTTLS` must not be advertised. A session that is not
    /// told (a unit test driving the table) assumes it can — which is what
    /// makes [`Transport`] alone a safe default.
    pub(crate) starttls: bool,
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
