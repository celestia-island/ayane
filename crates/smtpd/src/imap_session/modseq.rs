//! The CONDSTORE mod-sequence table: one folder's `ayane-modseq` sidecar.
//!
//! RFC 7162 gives every message a per-mailbox revision number and the mailbox
//! a highest watermark, so a client can ask "what changed since `n`" and
//! "which UIDs vanished since `n`" without re-reading anything. The values
//! live in a sidecar next to [`super::UIDLIST`], keyed by the maildir name's
//! `unique` half — the part neither a flag rename nor a `new/`→`cur/` move
//! touches — because a message delivered by SMTP has no UID until an IMAP
//! session scans the folder, and the delivery process must not need to know
//! this file exists.
//!
//! ```text
//! h <highest-modseq>            the mailbox watermark, one line
//! m <unique> <modseq>           per-message mod-sequence (dead lines kept)
//! x <unique> <modseq>           expunge records for QRESYNC (FIFO, capped)
//! xf <modseq>                   the oldest mod-sequence trimmed out of `x`
//! ```
//!
//! Lines that do not parse are skipped, not fatal (the same discipline
//! `uidlist` follows — a corrupt line has never made a folder unreadable).
//! The watermark is the **maximum** over every number in the file, so a
//! last-writer-wins race between processes can only leave it stale-high, never
//! rolled back, and re-reading before every write merges the other writer's
//! lines by max rather than clobbering them.
//!
//! # The order contract (crash safety)
//!
//! The file is written **before** the rename that makes a change visible, and
//! every write is the uidlist's shape — `tmp` → `fsync(file)` → `rename` →
//! `fsync(dir)`. This ordering is a hard contract, not a style choice:
//!
//! - write-first, crash before the rename: the mod-sequence advanced but the
//!   flags did not change — a client re-fetches one message and caches the
//!   old flags under the new value. A planned change that did not happen;
//!   RFC 7162 §3.1 forbids *missing* a real change, not an empty advance.
//! - rename-first (forbidden here), crash before the write: the flags changed
//!   under the old value, and the client's `CHANGEDSINCE` filter skips the
//!   message forever — a lost update.
//!
//! `purge` is the one deliberate exception the other way: the quarantine
//! rename into `tmp/` happens first (it is what makes the message
//! un-listable), the record second, the unlink last — so a record and the
//! message's visibility never disagree.
//!
//! # Concurrency
//!
//! Production runs IMAP sessions and the webmail RPCs in one process
//! (`ayane serve`), and both write through [`crate::maildir_reader`]'s
//! primitives — so one process-wide mutex around each read-modify-write
//! closes the lost-update window between concurrent tasks. Across processes
//! the merge rule above is the whole story: every write re-reads, takes max,
//! and appends, which is order-free to merge.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};

use crate::maildir_reader::MessageId;

/// The sidecar's name, inside the folder it describes (`ayane-modseq`).
pub(crate) const MODSEQ: &str = "ayane-modseq";

/// The most expunge records a folder's queue holds. RFC 7162 §5.1 wants *an*
/// implementation-defined cap; past it the oldest records merge into
/// [`ModSeqTable::expired_through`], which is the one number a client older
/// than the trim can still be answered from (as "report everything").
pub(crate) const EXPUNGE_QUEUE_CAP: usize = 4096;

/// RFC 7162 §3.1: mod-sequences are unsigned 63-bit values. Assignment past
/// this returns an error the caller answers `NO cannot assign mod-sequence`
/// with — at one bump per flag change this needs a few thousand years to
/// fire, but the protocol forbids wrapping, so it is checked, not assumed.
pub(crate) const MODSEQ_LIMIT: u64 = (1 << 63) - 1;

/// A folder's mod-sequence table, as it was read from disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ModSeqTable {
    /// The mailbox watermark: every assigned value is at most this, and the
    /// next assignment is this plus one. Never decreases.
    highest: u64,
    /// `(unique, mod-sequence)` per message — live and dead alike.
    messages: Vec<(String, u64)>,
    /// `(unique, mod-sequence)` expunge records, oldest first.
    expunged: Vec<(String, u64)>,
    /// The oldest mod-sequence trimmed out of `expunged`; `0` when nothing
    /// was ever trimmed. Requests older than this are answered as
    /// "report everything" (RFC 7162 §3.2.6 note).
    expired_through: u64,
}

impl Default for ModSeqTable {
    /// A fresh table: the watermark starts at `1`, so the first assignment is
    /// `2` and `UNCHANGEDSINCE 1` is a client that has never seen anything.
    fn default() -> Self {
        Self {
            highest: 1,
            messages: Vec::new(),
            expunged: Vec::new(),
            expired_through: 0,
        }
    }
}

impl ModSeqTable {
    /// Where the sidecar lives inside `dir`.
    #[must_use]
    pub(crate) fn path(dir: &Path) -> PathBuf {
        dir.join(MODSEQ)
    }

    /// Read the sidecar, or a fresh table when the folder has none (a folder
    /// no CONDSTORE session has scanned yet). The watermark is the maximum
    /// over every number the file carries — see the module documentation.
    ///
    /// # Errors
    ///
    /// Returns [`io::Error`] when the file exists and cannot be read.
    pub(crate) fn load(dir: &Path) -> io::Result<Self> {
        let raw = match fs::read_to_string(Self::path(dir)) {
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(Self::default()),
            other => other?,
        };
        let mut table = Self::default();
        for line in raw.lines() {
            let Some((kind, rest)) = line.split_once(' ') else {
                continue;
            };
            match kind {
                "h" => {
                    if let Ok(value) = rest.trim().parse::<u64>() {
                        table.highest = table.highest.max(value);
                    }
                }
                "m" => {
                    if let Some((unique, value)) = message_line(rest) {
                        table.highest = table.highest.max(value);
                        table.set_message(&unique, value);
                    }
                }
                "x" => {
                    if let Some((unique, value)) = message_line(rest) {
                        table.highest = table.highest.max(value);
                        table.record_expunged(unique, value);
                    }
                }
                "xf" => {
                    if let Ok(value) = rest.trim().parse::<u64>() {
                        table.expired_through = table.expired_through.max(value);
                        table.highest = table.highest.max(value);
                    }
                }
                _ => {}
            }
        }
        Ok(table)
    }

    /// Write the sidecar durably and atomically — the uidlist's shape.
    ///
    /// # Errors
    ///
    /// Returns [`io::Error`] when the temporary file, the `fsync` or the
    /// rename fails — a caller that swallows it has let a client believe a
    /// change is recorded that the next crash may forget.
    pub(crate) fn store(&self, dir: &Path) -> io::Result<()> {
        fs::create_dir_all(dir)?;
        let mut text = format!("h {}\n", self.highest);
        for (unique, value) in &self.messages {
            text.push_str(&format!("m {unique} {value}\n"));
        }
        for (unique, value) in &self.expunged {
            text.push_str(&format!("x {unique} {value}\n"));
        }
        if self.expired_through > 0 {
            text.push_str(&format!("xf {}\n", self.expired_through));
        }
        let tmp = dir.join(format!("{MODSEQ}.tmp"));
        let mut file = fs::File::create(&tmp)?;
        io::Write::write_all(&mut file, text.as_bytes())?;
        file.sync_all()?;
        drop(file);
        fs::rename(&tmp, Self::path(dir))?;
        crate::queue::fsync_dir(dir)
    }

    /// The mod-sequence of one message, if the table holds it.
    #[must_use]
    pub(crate) fn of(&self, unique: &str) -> Option<u64> {
        self.messages
            .iter()
            .find(|(name, _)| name == unique)
            .map(|(_, value)| *value)
    }

    /// The watermark.
    #[must_use]
    pub(crate) fn highest(&self) -> u64 {
        self.highest
    }

    /// The expunge records newer than `since`, oldest first.
    #[must_use]
    pub(crate) fn expunged_since(&self, since: u64) -> Vec<(String, u64)> {
        self.expunged
            .iter()
            .filter(|(_, value)| *value > since)
            .cloned()
            .collect()
    }

    /// Whether a request for "changes since `since`" predates what this
    /// table still remembers: RFC 7162 §3.2.6's note turns that into
    /// "report every message the uidlist holds as dead".
    ///
    /// The note's `<minmodseq>` is "the smallest expunged mod-sequence the
    /// server remembers minus one" — the oldest record still in the queue,
    /// or, when the queue has been trimmed empty, the trim watermark plus
    /// one (nothing earlier is remembered, so a request below it cannot be
    /// answered exactly). The distinction is load-bearing: a client sitting
    /// exactly at `expired_through` is still answered from the queue,
    /// because the record *at* the watermark is exactly the one the trim
    /// forgot.
    #[must_use]
    pub(crate) fn predates_memory(&self, since: u64) -> bool {
        let oldest = self
            .expunged
            .first()
            .map_or(self.expired_through.saturating_add(1), |(_, value)| *value);
        oldest > 1 && since < oldest - 1
    }

    /// Sets one message's mod-sequence (inserting or replacing).
    fn set_message(&mut self, unique: &str, value: u64) {
        match self.messages.iter().position(|(name, _)| name == unique) {
            Some(at) => self.messages[at].1 = value,
            None => self.messages.push((unique.to_owned(), value)),
        }
    }

    /// Records an expunge, keeping the queue sorted by mod-sequence and
    /// de-duplicated by unique.
    fn record_expunged(&mut self, unique: String, value: u64) {
        if self.expunged.iter().any(|(name, _)| *name == unique) {
            return;
        }
        let at = self
            .expunged
            .iter()
            .position(|(_, other)| *other > value)
            .unwrap_or(self.expunged.len());
        self.expunged.insert(at, (unique, value));
    }

    /// Trims the queue to the cap, merging the trimmed mod-sequences into
    /// `expired_through` (the minimum of what was trimmed — the watermark is
    /// what a request older than it can no longer be answered from exactly).
    fn trim(&mut self) {
        while self.expunged.len() > EXPUNGE_QUEUE_CAP {
            let (_, oldest) = self.expunged.remove(0);
            self.expired_through = self.expired_through.max(oldest);
        }
    }
}

/// `(unique, mod-sequence)` out of one `m`/`x` line's remainder.
fn message_line(rest: &str) -> Option<(String, u64)> {
    let (unique, value) = rest.split_once(' ')?;
    let value = value.trim().parse::<u64>().ok()?;
    MessageId::parse(unique)
        .is_ok()
        .then_some((unique.to_owned(), value))
}

/// The process-wide write lock: one read-modify-write at a time (see the
/// module documentation). A poisoned guard is taken over, not propagated —
/// a panicked writer left the sidecar's *file* intact (every write is a
/// rename), so the next writer's re-read-and-merge is still correct.
fn lock() -> io::Result<MutexGuard<'static, ()>> {
    static SIDECAR: Mutex<()> = Mutex::new(());
    SIDECAR
        .lock()
        .map_err(|poisoned| poisoned.into_inner())
        .map_err(|_| io::Error::other("modseq table lock"))
}

/// Assigns or reads back the mod-sequences of `uniques`, oldest order first,
/// and — when the sidecar did not exist yet — records `dead` as expunged at
/// the values it hands out (the upgrade path: a folder with an old uidlist
/// adopts CONDSTORE and its already-dead lines become exactly the history a
/// fresh client needs; RFC 7162 §5.1 allows dropping that history, and this
/// keeps it instead).
///
/// This is the one entry point [`super::maildir_ops`] calls when it scans a
/// folder: every live message the uidlist has no entry for yet gets the next
/// values in scan order, which is what makes "a new message's mod-sequence is
/// higher than anything before it" hold for deliveries and APPENDs too.
///
/// # Errors
///
/// Returns [`io::Error`] when the sidecar cannot be read or written.
pub(crate) fn scan_sync(
    dir: &Path,
    live: &[String],
    dead: &[String],
) -> io::Result<Vec<(String, u64)>> {
    let _guard = lock()?;
    let fresh = !ModSeqTable::path(dir).exists();
    let mut table = ModSeqTable::load(dir)?;
    let mut assigned = Vec::new();
    let mut changed = false;
    let mut advance = |table: &mut ModSeqTable, unique: &str| -> io::Result<u64> {
        if let Some(value) = table.of(unique) {
            return Ok(value);
        }
        if table.highest >= MODSEQ_LIMIT {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "cannot assign mod-sequence",
            ));
        }
        table.highest += 1;
        table.set_message(unique, table.highest);
        changed = true;
        Ok(table.highest)
    };
    if fresh {
        for unique in dead {
            let value = advance(&mut table, unique)?;
            table.record_expunged(unique.clone(), value);
        }
    }
    for unique in live {
        let value = advance(&mut table, unique)?;
        assigned.push((unique.clone(), value));
    }
    if changed {
        table.store(dir)?;
    }
    Ok(assigned)
}

/// Advances the watermark and stamps `uniques` with the new value.
///
/// Called by [`crate::maildir_reader`]'s mutation primitives *before* the
/// rename that makes the change visible — the order contract in the module
/// documentation. One call is one mod-sequence for the whole change (RFC
/// 7162 §3.1: every STORE gets exactly one, however many flags it moves).
///
/// # Errors
///
/// Returns [`io::Error`] when the sidecar cannot be read or written, or the
/// 63-bit domain is exhausted.
pub(crate) fn bump(dir: &Path, uniques: &[String]) -> io::Result<u64> {
    let _guard = lock()?;
    let mut table = ModSeqTable::load(dir)?;
    if table.highest >= MODSEQ_LIMIT {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "cannot assign mod-sequence",
        ));
    }
    table.highest += 1;
    for unique in uniques {
        table.set_message(unique, table.highest);
    }
    table.store(dir)?;
    Ok(table.highest)
}

/// Records that one message left the folder: the watermark advances, the
/// message's own entry moves to the new value, and the `(unique, value)`
/// pair joins the QRESYNC queue (trimmed to the cap, the trim merged into
/// `expired_through`).
///
/// For `purge` the caller has already quarantined the file into `tmp/` (the
/// record-and-visibility exception in the module documentation); for `move_to`
/// the record is written **before** the rename, per the order contract.
///
/// # Errors
///
/// Returns [`io::Error`] when the sidecar cannot be read or written, or the
/// 63-bit domain is exhausted.
pub(crate) fn record_expunge(dir: &Path, unique: &str) -> io::Result<u64> {
    let _guard = lock()?;
    let mut table = ModSeqTable::load(dir)?;
    if table.highest >= MODSEQ_LIMIT {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "cannot assign mod-sequence",
        ));
    }
    table.highest += 1;
    table.set_message(unique, table.highest);
    table.record_expunged(unique.to_owned(), table.highest);
    table.trim();
    table.store(dir)?;
    Ok(table.highest)
}

/// Reads the table fresh (the caller is about to answer from it).
///
/// # Errors
///
/// Returns [`io::Error`] when the sidecar exists and cannot be read.
pub(crate) fn table(dir: &Path) -> io::Result<ModSeqTable> {
    let _guard = lock()?;
    ModSeqTable::load(dir)
}

#[cfg(test)]
mod tests;
