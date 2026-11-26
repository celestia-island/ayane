//! The crash-safe file spool.
//!
//! Layout (one directory per spool root):
//!
//! ```text
//! spool/
//!   tmp/<id>.eml     message being written (never delivered)
//!   tmp/<id>.json    envelope metadata being written
//!   new/<id>.eml     committed, awaiting delivery       ← W1 stops here
//!   new/<id>.json    its envelope, written *before* the rename
//!   cur/<id>.eml     being delivered (W2 moves files here)
//!   cur/<id>.json
//! ```
//!
//! **The commit order is the durability contract** (MAP §四 rule 5):
//!
//! ```text
//! write(.eml) → fsync(.eml) → rename(json → new/) → rename(eml → new/)
//!             → fsync(dir new/) → 250
//! ```
//!
//! * The metadata is renamed first so that a message file in `new/` always has
//!   its envelope beside it; a crash between the two leaves an orphan
//!   `.json` that recovery removes.
//! * `fsync(dir)` is what makes the two renames durable. Returning 250 before
//!   it would acknowledge a message a power cut can still erase.
//! * Every step that can be interrupted is pinned by recovery tests that put
//!   the spool into the state that step leaves behind: a truncated message, an
//!   orphan `.json`, a same-length bit flip, and a leftover in `tmp/`. After
//!   such a state the outcome must be "fully deliverable" or "never
//!   acknowledged", never "acknowledged but broken". (This crate does not
//!   spawn a process and `kill -9` it; the `SyncHook`s exist so a test can
//!   stop between two fsyncs, not so they can kill themselves.)
//!
//! Recovery ([`Spool::recover`]) runs at start-up and is idempotent:
//! temporary files that are provably abandoned are deleted, `new/` entries are
//! checked against the length and SHA-256 recorded in their metadata, and
//! anything that does not match is moved out of the delivery path into
//! `corrupt/`. Every removal or move it could not carry out is recorded in
//! [`RecoveryReport::failed`], so a full disk cannot make a run look clean.
//!
//! **Recovery does not delete a live writer's file.** A temporary file that a
//! process still holds open stays where it is. So does a young file whose id
//! names a running process — including this one: a short-lived `tmp/` file
//! (a dropped handle, a cancelled task) is left untouched during the grace
//! window [`TMP_RESIDUE_AGE`], because a late leftover costs disk and a wrong
//! deletion costs a message. Only after that window can the id alone make it
//! a leftover.
//!
//! For that to work with more than one process, the writer must ask the spool
//! for its ids: [`Spool::open`] → [`Spool::recover`] →
//! [`Spool::next_id`] → [`Spool::stage`]. An id minted *before* recovery's
//! sweep can be mistaken for a crash leftover and is discarded.

use std::collections::BTreeMap;
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{self, Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Temporary files whose writer cannot be identified (`<id>.json`, or a name
/// that is not a spool id at all) are deleted once they are this old: the
/// commit path only ever leaves such a file behind for the duration of one
/// commit, and a process elsewhere may have a different idea of "now".
pub const TMP_RESIDUE_AGE: Duration = Duration::from_secs(60 * 60);

/// The octets a streaming hash reads per call. Kept small and constant so the
/// peak memory of [`Spool::recover`] does not grow with the message size.
const HASH_CHUNK: usize = 64 * 1024;

/// Where a message sits in the spool.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueueState {
    /// Durably committed, not yet picked up by a delivery agent.
    New,
    /// Picked up by a delivery agent (W2).
    Cur,
}

impl QueueState {
    fn dir(self) -> &'static str {
        match self {
            Self::New => "new",
            Self::Cur => "cur",
        }
    }
}

impl Envelope {
    /// An envelope with only the queue id and host filled in; the driver
    /// completes it once the message is known.
    #[must_use]
    pub fn placeholder(id: &str, hostname: &str) -> Self {
        Self {
            id: id.to_owned(),
            received_at: String::new(),
            mail_from: String::new(),
            mail_from_wire: String::new(),
            helo: hostname.to_owned(),
            remote_ip: String::new(),
            authenticated: None,
            received: String::new(),
            auth_summary: String::new(),
            recipients: Vec::new(),
            declared_size: None,
            smtputf8: false,
            sha256: String::new(),
            size: 0,
        }
    }
}

/// Envelope metadata stored beside every message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope {
    /// Queue identifier (also the file stem).
    pub id: String,
    /// When the MTA accepted the message (RFC 3339, UTC).
    pub received_at: String,
    /// The reverse-path, `""` for the null sender.
    pub mail_from: String,
    /// The reverse-path as rendered on the wire (`<>` for the null sender).
    pub mail_from_wire: String,
    /// The HELO/EHLO name.
    pub helo: String,
    /// The client address.
    pub remote_ip: String,
    /// The authenticated identity, when the session authenticated.
    pub authenticated: Option<String>,
    /// The `Received:` line prepended to the message file.
    pub received: String,
    /// The verification summary (`spf=… dkim=… dmarc=…`).
    pub auth_summary: String,
    /// Every accepted recipient.
    pub recipients: Vec<String>,
    /// The declared `SIZE=` estimate, when the client sent one.
    pub declared_size: Option<u64>,
    /// `SMTPUTF8` was in effect.
    pub smtputf8: bool,
    /// SHA-256 of the `.eml` file as committed.
    pub sha256: String,
    /// Length of the `.eml` file in octets.
    pub size: u64,
}

/// One committed queue entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueuedMessage {
    /// Queue identifier.
    pub id: String,
    /// Where it lives.
    pub state: QueueState,
    /// The envelope.
    pub envelope: Envelope,
}

/// The spool root with its three directories and the fsync hook.
#[derive(Debug, Clone)]
pub struct Spool {
    root: PathBuf,
    hooks: Arc<Hooks>,
    counter: Arc<AtomicU64>,
}

/// A hook the durability tests install to stop between two fsync steps, so a
/// test can inspect the spool exactly on the boundary (a `kill -9` there is
/// what the boundary protects against; this crate does not spawn one). It
/// receives the queue id of the message being committed.
pub type SyncHook = Arc<dyn Fn(&str) + Send + Sync>;

/// One `fsync` the spool performed, in the order it performed them.
///
/// The durability contract is an *order* — `fsync(file)` before the renames,
/// `fsync(dir)` after them — so a test that only looks at the spool after a
/// crash cannot tell whether either call exists: it observes the outcome, and
/// the outcome of a crash that never happened to drop the page cache is
/// identical with and without the call. This record is what a test asserts on
/// instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsyncKind {
    /// `fsync` of the message file, before the renames.
    File,
    /// `fsync` of the directory a rename landed in, after the rename.
    Dir,
}

/// Receives every [`FsyncKind`] as the commit path issues it.
pub type FsyncObserver = Arc<dyn Fn(FsyncKind) + Send + Sync>;

/// Test hooks: a place to stop between two fsync steps, so a test lands
/// exactly on the durability boundary instead of somewhere random, plus the
/// record of which fsyncs actually ran.
///
/// The production binary never sets any of these; the fields are `Option`s so
/// the compiler cannot elide them, and the test-only API below is the only
/// way in.
#[derive(Default)]
struct Hooks {
    /// Called after `fsync(file)` and before the renames.
    after_file_sync: Mutex<Option<SyncHook>>,
    /// Called after the renames and before `fsync(dir)`.
    before_dir_sync: Mutex<Option<SyncHook>>,
    /// Every fsync the commit path issues, in order.
    fsync_observer: Mutex<Option<FsyncObserver>>,
}

impl Spool {
    /// Opens (and creates) a spool root.
    ///
    /// # Errors
    ///
    /// Returns the underlying I/O error when the directories cannot be made.
    pub fn open(root: impl Into<PathBuf>) -> io::Result<Self> {
        let root = root.into();
        for dir in ["tmp", "new", "cur", "corrupt"] {
            std::fs::create_dir_all(root.join(dir))?;
        }
        Ok(Self {
            root,
            hooks: Arc::new(Hooks::default()),
            counter: Arc::new(AtomicU64::new(counter_seed())),
        })
    }

    /// The spool root.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Installs the hook that runs after `fsync(file)`, before the renames.
    pub fn set_after_file_sync_hook(&self, hook: SyncHook) {
        if let Ok(mut slot) = self.hooks.after_file_sync.lock() {
            *slot = Some(hook);
        }
    }

    /// Installs the hook that runs after the renames, before `fsync(dir)`.
    pub fn set_before_dir_sync_hook(&self, hook: SyncHook) {
        if let Ok(mut slot) = self.hooks.before_dir_sync.lock() {
            *slot = Some(hook);
        }
    }

    /// Installs the observer that receives every fsync the commit path issues,
    /// in order. Replaces any observer already installed.
    pub fn set_fsync_observer(&self, observer: FsyncObserver) {
        if let Ok(mut slot) = self.hooks.fsync_observer.lock() {
            *slot = Some(observer);
        }
    }

    /// Records one `fsync` as it is issued.
    fn note_fsync(&self, kind: FsyncKind) {
        let observer = self
            .hooks
            .fsync_observer
            .lock()
            .ok()
            .and_then(|slot| slot.clone());
        if let Some(observer) = observer {
            observer(kind);
        }
    }

    /// `fsync` the message file, reporting it to the observer *only when the
    /// call succeeded* — the same shape as [`Spool::sync_dir`], so the report
    /// and the sync are one event.
    ///
    /// The handle is taken by value so this is the only place a message file
    /// can be synced: a commit cannot report `FsyncKind::File` while syncing
    /// somewhere else, because it no longer has anything to sync.
    ///
    /// # Test reach
    ///
    /// Deleting the `sync_all` below is **not** observable from a test: with
    /// an honest observer the file report comes from here, and the file report
    /// is the only evidence any test in this crate can see — an in-process
    /// test cannot observe whether a `fsync` really reached the medium (no
    /// allocator hook, no `/proc` state and no `fdinfo` field moves). The
    /// direction that *is* guarded is the honest one: no sync, no report.
    /// The reverse — a report without a sync — is guarded by construction
    /// (one sync site, taking the handle) and by review, not by a test.
    fn sync_file(&self, file: File) -> io::Result<()> {
        file.sync_all()?;
        drop(file);
        self.note_fsync(FsyncKind::File);
        Ok(())
    }

    /// `fsync` the directory `dir`, reporting it to the observer.
    ///
    /// Only the commit path's call is pinned by a test
    /// (`commit_syncs_the_file_then_the_directory_before_acknowledging`); the
    /// calls in `remove()` and `claim()` are not observed by any test today,
    /// so removing those would not turn anything red.
    ///
    /// The same limit as [`Spool::sync_file`] applies, and it is worth
    /// stating on both: removing the `fsync` *inside* this call is not
    /// observable from a test in this process either. What the tests pin is
    /// the report order — so they go red when a whole `sync_dir` call is
    /// removed or the two reports are swapped, not when the syscall behind
    /// one of them is deleted. Verified out of process once with an
    /// `LD_PRELOAD` shim on `fsync(2)`: the commit path issues
    /// `FILE <id>.eml` → `FILE <id>.json` → `DIR new`, in that order.
    fn sync_dir(&self, dir: &Path) -> io::Result<()> {
        let result = fsync_dir(dir);
        if result.is_ok() {
            self.note_fsync(FsyncKind::Dir);
        }
        result
    }

    /// A fresh queue identifier: microsecond stamp, pid and a counter.
    ///
    /// The stamp alone is not enough — two calls in the same microsecond, or
    /// two spools in one pid (every test opens several), produce the same
    /// stamp — so the counter is seeded per instance and then advanced
    /// monotonically.
    ///
    /// **The id is still not provably unique**: two instances of one pid can
    /// land on the same value, and a seeded counter is a probability, not a
    /// proof. That is why [`Spool::stage`] refuses an id that is already in
    /// the queue — a collision must surface as a clear error the caller
    /// handles, never as a retry and never as a silent overwrite.
    #[must_use]
    pub fn next_id(&self) -> String {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_micros());
        let counter = self.counter.fetch_add(1, Ordering::Relaxed);
        format!("{stamp:016x}-{:08x}-{counter:06}", std::process::id())
    }

    /// Begins writing a message: creates `tmp/<id>.eml`, hashes as it writes,
    /// and commits atomically when [`StagedMessage::commit`] runs.
    ///
    /// # Errors
    ///
    /// `io::ErrorKind::AlreadyExists` when the spool already holds something
    /// under this id (`new/`, `cur/` or `tmp/`) — a [`Spool::next_id`]
    /// collision, **not** a transient failure: the caller must report it, not
    /// retry with the same id. The existing message is left untouched.
    ///
    /// Returns the underlying I/O error when the temporary file cannot be
    /// created for any other reason.
    pub fn stage(&self, id: &str, envelope: Envelope) -> io::Result<StagedMessage> {
        let message_tmp = self.root.join("tmp").join(format!("{id}.eml"));
        // An id already on the shelf or in delivery is a collision: writing
        // it would rename over a committed message of the same name and
        // leave two acknowledged messages where one file is. `create_new`
        // alone only guards the instant a live handle exists in `tmp/`; once
        // the first message is renamed into `new/` the name is free again.
        if let Some(taken) = self.find_taken(id) {
            tracing::warn!(id, file = %taken.display(), "queue id already in use; refusing to stage");
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("queue id {id} is already held by {}", taken.display()),
            ));
        }
        // Read as well as write: the prepend step moves the received octets up
        // inside this same file, so the handle has to be able to read it back.
        // `create_new` still closes the window between the check above and
        // this call for the `tmp/` half.
        let file = match OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&message_tmp)
        {
            Ok(file) => file,
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    format!("queue id {id} is already held by {}", message_tmp.display()),
                ));
            }
            Err(err) => return Err(err),
        };
        Ok(StagedMessage {
            spool: self.clone(),
            id: id.to_owned(),
            envelope,
            file: Some(file),
            message_tmp,
            hasher: Sha256::new(),
            size: 0,
            failed: None,
        })
    }

    /// The file that already owns `id`, or `None` when the id is free.
    fn find_taken(&self, id: &str) -> Option<PathBuf> {
        ["tmp", "new", "cur"]
            .into_iter()
            .flat_map(|dir| {
                let dir = self.root.join(dir);
                [
                    dir.join(format!("{id}.eml")),
                    dir.join(format!("{id}.json")),
                ]
            })
            .find(|path| path.exists())
    }

    /// Lists committed messages.
    ///
    /// # Errors
    ///
    /// Returns the I/O error when the directory cannot be read.
    pub fn list(&self, state: QueueState) -> io::Result<Vec<QueuedMessage>> {
        let mut out = Vec::new();
        let dir = self.root.join(state.dir());
        for entry in std::fs::read_dir(&dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|ext| ext.to_str()) != Some("eml") {
                continue;
            }
            let id = path
                .file_stem()
                .and_then(|stem| stem.to_str())
                .unwrap_or_default()
                .to_owned();
            let envelope = match read_envelope(&dir, &id) {
                Ok(envelope) => envelope,
                Err(_) => continue,
            };
            out.push(QueuedMessage {
                id,
                state,
                envelope,
            });
        }
        out.sort_by(|left, right| left.id.cmp(&right.id));
        Ok(out)
    }

    /// Reads a committed message: the prepended block followed by the original
    /// bytes, exactly as they were verified.
    ///
    /// # Errors
    ///
    /// Returns the I/O error when the message cannot be read.
    pub fn read_message(&self, state: QueueState, id: &str) -> io::Result<Vec<u8>> {
        std::fs::read(self.root.join(state.dir()).join(format!("{id}.eml")))
    }

    /// Deletes a committed message and its envelope. This is the W2 handoff
    /// point: nothing in W1 calls it outside tests.
    ///
    /// # Errors
    ///
    /// Returns the I/O error when either file cannot be removed.
    pub fn remove(&self, state: QueueState, id: &str) -> io::Result<()> {
        let dir = self.root.join(state.dir());
        let _ = std::fs::remove_file(dir.join(format!("{id}.eml")));
        let _ = std::fs::remove_file(dir.join(format!("{id}.json")));
        self.sync_dir(&dir)?;
        Ok(())
    }

    /// Moves a committed message to `cur/` (W2's pickup step).
    ///
    /// # Errors
    ///
    /// Returns the I/O error when a rename fails.
    pub fn claim(&self, id: &str) -> io::Result<()> {
        let new = self.root.join("new");
        let cur = self.root.join("cur");
        std::fs::rename(
            new.join(format!("{id}.json")),
            cur.join(format!("{id}.json")),
        )?;
        std::fs::rename(new.join(format!("{id}.eml")), cur.join(format!("{id}.eml")))?;
        self.sync_dir(&new)?;
        self.sync_dir(&cur)?;
        Ok(())
    }

    /// Cleans up after a crash and reports what was found.
    ///
    /// Idempotent and safe to run while another process is writing. A `tmp/`
    /// file is deleted only when no process holds it open *and* either its id
    /// names a process that no longer exists, or — when the id names a
    /// process that still runs, this one included — it is older than
    /// [`TMP_RESIDUE_AGE`]; a file without a usable id must be that old too.
    ///
    /// A young file is never deleted on the strength of its id alone: the
    /// writer that owns it may be this very process, between dropping a
    /// handle and committing. Writers must still take their ids from
    /// [`Spool::next_id`] *after* calling `recover` (see the module docs) so
    /// their live files are recognisably live.
    ///
    /// Failures to remove or move something are not swallowed: they are
    /// logged and returned in [`RecoveryReport::failed`], so a full disk
    /// cannot make a run look clean.
    ///
    /// # Errors
    ///
    /// Returns the I/O error when a directory cannot be read.
    pub fn recover(&self) -> io::Result<RecoveryReport> {
        let mut report = RecoveryReport::default();
        let tmp = self.root.join("tmp");
        for entry in std::fs::read_dir(&tmp)? {
            let path = entry?.path();
            match tmp_leftover(&path) {
                Some(reason) => {
                    if let Err(err) = std::fs::remove_file(&path) {
                        tracing::warn!(file = %path.display(), %err, "recovery could not remove a temporary file");
                        report.record_failure(&path, "remove", &err);
                    } else {
                        tracing::debug!(file = %path.display(), reason, "recovery removed a temporary leftover");
                        report.tmp_removed += 1;
                    }
                }
                None => {
                    tracing::debug!(file = %path.display(), "recovery left a live writer's file alone")
                }
            }
        }
        if let Err(err) = fsync_dir(&tmp) {
            report.record_failure(&tmp, "fsync", &err);
        }

        for state in [QueueState::New, QueueState::Cur] {
            let dir = self.root.join(state.dir());
            let mut messages = BTreeMap::new();
            let mut metadata = BTreeMap::new();
            for entry in std::fs::read_dir(&dir)? {
                let path = entry?.path();
                let Some(stem) = path.file_stem().and_then(|stem| stem.to_str()) else {
                    continue;
                };
                match path.extension().and_then(|ext| ext.to_str()) {
                    Some("eml") => {
                        messages.insert(stem.to_owned(), path);
                    }
                    Some("json") => {
                        metadata.insert(stem.to_owned(), path);
                    }
                    _ => {}
                }
            }
            for (id, json) in &metadata {
                if !messages.contains_key(id) {
                    // The envelope without a message: the rename order makes
                    // this the only reachable orphan.
                    if let Err(err) = std::fs::remove_file(json) {
                        tracing::warn!(file = %json.display(), %err, "recovery could not remove orphan metadata");
                        report.record_failure(json, "remove", &err);
                    } else {
                        report.orphan_metadata += 1;
                    }
                }
            }
            for (id, eml) in &messages {
                let Some(json) = metadata.get(id) else {
                    if quarantine(&self.root, eml, id) {
                        report.corrupt += 1;
                    } else {
                        report.record_failure(eml, "quarantine", &"rename into corrupt/ failed");
                    }
                    continue;
                };
                let check = match read_envelope(&dir, id) {
                    Ok(envelope) => verify_integrity(eml, &envelope),
                    Err(_) => Err("unreadable envelope".to_owned()),
                };
                match check {
                    Ok(()) => report.intact += 1,
                    Err(reason) => {
                        tracing::warn!(id, %reason, "recovery moved an entry that failed its integrity check to corrupt/");
                        if quarantine(&self.root, eml, id) {
                            report.corrupt += 1;
                        } else {
                            report.record_failure(
                                eml,
                                "quarantine",
                                &"rename into corrupt/ failed",
                            );
                        }
                        if let Err(err) = std::fs::remove_file(json) {
                            tracing::warn!(file = %json.display(), %err, "recovery could not remove the envelope of a quarantined entry");
                            report.record_failure(json, "remove", &err);
                        }
                    }
                }
            }
            if let Err(err) = fsync_dir(&dir) {
                report.record_failure(&dir, "fsync", &err);
            }
        }
        if !report.failed.is_empty() {
            tracing::warn!(
                failed = report.failed.len(),
                "recovery finished with unhandled errors"
            );
        }
        Ok(report)
    }
}

/// What [`Spool::recover`] found and did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RecoveryReport {
    /// Temporary files discarded.
    pub tmp_removed: usize,
    /// Metadata files without a message discarded.
    pub orphan_metadata: usize,
    /// Entries that passed the length and checksum check.
    pub intact: usize,
    /// Entries moved to `corrupt/` because they failed it.
    pub corrupt: usize,
    /// One `<operation>: <path>: <error>` line per step recovery could not
    /// carry out. Empty means the run left nothing behind.
    pub failed: Vec<String>,
}

impl RecoveryReport {
    /// Records a failed step, in the shape [`RecoveryReport::failed`] documents.
    fn record_failure(&mut self, path: &Path, operation: &str, error: &dyn fmt::Display) {
        self.failed
            .push(format!("{operation}: {}: {error}", path.display()));
    }
}

/// A message being written into `tmp/`.
pub struct StagedMessage {
    spool: Spool,
    id: String,
    envelope: Envelope,
    file: Option<File>,
    message_tmp: PathBuf,
    hasher: Sha256,
    size: u64,
    failed: Option<String>,
}

impl StagedMessage {
    /// The committed message file, before the queued metadata was attached.
    /// Used by the driver to prepend the `Received:` and result headers.
    pub fn file_mut(&mut self) -> Option<&mut File> {
        self.file.as_mut()
    }

    /// Replaces the envelope recorded in the metadata that will be written by
    /// [`StagedMessage::commit`]. `sha256` and `size` are filled in there.
    pub fn set_envelope(&mut self, envelope: Envelope) {
        self.envelope = envelope;
    }

    /// Appends octets exactly as received (no dot-unstuffing, no re-wrapping).
    ///
    /// # Errors
    ///
    /// Returns the I/O error the write failed with; the staged file is then
    /// discarded by [`StagedMessage::commit`] / [`StagedMessage::abandon`].
    pub fn write(&mut self, chunk: &[u8]) -> io::Result<()> {
        if let Some(reason) = &self.failed {
            return Err(io::Error::other(reason.clone()));
        }
        let Some(file) = self.file.as_mut() else {
            return Err(io::Error::other("staged message already finished"));
        };
        if let Err(err) = file.write_all(chunk) {
            self.failed = Some(err.to_string());
            return Err(err);
        }
        self.hasher.update(chunk);
        self.size += chunk.len() as u64;
        Ok(())
    }

    /// The envelope as it will be stored, with `sha256` / `size` still unset.
    #[must_use]
    pub fn envelope(&self) -> &Envelope {
        &self.envelope
    }

    /// The octets written so far.
    #[must_use]
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Writes the metadata, fsyncs the message, renames both into `new/` and
    /// fsyncs the directory. Only after this call returns `Ok` may the driver
    /// send 250.
    ///
    /// # Errors
    ///
    /// Returns the I/O error of the first failing step. Every step leaves the
    /// spool in a state [`Spool::recover`] accepts: either the entry is
    /// complete in `new/` or it is not there at all.
    pub fn commit(self) -> io::Result<QueuedMessage> {
        self.commit_with_prepend(&[])
    }

    /// [`StagedMessage::commit`] with a block of header fields written in front
    /// of the received octets — the `Received:` and `Authentication-Results:`
    /// lines. The block is part of the file that is hashed and fsynced, so the
    /// checksum covers what is stored, and the verified original bytes follow
    /// unchanged.
    ///
    /// # Errors
    ///
    /// Same as [`StagedMessage::commit`].
    pub fn commit_with_prepend(mut self, prepend: &[u8]) -> io::Result<QueuedMessage> {
        if let Some(reason) = self.failed.take() {
            self.discard();
            return Err(io::Error::other(reason));
        }
        let file = match self.file.take() {
            Some(file) => file,
            None => {
                self.discard();
                return Err(io::Error::other("staged message already finished"));
            }
        };
        // 1. Prepend `Received:` / `Authentication-Results:` in front of the
        //    received octets, in place: the message was written to the file
        //    while it arrived, so it is moved up by one block. The block is a
        //    few hundred octets and the body never passes through memory.
        //
        if !prepend.is_empty() {
            let length = self.size;
            let moved = match move_in_file(&file, length, prepend.len() as u64) {
                Ok(moved) => moved,
                Err(err) => {
                    drop(file);
                    self.discard();
                    return Err(err);
                }
            };
            if let Err(err) = write_at_start(&file, prepend) {
                drop(file);
                self.discard();
                return Err(err);
            }
            // A SHA-256 state cannot be prepended to, and the digest of the
            // received octets is not enough: the record must cover the file
            // as stored. Hash the stored file again in [`HASH_CHUNK`] steps —
            // one streaming pass over tmp, and peak memory stays one buffer
            // however large the message is.
            let mut handle = &file;
            match hash_file(&mut handle, Some(moved)) {
                Ok(hasher) => self.hasher = hasher,
                Err(err) => {
                    drop(file);
                    self.discard();
                    return Err(err);
                }
            }
            self.size = moved;
        }
        // 2. The message survives a power cut: fsync the file itself. One
        //    handle and one write head cover the moved body and the prepended
        //    block alike, which keeps the cursor story in one place: `*&File`
        //    is a place expression, so `seek`/`write` through a rebound local
        //    (`let mut handle = file`) move this file's offset, while a second
        //    `OpenOptions` handle would carry a cursor of its own. (The move
        //    leaves `[0, offset)` empty, so a second descriptor writing
        //    exactly `offset` octets at 0 fills that hole rather than
        //    clobbering the message — the single head is clarity, not a
        //    correctness fix.)
        // The contract's first half: the octets are on the medium before any
        // name points at them. `sync_file` takes the handle and reports the
        // call *only when it succeeded* — the file half of the same rule
        // `Spool::sync_dir` applies to the directory half.
        if let Err(err) = self.spool.sync_file(file) {
            self.discard();
            return Err(err);
        }
        if let Some(hook) = self.spool.hooks.after_file_sync() {
            hook(&self.id);
        }

        let hash = format!("{:x}", self.hasher.clone().finalize());
        self.envelope.sha256.clone_from(&hash);
        self.envelope.size = self.size;

        // 3. The metadata goes first so a message file in `new/` always has
        //    its envelope beside it.
        let json_tmp = self
            .spool
            .root
            .join("tmp")
            .join(format!("{}.json", self.id));
        let json_bytes = match serde_json::to_vec_pretty(&self.envelope) {
            Ok(bytes) => bytes,
            Err(err) => {
                self.discard();
                return Err(io::Error::other(err.to_string()));
            }
        };
        let write_meta = || -> io::Result<()> {
            let mut meta = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&json_tmp)?;
            meta.write_all(&json_bytes)?;
            // The metadata's own sync: like the data file's, deleting this
            // line is invisible in-process (nothing reports it); the shim
            // above is what confirmed it really reaches the medium, between
            // the data file's sync and the directory's.
            meta.sync_all()
        };
        if let Err(err) = write_meta() {
            let _ = std::fs::remove_file(&json_tmp);
            self.discard();
            return Err(err);
        }
        let new_dir = self.spool.root.join("new");
        if let Err(err) = std::fs::rename(&json_tmp, new_dir.join(format!("{}.json", self.id))) {
            let _ = std::fs::remove_file(&json_tmp);
            self.discard();
            return Err(err);
        }
        if let Err(err) =
            std::fs::rename(&self.message_tmp, new_dir.join(format!("{}.eml", self.id)))
        {
            // The metadata rename already happened: recovery removes the
            // orphan, and the caller never sends 250.
            let _ = std::fs::remove_file(new_dir.join(format!("{}.json", self.id)));
            self.discard();
            return Err(err);
        }
        if let Some(hook) = self.spool.hooks.before_dir_sync() {
            hook(&self.id);
        }
        // 4. Make the two renames durable before acknowledging. Without this
        //    the message is acknowledged while the directory entry that names
        //    it can still be lost: the exact "acknowledged but broken" state
        //    the recovery tests exist to forbid.
        self.spool.sync_dir(&new_dir)?;
        Ok(QueuedMessage {
            id: self.id.clone(),
            state: QueueState::New,
            envelope: self.envelope.clone(),
        })
    }

    /// Deletes the staged file without committing it.
    pub fn abandon(mut self) {
        self.discard();
    }

    fn discard(&mut self) {
        self.file.take();
        let _ = std::fs::remove_file(&self.message_tmp);
        let _ = std::fs::remove_file(
            self.spool
                .root
                .join("tmp")
                .join(format!("{}.json", self.id)),
        );
    }
}

impl fmt::Debug for Hooks {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let file = self
            .after_file_sync
            .lock()
            .map(|slot| slot.is_some())
            .unwrap_or(false);
        let dir = self
            .before_dir_sync
            .lock()
            .map(|slot| slot.is_some())
            .unwrap_or(false);
        f.debug_struct("Hooks")
            .field("after_file_sync", &file)
            .field("before_dir_sync", &dir)
            .finish()
    }
}

impl Hooks {
    fn after_file_sync(&self) -> Option<SyncHook> {
        self.after_file_sync
            .lock()
            .ok()
            .and_then(|slot| slot.clone())
    }

    fn before_dir_sync(&self) -> Option<SyncHook> {
        self.before_dir_sync
            .lock()
            .ok()
            .and_then(|slot| slot.clone())
    }
}

/// Shifts the first `length` octets of `file` up by `offset`, leaving the
/// first `offset` octets free, without reading the body into memory. Returns
/// the new length.
///
/// The handle must be opened read+write ([`Spool::stage`] does): the octets
/// are read back out of the file they were written to.
fn move_in_file(file: &File, length: u64, offset: u64) -> io::Result<u64> {
    use std::io::{Seek as _, SeekFrom};
    let mut file = file;
    let mut buffer = vec![0u8; 64 * 1024];
    let mut remaining = length;
    while remaining > 0 {
        let chunk = (remaining as usize).min(buffer.len());
        let from = remaining - chunk as u64;
        file.seek(SeekFrom::Start(from))?;
        file.read_exact(&mut buffer[..chunk])?;
        file.seek(SeekFrom::Start(from + offset))?;
        file.write_all(&buffer[..chunk])?;
        remaining = from;
    }
    Ok(length + offset)
}

/// The SHA-256 of the first `length` octets of `file` (`None`: to the end),
/// read in [`HASH_CHUNK`] steps — the one place a message is hashed, both when
/// a prepended block joins the running digest and when recovery verifies a
/// committed file. Peak memory is one buffer, whatever the message size.
fn hash_file(file: &mut &File, length: Option<u64>) -> io::Result<Sha256> {
    let mut hasher = Sha256::new();
    hash_until(file, length, &mut hasher)?;
    Ok(hasher)
}

/// Feeds the first `length` octets of `file` (`None`: to the end) to `hasher`,
/// reading from the start in [`HASH_CHUNK`] steps.
fn hash_until(file: &mut &File, length: Option<u64>, hasher: &mut Sha256) -> io::Result<()> {
    use std::io::{Seek as _, SeekFrom};
    file.seek(SeekFrom::Start(0))?;
    let mut buffer = vec![0u8; HASH_CHUNK];
    let mut remaining = length;
    loop {
        let chunk = remaining.map_or(buffer.len(), |left| (left as usize).min(buffer.len()));
        if chunk == 0 {
            break;
        }
        let read = file.read(&mut buffer[..chunk])?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        if let Some(left) = remaining.as_mut() {
            *left -= read as u64;
        }
    }
    Ok(())
}

/// Writes `block` over the first octets the move left free.
///
/// Neither `seek` nor `write_all` on a `File` touches the offset (the
/// `io::Seek`/`io::Write` impls for `*&File` -> `&mut File` would move it), so
/// the single write head stays past the end of the message, exactly where
/// [`StagedMessage::write`] left it. Writability alone would suffice here —
/// `[0, block.len())` is the hole `move_in_file` left — so this is about not
/// juggling a second cursor, not about where the octets land.
fn write_at_start(file: &File, block: &[u8]) -> io::Result<()> {
    use std::io::{Seek as _, SeekFrom};
    let mut handle = file;
    handle.seek(SeekFrom::Start(0))?;
    handle.write_all(block)
}

fn read_envelope(dir: &Path, id: &str) -> io::Result<Envelope> {
    let bytes = std::fs::read(dir.join(format!("{id}.json")))?;
    serde_json::from_slice(&bytes).map_err(io::Error::other)
}

/// Why a `tmp/` entry is a crash leftover, or `None` when a live writer may
/// still own it. The decision, in order:
///
/// 1. **Held open** by any process (`/proc/<pid>/fd` points at it): a writer is
///    in the middle of staging it. This is the only signal that survives the
///    pid checks below being wrong (a crashed process whose pid got reused, a
///    file from another host), so it comes first and wins.
/// 2. Carrying the pid of a process that is **gone**: the writer died.
/// 3. Carrying **any** live pid — this process's included — or no id at all:
///    only the residue-age threshold (clocked on the `.eml` of the same id)
///    can decide. A live id is not proof of abandonment; a file somebody is
///    still writing in this process has a live id too.
fn tmp_leftover(path: &Path) -> Option<&'static str> {
    let name = path.file_name()?.to_string_lossy();
    let id = if let Some(stem) = name.strip_suffix(".eml") {
        stem
    } else {
        name.strip_suffix(".json").unwrap_or(&name)
    };
    if is_open_somewhere(path) {
        return None;
    }
    let Some(pid) = id_pid(id) else {
        return residue_expired(path).then_some("no queue id and older than the residue threshold");
    };
    if pid == std::process::id() {
        // Our own id: the staging handle is gone, but the writer may still be
        // this process — a dropped handle, a cancelled task, a panic unwind
        // leaves a young file behind until the commit that owns it runs.
        // Only a file nobody has touched for a whole residue window is a
        // leftover; a young one is left alone.
        return residue_expired(path)
            .then_some("this process's own id, untouched for the residue age");
    }
    if !process_alive(pid) {
        return Some("the process that staged it is gone");
    }
    residue_expired(path).then_some("older than the residue threshold despite a live pid")
}

/// Whether some process currently holds `path` open. Costs one `readdir` over
/// `/proc/<pid>/fd` per spool file at start-up and nothing afterwards.
fn is_open_somewhere(path: &Path) -> bool {
    let Ok(target) = std::fs::canonicalize(path) else {
        return false;
    };
    let Ok(processes) = std::fs::read_dir("/proc") else {
        // Without `/proc` this check cannot see any descriptor, so it cannot
        // prove a file is free; say so, because the sweep then has to lean on
        // the pid and age rules alone (the side that can delete a live file).
        tracing::warn!(
            file = %path.display(),
            "cannot read /proc: the open-handle check is unavailable, the tmp sweep falls back to pid and age"
        );
        return false;
    };
    processes.filter_map(Result::ok).any(|process| {
        let Ok(handles) = std::fs::read_dir(process.path().join("fd")) else {
            return false;
        };
        handles
            .filter_map(Result::ok)
            .any(|handle| std::fs::read_link(handle.path()).is_ok_and(|link| link == target))
    })
}

/// Whether the `.eml` of the same id was last written more than
/// [`TMP_RESIDUE_AGE`] ago — for a `.eml` itself, that is its own stamp. A
/// stamp we cannot read (or one in the future) is never "old". The `.json`
/// only appears for the duration of one commit, so it asks its `.eml`.
fn residue_expired(path: &Path) -> bool {
    let watched = if path.extension().and_then(|ext| ext.to_str()) == Some("json") {
        path.with_extension("eml")
    } else {
        path.to_path_buf()
    };
    std::fs::metadata(&watched)
        .and_then(|metadata| metadata.modified())
        .ok()
        .and_then(|modified| SystemTime::now().duration_since(modified).ok())
        .is_some_and(|age| age > TMP_RESIDUE_AGE)
}

/// The pid encoded in a queue id (`<micros:016x>-<pid:08x>-<counter:06>`).
fn id_pid(id: &str) -> Option<u32> {
    let mut parts = id.split('-');
    let (Some(_stamp), Some(pid), Some(counter), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return None;
    };
    if counter.len() != 6 {
        return None;
    }
    u32::from_str_radix(pid, 16).ok().filter(|pid| *pid != 0)
}

/// Where each spool instance's counter starts, so two spools opening in the
/// same pid do not hand out the same ids back to back.
///
/// Nanosecond time mixed with the pid, then spread over the counter's field
/// with a 64-bit finalizer (splitmix64) so neighbouring seeds are not
/// neighbouring counters. No external dependency, and no `/dev/urandom` read
/// on a path that runs at start-up.
fn counter_seed() -> u64 {
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_nanos() as u64);
    let mixed = nanos ^ (u64::from(std::process::id()) << 32);
    let mut z = mixed.wrapping_add(0x9e37_79b9_7f4a_7c15);
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

/// Whether `pid` still runs. Only meaningful for writers on this host, which
/// is where the spool lives.
fn process_alive(pid: u32) -> bool {
    if pid == std::process::id() {
        return true;
    }
    Path::new(&format!("/proc/{pid}")).exists()
}

/// Hashes the message and compares it with the length and digest its envelope
/// recorded. Reads in [`HASH_CHUNK`] steps so a 25 MiB message costs 64 KiB of
/// buffer, not 25 MiB.
fn verify_integrity(message: &Path, envelope: &Envelope) -> Result<(), String> {
    let metadata = std::fs::metadata(message).map_err(|err| err.to_string())?;
    if metadata.len() != envelope.size {
        return Err(format!(
            "length {} != recorded {}",
            metadata.len(),
            envelope.size
        ));
    }
    let file = File::open(message).map_err(|err| err.to_string())?;
    let mut file = &file;
    let hasher = hash_file(&mut file, None).map_err(|err| err.to_string())?;
    let hash = format!("{:x}", hasher.finalize());
    if hash != envelope.sha256 {
        return Err("checksum mismatch".to_owned());
    }
    Ok(())
}

/// Moves a message out of the delivery path. Returns whether it landed: a
/// rename that failed (a full disk, `corrupt/` gone) must not look clean.
fn quarantine(root: &Path, message: &Path, id: &str) -> bool {
    let target = root.join("corrupt").join(format!("{id}.eml"));
    match std::fs::rename(message, &target) {
        Ok(()) => true,
        Err(err) => {
            tracing::warn!(%id, target = %target.display(), %err, "could not quarantine a message");
            false
        }
    }
}

/// `fsync` a directory: the only way to make a rename inside it durable.
pub(crate) fn fsync_dir(dir: &Path) -> io::Result<()> {
    let handle = File::open(dir)?;
    handle.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn envelope(id: &str) -> Envelope {
        Envelope {
            id: id.to_owned(),
            received_at: "2026-11-26T00:00:00Z".to_owned(),
            mail_from: "a@b.example".to_owned(),
            mail_from_wire: "<a@b.example>".to_owned(),
            helo: "client.test".to_owned(),
            remote_ip: "192.0.2.9".to_owned(),
            authenticated: None,
            received: "from client.test".to_owned(),
            auth_summary: "spf=none dkim=0/0 dmarc=None".to_owned(),
            recipients: vec!["ops@example.com".to_owned()],
            declared_size: None,
            smtputf8: false,
            sha256: String::new(),
            size: 0,
        }
    }

    fn temp_root(name: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "ayane-spool-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |elapsed| elapsed.as_nanos())
        ));
        let _ = std::fs::remove_dir_all(&root);
        root
    }

    #[test]
    fn commit_puts_the_message_and_its_envelope_in_new() {
        let root = temp_root("commit");
        let spool = Spool::open(&root).expect("spool");
        let id = spool.next_id();
        let mut staged = spool.stage(&id, envelope(&id)).expect("stage");
        staged.write(b"Subject: hi\r\n\r\nbody\r\n").expect("write");
        let queued = staged.commit().expect("commit");
        assert_eq!(queued.state, QueueState::New);
        assert_eq!(queued.envelope.size, 21);
        let bytes = spool.read_message(QueueState::New, &id).expect("read");
        assert_eq!(bytes, b"Subject: hi\r\n\r\nbody\r\n");
        let listed = spool.list(QueueState::New).expect("list");
        assert_eq!(listed.len(), 1);
        let report = spool.recover().expect("recover");
        assert_eq!(report.intact, 1);
        assert_eq!(report.corrupt, 0);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn commit_syncs_the_file_then_the_directory_before_acknowledging() {
        // The durability contract is an order, so the test asserts the order:
        // `fsync(file)` before the renames (the octets must be on the medium
        // before a name points at them) and `fsync(dir)` after them (the names
        // must be on the medium before the client is told). No crash test can
        // observe either call — a crash between the two only differs when the
        // page cache is really lost — so the report is the evidence, and the
        // report is only issued by a successful sync (`Spool::sync_file`,
        // `Spool::sync_dir`). Deleting either call therefore deletes its entry
        // here. `a_failed_stage_syncs_nothing` is the negative control.
        let root = temp_root("fsync-order");
        let spool = Spool::open(&root).expect("spool");
        let recorded = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&recorded);
        spool.set_fsync_observer(Arc::new(move |kind| {
            sink.lock().expect("observer").push(kind);
        }));
        let id = spool.next_id();
        let mut staged = spool.stage(&id, envelope(&id)).expect("stage");
        staged.write(b"Subject: hi\r\n\r\nbody\r\n").expect("write");
        let queued = staged.commit().expect("commit");
        assert_eq!(queued.state, QueueState::New);
        let order = recorded.lock().expect("observer").clone();
        assert_eq!(
            order,
            vec![FsyncKind::File, FsyncKind::Dir],
            "the commit must fsync the message, then the directory, in that order"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn commit_with_prepend_reports_the_same_sync_order() {
        // The prepend path has its own `fsync(file)` call site; both files of
        // the contract must be reported there too, in the same order.
        let root = temp_root("fsync-order-prepend");
        let spool = Spool::open(&root).expect("spool");
        let recorded = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&recorded);
        spool.set_fsync_observer(Arc::new(move |kind| {
            sink.lock().expect("observer").push(kind);
        }));
        let id = spool.next_id();
        let mut staged = spool.stage(&id, envelope(&id)).expect("stage");
        staged.write(b"Subject: hi\r\n\r\nbody\r\n").expect("write");
        staged
            .commit_with_prepend(b"Received: from client.test\r\n")
            .expect("prepend commit");
        assert_eq!(
            recorded.lock().expect("observer").clone(),
            vec![FsyncKind::File, FsyncKind::Dir],
            "the prepend commit must fsync the message, then the directory"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_failed_stage_syncs_nothing() {
        // The control for the test above: nothing is reported for a message
        // that is never acknowledged.
        let root = temp_root("fsync-none");
        let spool = Spool::open(&root).expect("spool");
        let recorded = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&recorded);
        spool.set_fsync_observer(Arc::new(move |kind| {
            sink.lock().expect("observer").push(kind);
        }));
        let id = spool.next_id();
        let mut staged = spool.stage(&id, envelope(&id)).expect("stage");
        staged.write(b"Subject: hi\r\n\r\n").expect("write");
        staged.abandon();
        assert!(recorded.lock().expect("observer").is_empty());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn abandoned_message_never_appears() {
        let root = temp_root("abandon");
        let spool = Spool::open(&root).expect("spool");
        let id = spool.next_id();
        let mut staged = spool.stage(&id, envelope(&id)).expect("stage");
        staged.write(b"Subject: hi\r\n\r\n").expect("write");
        staged.abandon();
        assert!(spool.list(QueueState::New).expect("list").is_empty());
        assert!(std::fs::read_dir(root.join("tmp"))
            .expect("tmp")
            .next()
            .is_none());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn truncated_message_is_quarantined_on_recovery() {
        let root = temp_root("truncate");
        let spool = Spool::open(&root).expect("spool");
        let id = spool.next_id();
        let mut staged = spool.stage(&id, envelope(&id)).expect("stage");
        staged
            .write(b"Subject: hi\r\n\r\nbody that will be cut\r\n")
            .expect("write");
        staged.commit().expect("commit");
        let path = root.join("new").join(format!("{id}.eml"));
        let bytes = std::fs::read(&path).expect("read");
        std::fs::write(&path, &bytes[..bytes.len() - 8]).expect("truncate");
        let report = spool.recover().expect("recover");
        assert_eq!(report.corrupt, 1);
        assert!(spool.list(QueueState::New).expect("list").is_empty());
        assert!(root.join("corrupt").join(format!("{id}.eml")).exists());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn orphan_metadata_is_removed() {
        let root = temp_root("orphan");
        let spool = Spool::open(&root).expect("spool");
        let id = spool.next_id();
        let mut staged = spool.stage(&id, envelope(&id)).expect("stage");
        staged.write(b"Subject: hi\r\n\r\n").expect("write");
        staged.commit().expect("commit");
        std::fs::remove_file(root.join("new").join(format!("{id}.eml"))).expect("unlink");
        let report = spool.recover().expect("recover");
        assert_eq!(report.orphan_metadata, 1);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn claim_moves_both_files_to_cur() {
        let root = temp_root("claim");
        let spool = Spool::open(&root).expect("spool");
        let id = spool.next_id();
        let mut staged = spool.stage(&id, envelope(&id)).expect("stage");
        staged.write(b"Subject: hi\r\n\r\n").expect("write");
        staged.commit().expect("commit");
        spool.claim(&id).expect("claim");
        assert!(spool.list(QueueState::New).expect("list").is_empty());
        assert_eq!(spool.list(QueueState::Cur).expect("list").len(), 1);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A spool id for a process that cannot exist: pids are `i32`, so
    /// `u32::MAX` can never name a live writer.
    fn dead_id() -> String {
        "0000000000000001-ffffffff-000000".to_owned()
    }

    fn sha256_of(bytes: &[u8]) -> String {
        format!("{:x}", Sha256::digest(bytes))
    }

    fn write_residue(path: &Path) {
        std::fs::write(path, b"left by a writer that is gone").expect("residue");
    }

    /// Backdates `path` to `age` before now.
    fn age_to(path: &Path, age: Duration) {
        let stamp = SystemTime::now() - age;
        File::options()
            .write(true)
            .open(path)
            .expect("open")
            .set_modified(stamp)
            .expect("age it");
    }

    /// Commits `original` behind `prepend` and returns the spool with both
    /// the stored bytes and the queue's own record of the file.
    fn staged_with_prepend(
        name: &str,
        prepend: &str,
        original: &[u8],
    ) -> (PathBuf, Vec<u8>, Envelope) {
        let root = temp_root(name);
        let spool = Spool::open(&root).expect("spool");
        let id = spool.next_id();
        let mut staged = spool.stage(&id, envelope(&id)).expect("stage");
        staged.write(original).expect("write");
        let queued = staged
            .commit_with_prepend(prepend.as_bytes())
            .expect("a prepend commit must not fail");
        let stored = spool.read_message(QueueState::New, &id).expect("read");
        assert!(
            std::fs::read_dir(root.join("tmp"))
                .expect("tmp")
                .next()
                .is_none(),
            "a committed message leaves nothing in tmp/"
        );
        let report = spool.recover().expect("recover");
        assert_eq!(
            report.intact, 1,
            "the committed entry must survive recovery"
        );
        assert!(report.failed.is_empty());
        (root, stored, queued.envelope)
    }

    #[test]
    fn commit_with_prepend_puts_the_block_in_front_of_the_message() {
        // The inbound path always prepends `Received:` /
        // `Authentication-Results:`, and the file has to end up as
        // `block || received`, in that order: a block that lands on top of the
        // message (or behind it) is a message the receiver never sent.
        //
        // The block is longer than `HASH_CHUNK`, so the move inside the file
        // takes several steps and a multi-buffer block cannot hide behind one
        // buffer-sized write.
        let original = b"Subject: hi\r\n\r\nbody\r\n";
        let prepend = format!(
            "Received: from client.test by mx.example\r\nAuthentication-Results: spf=none\r\n{}",
            format_args!("X-Trace: {}\r\n", "a".repeat(HASH_CHUNK))
        );
        let (root, stored, queued) = staged_with_prepend("prepend", &prepend, original);
        let mut expected = prepend.as_bytes().to_vec();
        expected.extend_from_slice(original);
        assert_eq!(
            stored, expected,
            "the stored file is the block, then the message"
        );
        assert_eq!(queued.size, expected.len() as u64);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn commit_with_prepend_records_the_digest_of_the_whole_file() {
        // The size and SHA-256 in the envelope describe the file as stored —
        // block included — which is what recovery re-checks. A digest of the
        // received octets alone would quarantine every prepended message on
        // the first recovery.
        let (root, stored, queued) = staged_with_prepend(
            "prepend-digest",
            "Received: from client.test by mx.example\r\nAuthentication-Results: spf=none\r\n",
            b"Subject: hi\r\n\r\nbody\r\n",
        );
        assert_eq!(queued.size, stored.len() as u64);
        assert_eq!(queued.sha256, sha256_of(&stored));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn recovery_leaves_a_live_writers_file_alone() {
        // The probe: a writer holds `tmp/<id>.eml` open, a second process runs
        // recovery. Deleting the file would make the writer's commit fail with
        // ENOENT after it had already proved it could write.
        let root = temp_root("live-writer");
        let writer = Spool::open(&root).expect("writer spool");
        let id = writer.next_id();
        let mut staged = writer.stage(&id, envelope(&id)).expect("stage");
        staged
            .write(b"Subject: hi\r\n\r\nhalf the body\r\n")
            .expect("write");

        let other = Spool::open(&root).expect("second spool");
        let report = other.recover().expect("recover");
        assert_eq!(
            report.tmp_removed, 0,
            "a live writer's file is not a leftover"
        );
        assert!(report.failed.is_empty());
        assert!(report.intact == 0);
        assert!(root.join("tmp").join(format!("{id}.eml")).exists());

        staged.write(b"the rest of the body\r\n").expect("write");
        let queued = staged.commit().expect("the writer still commits");
        assert_eq!(queued.envelope.size, 52);
        assert_eq!(other.list(QueueState::New).expect("list").len(), 1);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn recovery_removes_temporary_leftovers_and_reports_them() {
        // Three leftovers and one live writer: the dead pid proves itself, the
        // `.json` and the foreign name can only be judged by age, and the live
        // file must survive all three.
        let root = temp_root("tmp-sweep");
        let spool = Spool::open(&root).expect("spool");
        let tmp = root.join("tmp");
        let dead = dead_id();
        write_residue(&tmp.join(format!("{dead}.eml")));
        let stale_json = tmp.join(format!("{dead}.json"));
        write_residue(&stale_json);
        let foreign = tmp.join("not-a-spool-id");
        write_residue(&foreign);
        let old = SystemTime::now() - TMP_RESIDUE_AGE - Duration::from_secs(60);
        for path in [&stale_json, &foreign] {
            File::options()
                .write(true)
                .open(path)
                .expect("open")
                .set_modified(old)
                .expect("age it");
        }
        let live_id = spool.next_id();
        let mut live = spool.stage(&live_id, envelope(&live_id)).expect("stage");
        live.write(b"Subject: hi\r\n\r\n").expect("write");

        let report = spool.recover().expect("recover");
        assert_eq!(
            report.tmp_removed, 3,
            "dead pid, stale json, stale foreign name"
        );
        assert!(report.failed.is_empty());
        assert!(!tmp.join(format!("{dead}.eml")).exists());
        assert!(!stale_json.exists());
        assert!(!foreign.exists());
        assert!(
            tmp.join(format!("{live_id}.eml")).exists(),
            "the live writer's file stays"
        );
        live.abandon();
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_same_length_bit_flip_is_quarantined_on_recovery() {
        // Length alone cannot catch this: one octet changes, the size still
        // matches, and only the recorded SHA-256 separates it from a message
        // that may be delivered.
        let root = temp_root("bit-flip");
        let spool = Spool::open(&root).expect("spool");
        let id = spool.next_id();
        let mut staged = spool.stage(&id, envelope(&id)).expect("stage");
        staged
            .write(b"Subject: hi\r\n\r\nthe body says hello\r\n")
            .expect("write");
        staged.commit().expect("commit");
        let path = root.join("new").join(format!("{id}.eml"));
        let mut bytes = std::fs::read(&path).expect("read");
        let last = bytes.len() - 3;
        bytes[last] ^= 0x01;
        std::fs::write(&path, &bytes).expect("flip");

        let report = spool.recover().expect("recover");
        assert_eq!(
            report.corrupt, 1,
            "a same-length change must fail the digest check"
        );
        assert_eq!(report.intact, 0);
        assert!(report.failed.is_empty());
        assert!(spool.list(QueueState::New).expect("list").is_empty());
        assert!(root.join("corrupt").join(format!("{id}.eml")).exists());
        assert!(!root.join("new").join(format!("{id}.json")).exists());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn recovery_keeps_this_process_s_young_tmp_file() {
        // N2: the id names this very process, the staging handle is gone (a
        // dropped handle, a cancelled task, a panic unwind), and the file is
        // fresh. The writer that owns it may still commit it, so it must
        // survive recovery; only once nobody has touched it for the whole
        // residue window is it a leftover.
        let root = temp_root("own-pid");
        let spool = Spool::open(&root).expect("spool");
        let tmp = root.join("tmp");

        let young_id = spool.next_id();
        let young = tmp.join(format!("{young_id}.eml"));
        {
            let mut staged = spool.stage(&young_id, envelope(&young_id)).expect("stage");
            staged
                .write(b"Subject: hi\r\n\r\nhalf a message\r\n")
                .expect("write");
            // Give the handle up without committing or abandoning.
            drop(staged);
        }
        assert!(young.exists(), "the file outlives its handle");

        let report = spool.recover().expect("recover");
        assert_eq!(
            report.tmp_removed, 0,
            "a young own-pid file is not a leftover"
        );
        assert!(report.failed.is_empty());
        assert!(young.exists(), "the message must still be there");

        age_to(&young, TMP_RESIDUE_AGE + Duration::from_secs(3600));
        let report = spool.recover().expect("recover");
        assert_eq!(
            report.tmp_removed, 1,
            "two hours untouched makes it a leftover"
        );
        assert!(!young.exists());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn two_spools_in_one_process_do_not_hand_out_the_same_id() {
        // Every test opens several spools in one pid, and so does any process
        // that opens a second spool. A counter starting at zero in both put
        // them on the same ids back to back; the seeded counter spreads them.
        let root = temp_root("id-spread");
        let first = Spool::open(&root).expect("first spool");
        let second = Spool::open(&root).expect("second spool");
        let mut seen = std::collections::BTreeSet::new();
        for _ in 0..256 {
            for id in [first.next_id(), second.next_id()] {
                assert!(seen.insert(id.clone()), "{id} handed out twice");
            }
        }
        assert_eq!(seen.len(), 512);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn staging_an_id_that_is_already_committed_is_a_clear_error() {
        // R5: the id is taken again after the first message was renamed into
        // `new/`, where `create_new` no longer protects the name. Staging
        // must fail loudly — a second 250 for a message that overwrote the
        // first is a lost mail that recovery cannot detect (`intact=1
        // corrupt=0`).
        let root = temp_root("id-collision");
        let spool = Spool::open(&root).expect("spool");
        let id = spool.next_id();
        let first = b"Subject: first\r\n\r\nthe message that must survive\r\n";
        let mut staged = spool.stage(&id, envelope(&id)).expect("stage");
        staged.write(first).expect("write");
        staged.commit().expect("commit");

        let other = Spool::open(&root).expect("second spool");
        let err = other
            .stage(&id, envelope(&id))
            .err()
            .expect("staging a taken id must fail");
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists, "{err}");
        assert!(
            err.to_string().contains(&id),
            "the error names the id: {err}"
        );
        assert!(
            err.to_string().contains("new"),
            "the error names the file that holds it: {err}"
        );

        assert_eq!(
            spool.read_message(QueueState::New, &id).expect("read"),
            first,
            "the committed message must be byte-for-byte untouched"
        );
        let report = spool.recover().expect("recover");
        assert_eq!((report.intact, report.corrupt), (1, 0));
        assert!(report.failed.is_empty());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn recovery_keeps_a_file_that_is_open_even_when_its_pid_is_dead() {
        // S2-2: the order of the rules is load-bearing. A file somebody holds
        // open is live no matter what its id says — the pid can be dead (a
        // pid reused by another tool, a file copied in) or the mtime can be
        // ancient (a slow writer). The open-handle check must win over both,
        // or the sweep deletes a descriptor that is still being written.
        let root = temp_root("open-beats-pid");
        let spool = Spool::open(&root).expect("spool");
        let tmp = root.join("tmp");
        let dead = dead_id();
        let held = tmp.join(format!("{dead}.eml"));
        write_residue(&held);
        age_to(&held, TMP_RESIDUE_AGE + Duration::from_secs(3600));
        // Held open for the duration of the recovery below (as a writer
        // mid-receive would hold it), with a dead id and a stale mtime.
        let handle = File::options()
            .write(true)
            .open(&held)
            .expect("hold it open");

        let report = spool.recover().expect("recover");
        assert_eq!(
            report.tmp_removed, 0,
            "an open file is live, whatever its id and age say"
        );
        assert!(report.failed.is_empty());
        assert!(held.exists(), "the open file must still be there");
        drop(handle);

        // The control: the same file, no longer held, is swept now that the
        // id is dead — the age and id rules do fire once nobody holds it.
        let report = spool.recover().expect("recover");
        assert_eq!(report.tmp_removed, 1);
        assert!(!held.exists());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn recovery_reports_an_orphan_metadata_it_could_not_remove() {
        // N3: the envelope without its message is the one orphan the commit
        // order can leave. When the removal fails (here: a read-only `new/`,
        // as on a full or read-only medium) recovery must not count it as
        // discarded and must not stay silent.
        let root = temp_root("orphan-failure");
        let spool = Spool::open(&root).expect("spool");
        let new = root.join("new");
        let id = dead_id();
        let orphan = new.join(format!("{id}.json"));
        std::fs::write(&orphan, b"{}").expect("orphan");

        let meta = std::fs::metadata(&new).expect("meta");
        let mut permissions = meta.permissions();
        let writable = permissions.clone();
        std::os::unix::fs::PermissionsExt::set_mode(&mut permissions, 0o500);
        std::fs::set_permissions(&new, permissions).expect("make new/ read-only");

        let report = spool.recover().expect("recover");
        std::fs::set_permissions(&new, writable).expect("restore new/");

        assert_eq!(report.orphan_metadata, 0, "nothing was discarded");
        assert!(
            report
                .failed
                .iter()
                .any(|line| line.contains(&id) && line.contains("remove")),
            "the report names the orphan and the step: {:?}",
            report.failed
        );
        assert!(orphan.exists());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn recovery_reports_a_cleanup_it_could_not_carry_out() {
        // A dead-pid leftover inside a read-only `tmp/`: the removal cannot
        // succeed (as on a full or read-only medium), so the run must not
        // report it as removed — the operator needs the difference between
        // "swept" and "still there".
        let root = temp_root("tmp-failure");
        let spool = Spool::open(&root).expect("spool");
        let tmp = root.join("tmp");
        let dead = dead_id();
        write_residue(&tmp.join(format!("{dead}.eml")));
        let handle = File::open(&tmp).expect("tmp");
        let mut permissions = handle.metadata().expect("meta").permissions();
        let writable = permissions.clone();
        std::os::unix::fs::PermissionsExt::set_mode(&mut permissions, 0o500);
        std::fs::set_permissions(&tmp, permissions).expect("make tmp read-only");

        let report = spool.recover().expect("recover");
        std::fs::set_permissions(&tmp, writable).expect("restore tmp");

        assert_eq!(report.tmp_removed, 0, "nothing was removed");
        assert!(!report.failed.is_empty(), "the failure must be reported");
        assert!(
            report
                .failed
                .iter()
                .any(|line| line.contains(&dead) && line.contains("remove")),
            "the report names the file and the step: {:?}",
            report.failed
        );
        assert!(tmp.join(format!("{dead}.eml")).exists());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn recovery_hashes_a_large_message_in_bounded_steps() {
        // `verify_integrity` reads in fixed `HASH_CHUNK` steps, so a 25 MiB
        // message costs one buffer of this size no matter how large it is.
        // The test asserts the step count directly; the peak itself is not
        // measurable in-process without an allocator hook.
        let root = temp_root("large");
        let spool = Spool::open(&root).expect("spool");
        let id = spool.next_id();
        let body = vec![b'x'; 25 * 1024 * 1024];
        let mut staged = spool.stage(&id, envelope(&id)).expect("stage");
        staged.write(&body).expect("write");
        staged.commit().expect("commit");
        drop(body);
        let path = root.join("new").join(format!("{id}.eml"));

        let mut file = File::open(&path).expect("open");
        let mut buffer = vec![0u8; HASH_CHUNK];
        let mut steps = 0;
        loop {
            let read = file.read(&mut buffer).expect("read");
            if read == 0 {
                break;
            }
            steps += 1;
        }
        assert_eq!(steps, 25 * 1024 * 1024 / HASH_CHUNK);
        assert!(
            steps > 1,
            "the hash must stream, not read the message in one call"
        );

        let report = spool.recover().expect("recover");
        assert_eq!(report.intact, 1);
        let _ = std::fs::remove_dir_all(&root);
    }
}
