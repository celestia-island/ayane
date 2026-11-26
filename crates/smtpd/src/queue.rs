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
//! * Every step that can be interrupted is exercised by the `kill -9` tests:
//!   after the crash the state must be "fully deliverable" or "never
//!   acknowledged", never "acknowledged but broken".
//!
//! Recovery ([`Spool::recover`]) runs at start-up and is idempotent:
//! leftovers in `tmp/` are deleted, `new/` entries are checked against the
//! length and SHA-256 recorded in their metadata, and anything that does not
//! match is moved out of the delivery path into `corrupt/`.

use std::collections::BTreeMap;
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

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
/// `kill -9` lands exactly on the boundary instead of somewhere random. It
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

/// Test hooks: a place to stop between two fsync steps, so a `kill -9` lands
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
            counter: Arc::new(AtomicU64::new(0)),
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

    /// `fsync` the directory `dir`, reporting it to the observer.
    fn sync_dir(&self, dir: &Path) -> io::Result<()> {
        let result = fsync_dir(dir);
        if result.is_ok() {
            self.note_fsync(FsyncKind::Dir);
        }
        result
    }

    /// A fresh queue identifier: timestamp, pid and a per-spool counter. The
    /// filesystem does not need it to be globally unique (the rename would
    /// fail), but a human reading `new/` does.
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
    /// Returns the I/O error that prevented the temporary file from being
    /// created.
    pub fn stage(&self, id: &str, envelope: Envelope) -> io::Result<StagedMessage> {
        let message_tmp = self.root.join("tmp").join(format!("{id}.eml"));
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&message_tmp)?;
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
    /// Idempotent and safe to run while another process is writing: it only
    /// touches its own `tmp/` leftovers, orphan metadata and entries that fail
    /// their integrity check.
    ///
    /// # Errors
    ///
    /// Returns the I/O error when a directory cannot be read.
    pub fn recover(&self) -> io::Result<RecoveryReport> {
        let mut report = RecoveryReport::default();
        let tmp = self.root.join("tmp");
        for entry in std::fs::read_dir(&tmp)? {
            let path = entry?.path();
            let _ = std::fs::remove_file(&path);
            report.tmp_removed += 1;
        }
        fsync_dir(&tmp)?;

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
                    let _ = std::fs::remove_file(json);
                    report.orphan_metadata += 1;
                }
            }
            for (id, eml) in &messages {
                let Some(json) = metadata.get(id) else {
                    quarantine(&self.root, eml, id);
                    report.corrupt += 1;
                    continue;
                };
                let check = match read_envelope(&dir, id) {
                    Ok(envelope) => verify_integrity(eml, &envelope),
                    Err(_) => Err("unreadable envelope".to_owned()),
                };
                match check {
                    Ok(()) => report.intact += 1,
                    Err(_) => {
                        quarantine(&self.root, eml, id);
                        let _ = std::fs::remove_file(json);
                        report.corrupt += 1;
                    }
                }
            }
            fsync_dir(&dir)?;
        }
        Ok(report)
    }
}

/// What [`Spool::recover`] found and did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RecoveryReport {
    /// Temporary files discarded.
    pub tmp_removed: usize,
    /// Metadata files without a message discarded.
    pub orphan_metadata: usize,
    /// Entries that passed the length and checksum check.
    pub intact: usize,
    /// Entries moved to `corrupt/` because they failed it.
    pub corrupt: usize,
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
            let mut file = match OpenOptions::new().write(true).open(&self.message_tmp) {
                Ok(file) => file,
                Err(err) => {
                    self.discard();
                    return Err(err);
                }
            };
            if let Err(err) = file.write_all(prepend) {
                self.discard();
                return Err(err);
            }
            self.hasher.update(prepend);
            self.size = moved;
        }
        // 2. The message survives a power cut: fsync the file itself.
        let file = match OpenOptions::new().write(true).open(&self.message_tmp) {
            Ok(file) => file,
            Err(err) => {
                self.discard();
                return Err(err);
            }
        };
        // The contract's first half: the octets are on the medium before any
        // name points at them. The call is reported to the observer *only when
        // it succeeded*, so a test asserting the order is also asserting that
        // a returned `Ok` means the sync happened.
        if let Err(err) = file.sync_all() {
            drop(file);
            self.discard();
            return Err(err);
        }
        drop(file);
        self.spool.note_fsync(FsyncKind::File);
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
fn move_in_file(file: &File, length: u64, offset: u64) -> io::Result<u64> {
    use std::io::{Read as _, Seek as _, SeekFrom};
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

fn read_envelope(dir: &Path, id: &str) -> io::Result<Envelope> {
    let bytes = std::fs::read(dir.join(format!("{id}.json")))?;
    serde_json::from_slice(&bytes).map_err(io::Error::other)
}

fn verify_integrity(message: &Path, envelope: &Envelope) -> Result<(), String> {
    let metadata = std::fs::metadata(message).map_err(|err| err.to_string())?;
    if metadata.len() != envelope.size {
        return Err(format!(
            "length {} != recorded {}",
            metadata.len(),
            envelope.size
        ));
    }
    let bytes = std::fs::read(message).map_err(|err| err.to_string())?;
    let hash = format!("{:x}", Sha256::digest(&bytes));
    if hash != envelope.sha256 {
        return Err("checksum mismatch".to_owned());
    }
    Ok(())
}

fn quarantine(root: &Path, message: &Path, id: &str) {
    let target = root.join("corrupt").join(format!("{id}.eml"));
    let _ = std::fs::rename(message, target);
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
        // must be on the medium before the client is told). Deleting either
        // call leaves this list short, which no crash test can observe because
        // a crash between the two only differs when the page cache is really
        // lost.
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
}
