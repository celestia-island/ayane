//! A folder's identity table: UID to maildir name, and the folder's
//! `UIDVALIDITY`.
//!
//! A maildir name is not a stable identity — a flag change renames the file
//! (`:2,S`) and so does a move from `new/` into `cur/` — so a UID is mapped to
//! the name's `unique` half, which neither touches. The table never reassigns a
//! UID, gives an unknown message the next free one in name order (so two
//! sessions agree), and is replaced atomically (`tmp` → `fsync` → `rename` →
//! `fsync(dir)`), skipping a line it cannot parse rather than making the
//! folder unreadable.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::maildir_reader::MessageId;

use super::{Row, UIDLIST};

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
