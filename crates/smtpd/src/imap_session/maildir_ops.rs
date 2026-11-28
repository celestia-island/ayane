//! The maildir side of an open folder: its messages as the selection holds
//! them, the UID table brought into step with the files, and a message
//! appended to it.

use std::fs;
use std::io;
use std::path::Path;

use imap_codec::imap_types::{
    core::NonEmptyVec,
    fetch::MessageDataItem,
    flag::Flag,
    mailbox::Mailbox,
    response::Data,
    sequence::{SequenceSet, Strategy},
};

use crate::maildir_reader::{Flags, MessageId};

use super::session::{By, ImapSession, Selected};
use super::uidlist::UidMap;
use super::wire::non_zero;
use super::{Outcome, Row};

impl ImapSession<'_> {
    /// The folder's messages as `(unique, file name, in_cur)`. `new/` first.
    pub(crate) fn live(dir: &Path) -> io::Result<Vec<(String, String, bool)>> {
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

    /// Rescan a folder through its table, storing the table if it grew, and
    /// bring the mod-sequence sidecar into step.
    ///
    /// The mod-sequence assignment is lazy by design (RFC 7162 §3.1 wants
    /// APPENDs and outside mechanisms — here, SMTP delivery — to land above
    /// the watermark without the writer knowing the table exists): a message
    /// gets its value at the first scan that lists it, which is also where it
    /// gets its UID. The values are sequential in scan order, so "newer than
    /// everything before it" holds by construction.
    pub(crate) fn scan(&self, dir: &Path, map: &mut UidMap) -> io::Result<Vec<Row>> {
        let before = map.clone();
        let list = map.sync(&Self::live(dir)?);
        let live: Vec<String> = list
            .iter()
            .filter_map(|(uid, _, _)| map.name_of(*uid).map(str::to_owned))
            .collect();
        let live_set: std::collections::HashSet<&str> = live.iter().map(String::as_str).collect();
        let dead: Vec<String> = map
            .lines
            .iter()
            .map(|(_, unique)| unique.clone())
            .filter(|unique| !live_set.contains(unique.as_str()))
            .collect();
        // The mod-sequence sync runs **before** the uidlist store: it reads
        // whether the uidlist already carries a persisted validity to tell a
        // lost sidecar from a first scan, and storing the table first would
        // make every first scan look like a loss.
        let sidecar_missing = !super::modseq::ModSeqTable::path(dir).exists();
        let uidlist_existed = UidMap::path(dir).exists();
        super::modseq::scan_sync(dir, &live, &dead)?;
        if sidecar_missing && uidlist_existed {
            // That sync wrote the table's persisted validity on its own: it
            // rotated a lost sidecar's identity (§5.3), or froze the value a
            // first CONDSTORE scan minted into a table that predates the
            // sidecar. Either way the file no longer says what the table in
            // hand was read from, and the store below would write the stale
            // value back — a QRESYNC client would keep mod-sequence state
            // this server can no longer answer for, which is exactly what the
            // rotation exists to prevent.
            let synced = UidMap::load(dir)?;
            map.validity = synced.validity;
            map.validity_persisted = synced.validity_persisted;
        }
        if *map != before {
            map.store(dir)?;
        }
        Ok(list)
    }

    /// Re-derive a selection's list.
    pub(crate) fn rescan(&self, selected: &Selected) -> io::Result<Vec<Row>> {
        self.scan(&selected.dir, &mut UidMap::load(&selected.dir)?)
    }

    /// One untagged `FETCH` line for a message, if every item can be built.
    pub(crate) fn fetch_line(
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
    pub(crate) fn resolve(selected: &Selected, set: &SequenceSet, by: By) -> Vec<(u32, String)> {
        set.iter(Strategy::Naive {
            largest: non_zero(selected.largest(by)),
        })
        .filter_map(|n| selected.row(n.get(), by))
        .collect()
    }

    pub(crate) fn append(
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
        // so the bytes are stored as they arrived. The census that follows is
        // what gives the message both its UID and — through the mod-sequence
        // assignment that scan performs — its CONDSTORE value.
        let Some((validity, uid)) = self
            .reader
            .append(&self.mailbox, &folder, bytes, wanted)
            .ok()
            .and_then(|name| {
                self.census(&folder).ok().and_then(|census| {
                    census
                        .map
                        .uid_of(&name)
                        .map(|uid| (census.map.validity, uid))
                })
            })
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
        // RFC 4315 §3: advertising UIDPLUS obliges the code — the plain
        // `(UID n)` text it replaces was advisory only.
        out.extend(super::uidplus::append_ok(
            tag,
            non_zero(validity).get(),
            uid,
            "APPEND completed",
        ));
        Outcome {
            out,
            ..Outcome::default()
        }
    }
}
