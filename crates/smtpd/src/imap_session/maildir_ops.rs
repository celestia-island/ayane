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
use super::wire::{line, non_zero};
use super::{Kind, Outcome, Row};

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

    /// Rescan a folder through its table, storing the table if it grew.
    pub(crate) fn scan(&self, dir: &Path, map: &mut UidMap) -> io::Result<Vec<Row>> {
        let before = map.clone();
        let list = map.sync(&Self::live(dir)?);
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
}
