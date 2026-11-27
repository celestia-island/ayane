//! The queries and mutations a selected mailbox answers: `FETCH`, `STORE`,
//! `SEARCH` and `COPY`/`MOVE`.
//!
//! Everything here runs over the octets the maildir holds: this server stores
//! messages, it does not reparse them, so an item it cannot answer is refused
//! rather than approximated.

use std::fs;

use imap_codec::imap_types::{
    fetch::{MacroOrMessageDataItemNames, MessageDataItem, MessageDataItemName},
    flag::{Flag, StoreResponse, StoreType},
    mailbox::Mailbox,
    response::Data,
    search::SearchKey,
    sequence::SequenceSet,
};

use crate::maildir_reader::{FlagChange, Flags, MessageId, ReaderError, Renamed};

use super::render::{matches_key, render_item, SearchContext};
use super::session::By;
use super::session::ImapSession;
use super::uidlist::UidMap;
use super::wire::{flags_of, non_zero, reader_dir};
use super::{answer, Outcome, READ_ONLY};

impl ImapSession<'_> {
    pub(crate) fn fetch(
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

    pub(crate) fn store(
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
    pub(crate) fn apply_flags(
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

    pub(crate) fn search(&mut self, tag: &str, criteria: &SearchKey<'_>, uid: bool) -> Outcome {
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

    pub(crate) fn copy(
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
