//! The queries and mutations a selected mailbox answers: `FETCH`, `STORE`,
//! `SEARCH` and `COPY`/`MOVE` — with the CONDSTORE/QRESYNC surface RFC 7162
//! §3.1.4–§3.1.5 and §3.1.3 hang off them, and the UIDPLUS codes RFC 4315 §3
//! puts on `COPY`/`MOVE`.
//!
//! Everything here runs over the octets the maildir holds: this server stores
//! messages, it does not reparse them, so an item it cannot answer is refused
//! rather than approximated. The extension parameters arrive in
//! [`ExtParams`](super::ext_wire::ExtParams), lifted off the raw bytes before
//! the codec saw the line.

use imap_codec::imap_types::{
    fetch::{MacroOrMessageDataItemNames, MessageDataItemName},
    mailbox::Mailbox,
    response::Data,
    search::SearchKey,
    sequence::SequenceSet,
};

use crate::maildir_reader::{FlagChange, MessageId};

use super::ext_wire::{self, ExtParams};
use super::modseq;
use super::render::{matches_key, render_item, SearchContext};
use super::session::By;
use super::session::ImapSession;
use super::uidlist::UidMap;
use super::uidplus::CopyMapping;
use super::wire::{non_zero, reader_dir};
use super::{answer, Outcome, READ_ONLY};

impl ImapSession<'_> {
    pub(crate) fn fetch(
        &mut self,
        tag: &str,
        set: &SequenceSet,
        names: &MacroOrMessageDataItemNames<'_>,
        uid: bool,
        ext: &ExtParams,
    ) -> Outcome {
        // RFC 7162 §3.2.6: the VANISHED modifier needs QRESYNC enabled, UID
        // FETCH only, and CHANGEDSINCE alongside — each refusal is a BAD,
        // and the first one fires before anything else happens.
        if ext.fetch_vanished {
            if !self.qresync_enabled {
                return self.bad(tag, "VANISHED is only valid after ENABLE QRESYNC");
            }
            if !uid {
                return self.bad(tag, "VANISHED is only valid on UID FETCH");
            }
            if ext.fetch_changedsince.is_none() {
                return self.bad(tag, "VANISHED requires CHANGEDSINCE in the same command");
            }
        }
        let selected = answer!(self.current(tag));
        let mut wanted: Vec<MessageDataItemName<'_>> = match names {
            MacroOrMessageDataItemNames::Macro(macro_item) => macro_item.expand(),
            MacroOrMessageDataItemNames::MessageDataItemNames(names) => names.clone(),
        };
        let mut out = Vec::new();
        // `CHANGEDSINCE` and the `MODSEQ` item are CONDSTORE enabling
        // commands (RFC 7162 §3.1.2) — the one-time notice rides first.
        if ext.fetch_changedsince.is_some() || ext.fetch_modseq {
            out.extend(self.enable_condstore());
        }
        // RFC 3501 §6.4.8: a UID FETCH answer carries the UID; RFC 7162
        // §3.2.4 (errata 1807): a QRESYNC session hears it on every untagged
        // FETCH.
        if (uid || self.qresync_enabled)
            && !wanted
                .iter()
                .any(|item| matches!(item, MessageDataItemName::Uid))
        {
            wanted.insert(0, MessageDataItemName::Uid);
        }
        // The `VANISHED (EARLIER)` line goes out before the FETCH lines it
        // summarizes (RFC 7162 §3.2.6).
        if ext.fetch_vanished {
            let map = UidMap::load(&selected.dir).unwrap_or_default();
            let vanished = self.vanished_earlier_uids(
                &selected,
                &map,
                ext.fetch_changedsince.unwrap_or(0),
                None,
                None,
            );
            if !vanished.is_empty() {
                out.extend(ext_wire::vanished_line(&vanished, true));
            }
        }
        let mut table = modseq::table(&selected.dir).ok();
        for (message_uid, name) in
            Self::resolve(&selected, set, if uid { By::Uid } else { By::Seq })
        {
            let Ok(id) = MessageId::parse(&name) else {
                continue;
            };
            let mut value = table.as_ref().and_then(|table| table.of(id.unique()));
            if let Some(since) = ext.fetch_changedsince {
                // RFC 7162 §3.1.4.1: strictly above `since` — a message
                // sitting exactly at the client's value is not reported.
                match value {
                    Some(value) if value > since => {}
                    _ => continue,
                }
            }
            // The bare MODSEQ item leaves the codec's item list empty after
            // the sidecar lift — RFC 7162 §3.1.4.2's `FETCH … (MODSEQ)` is
            // answered by hand (atoms and numbers only), with UID added
            // where RFC 3501 §6.4.8 / RFC 7162 §3.2.4 put it.
            if wanted.is_empty() {
                let Some(value) = value else {
                    continue;
                };
                let seq = non_zero(selected.seq_of(message_uid)).get();
                let uid_item = if uid || self.qresync_enabled {
                    format!("UID {message_uid} ")
                } else {
                    String::new()
                };
                out.extend(format!("* {seq} FETCH ({uid_item}MODSEQ ({value}))\r\n").into_bytes());
                continue;
            }
            let Ok(raw) = self
                .reader
                .read_raw(&self.mailbox, &selected.folder, &id.file_name())
            else {
                continue;
            };
            // `BODY[…]` (not `BODY.PEEK[…]`) sets `\Seen` — RFC 3501
            // §6.4.5. The rename is what carries the flag, so the items are
            // rendered from the *new* name: the FLAGS the client reads and
            // the MODSEQ stamped over them describe the same instant.
            let mut id_now = id.clone();
            if wanted
                .iter()
                .any(|item| matches!(item, MessageDataItemName::BodyExt { peek: false, .. }))
                && !selected.read_only
                && !id.flags().seen
            {
                if let Ok(renamed) = self.reader.set_flags(
                    &self.mailbox,
                    &selected.folder,
                    &id.file_name(),
                    FlagChange {
                        seen: Some(true),
                        flagged: None,
                    },
                ) {
                    id_now = MessageId::parse(&renamed.to).unwrap_or_else(|_| id.clone());
                    // The rename bumped the folder: read the fresh value
                    // rather than report the stale one.
                    table = modseq::table(&selected.dir).ok();
                    value = table.as_ref().and_then(|table| table.of(id_now.unique()));
                }
            }
            let Some(rendered) = wanted
                .iter()
                .map(|item| render_item(item, &raw, &id_now, message_uid, &selected))
                .collect::<Option<Vec<_>>>()
            else {
                return self.bad(tag, "that data item is not supported here");
            };
            if let Some(mut line) = self.fetch_line(&selected, message_uid, rendered) {
                // RFC 7162 §3.1.2.1: every untagged FETCH of a CONDSTORE
                // session carries MODSEQ — appended here because the codec's
                // item list has no MODSEQ member at 1.0.
                if self.condstore_enabled {
                    if let Some(value) = value {
                        ext_wire::insert_modseq(&mut line, value);
                    }
                }
                out.extend(line);
            }
        }
        out.extend(self.ok(tag, "FETCH completed"));
        Outcome {
            out,
            ..Outcome::default()
        }
    }

    pub(crate) fn search(
        &mut self,
        tag: &str,
        criteria: &SearchKey<'_>,
        uid: bool,
        ext: &ExtParams,
    ) -> Outcome {
        let selected = answer!(self.current(tag));
        let mut out = Vec::new();
        // RFC 7162 §3.1.2: the MODSEQ search key is an enabling command.
        if ext.search_modseq.is_some() {
            out.extend(self.enable_condstore());
        }
        let table = modseq::table(&selected.dir).ok();
        let mut hits = Vec::new();
        let mut highest_hit = 0u64;
        for (index, (message_uid, name, in_cur)) in selected.messages.iter().enumerate() {
            let Ok(id) = MessageId::parse(name) else {
                continue;
            };
            let (Ok(seq), Ok(size)) = (
                u32::try_from(index + 1),
                std::fs::metadata(
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
            // RFC 7162 §3.1.5: the MODSEQ key survived the sidecar parser as
            // `search_modseq`; it is one more conjunct — strictly above, like
            // CHANGEDSINCE.
            if !matches_key(criteria, &ctx, &raw) {
                continue;
            }
            if let Some(since) = ext.search_modseq {
                let value = table
                    .as_ref()
                    .and_then(|table| table.of(id.unique()))
                    .unwrap_or(0);
                if value <= since {
                    continue;
                }
                highest_hit = highest_hit.max(value);
            }
            hits.push(non_zero(if uid { *message_uid } else { seq }));
        }
        let mut line = self.untagged(&Data::Search(hits.clone()));
        // RFC 7162 §3.1.6: a non-empty result set answers with the highest
        // mod-sequence among the hits appended to the SEARCH line.
        if ext.search_modseq.is_some() && !hits.is_empty() {
            ext_wire::search_modseq_suffix(&mut line, highest_hit);
        }
        out.extend(line);
        out.extend(self.ok(tag, "SEARCH completed"));
        Outcome {
            out,
            ..Outcome::default()
        }
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
        let mut mapping = CopyMapping::default();
        let mut moved: Vec<(usize, u32)> = Vec::new();
        let mut validity = 1u32;
        for (message_uid, name) in
            Self::resolve(&selected, set, if uid { By::Uid } else { By::Seq })
        {
            let Ok(id) = MessageId::parse(&name) else {
                continue;
            };
            let written = if remove {
                self.reader
                    .move_to(&self.mailbox, &selected.folder, &id.file_name(), &folder)
                    .map(|renamed| renamed.to)
            } else {
                self.reader
                    .read_raw(&self.mailbox, &selected.folder, &id.file_name())
                    .and_then(|raw| self.reader.append(&self.mailbox, &folder, &raw, id.flags()))
            };
            let Ok(written) = written else {
                continue;
            };
            // The copy needs a UID in its new folder before the client can
            // name it; the scan that assigns one also assigns the arriving
            // message's mod-sequence.
            let dir = reader_dir(&self.reader, &self.mailbox, &folder);
            let target_map = {
                let mut map = UidMap::load(&dir).unwrap_or_default();
                let _ = self.scan(&dir, &mut map);
                map
            };
            validity = target_map.validity;
            if let Some(to_uid) = target_map.uid_of(&written) {
                mapping.push(message_uid, to_uid);
            }
            if remove {
                let at = selected
                    .messages
                    .iter()
                    .position(|(it, _, _)| *it == message_uid)
                    .unwrap_or(0);
                moved.push((at, message_uid));
            }
        }
        if remove {
            // RFC 6851 §4.3 / RFC 7162 §3.2.9: the mapping goes out before
            // the removals, so the client can name what it lost; the removal
            // itself is `* VANISHED` once QRESYNC is enabled (RFC 7162
            // §3.2.10.2) and the renumbering `* n EXPUNGE` lines otherwise.
            if !mapping.is_empty() {
                out.extend(ext_wire::copyuid_ok(
                    // A `*` tag is the untagged shape: the mapping must reach
                    // the client before it learns the messages are gone.
                    "*",
                    validity,
                    &ext_wire::compress_ranges(&mapping.sources()),
                    &ext_wire::compress_ranges(&mapping.targets()),
                    "messages moved",
                ));
            }
            if self.qresync_enabled {
                let mut uids: Vec<u32> = moved.iter().map(|(_, uid)| *uid).collect();
                uids.sort_unstable();
                if !uids.is_empty() {
                    out.extend(ext_wire::vanished_line(&uids, false));
                }
            } else {
                for (count, (at, _)) in moved.iter().enumerate() {
                    let original = u32::try_from(at + 1).unwrap_or(1);
                    out.extend(self.untagged(&Data::Expunge(non_zero(
                        original.saturating_sub(u32::try_from(count).unwrap_or(u32::MAX)),
                    ))));
                }
            }
            let kept: Vec<super::Row> = selected
                .messages
                .iter()
                .filter(|(it, _, _)| !moved.iter().any(|(_, uid)| uid == it))
                .cloned()
                .collect();
            self.selected = Some(selected.with(kept));
        }
        let done = if remove { "MOVE" } else { "COPY" };
        if mapping.is_empty() {
            out.extend(self.ok(tag, &format!("{done} completed")));
        } else if !remove {
            // RFC 4315 §3: COPY carries the code on the tagged OK, aligned
            // with the resolution order.
            out.extend(mapping.ok_line(tag, validity, &format!("{done} completed")));
        } else {
            out.extend(self.ok(tag, &format!("{done} completed")));
        }
        Outcome {
            out,
            ..Outcome::default()
        }
    }
}
