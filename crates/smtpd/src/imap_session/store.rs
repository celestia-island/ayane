//! `STORE`: RFC 3501 §6.4.6's flag mutation, wearing the CONDSTORE
//! conditions RFC 7162 §3.1.3 hangs on it — the `UNCHANGEDSINCE` check
//! (equality passes, anything newer lands in `[MODIFIED]`), the untagged
//! FETCH an executed conditional STORE owes even under `.SILENT`, and the
//! no-change skip that keeps a pseudo STORE from advancing anything.

use imap_codec::imap_types::{
    fetch::MessageDataItem,
    flag::{Flag, StoreResponse, StoreType},
    sequence::SequenceSet,
};

use crate::maildir_reader::{FlagChange, Flags, MessageId, ReaderError, Renamed};

use super::ext_wire::{self, ExtParams};
use super::modseq;
use super::session::By;
use super::session::ImapSession;
use super::wire::{flags_of, flags_text, non_zero};
use super::{answer, Outcome, READ_ONLY};

/// What one `STORE` asked for, as the codec parsed it plus the extension
/// parameters the sidecar parser lifted.
pub(crate) struct StoreRequest<'a> {
    pub(crate) kind: StoreType,
    pub(crate) response: StoreResponse,
    pub(crate) flags: &'a [Flag<'a>],
    pub(crate) uid: bool,
    pub(crate) ext: &'a ExtParams,
}

impl ImapSession<'_> {
    pub(crate) fn store(
        &mut self,
        tag: &str,
        set: &SequenceSet,
        request: StoreRequest<'_>,
    ) -> Outcome {
        let StoreRequest {
            kind,
            response,
            flags,
            uid,
            ext,
        } = request;
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
        let conditional = ext.store_unchangedsince.is_some();
        let mut out = Vec::new();
        // RFC 7162 §3.1.2: `UNCHANGEDSINCE` is a CONDSTORE enabling command.
        if conditional {
            out.extend(self.enable_condstore());
        }
        let mut failures: Vec<u32> = Vec::new();
        for (message_uid, name) in
            Self::resolve(&selected, set, if uid { By::Uid } else { By::Seq })
        {
            let Ok(id) = MessageId::parse(&name) else {
                continue;
            };
            // The flags the STORE would leave behind (RFC 3501 §6.4.6's
            // semantics, computed before anything is touched — RFC 7162
            // §3.1.12 wants the no-change case detected before the check).
            let now = id.flags();
            let final_flags = Flags {
                seen: match kind {
                    StoreType::Replace => wanted.seen,
                    StoreType::Add => now.seen || wanted.seen,
                    StoreType::Remove => now.seen && !wanted.seen,
                },
                flagged: match kind {
                    StoreType::Replace => wanted.flagged,
                    StoreType::Add => now.flagged || wanted.flagged,
                    StoreType::Remove => now.flagged && !wanted.flagged,
                },
                trashed: match kind {
                    StoreType::Replace => wanted.trashed,
                    StoreType::Add => now.trashed || wanted.trashed,
                    StoreType::Remove => now.trashed && !wanted.trashed,
                },
                draft: now.draft,
            };
            let target_name = id.with_flags(final_flags).file_name();
            if target_name == name {
                // RFC 7162 §3.1.12: a STORE that would not change the flags
                // does not take part — no check, no failure entry, no bump
                // (the maildir rename primitive's early return is the
                // no-bump path). A plain STORE still answers with the flags,
                // which is what RFC 3501 §6.4.6 clients expect.
                if !conditional && response == StoreResponse::Answer {
                    let items = vec![
                        MessageDataItem::Uid(non_zero(message_uid)),
                        MessageDataItem::Flags(flags_of(&name)),
                    ];
                    if let Some(mut line) = self.fetch_line(&selected, message_uid, items) {
                        if self.condstore_enabled {
                            let value = modseq::table(&selected.dir)
                                .ok()
                                .and_then(|table| table.of(id.unique()));
                            if let Some(value) = value {
                                ext_wire::insert_modseq(&mut line, value);
                            }
                        }
                        out.extend(line);
                    }
                }
                continue;
            }
            if let Some(since) = ext.store_unchangedsince {
                // RFC 7162 §3.1.3: the message is stored only when its
                // mod-sequence is at or below the client's value — equality
                // passes, anything newer is a failure entry (STORE answers
                // in sequence numbers, UID STORE in UIDs).
                let passes = modseq::table(&selected.dir)
                    .ok()
                    .and_then(|table| table.of(id.unique()))
                    .is_some_and(|value| value <= since);
                if !passes {
                    failures.push(if uid {
                        message_uid
                    } else {
                        selected.seq_of(message_uid)
                    });
                    continue;
                }
            }
            let Ok(renamed) = self.apply_flags(&selected.folder, &id, kind, wanted) else {
                continue;
            };
            let value = modseq::table(&selected.dir)
                .ok()
                .and_then(|table| table.of(id.unique()))
                .unwrap_or(0);
            let text = flags_text(&renamed.to, selected.is_recent(message_uid));
            if conditional {
                // RFC 7162 §3.1.3: an executed conditional STORE answers an
                // untagged FETCH with UID, FLAGS and MODSEQ — even for
                // `.SILENT`, whose ordinary answer it replaces.
                let seq = non_zero(selected.seq_of(message_uid)).get();
                out.extend(ext_wire::fetch_modseq_line(seq, message_uid, value, &text));
            } else if response == StoreResponse::Answer {
                let items = vec![
                    MessageDataItem::Uid(non_zero(message_uid)),
                    MessageDataItem::Flags(flags_of(&renamed.to)),
                ];
                if let Some(mut line) = self.fetch_line(&selected, message_uid, items) {
                    if self.condstore_enabled && value > 0 {
                        ext_wire::insert_modseq(&mut line, value);
                    }
                    out.extend(line);
                }
            }
        }
        if failures.is_empty() {
            out.extend(self.ok(tag, "STORE completed"));
        } else {
            // RFC 7162 §3.1.3: the ones that did not run are named in the
            // `[MODIFIED <set>]` code, ascending and compressed.
            failures.sort_unstable();
            failures.dedup();
            let set = ext_wire::compress_ranges(&failures);
            out.extend(ext_wire::modified_ok(tag, &set, "Conditional STORE failed"));
        }
        Outcome {
            out,
            ..Outcome::default()
        }
    }

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
        self.reader.set_flags_full(
            &self.mailbox,
            folder,
            &id.file_name(),
            FlagChange {
                seen: Some(seen),
                flagged: Some(flagged),
            },
            Some(trashed),
        )
    }
}
