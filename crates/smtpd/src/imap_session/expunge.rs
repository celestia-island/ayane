//! How messages leave a folder: `EXPUNGE`, `UID EXPUNGE`, the `CLOSE` sweep,
//! and the two wire shapes a removal is reported in.
//!
//! RFC 3501 reports a removal as `* n EXPUNGE`, renumbering as it goes. A
//! QRESYNC session (RFC 7162 §3.2.10.2) reports **every** removal — from
//! `EXPUNGE`, `UID EXPUNGE`, another session, or a webmail purge — as one
//! `* VANISHED <uids>` line instead, and its tagged `OK` carries
//! `[HIGHESTMODSEQ]`. `CLOSE` is the odd one out (RFC 7162 §3.2.8, errata
//! 1808): it still deletes and still records, but reports nothing at all and
//! its `OK` carries no code — which is also what RFC 3501 §6.4.2 always
//! asked for, and what this server's earlier `CLOSE` (which emitted the
//! same `* n EXPUNGE` lines `EXPUNGE` does) got wrong.

use imap_codec::imap_types::response::Data;

use crate::maildir_reader::MessageId;

use super::ext_wire;
use super::modseq;
use super::session::{ImapSession, Selected, State};
use super::uidplus;
use super::wire::{flags_text, is_deleted, non_zero};
use super::{Outcome, READ_ONLY};

impl ImapSession<'_> {
    /// `EXPUNGE`: remove every `\Deleted` message, lowest number first.
    pub(crate) fn expunge(&mut self, tag: &str) -> Outcome {
        let Some(selected) = self.selected.clone() else {
            return self.bad(tag, super::NO_MAILBOX);
        };
        if selected.read_only {
            return self.no(tag, READ_ONLY);
        }
        let Ok(messages) = self.rescan(&selected) else {
            return self.no(tag, "cannot rescan");
        };
        let selected = selected.with(messages);
        let targets: Vec<(u32, String)> = selected
            .messages
            .iter()
            .filter(|(_, name, _)| is_deleted(name))
            .map(|(uid, name, _)| (*uid, name.clone()))
            .collect();
        self.run_expunge(tag, &selected, &targets)
    }

    /// `UID EXPUNGE <set>` (RFC 4315 §2.1): only messages that carry
    /// `\Deleted` **and** lie in the set are removed — the set narrows the
    /// deletion, so a client can drop exactly what it knows is gone.
    pub(crate) fn uid_expunge(&mut self, tag: &str, ranges: &[(u32, u32)]) -> Outcome {
        let Some(selected) = self.selected.clone() else {
            return self.bad(tag, super::NO_MAILBOX);
        };
        if selected.read_only {
            return self.no(tag, READ_ONLY);
        }
        let Ok(messages) = self.rescan(&selected) else {
            return self.no(tag, "cannot rescan");
        };
        let selected = selected.with(messages);
        let largest = selected.largest(super::session::By::Uid);
        let ranges = ext_wire::resolve_star(ranges, largest);
        let targets = uidplus::uid_expunge_targets(&selected.messages, &ranges);
        self.run_expunge(tag, &selected, &targets)
    }

    /// The shared back end of both expunge commands: purge the targets, emit
    /// the report this connection owes, and answer.
    fn run_expunge(
        &mut self,
        tag: &str,
        selected: &Selected,
        targets: &[(u32, String)],
    ) -> Outcome {
        let (details, uids, highest) = self.purge(selected, targets);
        let kept: Vec<super::Row> = selected
            .messages
            .iter()
            .filter(|(uid, _, _)| !uids.contains(uid))
            .cloned()
            .collect();
        let recent = selected
            .recent
            .iter()
            .copied()
            .filter(|uid| kept.iter().any(|(it, _, _)| it == uid))
            .collect();
        self.selected = Some(Selected {
            messages: kept,
            recent,
            ..selected.clone()
        });
        let mut out = details;
        if self.qresync_enabled {
            // RFC 7162 §3.2.10.2: once QRESYNC is enabled, a removal is
            // `* VANISHED <uids>` and never an `* n EXPUNGE` line.
            let mut sorted = uids.clone();
            sorted.sort_unstable();
            if !sorted.is_empty() {
                out.extend(ext_wire::vanished_line(&sorted, false));
            }
            out.extend(ext_wire::highestmodseq_ok(
                tag,
                highest,
                "EXPUNGE completed",
            ));
        } else {
            out.extend(self.ok(tag, "EXPUNGE completed"));
        }
        Outcome {
            out,
            ..Outcome::default()
        }
    }

    /// `CLOSE`: sweep the deleted messages without a word about them, and
    /// answer a bare `OK` (see the module documentation).
    pub(crate) fn close(&mut self, tag: &str) -> Outcome {
        if let Some(selected) = self.selected.take().filter(|s| !s.read_only) {
            // The names in the selection may be stale — a `STORE` in this
            // session renamed the files without touching the selection — so
            // the sweep re-derives the list before deciding what is deleted.
            if let Ok(messages) = self.rescan(&selected) {
                let selected = selected.with(messages);
                let targets: Vec<(u32, String)> = selected
                    .messages
                    .iter()
                    .filter(|(_, name, _)| is_deleted(name))
                    .map(|(uid, name, _)| (*uid, name.clone()))
                    .collect();
                // RFC 7162 §3.2.8: the deletions still bump and record — the
                // purges inside `purge` do that — but no detail line is
                // emitted and the tagged `OK` below carries no
                // `[HIGHESTMODSEQ]`.
                let _ = self.purge(&selected, &targets);
            }
        }
        self.state = State::Authenticated;
        Outcome {
            out: self.ok(tag, "CLOSE completed"),
            ..Outcome::default()
        }
    }

    /// Purges `targets` out of the selection.
    ///
    /// Answers the untagged report (empty for `CLOSE`, `* n EXPUNGE` lines
    /// for a plain session, nothing but the caller's `VANISHED` for a
    /// QRESYNC session — the caller decides), the removed UIDs, and the
    /// folder's watermark after the last purge (the value RFC 7162 §3.2.7
    /// puts on the tagged OK).
    ///
    /// The renumbering is RFC 3501 §7.4.1's: a message's number when it goes
    /// is its original position minus the ones already gone, counting itself.
    fn purge(&self, selected: &Selected, targets: &[(u32, String)]) -> (Vec<u8>, Vec<u32>, u64) {
        let mut out = Vec::new();
        let mut removed = Vec::new();
        for (uid, name) in targets {
            let Ok(id) = MessageId::parse(name) else {
                continue;
            };
            if self
                .reader
                .purge(&self.mailbox, &selected.folder, &id.file_name())
                .is_err()
            {
                continue;
            }
            removed.push(*uid);
            if !self.qresync_enabled {
                // The `* n EXPUNGE` shape: only a plain session reports these;
                // a QRESYNC session gets one `VANISHED` line instead.
                if let Some(original) = selected
                    .messages
                    .iter()
                    .position(|(it, _, _)| it == uid)
                    .and_then(|at| u32::try_from(at + 1).ok())
                {
                    out.extend(self.untagged(&Data::Expunge(
                        non_zero(
                            original.saturating_sub(
                                u32::try_from(removed.len()).unwrap_or(u32::MAX) - 1,
                            ),
                        ),
                    )));
                }
            }
        }
        let highest = super::modseq::table(&selected.dir)
            .map(|table| table.highest())
            .unwrap_or_else(|_| selected.highest_modseq);
        (out, removed, highest)
    }
    /// Rescan the selection, report what another session did, and answer.
    ///
    /// RFC 3501 puts an update obligation on `NOOP` (§7.5.1) and on untagged
    /// responses generally (§7.4.1): removals are announced, and so are flag
    /// changes — which is the correction this makes to a refresh that only
    /// ever counted new mail. A QRESYNC session hears `* VANISHED` for the
    /// removals (RFC 7162 §3.2.10.2); a plain session hears the renumbering
    /// `* n EXPUNGE` lines.
    pub(crate) fn refresh(&mut self, tag: &str) -> Outcome {
        let mut out = Vec::new();
        if let Some(selected) = self.selected.clone() {
            if let Ok(messages) = self.rescan(&selected) {
                // Removals first — the client renumbers before it reads the
                // FETCH lines below, whose sequence numbers are the new
                // list's.
                let gone: Vec<(usize, u32)> = selected
                    .messages
                    .iter()
                    .enumerate()
                    .filter(|(_, (uid, _, _))| !messages.iter().any(|(it, _, _)| it == uid))
                    .map(|(at, (uid, _, _))| (at, *uid))
                    .collect();
                if self.qresync_enabled {
                    let mut uids: Vec<u32> = gone.iter().map(|(_, uid)| *uid).collect();
                    uids.sort_unstable();
                    if !uids.is_empty() {
                        out.extend(ext_wire::vanished_line(&uids, false));
                    }
                } else {
                    for (count, (at, _)) in gone.iter().enumerate() {
                        let original = u32::try_from(at + 1).unwrap_or(1);
                        out.extend(self.untagged(&Data::Expunge(non_zero(
                            original.saturating_sub(u32::try_from(count).unwrap_or(u32::MAX)),
                        ))));
                    }
                }
                // Flag changes: the file name is where the flags live, so a
                // changed name is a changed flag set — one FETCH line each,
                // with UID and MODSEQ once CONDSTORE is active (RFC 7162
                // §3.2.4).
                let table = modseq::table(&selected.dir).ok();
                for (index, (uid, name, _)) in messages.iter().enumerate() {
                    let Some((_, old_name, _)) =
                        selected.messages.iter().find(|(it, _, _)| it == uid)
                    else {
                        continue; // a new message rides the EXISTS below
                    };
                    if old_name == name {
                        continue;
                    }
                    let seq = non_zero(u32::try_from(index + 1).unwrap_or(1)).get();
                    let flags = flags_text(name, selected.is_recent(*uid));
                    let value = table
                        .as_ref()
                        .and_then(|table| {
                            MessageId::parse(name)
                                .ok()
                                .and_then(|id| table.of(id.unique()))
                        })
                        .filter(|_| self.condstore_enabled);
                    match value {
                        Some(mod_seq) => {
                            out.extend(ext_wire::fetch_modseq_line(seq, *uid, mod_seq, &flags))
                        }
                        None => {
                            out.extend(format!("* {seq} FETCH (FLAGS ({flags}))\r\n").into_bytes())
                        }
                    }
                }
                let mut recent = selected.recent.clone();
                recent.extend(
                    messages
                        .iter()
                        .map(|(uid, _, _)| *uid)
                        .filter(|uid| !selected.is_recent(*uid)),
                );
                let grew = messages.len() > selected.messages.len();
                self.selected = Some(Selected {
                    messages: messages.clone(),
                    recent,
                    ..selected
                });
                if grew {
                    out.extend(self.untagged(&Data::Exists(messages.len() as u32)));
                    out.extend(
                        self.untagged(&Data::Recent(
                            self.selected
                                .as_ref()
                                .map_or(0, |selected| selected.recent.len() as u32),
                        )),
                    );
                }
            }
        }
        out.extend(self.ok(tag, "NOOP completed"));
        Outcome {
            out,
            ..Outcome::default()
        }
    }
}
