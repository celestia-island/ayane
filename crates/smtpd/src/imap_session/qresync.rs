//! QRESYNC: the RFC 7162 §3.2 SELECT parameter and the initial
//! synchronization it drives — the parameter grammar (which `extract`
//! dispatches to), the `VANISHED (EARLIER)` set a resyncing client is
//! answered from, and the changed message FETCH lines that follow it.
//! The expunged report goes out before the FETCH lines it summarizes
//! (RFC 7162 §3.2.5).

use std::collections::HashSet;

use crate::maildir_reader::MessageId;

use super::ext_scan::Scan;
use super::ext_wire;
use super::ext_wire::{parse_ranges, parse_u64, UidRanges};
use super::modseq;
use super::session::{ImapSession, Selected};
use super::uidlist::UidMap;
use super::wire::{flags_text, non_zero};

/// The `(uidvalidity modseq [known-uids [(seq-set uid-set)]])` of a QRESYNC
/// SELECT (RFC 7162 §3.2.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct QresyncParam {
    pub(crate) uidvalidity: u32,
    pub(crate) modseq: u64,
    /// The UIDs the client still holds; `None` means `1:<UIDNEXT-1>`. The
    /// ABNF forbids `*` and requires ascending order — enforced at parse.
    pub(crate) known_uids: Option<UidRanges>,
    /// The client's `(known-sequence-set known-uid-set)` pair, used to trim
    /// the `VANISHED` report (RFC 7162 §3.2.5.2).
    pub(crate) seq_match: Option<(UidRanges, UidRanges)>,
}

/// `(uidvalidity modseq [known-uids [(seq-set uid-set)]])` — RFC 7162 §3.2.5.
/// `*` is forbidden in all three sets and the order must be ascending; a
/// violation is a syntax error, and RFC 7162 §3.2.5.1 answers a syntax error
/// with `BAD` and no mailbox selected.
pub(crate) fn parse_qresync(inner: &[u8]) -> Option<QresyncParam> {
    let mut words = Scan::new(inner);
    let uidvalidity = parse_u64(words.word()?.1)?;
    if uidvalidity == 0 || uidvalidity > u32::MAX as u64 {
        return None;
    }
    let modseq = parse_u64(words.word()?.1)?;
    let mut param = QresyncParam {
        uidvalidity: uidvalidity as u32,
        modseq,
        known_uids: None,
        seq_match: None,
    };
    match words.word() {
        None => return Some(param),
        Some((_, set)) => param.known_uids = Some(parse_ranges(set, true)?),
    }
    // The seq-match pair is optional; known-uids without it is the shape a
    // resyncing client sends most.
    if let Some((_, _, pair)) = words.group() {
        let mut sets = Scan::new(pair);
        let seq = parse_ranges(sets.word()?.1, true)?;
        let uids = parse_ranges(sets.word()?.1, true)?;
        if !sets.done() {
            return None;
        }
        param.seq_match = Some((seq, uids));
        if !words.done() {
            return None;
        }
    }
    Some(param)
}

impl ImapSession<'_> {
    /// The UIDs `VANISHED (EARLIER)` reports for "everything since `since`":
    /// the expunge queue exactly, or — when the request predates the trim
    /// watermark — every dead uidlist line (RFC 7162 §3.2.6's note), minus
    /// what still lives, intersected with the client's known set and trimmed
    /// by its seq-match data.
    pub(crate) fn vanished_earlier_uids(
        &self,
        selected: &Selected,
        map: &UidMap,
        since: u64,
        known: Option<&UidRanges>,
        seq_match: Option<&(UidRanges, UidRanges)>,
    ) -> Vec<u32> {
        let Ok(table) = modseq::table(&selected.dir) else {
            return Vec::new();
        };
        let live: HashSet<String> = selected
            .messages
            .iter()
            .filter_map(|(_, name, _)| MessageId::parse(name).ok().map(|id| id.unique().to_owned()))
            .collect();
        let mut candidates: Vec<String> = if table.predates_memory(since) {
            // RFC 7162 §3.2.6, note: a client older than what this server
            // still remembers is treated as asking about *every* dead UID.
            map.lines
                .iter()
                .map(|(_, unique)| unique.clone())
                .filter(|unique| !live.contains(unique))
                .collect()
        } else {
            table
                .expunged_since(since)
                .into_iter()
                .map(|(unique, _)| unique)
                .filter(|unique| !live.contains(unique))
                .collect()
        };
        candidates.sort();
        candidates.dedup();
        let mut uids: Vec<u32> = candidates
            .iter()
            .filter_map(|unique| map.uid_of(unique))
            .filter(|uid| known.is_none_or(|ranges| ext_wire::ranges_contain(ranges, *uid)))
            .collect();
        uids.sort_unstable();
        uids.dedup();
        if let Some((seqs, uids_set)) = seq_match {
            if let Some(bound) = seq_match_bound(selected, seqs, uids_set) {
                // RFC 7162 §3.2.5.2: the client that supplied matching
                // seq/UID data already knows everything before that pair.
                uids.retain(|uid| *uid >= bound);
            }
        }
        uids
    }

    pub(crate) fn changed_fetch_lines(
        &self,
        selected: &Selected,
        since: u64,
        known: Option<&UidRanges>,
    ) -> Vec<u8> {
        let mut out = Vec::new();
        let Ok(table) = modseq::table(&selected.dir) else {
            return out;
        };
        for (index, (uid, name, _)) in selected.messages.iter().enumerate() {
            let Some(id) = MessageId::parse(name).ok() else {
                continue;
            };
            let Some(value) = table.of(id.unique()) else {
                continue;
            };
            if value <= since {
                continue;
            }
            if known.is_some_and(|ranges| !ext_wire::ranges_contain(ranges, *uid)) {
                continue;
            }
            let seq = non_zero(u32::try_from(index + 1).unwrap_or(1)).get();
            let flags = flags_text(name, selected.is_recent(*uid));
            out.extend(ext_wire::fetch_modseq_line(seq, *uid, value, &flags));
        }
        out
    }
}
/// The UID below which a QRESYNC client that supplied seq-match data already
/// knows its messages (RFC 7162 §3.2.5.2): the UID of the first
/// `(seq, uid)` pair whose current sequence slot really holds that UID.
///
/// The two sets pair element-wise once expanded; expansion is bounded so a
/// set like `1:4294967295` cannot walk the server off a cliff — past the
/// bound the client gets the untrimmed report, which is strictly more
/// information than it asked to skip, never less.
fn seq_match_bound(selected: &Selected, seqs: &UidRanges, uids: &UidRanges) -> Option<u32> {
    const MAX_PAIRS: usize = 10_000;
    let seq_points = expand_ranges(seqs).take(MAX_PAIRS);
    let uid_points = expand_ranges(uids).take(MAX_PAIRS);
    for (seq, uid) in seq_points.zip(uid_points) {
        let at = usize::try_from(seq.saturating_sub(1)).ok()?;
        if selected.messages.get(at).map(|row| row.0) == Some(uid) {
            return Some(uid);
        }
    }
    None
}

/// Flattens ascending ranges into their points, in order (an inverted or
/// empty range contributes nothing).
fn expand_ranges(ranges: &UidRanges) -> impl Iterator<Item = u32> + '_ {
    ranges
        .iter()
        .flat_map(|(lo, hi)| (*lo).min(*hi)..=(*lo).max(*hi))
}
