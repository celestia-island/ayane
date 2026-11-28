//! The hand-written extension lines: the responses the codec cannot
//! spell at 1.0 — `CLOSED`, `HIGHESTMODSEQ`, the two `VANISHED` forms,
//! `MODIFIED`, `APPENDUID`, `COPYUID`, the FETCH/SEARCH mod-sequence
//! insertions, and the sequence-set compression they share. Every one
//! emits atoms, numbers and parentheses only (the literal contract stays
//! with the codec), and [`super::ext_wire`] re-exports them so call sites
//! read as one vocabulary.

use super::ext_wire::{UidRanges, STAR};

// ── the hand-written encoders ─────────────────────────────────────────────
//
// All of these emit atoms, numbers and parentheses only (see the module
// documentation); every `tag` is one the codec already accepted.

/// `* OK [CLOSED] …` — RFC 7162 §3.2.11: an unconditional obligation once
/// CONDSTORE or QRESYNC is advertised, before the responses that follow a
/// change of mailbox.
pub(crate) fn closed_line() -> Vec<u8> {
    b"* OK [CLOSED] Previous mailbox is now closed\r\n".to_vec()
}

/// `* OK [HIGHESTMODSEQ n] …` — RFC 7162 §3.1.2.1.
pub(crate) fn highestmodseq_line(highest: u64) -> Vec<u8> {
    format!("* OK [HIGHESTMODSEQ {highest}] The highest mod-sequence value is {highest}\r\n")
        .into_bytes()
}

/// `tag OK [HIGHESTMODSEQ n] text` — the tagged form RFC 7162 §3.2.7 puts on
/// `EXPUNGE` once QRESYNC is enabled.
pub(crate) fn highestmodseq_ok(tag: &str, highest: u64, text: &str) -> Vec<u8> {
    format!("{tag} OK [HIGHESTMODSEQ {highest}] {text}\r\n").into_bytes()
}

/// `* VANISHED (EARLIER) <set>` or `* VANISHED <set>` — the two forms RFC
/// 7162 §3.2.10 forbids mixing. `uids` must be ascending; they are
/// compressed into ranges.
pub(crate) fn vanished_line(uids: &[u32], earlier: bool) -> Vec<u8> {
    let head: &str = if earlier {
        "* VANISHED (EARLIER) "
    } else {
        "* VANISHED "
    };
    let mut out = head.as_bytes().to_vec();
    out.extend_from_slice(compress_ranges(uids).as_bytes());
    out.extend_from_slice(b"\r\n");
    out
}

/// `tag OK [MODIFIED <set>] text` — RFC 7162 §3.1.3's answer to an
/// `UNCHANGEDSINCE` STORE whose failure table is not empty.
pub(crate) fn modified_ok(tag: &str, set: &str, text: &str) -> Vec<u8> {
    format!("{tag} OK [MODIFIED {set}] {text}\r\n").into_bytes()
}

/// `tag OK [APPENDUID uidvalidity uid] text` — RFC 4315 §3.
pub(crate) fn appenduid_ok(tag: &str, validity: u32, uid: u32, text: &str) -> Vec<u8> {
    format!("{tag} OK [APPENDUID {validity} {uid}] {text}\r\n").into_bytes()
}

/// `tag OK [COPYUID uidvalidity src dst] text` — RFC 4315 §3; RFC 6851 §4.3
/// makes the same code mandatory for `UID MOVE`.
pub(crate) fn copyuid_ok(tag: &str, validity: u32, src: &str, dst: &str, text: &str) -> Vec<u8> {
    format!("{tag} OK [COPYUID {validity} {src} {dst}] {text}\r\n").into_bytes()
}

/// `* n FETCH (UID u FLAGS (…) MODSEQ (m))` — the fetch line QRESYNC's
/// initial synchronization and the NOOP refresh are built from (RFC 7162
/// §3.2.4, errata 1807).
pub(crate) fn fetch_modseq_line(seq: u32, uid: u32, modseq: u64, flags: &str) -> Vec<u8> {
    format!("* {seq} FETCH (UID {uid} FLAGS ({flags}) MODSEQ ({modseq}))\r\n").into_bytes()
}

/// Appends `text` just before a rendered line's trailing CRLF — the shape
/// `… (MODSEQ n)` needs on a SEARCH line the codec cannot spell (1.0 has no
/// MODSEQ search tail either). Nothing here is a literal, so the point
/// before the CRLF is exact.
pub(crate) fn insert_before_close(line: &mut Vec<u8>, addition: &str) {
    let Some(close) = line.len().checked_sub(3) else {
        return;
    };
    if !line.ends_with(b")\r\n") {
        return;
    }
    // An empty item list takes the addition bare (`()` → `(HIGHESTMODSEQ n)`).
    let addition = if close > 0 && line[close - 1] == b'(' {
        addition.strip_prefix(' ').unwrap_or(addition)
    } else {
        addition
    };
    line.splice(close..close, addition.bytes());
}

/// Appends ` MODSEQ (m)` inside a rendered FETCH line's item list — the
/// untagged-FETCH obligation RFC 7162 §3.1.2.1 puts on every CONDSTORE
/// session.
pub(crate) fn insert_modseq(line: &mut Vec<u8>, modseq: u64) {
    let Some(close) = line.len().checked_sub(3) else {
        return;
    };
    if !line.ends_with(b")\r\n") {
        return;
    }
    let addition = format!(" MODSEQ ({modseq})");
    line.splice(close..close, addition.bytes());
}

/// Appends ` (MODSEQ n)` to a rendered untagged SEARCH line — RFC 7162
/// §3.1.6's tail on a non-empty result set. No literal can be in a SEARCH
/// line, so the point before the CRLF is exact.
pub(crate) fn search_modseq_suffix(line: &mut Vec<u8>, highest_in_results: u64) {
    let Some(without_crlf) = line.len().checked_sub(2) else {
        return;
    };
    if !line.ends_with(b"\r\n") {
        return;
    }
    let addition = format!(" (MODSEQ {highest_in_results})");
    line.splice(without_crlf..without_crlf, addition.bytes());
}

/// Compresses ascending UIDs into a sequence-set string (`1:3,5,7:9`);
/// empty input answers an empty string, and callers must not emit a line
/// from it (a `VANISHED` needs at least one UID).
pub(crate) fn compress_ranges(uids: &[u32]) -> String {
    let mut out = String::new();
    let mut at = 0usize;
    while at < uids.len() {
        let start = uids[at];
        let mut end = start;
        let mut run = at + 1;
        while run < uids.len() && Some(uids[run]) == end.checked_add(1) {
            end = uids[run];
            run += 1;
        }
        if !out.is_empty() {
            out.push(',');
        }
        if end > start {
            out.push_str(&start.to_string());
            out.push(':');
            out.push_str(&end.to_string());
        } else {
            out.push_str(&start.to_string());
        }
        at = run;
    }
    out
}

/// Whether a UID lies in a parsed set (`*` already resolved).
pub(crate) fn ranges_contain(ranges: &[(u32, u32)], uid: u32) -> bool {
    ranges.iter().any(|(lo, hi)| *lo <= uid && uid <= *hi)
}

/// The largest UID a set's `*` stands for, resolved against the mailbox's
/// largest known UID.
pub(crate) fn resolve_star(ranges: &[(u32, u32)], largest: u32) -> UidRanges {
    ranges
        .iter()
        .map(|(lo, hi)| {
            let lo = if *lo == STAR { largest } else { *lo };
            let hi = if *hi == STAR { largest } else { *hi };
            (lo.min(hi), lo.max(hi))
        })
        .collect()
}
