//! The extension-parameter sidecar: parse what codec 1.0 cannot, and write
//! the extension lines it cannot encode.
//!
//! `imap-codec`/`imap-types` 1.0 — the stable release line this workspace
//! pins — parses neither `SELECT`/`EXAMINE` parameters (`(CONDSTORE)`,
//! `(QRESYNC …)`), nor FETCH/STORE/SEARCH extension arguments
//! (`(CHANGEDSINCE n VANISHED)`, `(UNCHANGEDSINCE n)`, a `MODSEQ` item or
//! key), nor `UID EXPUNGE <set>`; it has no constructor for the
//! `CLOSED`/`HIGHESTMODSEQ`/`MODIFIED`/`APPENDUID`/`COPYUID` response codes
//! either. Upstream's 2.0 line does, but it is alpha-only and a whole-API
//! rewrite — not this workspace's trade while a stable 1.0 exists. So the
//! bytes are handled here, next to the codec:
//!
//! * [`extract`] takes the **complete** command bytes (the caller holds them
//!   in [`crate::imap_server`] before decode), lifts the extension parameters
//!   into [`ExtParams`], and answers the **stripped** bytes the codec does
//!   parse. A line it does not recognise passes through untouched; a line it
//!   recognises but cannot parse answers [`Extraction::Malformed`] — the
//!   command is refused whole, never served degraded (a `UID EXPUNGE` with a
//!   set that did not parse must not quietly become an `EXPUNGE`).
//! * the `*_line`/`insert_*` helpers write the extension responses by hand.
//!   Every one emits atoms, numbers and parentheses only — no literal, no
//!   quoted string — which is what makes hand-writing safe; the literal
//!   contract stays entirely with the codec's own encoder.
//!
//! Known limits of the sidecar tokenizer (deliberate, documented): a mailbox
//! named by a literal (`SELECT {5+} …`) combined with extension parameters
//! does not parse here, and the command is refused rather than guessed at.

use super::qresync::QresyncParam;

/// The extension parameters one command carried, lifted out of the bytes.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct ExtParams {
    /// `SELECT/EXAMINE … (CONDSTORE)`.
    pub(crate) select_condstore: bool,
    /// `SELECT/EXAMINE … (QRESYNC (uidvalidity modseq [known-uids [match]]))`.
    pub(crate) select_qresync: Option<QresyncParam>,
    /// `FETCH … (CHANGEDSINCE n …)`.
    pub(crate) fetch_changedsince: Option<u64>,
    /// `FETCH … (… VANISHED)` — only legal on `UID FETCH` together with
    /// `CHANGEDSINCE`; the session answers `BAD` otherwise (RFC 7162 §3.2.6).
    pub(crate) fetch_vanished: bool,
    /// A `MODSEQ` item inside the FETCH item list (a CONDSTORE enabling
    /// command in its own right, RFC 7162 §3.1.2).
    pub(crate) fetch_modseq: bool,
    /// `STORE … (UNCHANGEDSINCE n) …`.
    pub(crate) store_unchangedsince: Option<u64>,
    /// `SEARCH … MODSEQ n` (RFC 7162 §3.1.5); several keys take the
    /// strictest bound.
    pub(crate) search_modseq: Option<u64>,
    /// `UID EXPUNGE <set>`: the set as inclusive ranges (`*` = [`STAR`]).
    pub(crate) uid_expunge: Option<UidRanges>,
}

/// A sequence set as inclusive ranges; [`STAR`] means the mailbox's largest
/// UID until resolved.
pub(crate) type UidRanges = Vec<(u32, u32)>;

/// The wildcard a sequence set may carry, until the session resolves it.
pub(crate) const STAR: u32 = u32::MAX;

/// What [`extract`] made of one command's bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Extraction {
    /// No extension parameters; the bytes are exactly what was sent.
    None,
    /// Parameters parsed; the second element is the bytes with them stripped,
    /// still ending in CRLF.
    Parsed(ExtParams, Vec<u8>),
    /// The line names a command this parser handles but its parameters do not
    /// parse. The command is refused whole.
    Malformed,
}

/// Lifts the extension parameters out of one complete command's bytes and
/// answers the bytes the codec should see (see the module documentation).
#[must_use]
pub(crate) fn extract(bytes: &[u8]) -> Extraction {
    let Some(line) = bytes.strip_suffix(b"\r\n") else {
        return Extraction::None;
    };
    let mut scan = Scan::new(line);
    let Some((tag_start, _)) = scan.word() else {
        return Extraction::None;
    };
    let Some((verb_start, verb)) = scan.word() else {
        return Extraction::None;
    };
    // `UID EXPUNGE <set>` is the one command the codec cannot even frame; the
    // other `UID …` forms behave like their plain verbs for parameter
    // purposes.
    let (verb, uid_expunge_start) = if verb.eq_ignore_ascii_case(b"UID") {
        match scan.word() {
            Some((_, second)) => (second, Some(verb_start)),
            None => return Extraction::None,
        }
    } else {
        (verb, None)
    };
    let verb = verb.to_ascii_uppercase();
    match verb.as_slice() {
        b"EXPUNGE" => {
            let Some(uid_start) = uid_expunge_start else {
                return Extraction::None; // a plain EXPUNGE belongs to the codec
            };
            uid_expunge(line, tag_start, uid_start, &mut scan)
        }
        b"SELECT" | b"EXAMINE" => select(line),
        b"FETCH" => fetch(line, &mut scan),
        b"STORE" => store(line, &mut scan),
        b"SEARCH" => search(line, scan.at),
        _ => Extraction::None,
    }
}

/// `tag UID EXPUNGE <set>` → `tag EXPUNGE` plus the parsed set. The set is
/// the one remaining word; anything else is malformed.
fn uid_expunge(line: &[u8], tag_start: usize, uid_start: usize, scan: &mut Scan<'_>) -> Extraction {
    let Some((_, set)) = scan.word() else {
        return Extraction::Malformed;
    };
    if !scan.done() {
        return Extraction::Malformed;
    }
    let Some(ranges) = parse_ranges(set, false) else {
        return Extraction::Malformed;
    };
    let mut out = line[..uid_start].to_vec();
    out.extend_from_slice(b"EXPUNGE");
    let _ = tag_start;
    trim_end_spaces(&mut out);
    out.extend_from_slice(b"\r\n");
    Extraction::Parsed(
        ExtParams {
            uid_expunge: Some(ranges),
            ..ExtParams::default()
        },
        out,
    )
}

/// `SELECT/EXAMINE mailbox (CONDSTORE)` / `(QRESYNC (…))`: the trailing
/// group — only when its first word is one of the two — is lifted and
/// stripped. A trailing group naming anything else is the codec's business,
/// which is what keeps a quoted mailbox containing parentheses safe.
fn select(line: &[u8]) -> Extraction {
    let Some((open, close, inner)) = trailing_group(line) else {
        return Extraction::None;
    };
    let mut words = Scan::new(inner);
    let Some(head) = words.word().map(|(_, word)| word.to_ascii_uppercase()) else {
        return Extraction::None;
    };
    match head.as_slice() {
        b"CONDSTORE" => {
            if !words.done() {
                return Extraction::Malformed;
            }
            Extraction::Parsed(
                ExtParams {
                    select_condstore: true,
                    ..ExtParams::default()
                },
                splice_without(line, open, close + 1),
            )
        }
        b"QRESYNC" => {
            let Some((_, _, param_group)) = words.group() else {
                return Extraction::Malformed;
            };
            if !words.done() {
                return Extraction::Malformed;
            }
            match parse_qresync(param_group) {
                Some(param) => Extraction::Parsed(
                    ExtParams {
                        select_qresync: Some(param),
                        ..ExtParams::default()
                    },
                    splice_without(line, open, close + 1),
                ),
                None => Extraction::Malformed,
            }
        }
        _ => Extraction::None,
    }
}

/// `FETCH set (items) (CHANGEDSINCE n VANISHED)`: the trailing group is the
/// modifier list; a bare `MODSEQ` item inside the item list is lifted too.
fn fetch(line: &[u8], scan: &mut Scan<'_>) -> Extraction {
    if scan.word().is_none() {
        // No sequence set: the codec answers the BAD itself.
        return Extraction::None;
    }
    let Some((items_open, items_close, items_inner)) = scan.group() else {
        return Extraction::None;
    };
    let mut params = ExtParams::default();
    let mut edits: Vec<(usize, usize, Option<Vec<u8>>)> = Vec::new();
    // The modifier group: anything parenthesized left after the item list.
    let after = &line[items_close + 1..];
    if let Some((open, close, inner)) = trailing_group(after) {
        let mut words = Scan::new(inner);
        while let Some(head) = words.word().map(|(_, word)| word.to_ascii_uppercase()) {
            match head.as_slice() {
                b"CHANGEDSINCE" => match words.word().and_then(|(_, n)| parse_u64(n)) {
                    Some(n) => params.fetch_changedsince = Some(n),
                    None => return Extraction::Malformed,
                },
                b"VANISHED" => params.fetch_vanished = true,
                _ => return Extraction::Malformed,
            }
        }
        let base = items_close + 1;
        edits.push((base + open, base + close + 1, None));
    }
    // A `MODSEQ` item sits directly inside the item list; every section
    // (`BODY[…]`, its header-field lists) is deeper, so a depth-counted scan
    // finds exactly the items that are the client's own request.
    if let Some(rebuilt) = strip_modseq_items(items_inner) {
        params.fetch_modseq = true;
        edits.push((items_open, items_close + 1, Some(rebuilt)));
    }
    if params == ExtParams::default() {
        return Extraction::None;
    }
    Extraction::Parsed(params, apply(line, &edits))
}

/// `STORE set (UNCHANGEDSINCE n) +FLAGS (…)`: the modifier group sits between
/// the set and the item.
fn store(line: &[u8], scan: &mut Scan<'_>) -> Extraction {
    if scan.word().is_none() {
        return Extraction::None;
    }
    let Some((open, close, inner)) = scan.group() else {
        return Extraction::None;
    };
    let mut params = ExtParams::default();
    let mut words = Scan::new(inner);
    while let Some(head) = words.word().map(|(_, word)| word.to_ascii_uppercase()) {
        match head.as_slice() {
            b"UNCHANGEDSINCE" => match words.word().and_then(|(_, n)| parse_u64(n)) {
                Some(n) => params.store_unchangedsince = Some(n),
                None => return Extraction::Malformed,
            },
            _ => return Extraction::Malformed,
        }
    }
    if params == ExtParams::default() {
        // Not our group (an empty one is the codec's BAD to answer).
        return Extraction::None;
    }
    Extraction::Parsed(params, splice_without(line, open, close + 1))
}

/// `SEARCH … MODSEQ n …`: lifts every top-level `MODSEQ <n>` pair out of the
/// criteria; the effective bound is the strictest one.
fn search(line: &[u8], from: usize) -> Extraction {
    let depths = depth_map(line);
    let top = depths
        .get(from.min(depths.len().saturating_sub(1)))
        .copied()
        .unwrap_or(0);
    let mut scan = Scan::new(line);
    scan.at = from;
    let mut edits: Vec<(usize, usize, Option<Vec<u8>>)> = Vec::new();
    let mut bound: Option<u64> = None;
    while let Some((start, word)) = scan.word() {
        if depths.get(start).copied().unwrap_or(0) != top || !word.eq_ignore_ascii_case(b"MODSEQ") {
            continue;
        }
        let Some((number_start, number)) = scan.word() else {
            // A dangling MODSEQ: put nothing away — the codec refuses the
            // line, and stripping half a pair would change the refusal.
            return Extraction::None;
        };
        match parse_u64(number) {
            Some(n) => {
                bound = Some(bound.map_or(n, |seen: u64| seen.max(n)));
                edits.push((start, number_start + number.len(), None));
            }
            None => return Extraction::None,
        }
    }
    let Some(bound) = bound else {
        return Extraction::None;
    };
    let mut stripped = apply(line, &edits);
    // `SEARCH MODSEQ n` alone strips to a bare `SEARCH`, which has no keys
    // and cannot be framed; RFC 7162 §3.1.5's key pairs with the session's
    // own mod-sequence filter, and `ALL` is exactly that filter's universe.
    if stripped.ends_with(b"SEARCH\r\n") {
        let at = stripped.len() - 2;
        stripped.splice(at..at, b" ALL".iter().copied());
    }
    Extraction::Parsed(
        ExtParams {
            search_modseq: Some(bound),
            ..ExtParams::default()
        },
        stripped,
    )
}

/// A sequence set as inclusive ranges. `strict` forbids `*` and requires
/// ascending, non-overlapping order (RFC 7162 §7's ABNF for the QRESYNC
/// parameters); otherwise `*` maps to [`STAR`] and any order is accepted.
pub(crate) fn parse_ranges(set: &[u8], strict: bool) -> Option<UidRanges> {
    let text = std::str::from_utf8(set).ok()?;
    let mut ranges = Vec::new();
    for part in text.split(',') {
        let (mut lo, mut hi) = match part.split_once(':') {
            Some((a, b)) => (parse_point(a)?, parse_point(b)?),
            None => {
                let point = parse_point(part)?;
                (point, point)
            }
        };
        if lo > hi {
            std::mem::swap(&mut lo, &mut hi);
        }
        ranges.push((lo, hi));
    }
    if ranges.is_empty() {
        return None;
    }
    if strict {
        let mut last = 0;
        for (lo, hi) in &ranges {
            if *lo == STAR || *hi == STAR || *lo <= last {
                return None;
            }
            last = *hi;
        }
    }
    Some(ranges)
}

/// One sequence-set point; `*` is [`STAR`].
fn parse_point(text: &str) -> Option<u32> {
    if text == "*" {
        return Some(STAR);
    }
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    text.parse::<u64>().ok().and_then(|n| u32::try_from(n).ok())
}

pub(crate) fn parse_u64(text: &[u8]) -> Option<u64> {
    let text = std::str::from_utf8(text).ok()?;
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    text.parse::<u64>().ok()
}

// The byte-level scanner and the edits it applies live in [`super::ext_scan`];
// this file re-exports them so the parsers above read as one grammar.
use super::ext_scan::{
    apply, depth_map, splice_without, strip_modseq_items, trailing_group, trim_end_spaces, Scan,
};
use super::qresync::parse_qresync;

pub(crate) use super::ext_lines::{
    appenduid_ok, closed_line, compress_ranges, copyuid_ok, fetch_modseq_line, highestmodseq_line,
    highestmodseq_ok, insert_before_close, insert_modseq, modified_ok, ranges_contain,
    resolve_star, search_modseq_suffix, vanished_line,
};
