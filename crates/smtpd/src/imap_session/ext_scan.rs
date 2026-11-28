//! The byte-level scanner the parameter parsers run on: whitespace words,
//! quoted strings and parenthesized groups over one command line, plus the
//! edits (removals and replacements) that answer the bytes the codec sees
//! after the parameters are lifted. Positions are absolute in the line, so
//! the parsers can describe a cut without re-deriving it.

/// Removes every depth-zero `MODSEQ` item from a FETCH item list, answering
/// the list rebuilt (or `None` when there was nothing to remove).
pub(crate) fn strip_modseq_items(items: &[u8]) -> Option<Vec<u8>> {
    let depths = depth_map(items);
    let mut kept: Vec<&[u8]> = Vec::new();
    let mut removed = false;
    let mut scan = Scan::new(items);
    while let Some((start, word)) = scan.word() {
        if depths.get(start).copied().unwrap_or(0) == 0 && word.eq_ignore_ascii_case(b"MODSEQ") {
            removed = true;
            continue;
        }
        kept.push(word);
    }
    removed.then(|| {
        let mut out = Vec::with_capacity(items.len());
        out.push(b'(');
        for (at, word) in kept.iter().enumerate() {
            if at > 0 {
                out.push(b' ');
            }
            out.extend_from_slice(word);
        }
        out.push(b')');
        out
    })
}

/// The unbalanced-open-bracket depth at every byte of `line` (how many
/// `(`/`[` are open walking from the start).
pub(crate) fn depth_map(line: &[u8]) -> Vec<usize> {
    let mut out = Vec::with_capacity(line.len());
    let mut depth = 0usize;
    for byte in line {
        out.push(depth);
        match byte {
            b'(' | b'[' => depth += 1,
            b')' | b']' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    out
}

/// Applies removals (`None`) and replacements (`Some`) to `line`, drops
/// trailing spaces the removals stranded, and restores the CRLF.
pub(crate) fn apply(line: &[u8], edits: &[(usize, usize, Option<Vec<u8>>)]) -> Vec<u8> {
    let mut out = Vec::with_capacity(line.len());
    let mut at = 0usize;
    for (start, end, replacement) in edits {
        out.extend_from_slice(&line[at..*start]);
        if let Some(bytes) = replacement {
            out.extend_from_slice(bytes);
        } else if *start > 0 && out.last() == Some(&b' ') && line.get(*end) == Some(&b' ') {
            out.pop();
        }
        at = *end;
    }
    out.extend_from_slice(&line[at..]);
    trim_end_spaces(&mut out);
    out.push(b'\r');
    out.push(b'\n');
    out
}

/// `line` without the byte range `from..until`, with one stranded space
/// removed and the CRLF restored.
pub(crate) fn splice_without(line: &[u8], from: usize, until: usize) -> Vec<u8> {
    apply(line, &[(from, until, None)])
}

pub(crate) fn trim_end_spaces(out: &mut Vec<u8>) {
    while out.last() == Some(&b' ') {
        out.pop();
    }
}

// ── the byte-level scanner ────────────────────────────────────────────────

/// Whitespace-separated words over one command line (no CRLF), tracking
/// absolute positions. Quoted strings are one word; parenthesized groups are
/// taken by [`Scan::group`].
pub(crate) struct Scan<'a> {
    line: &'a [u8],
    pub(crate) at: usize,
}

impl<'a> Scan<'a> {
    pub(crate) fn new(line: &'a [u8]) -> Self {
        Self { line, at: 0 }
    }

    fn skip_spaces(&mut self) {
        while matches!(self.line.get(self.at), Some(b' ' | b'\t')) {
            self.at += 1;
        }
    }

    /// Nothing but spaces ahead?
    pub(crate) fn done(&mut self) -> bool {
        self.skip_spaces();
        self.at >= self.line.len()
    }

    /// The next word with its absolute start.
    pub(crate) fn word(&mut self) -> Option<(usize, &'a [u8])> {
        self.skip_spaces();
        let start = self.at;
        let rest = self.line.get(start..)?;
        if rest.is_empty() {
            return None;
        }
        if rest[0] == b'"' {
            let mut at = 1;
            while at < rest.len() {
                match rest[at] {
                    b'\\' => at += 2,
                    b'"' => {
                        self.at = start + at + 1;
                        return Some((start, &rest[..at + 1]));
                    }
                    _ => at += 1,
                }
            }
            // An unterminated quote: one word to the end, for the codec to
            // refuse.
            self.at = self.line.len();
            return Some((start, rest));
        }
        let end = rest
            .iter()
            .position(|byte| matches!(byte, b' ' | b'\t'))
            .unwrap_or(rest.len());
        self.at = start + end;
        Some((start, &rest[..end]))
    }

    /// The next parenthesized group: `(open, close, inner)` in absolute
    /// positions, `inner` excluding the parentheses.
    pub(crate) fn group(&mut self) -> Option<(usize, usize, &'a [u8])> {
        self.skip_spaces();
        let open = self.at;
        if self.line.get(open) != Some(&b'(') {
            return None;
        }
        let mut depth = 0usize;
        for (offset, byte) in self.line[open..].iter().enumerate() {
            match byte {
                b'(' => depth += 1,
                b')' => {
                    depth -= 1;
                    if depth == 0 {
                        let close = open + offset;
                        self.at = close + 1;
                        return Some((open, close, &self.line[open + 1..close]));
                    }
                }
                _ => {}
            }
        }
        None
    }
}

/// The last `(...)` group of a segment, only when nothing but spaces follows
/// its close: `(open, close, inner)` in positions relative to `bytes`.
pub(crate) fn trailing_group(bytes: &[u8]) -> Option<(usize, usize, &[u8])> {
    let end = bytes.iter().rposition(|byte| *byte != b' ')? + 1;
    if end == 0 || bytes[end - 1] != b')' {
        return None;
    }
    let mut depth = 0usize;
    let mut at = end;
    while at > 0 {
        at -= 1;
        match bytes[at] {
            b')' => depth += 1,
            b'(' => {
                depth -= 1;
                if depth == 0 {
                    return Some((at, end - 1, &bytes[at + 1..end - 1]));
                }
            }
            _ => {}
        }
    }
    None
}
