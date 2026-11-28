//! UIDPLUS (RFC 4315): the answers this server owes once it advertises
//! `UIDPLUS` — the `APPENDUID`/`COPYUID` response codes and the `UID
//! EXPUNGE` target selection.
//!
//! The codes are pure bookkeeping over state the session already has (the
//! appended message's UID, the copy's source/target UID pairs), so this file
//! is where they are *spelled*, and the session files are where they are
//! *decided*. `UID EXPUNGE`'s selection rule is RFC 4315 §2.1's whole
//! content: only messages that carry `\Deleted` **and** lie in the given set
//! are removed — a message that is deleted but outside the set, or in the
//! set but not deleted, stays exactly where it is.

/// The `(source uid, destination uid)` pairs one COPY/MOVE produced, in the
/// order the command resolved them — RFC 4315 §3 wants both sets spelled in
/// that order, aligned element for element.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct CopyMapping {
    pairs: Vec<(u32, u32)>,
}

impl CopyMapping {
    /// Records one copied message.
    pub(crate) fn push(&mut self, from: u32, to: u32) {
        self.pairs.push((from, to));
    }

    /// Whether any copy actually happened (RFC 4315 §3: an empty COPY that
    /// resolved no messages sends no code at all).
    pub(crate) fn is_empty(&self) -> bool {
        self.pairs.is_empty()
    }

    /// The source UIDs, in resolution order.
    pub(crate) fn sources(&self) -> Vec<u32> {
        self.pairs.iter().map(|(from, _)| *from).collect()
    }

    /// The destination UIDs, in the same order.
    pub(crate) fn targets(&self) -> Vec<u32> {
        self.pairs.iter().map(|(_, to)| *to).collect()
    }

    /// The tagged `OK [COPYUID uidvalidity src dst]` line for `tag`.
    ///
    /// The pairs are spelled as they were resolved, duplicates included —
    /// the two sets stay aligned element for element, which is the one
    /// property RFC 4315 §3 makes mandatory (an overlapping set in the
    /// command can name one message twice; both copies are real answers).
    pub(crate) fn ok_line(&self, tag: &str, validity: u32, text: &str) -> Vec<u8> {
        super::ext_wire::copyuid_ok(
            tag,
            validity,
            &super::ext_wire::compress_ranges(&self.sources()),
            &super::ext_wire::compress_ranges(&self.targets()),
            text,
        )
    }
}

/// The tagged `OK [APPENDUID uidvalidity uid]` line for `tag` — RFC 4315
/// §3's answer to APPEND, sent whenever the server knows the UID it gave the
/// message (which here is always: the uidlist scan that follows the append
/// is what produced it).
pub(crate) fn append_ok(tag: &str, validity: u32, uid: u32, text: &str) -> Vec<u8> {
    super::ext_wire::appenduid_ok(tag, validity, uid, text)
}

/// The subset of `messages` that `UID EXPUNGE <set>` removes: `\Deleted` and
/// inside `ranges` (`*` already resolved), in the order given — lowest
/// sequence first, which is the order the expunge reporter needs.
pub(crate) fn uid_expunge_targets(
    messages: &[super::Row],
    ranges: &[(u32, u32)],
) -> Vec<(u32, String)> {
    messages
        .iter()
        .filter(|(uid, name, _)| {
            super::ext_wire::ranges_contain(ranges, *uid) && super::wire::is_deleted(name)
        })
        .map(|(uid, name, _)| (*uid, name.clone()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(flags: &str) -> String {
        format!("1700000000.M1P1Q0.example:2,{flags}")
    }

    #[test]
    fn a_copy_mapping_spells_both_sets_aligned() {
        let mut mapping = CopyMapping::default();
        assert!(mapping.is_empty());
        mapping.push(1, 7);
        mapping.push(2, 8);
        mapping.push(4, 9);
        assert!(!mapping.is_empty());
        let line =
            String::from_utf8_lossy(&mapping.ok_line("a1", 5, "COPY completed")).into_owned();
        assert_eq!(line, "a1 OK [COPYUID 5 1:2,4 7:9] COPY completed\r\n");
    }

    #[test]
    fn the_pairs_are_spelled_exactly_as_resolved() {
        let mut mapping = CopyMapping::default();
        mapping.push(3, 10);
        mapping.push(3, 11);
        let line =
            String::from_utf8_lossy(&mapping.ok_line("a1", 1, "COPY completed")).into_owned();
        assert_eq!(
            line, "a1 OK [COPYUID 1 3,3 10:11] COPY completed\r\n",
            "duplicates stay, so the two sets remain aligned"
        );
    }

    #[test]
    fn uid_expunge_removes_only_deleted_and_in_set() {
        let messages: Vec<(u32, String, bool)> = vec![
            (1u32, name("S"), true),
            (2u32, name("ST"), true),
            (3u32, name("T"), true),
            (4u32, name("T"), true),
            (5u32, name(""), false),
        ];
        let targets = uid_expunge_targets(&messages, &[(2, 3)]);
        assert_eq!(
            targets,
            vec![(2u32, name("ST")), (3u32, name("T"))],
            "uid 1 is not deleted, uid 4 is outside the set"
        );
        // `*` resolved to the largest UID reaches only deleted members.
        let targets = uid_expunge_targets(&messages, &[(5, 5)]);
        assert!(targets.is_empty());
        let targets = uid_expunge_targets(&messages, &[(1, 5)]);
        assert_eq!(targets.len(), 3);
    }
}
