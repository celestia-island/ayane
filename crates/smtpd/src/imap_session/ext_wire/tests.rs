//! Unit tests for the extension-parameter sidecar: the parse-and-strip
//! pairs per command, the malformed refusals, the pass-throughs, and the
//! exact spelling of the hand-written lines.

use super::*;

use super::*;

fn parsed(line: &str) -> (ExtParams, String) {
    match extract(line.as_bytes()) {
        Extraction::Parsed(params, bytes) => {
            (params, String::from_utf8_lossy(&bytes).into_owned())
        }
        other => panic!("expected Parsed, got {other:?}"),
    }
}

fn none(line: &str) {
    assert_eq!(extract(line.as_bytes()), Extraction::None, "{line}");
}

fn malformed(line: &str) {
    assert_eq!(extract(line.as_bytes()), Extraction::Malformed, "{line}");
}

#[test]
fn a_select_condstore_is_parsed_and_stripped() {
    let (params, stripped) = parsed("a1 SELECT INBOX (CONDSTORE)\r\n");
    assert!(params.select_condstore);
    assert_eq!(params.select_qresync, None);
    assert_eq!(stripped, "a1 SELECT INBOX\r\n");
    none("a1 EXAMINE INBOX\r\n");
}

#[test]
fn a_full_qresync_parameter_set_parses() {
    let (params, stripped) = parsed("a1 SELECT INBOX (QRESYNC (123 45 1:10 (2,4 12,15)))\r\n");
    let param = params.select_qresync.expect("qresync");
    assert_eq!(param.uidvalidity, 123);
    assert_eq!(param.modseq, 45);
    assert_eq!(param.known_uids, Some(vec![(1, 10)]));
    assert_eq!(
        param.seq_match,
        Some((vec![(2, 2), (4, 4)], vec![(12, 12), (15, 15)])),
        "comma-separated sets: seq points 2 and 4, uid points 12 and 15"
    );
    assert_eq!(stripped, "a1 SELECT INBOX\r\n");
}

#[test]
fn a_qresync_parameter_set_without_optionals_parses() {
    let (params, stripped) = parsed("a1 EXAMINE INBOX (QRESYNC (7 9))\r\n");
    let param = params.select_qresync.expect("qresync");
    assert_eq!(param.known_uids, None, "known-uids defaults at the session");
    assert_eq!(param.seq_match, None);
    assert_eq!(stripped, "a1 EXAMINE INBOX\r\n");
}

#[test]
fn known_uids_without_seq_match_parses() {
    let (params, stripped) = parsed("s SELECT INBOX (QRESYNC (1357996159 5 1:10))\r\n");
    let param = params.select_qresync.expect("qresync");
    assert_eq!(param.uidvalidity, 1357996159);
    assert_eq!(param.modseq, 5);
    assert_eq!(param.known_uids, Some(vec![(1, 10)]));
    assert_eq!(param.seq_match, None);
    assert_eq!(stripped, "s SELECT INBOX\r\n");
}

#[test]
fn a_star_in_known_uids_is_a_syntax_error() {
    malformed("a1 SELECT INBOX (QRESYNC (123 45 1:10,*))\r\n");
    malformed("a1 SELECT INBOX (QRESYNC (123 45 5,1:3))\r\n");
}

#[test]
fn broken_qresync_parameters_are_malformed() {
    malformed("a1 SELECT INBOX (QRESYNC (123))\r\n");
    malformed("a1 SELECT INBOX (QRESYNC)\r\n");
    malformed("a1 SELECT INBOX (QRESYNC (x 1))\r\n");
    malformed("a1 SELECT INBOX (QRESYNC (0 1))\r\n");
}

#[test]
fn a_condstore_with_arguments_is_malformed() {
    malformed("a1 SELECT INBOX (CONDSTORE extra)\r\n");
}

#[test]
fn a_foreign_trailing_group_passes_through() {
    none("a1 SELECT \"Odd (name)\"\r\n");
    none("a1 SELECT INBOX\r\n");
}

#[test]
fn a_fetch_modifier_is_parsed_and_stripped() {
    let (params, stripped) = parsed("a1 FETCH 1:* (FLAGS) (CHANGEDSINCE 12 VANISHED)\r\n");
    assert_eq!(params.fetch_changedsince, Some(12));
    assert!(params.fetch_vanished);
    assert!(!params.fetch_modseq);
    assert_eq!(stripped, "a1 FETCH 1:* (FLAGS)\r\n");
}

#[test]
fn a_fetch_modseq_item_is_lifted_from_the_items() {
    let (params, stripped) = parsed("a1 FETCH 1 (MODSEQ)\r\n");
    assert!(params.fetch_modseq);
    assert_eq!(params.fetch_changedsince, None);
    assert_eq!(stripped, "a1 FETCH 1 ()\r\n");
    let (params, stripped) = parsed("a1 UID FETCH 1:5 (FLAGS MODSEQ UID)\r\n");
    assert!(params.fetch_modseq);
    assert_eq!(stripped, "a1 UID FETCH 1:5 (FLAGS UID)\r\n");
}

#[test]
fn a_modseq_inside_a_section_is_not_an_item() {
    none("a1 FETCH 1 (BODY[HEADER.FIELDS (MODSEQ DATE)])\r\n");
}

#[test]
fn an_unknown_fetch_modifier_is_malformed() {
    malformed("a1 FETCH 1 (FLAGS) (BOGUS 1)\r\n");
    malformed("a1 FETCH 1 (FLAGS) (CHANGEDSINCE x)\r\n");
}

#[test]
fn a_plain_fetch_passes_through() {
    none("a1 FETCH 1 (FLAGS)\r\n");
    none("a1 UID FETCH 1:* (FLAGS BODY[])\r\n");
}

#[test]
fn a_store_modifier_is_parsed_and_stripped() {
    let (params, stripped) = parsed("a1 STORE 1:2 (UNCHANGEDSINCE 7) +FLAGS (\\Seen)\r\n");
    assert_eq!(params.store_unchangedsince, Some(7));
    assert_eq!(stripped, "a1 STORE 1:2 +FLAGS (\\Seen)\r\n");
    let (params, stripped) =
        parsed("a1 UID STORE 1 (UNCHANGEDSINCE 0) +FLAGS.SILENT (\\Seen)\r\n");
    assert_eq!(params.store_unchangedsince, Some(0));
    assert_eq!(stripped, "a1 UID STORE 1 +FLAGS.SILENT (\\Seen)\r\n");
    none("a1 STORE 1 +FLAGS (\\Seen)\r\n");
}

#[test]
fn an_unknown_store_modifier_is_malformed() {
    malformed("a1 STORE 1 (WHENEVER 7) +FLAGS (\\Seen)\r\n");
}

#[test]
fn a_uid_expunge_is_parsed_and_stripped_to_expunge() {
    let (params, stripped) = parsed("a1 UID EXPUNGE 1:3,5\r\n");
    assert_eq!(params.uid_expunge, Some(vec![(1, 3), (5, 5)]));
    assert_eq!(stripped, "a1 EXPUNGE\r\n");
    let (params, _) = parsed("a1 UID EXPUNGE *\r\n");
    assert_eq!(params.uid_expunge, Some(vec![(STAR, STAR)]));
    let (params, _) = parsed("a1 UID EXPUNGE 5:1\r\n");
    assert_eq!(params.uid_expunge, Some(vec![(1, 5)]), "any order is a set");
}

#[test]
fn a_broken_uid_expunge_is_malformed_not_an_expunge() {
    malformed("a1 UID EXPUNGE\r\n");
    malformed("a1 UID EXPUNGE 1:x\r\n");
    malformed("a1 UID EXPUNGE 1:3 extra\r\n");
}

#[test]
fn a_plain_expunge_passes_through() {
    none("a1 EXPUNGE\r\n");
}

#[test]
fn a_search_modseq_key_is_parsed_and_stripped() {
    let (params, stripped) = parsed("a1 SEARCH MODSEQ 12345\r\n");
    assert_eq!(params.search_modseq, Some(12345));
    assert_eq!(stripped, "a1 SEARCH\r\n");
    let (params, stripped) = parsed("a1 SEARCH FLAGGED MODSEQ 9 MODSEQ 5\r\n");
    assert_eq!(params.search_modseq, Some(9), "the strictest bound wins");
    assert_eq!(stripped, "a1 SEARCH FLAGGED\r\n");
    none("a1 SEARCH FLAGGED\r\n");
    none("a1 SEARCH CHARSET UTF-8 FLAGGED\r\n");
}

#[test]
fn unrecognised_commands_pass_through() {
    none("a1 LIST \"\" *\r\n");
    none("a1 STATUS INBOX (MESSAGES HIGHESTMODSEQ)\r\n");
    none("a1 APPEND INBOX (\\Seen) {35}\r\nSubject: made up\r\n\r\nbody\r\n");
    none("a1 CAPABILITY\r\n");
}

#[test]
fn lines_without_a_crlf_are_left_alone() {
    none("a1 SELECT INBOX (CONDSTORE)");
}

#[test]
fn range_helpers_agree_with_the_parser() {
    let ranges = parse_ranges(b"1:3,5", false).expect("ranges");
    assert!(ranges_contain(&ranges, 2));
    assert!(ranges_contain(&ranges, 5));
    assert!(!ranges_contain(&ranges, 4));
    assert_eq!(compress_ranges(&[1, 2, 3, 5, 7, 8]), "1:3,5,7:8");
    assert_eq!(compress_ranges(&[9]), "9");
    assert_eq!(compress_ranges(&[]), "");
    assert_eq!(
        resolve_star(&[(1, 3), (STAR, STAR)], 42),
        vec![(1, 3), (42, 42)]
    );
}

#[test]
fn the_encoders_spell_the_lines_exactly() {
    assert_eq!(
        String::from_utf8_lossy(&closed_line()),
        "* OK [CLOSED] Previous mailbox is now closed\r\n"
    );
    assert_eq!(
        String::from_utf8_lossy(&highestmodseq_line(42)),
        "* OK [HIGHESTMODSEQ 42] The highest mod-sequence value is 42\r\n"
    );
    assert_eq!(
        String::from_utf8_lossy(&vanished_line(&[2, 3, 4, 9], true)),
        "* VANISHED (EARLIER) 2:4,9\r\n"
    );
    assert_eq!(
        String::from_utf8_lossy(&vanished_line(&[7], false)),
        "* VANISHED 7\r\n",
        "the live form carries no (EARLIER)"
    );
    assert_eq!(
        String::from_utf8_lossy(&modified_ok("a1", "7,9", "Conditional STORE failed")),
        "a1 OK [MODIFIED 7,9] Conditional STORE failed\r\n"
    );
    assert_eq!(
        String::from_utf8_lossy(&appenduid_ok("a1", 5, 12, "APPEND completed")),
        "a1 OK [APPENDUID 5 12] APPEND completed\r\n"
    );
    assert_eq!(
        String::from_utf8_lossy(&copyuid_ok("a1", 5, "1:2,4", "9:10,11", "COPY completed")),
        "a1 OK [COPYUID 5 1:2,4 9:10,11] COPY completed\r\n"
    );
    assert_eq!(
        String::from_utf8_lossy(&fetch_modseq_line(3, 11, 44, "\\Seen")),
        "* 3 FETCH (UID 11 FLAGS (\\Seen) MODSEQ (44))\r\n"
    );
    assert_eq!(
        String::from_utf8_lossy(&highestmodseq_ok("a1", 42, "EXPUNGE completed")),
        "a1 OK [HIGHESTMODSEQ 42] EXPUNGE completed\r\n"
    );
}

#[test]
fn inserting_a_modseq_lands_inside_the_item_list() {
    let mut line = b"* 1 FETCH (FLAGS (\\Seen))\r\n".to_vec();
    insert_modseq(&mut line, 12);
    assert_eq!(
        String::from_utf8_lossy(&line),
        "* 1 FETCH (FLAGS (\\Seen) MODSEQ (12))\r\n"
    );
    // A literal before the close does not move the insertion point.
    let mut line = b"* 1 FETCH (BODY[] {4}\r\nbody)\r\n".to_vec();
    insert_modseq(&mut line, 3);
    assert_eq!(
        String::from_utf8_lossy(&line),
        "* 1 FETCH (BODY[] {4}\r\nbody MODSEQ (3))\r\n"
    );
    let mut line = b"* 1 FETCH (FLAGS)\r\n".to_vec();
    insert_modseq(&mut line, 1);
    assert_eq!(
        String::from_utf8_lossy(&line),
        "* 1 FETCH (FLAGS MODSEQ (1))\r\n"
    );
    let mut search = b"* SEARCH 1 2\r\n".to_vec();
    search_modseq_suffix(&mut search, 5);
    assert_eq!(
        String::from_utf8_lossy(&search),
        "* SEARCH 1 2 (MODSEQ 5)\r\n"
    );
}
