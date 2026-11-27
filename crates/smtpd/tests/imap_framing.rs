//! Literal framing: the announcement and the octets it promises.
//!
//! The payload holds `{0}` and a line that looks like a command, so a reader
//! that framed by line would answer the wrong bytes.

use std::io::Cursor;

use ayane_smtpd::imap_session::{read_command, Framed};
use imap_codec::decode::Decoder;
use imap_codec::imap_types::command::CommandBody;
use imap_codec::CommandCodec;

/// The wire bytes of `A1 APPEND INBOX {n}\r\n<n octets>\r\n`.
fn wire(payload: &[u8]) -> Vec<u8> {
    let mut out = format!("A1 APPEND INBOX {{{}}}\r\n", payload.len()).into_bytes();
    out.extend_from_slice(payload);
    out.extend_from_slice(b"\r\n");
    out
}

#[test]
fn a_literal_is_read_as_octets_not_as_a_line() {
    let payload = b"Subject: long subject\r\n\r\n{0}\r\nB4 NOOP\r\n";
    let mut cursor = Cursor::new(wire(payload));
    let framed = read_command(&mut cursor).expect("read");
    let Framed::Complete {
        bytes,
        continuations,
    } = framed
    else {
        panic!("expected a complete command, got {framed:?}");
    };
    assert_eq!(
        continuations.len(),
        1,
        "the literal is announced before it is read"
    );
    let (rest, command) = CommandCodec::default().decode(&bytes).expect("parses");
    assert!(rest.is_empty());
    let CommandBody::Append { message, .. } = command.body else {
        panic!("expected APPEND")
    };
    assert_eq!(
        message.data(),
        payload,
        "the literal is exactly what the client sent"
    );
}

#[test]
fn a_non_sync_literal_needs_no_continuation() {
    let mut cursor = Cursor::new(b"A1 APPEND INBOX {3+}\r\nabc\r\n".to_vec());
    let framed = read_command(&mut cursor).expect("read");
    let Framed::Complete { continuations, .. } = framed else {
        panic!("expected a complete command")
    };
    assert!(
        continuations.is_empty(),
        "a non-sync literal needs no permission"
    );
}

#[test]
fn a_malformed_line_is_refused_by_its_tag() {
    let mut cursor = Cursor::new(b"A9 NOTACOMMAND\r\n".to_vec());
    assert_eq!(
        read_command(&mut cursor).expect("read"),
        Framed::Refused("A9".to_owned())
    );
}

#[test]
fn a_closed_stream_is_eof() {
    let mut cursor = Cursor::new(Vec::new());
    assert_eq!(read_command(&mut cursor).expect("read"), Framed::Eof);
}

#[test]
fn a_plain_command_still_parses() {
    let mut cursor = Cursor::new(b"A1 NOOP\r\nA2 CAPABILITY\r\n".to_vec());
    let framed = read_command(&mut cursor).expect("read");
    let Framed::Complete {
        bytes,
        continuations,
    } = framed
    else {
        panic!("expected a command")
    };
    assert!(continuations.is_empty());
    assert_eq!(bytes, b"A1 NOOP\r\n", "exactly one command, not two");
    let framed = read_command(&mut cursor).expect("read");
    assert!(matches!(framed, Framed::Complete { bytes, .. } if bytes == b"A2 CAPABILITY\r\n"));
}
