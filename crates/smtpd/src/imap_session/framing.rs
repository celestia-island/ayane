//! Literal framing: one client command, read as octets rather than as lines.
//!
//! A literal is **not a line**: `{n}` plus CRLF is answered with a `+` line,
//! then exactly `n` octets are read as they come (they may hold CRLF, `{0}`, a
//! whole message). [`read_command`] stops at the announcement, because a reader
//! that reads past it has swallowed the octets the client is still waiting to
//! be asked for.

use std::io::{self, Read};

use imap_codec::{
    decode::{CommandDecodeError, Decoder},
    imap_types::core::LiteralMode,
    CommandCodec,
};

use super::{MAX_COMMAND_BYTES, MAX_LINE_BYTES};

/// What [`read_command`] produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Framed {
    /// A complete command, plus the continuation lines the caller must write
    /// *before* the client will send the rest.
    Complete {
        /// The command's bytes, exactly as the codec wants them.
        bytes: Vec<u8>,
        /// `+ …` lines, in arrival order.
        continuations: Vec<Vec<u8>>,
    },
    /// The peer closed cleanly between commands.
    Eof,
    /// The command cannot be served; the caller writes `<tag> BAD …`.
    Refused(String),
}

/// Read one client command, literals included, from `stream`.
///
/// A literal is **not a line**: `{n}\r\n` is answered with a continuation
/// (unless the client wrote `{n+}`, which needs no permission), and then
/// exactly `n` octets are taken as they come — the `\r\n` inside them are data,
/// not framing.
///
/// # Errors
///
/// Returns [`io::Error`] when the stream fails.
pub fn read_command<R: Read>(stream: &mut R) -> io::Result<Framed> {
    let mut pending: Vec<u8> = Vec::new();
    let mut continuations: Vec<Vec<u8>> = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        // A literal's announcement is what the reader must *stop at*: the
        // client is waiting for `+` and will not send the octets until it
        // arrives. So bytes are taken one at a time, and the announcement is
        // looked for the moment a CRLF completes a line — never after octets
        // that belong to the literal have already been read.
        if let Some((tag, length, mode)) = announcement(&pending) {
            if pending.len() + length as usize > MAX_COMMAND_BYTES {
                return Ok(Framed::Refused(tag));
            }
            if mode == LiteralMode::Sync {
                continuations.push(format!("+ Ready for {length} octets\r\n").into_bytes());
            }
            let mut literal = vec![0u8; length as usize];
            stream.read_exact(&mut literal)?;
            pending.extend_from_slice(&literal);
            continue;
        }
        match CommandCodec::default().decode(&pending) {
            Ok(_) => {
                return Ok(Framed::Complete {
                    bytes: pending,
                    continuations,
                })
            }
            Err(CommandDecodeError::Incomplete | CommandDecodeError::LiteralFound { .. }) => {}
            Err(CommandDecodeError::Failed) => {
                // A malformed line is skipped to its CRLF, so the next command
                // starts where the client believes a command starts.
                if let Some(end) = pending.windows(2).position(|window| window == b"\r\n") {
                    // One refusal has a second chance: the extension-parameter
                    // grammar codec 1.0 cannot frame (`SELECT … (CONDSTORE)`,
                    // `UID EXPUNGE …`). The sidecar parser strips those
                    // parameters; a line that decodes stripped **is** a
                    // command, handed on as the client wrote it.
                    if let super::ext_wire::Extraction::Parsed(_, stripped) =
                        super::ext_wire::extract(&pending)
                    {
                        if CommandCodec::default().decode(&stripped).is_ok() {
                            return Ok(Framed::Complete {
                                bytes: pending,
                                continuations,
                            });
                        }
                    }
                    return Ok(Framed::Refused(tag_of(&pending[..end])));
                }
            }
        }
        if pending.len() > MAX_LINE_BYTES {
            return Ok(Framed::Refused(tag_of(&pending)));
        }
        if stream.read(&mut byte)? == 0 {
            return Ok(Framed::Eof);
        }
        pending.push(byte[0]);
    }
}

/// The literal announcement a client is waiting on, if `pending` ends with
/// one.
///
/// An announcement is the one part of an IMAP command an **unfinished** buffer
/// can hold: the client stops there and will not send the octets until it
/// hears `+`. So the check is on the last line's end — `…{123}` or `…{123+}`,
/// with or without the announcing CRLF. A `{5}` inside literal octets is never
/// there, and `{}` with nothing in the braces is an empty flag list.
fn announcement(pending: &[u8]) -> Option<(String, u32, LiteralMode)> {
    let body = pending.strip_suffix(b"\r\n").unwrap_or(pending);
    let line = match body.iter().rposition(|byte| *byte == b'\n') {
        Some(at) => &body[at + 1..],
        None => body,
    };
    if !line.ends_with(b"}") {
        return None;
    }
    let open = line[..line.len() - 1]
        .iter()
        .rposition(|byte| *byte == b'{')?;
    // A literal follows a separator: `{}` is an empty flag list.
    if open == 0 || line[open - 1] != b' ' {
        return None;
    }
    let (digits, mode) = match line[open + 1..line.len() - 1].strip_suffix(b"+") {
        Some(digits) => (digits, LiteralMode::NonSync),
        None => (&line[open + 1..line.len() - 1], LiteralMode::Sync),
    };
    if digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) {
        return None;
    }
    Some((
        tag_of(pending),
        std::str::from_utf8(digits).ok()?.parse().ok()?,
        mode,
    ))
}

/// The announcement [`read_command`] made for these bytes, as `(tag, octets,
/// whether it is non-sync)` — exposed so a test can assert the framing
/// without a socket.
#[must_use]
pub fn announcement_of(pending: &[u8]) -> Option<(String, u32, bool)> {
    announcement(pending).map(|(tag, length, mode)| (tag, length, mode == LiteralMode::NonSync))
}

/// The tag at the front of a partial command.
fn tag_of(bytes: &[u8]) -> String {
    let end = bytes
        .iter()
        .position(|byte| *byte == b' ')
        .unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}
