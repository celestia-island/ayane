//! Command syntax: turning one received line into a [`Command`].
//!
//! Parsing is deliberately separate from the session state machine: the
//! parser only answers "is this a well-formed SMTP command", the machine
//! answers "is it legal now". Keeping them apart is what lets `BDAT` be
//! reported as a sequence error (503) in the wrong state instead of a syntax
//! error (500), which is what the spike found `mailin` gets wrong.

use crate::mailbox::{Mailbox, MailboxError};

/// One SMTP command, arguments parsed but not yet authorised.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// `HELO domain`
    Hello(String),
    /// `EHLO domain`
    Ehlo(String),
    /// `MAIL FROM:<path> [SIZE=n] [SMTPUTF8] [BODY=...]`
    Mail {
        /// The reverse-path.
        path: Mailbox,
        /// The `SIZE=` parameter, when sent.
        size: Option<u64>,
        /// The `SMTPUTF8` parameter was present.
        smtputf8: bool,
        /// A parameter this server understands but does not honour, kept so
        /// the machine can answer 555 instead of silently ignoring it.
        unsupported: Option<String>,
    },
    /// `RCPT TO:<path> [NOTIFY=...]`
    Rcpt {
        /// The forward-path.
        path: Mailbox,
        /// The first unsupported parameter, if any.
        unsupported: Option<String>,
    },
    /// `DATA`
    Data,
    /// `BDAT n [LAST]`
    Bdat {
        /// Chunk length in octets.
        size: u64,
        /// The `LAST` keyword was present.
        last: bool,
    },
    /// `RSET`
    Rset,
    /// `NOOP`
    Noop,
    /// `QUIT`
    Quit,
    /// `VRFY name`
    Vrfy(String),
    /// `STARTTLS`
    StartTls,
    /// `AUTH mechanism [initial-response]`
    Auth {
        /// The mechanism, upper-cased.
        mechanism: AuthMechanism,
        /// The optional initial response, still base64-encoded.
        initial: Option<String>,
    },
}

/// The SASL mechanisms this server implements.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMechanism {
    /// RFC 4616 PLAIN.
    Plain,
    /// The login/challenge/response pair everyone calls LOGIN.
    Login,
}

impl AuthMechanism {
    /// The wire name.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Plain => "PLAIN",
            Self::Login => "LOGIN",
        }
    }
}

/// Why a line is not a well-formed command.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ParseError {
    /// No verb at all (empty line or only blanks).
    #[error("empty command")]
    Empty,
    /// The verb is not one this server implements.
    #[error("unknown command `{0}`")]
    UnknownCommand(String),
    /// A known verb with a broken argument list.
    #[error("{0}")]
    Syntax(&'static str),
    /// An envelope path that does not parse.
    #[error("bad path: {0}")]
    Path(MailboxError),
    /// A `SIZE=` / `BDAT` argument that is not a decimal count.
    #[error("bad size argument")]
    Size,
    /// An AUTH mechanism this server does not offer.
    #[error("unsupported authentication mechanism")]
    Mechanism,
}

impl ParseError {
    /// The reply a syntax failure earns: a wrong **shape** is `500`/`501`/`504`
    /// and never `503`.
    ///
    /// The distinction is the whole point of keeping parsing apart from the
    /// state machine. `503` means "this command is real, but not now" — a
    /// sequencing answer, which is the session's to give and which a client
    /// fixes by reordering. A shape answer means the bytes themselves were
    /// wrong, and a client fixes it by rewriting the line. Answering a
    /// malformed line with `503` tells a client to reorder something it can
    /// parse, and it will retry the same bytes forever.
    ///
    /// `504` is the one middle case: the verb and its grammar are both fine,
    /// but the mechanism named is a capability this server does not have.
    ///
    /// This lives beside the error rather than in the driver because it is
    /// part of the protocol contract, not part of any transport: every driver
    /// — a socket, a test, a future LMTP front end — must answer the same
    /// way, and a mapping kept per-driver is a mapping that can drift.
    #[must_use]
    pub fn reply(&self) -> crate::session::Reply {
        let (code, enhanced, text): (u16, &'static str, String) = match self {
            Self::Empty => (500, "5.5.2", "Empty command".to_owned()),
            Self::UnknownCommand(verb) => (500, "5.5.2", format!("Command unrecognized: {verb}")),
            Self::Syntax(reason) => (501, "5.5.4", format!("Syntax error: {reason}")),
            Self::Path(reason) => (501, "5.1.3", format!("Bad path syntax: {reason}")),
            Self::Size => (501, "5.5.4", "Syntax error in size argument".to_owned()),
            Self::Mechanism => (
                504,
                "5.5.4",
                "Unrecognized authentication mechanism".to_owned(),
            ),
        };
        crate::session::Reply {
            code,
            enhanced: Some(enhanced),
            text,
            lines: Vec::new(),
            action: crate::session::Action::Continue,
        }
    }
}

/// Parses one command line (without its CRLF).
///
/// `allow_utf8` follows the `SMTPUTF8` parameter of the transaction: a
/// `MAIL FROM` itself may only carry non-ASCII octets when the client already
/// asked for SMTPUTF8, so the flag is false for `MAIL` and true for `RCPT`
/// once the transaction extended.
///
/// # Errors
///
/// Returns [`ParseError`] when the verb is unknown, the arguments are
/// malformed, or a path does not parse.
pub fn parse(line: &str, allow_utf8: bool) -> Result<Command, ParseError> {
    let line = line.trim_end_matches([' ', '\t']);
    let (verb, rest) = match line.split_once(' ') {
        Some((verb, rest)) => (verb, rest),
        None => (line, ""),
    };
    if verb.is_empty() {
        return Err(ParseError::Empty);
    }
    match verb.to_ascii_uppercase().as_str() {
        "HELO" => Ok(Command::Hello(domain_argument(rest)?)),
        "EHLO" => Ok(Command::Ehlo(domain_argument(rest)?)),
        "MAIL" => parse_mail(rest),
        "RCPT" => parse_rcpt(rest, allow_utf8),
        "DATA" => {
            ensure_no_argument(rest)?;
            Ok(Command::Data)
        }
        "BDAT" => parse_bdat(rest),
        "RSET" => {
            ensure_no_argument(rest)?;
            Ok(Command::Rset)
        }
        "NOOP" => {
            // RFC 5321 lets NOOP carry an arbitrary string; ignore it.
            Ok(Command::Noop)
        }
        "QUIT" => {
            ensure_no_argument(rest)?;
            Ok(Command::Quit)
        }
        "VRFY" => {
            let name = rest.trim();
            if name.is_empty() || name.len() > 256 {
                return Err(ParseError::Syntax("VRFY needs a name"));
            }
            if name.chars().any(char::is_control) {
                return Err(ParseError::Syntax("VRFY name has a control character"));
            }
            Ok(Command::Vrfy(name.to_owned()))
        }
        "STARTTLS" => {
            ensure_no_argument(rest)?;
            Ok(Command::StartTls)
        }
        "AUTH" => parse_auth(rest),
        other => Err(ParseError::UnknownCommand(other.to_owned())),
    }
}

fn ensure_no_argument(rest: &str) -> Result<(), ParseError> {
    if rest.trim().is_empty() {
        Ok(())
    } else {
        Err(ParseError::Syntax("command takes no argument"))
    }
}

fn domain_argument(rest: &str) -> Result<String, ParseError> {
    let domain = rest.trim();
    if domain.is_empty() || domain.len() > 255 {
        return Err(ParseError::Syntax("HELO/EHLO needs a domain"));
    }
    if domain.chars().any(char::is_control)
        || domain.contains(' ')
        || domain.contains('@')
        || domain.contains('<')
    {
        return Err(ParseError::Syntax("HELO/EHLO domain is malformed"));
    }
    Ok(domain.to_owned())
}

fn parse_mail(rest: &str) -> Result<Command, ParseError> {
    let rest = rest.trim_start();
    let rest = rest
        .get(..4)
        .filter(|prefix| prefix.eq_ignore_ascii_case("FROM"))
        .map(|_| rest.get(4..).unwrap_or_default().trim_start())
        .ok_or(ParseError::Syntax("MAIL needs FROM:"))?;
    let rest = match rest.strip_prefix(':') {
        Some(rest) => rest.trim_start(),
        None => return Err(ParseError::Syntax("MAIL FROM needs a colon")),
    };
    let (path_text, params) = split_path(rest)?;
    // A non-ASCII reverse-path is admitted when the client announced
    // SMTPUTF8 on this very line (RFC 6531 §3.7); `parse` always sees the
    // ASCII alphabet first, so the flag is what widens it.
    let announced_utf8 = params
        .iter()
        .any(|param| param.eq_ignore_ascii_case("SMTPUTF8"));
    let path = Mailbox::parse(path_text, announced_utf8).map_err(ParseError::Path)?;
    let mut size = None;
    let mut smtputf8 = false;
    let mut unsupported = None;
    for param in params {
        if let Some(value) = key_value(&param, "SIZE") {
            if size.is_some() {
                return Err(ParseError::Syntax("duplicate SIZE parameter"));
            }
            size = Some(value.parse::<u64>().map_err(|_| ParseError::Size)?);
        } else if param.eq_ignore_ascii_case("SMTPUTF8") {
            smtputf8 = true;
        } else if key_value(&param, "BODY").is_some() {
            // 8BITMIME is advertised, so BODY=7BIT/8BITMIME is accepted and
            // needs no further action: the spool stores the octets as given.
        } else if unsupported.is_none() {
            unsupported = Some(param);
        }
    }
    Ok(Command::Mail {
        path,
        size,
        smtputf8,
        unsupported,
    })
}

fn parse_rcpt(rest: &str, allow_utf8: bool) -> Result<Command, ParseError> {
    let rest = rest.trim_start();
    let rest = rest
        .get(..2)
        .filter(|prefix| prefix.eq_ignore_ascii_case("TO"))
        .map(|_| rest.get(2..).unwrap_or_default().trim_start())
        .ok_or(ParseError::Syntax("RCPT needs TO:"))?;
    let rest = match rest.strip_prefix(':') {
        Some(rest) => rest.trim_start(),
        None => return Err(ParseError::Syntax("RCPT TO needs a colon")),
    };
    let (path_text, params) = split_path(rest)?;
    let path = Mailbox::parse(path_text, allow_utf8).map_err(ParseError::Path)?;
    let unsupported = params.into_iter().next();
    Ok(Command::Rcpt { path, unsupported })
}

fn parse_bdat(rest: &str) -> Result<Command, ParseError> {
    let mut parts = rest.split_whitespace();
    let size = parts
        .next()
        .ok_or(ParseError::Syntax("BDAT needs a size"))?
        .parse::<u64>()
        .map_err(|_| ParseError::Size)?;
    let mut last = false;
    for part in parts {
        if part.eq_ignore_ascii_case("LAST") {
            last = true;
        } else {
            return Err(ParseError::Syntax("BDAT takes only LAST"));
        }
    }
    Ok(Command::Bdat { size, last })
}

fn parse_auth(rest: &str) -> Result<Command, ParseError> {
    let mut parts = rest.split_whitespace();
    let mechanism = match parts.next() {
        Some(name) if name.eq_ignore_ascii_case("PLAIN") => AuthMechanism::Plain,
        Some(name) if name.eq_ignore_ascii_case("LOGIN") => AuthMechanism::Login,
        Some(_) => return Err(ParseError::Mechanism),
        None => return Err(ParseError::Syntax("AUTH needs a mechanism")),
    };
    let initial = parts.next().map(str::to_owned);
    if parts.next().is_some() {
        return Err(ParseError::Syntax("AUTH takes one mechanism"));
    }
    Ok(Command::Auth { mechanism, initial })
}

/// Splits `<path> [param param ...]` into the path text and the parameters.
///
/// The path is angle-bracketed on the wire. A bare address is tolerated (some
/// appliances omit the brackets) and then runs to the first blank.
fn split_path(rest: &str) -> Result<(&str, Vec<String>), ParseError> {
    if let Some(inner) = rest.strip_prefix('<') {
        // The path runs to the first `>`; a parameter may follow it.
        let close = inner
            .find('>')
            .ok_or(ParseError::Syntax("unterminated path"))?;
        let path = &inner[..close];
        let tail: String = inner[close + 1..]
            .chars()
            .filter(|ch| !ch.is_control())
            .collect();
        let params = tail.split_whitespace().map(str::to_owned).collect();
        Ok((path, params))
    } else {
        let (path, tail) = rest.split_once(' ').unwrap_or((rest, ""));
        let params = tail.split_whitespace().map(str::to_owned).collect();
        Ok((path, params))
    }
}

fn key_value<'a>(param: &'a str, key: &str) -> Option<&'a str> {
    let (name, value) = param.split_once('=')?;
    name.eq_ignore_ascii_case(key).then_some(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(line: &str) -> Command {
        parse(line, false).expect("fixture command")
    }

    #[test]
    fn verbs_parse_case_insensitively() {
        assert_eq!(ok("HELO client.test"), Command::Hello("client.test".into()));
        assert_eq!(ok("ehlo Client.Test"), Command::Ehlo("Client.Test".into()));
        assert_eq!(ok("NOOP"), Command::Noop);
        assert_eq!(ok("noop some text"), Command::Noop);
        assert_eq!(ok("RSET"), Command::Rset);
        assert_eq!(ok("QUIT"), Command::Quit);
    }

    #[test]
    fn mail_carries_size_and_smtputf8() {
        assert_eq!(
            ok("MAIL FROM:<a@b.example> SIZE=1234 SMTPUTF8 BODY=8BITMIME"),
            Command::Mail {
                path: Mailbox::parse("a@b.example", false).unwrap(),
                size: Some(1234),
                smtputf8: true,
                unsupported: None,
            }
        );
    }

    #[test]
    fn mail_null_path_and_unknown_parameter() {
        match ok("MAIL FROM:<> RET=HDRS") {
            Command::Mail {
                path, unsupported, ..
            } => {
                assert_eq!(path, Mailbox::Null);
                assert_eq!(unsupported.as_deref(), Some("RET=HDRS"));
            }
            other => panic!("expected MAIL, got {other:?}"),
        }
    }

    #[test]
    fn broken_arguments_are_syntax_errors() {
        assert_eq!(parse("", false), Err(ParseError::Empty));
        assert_eq!(
            parse("MAIL <a@b>", false),
            Err(ParseError::Syntax("MAIL needs FROM:"))
        );
        assert_eq!(
            parse("RCPT TO", false),
            Err(ParseError::Syntax("RCPT TO needs a colon"))
        );
        // A bare address without brackets is taken as sent (some appliances
        // omit them); only its content rules apply.
        assert!(parse("RCPT TO:a@b", false).is_ok());
        assert_eq!(
            parse("MAIL FROM:<a@b", false),
            Err(ParseError::Syntax("unterminated path"))
        );
        assert_eq!(
            parse("MAIL FROM:<a@b> SIZE=x", false),
            Err(ParseError::Size)
        );
        assert_eq!(
            parse("DATA now", false),
            Err(ParseError::Syntax("command takes no argument"))
        );
        assert_eq!(
            parse("EHLO a@b", false),
            Err(ParseError::Syntax("HELO/EHLO domain is malformed"))
        );
    }

    #[test]
    fn unknown_verbs_are_named() {
        assert_eq!(
            parse("EXPN list", false),
            Err(ParseError::UnknownCommand("EXPN".into()))
        );
    }

    #[test]
    fn bdat_takes_a_size_and_last() {
        assert_eq!(
            ok("BDAT 100"),
            Command::Bdat {
                size: 100,
                last: false
            }
        );
        assert_eq!(
            ok("BDAT 0 LAST"),
            Command::Bdat {
                size: 0,
                last: true
            }
        );
        assert_eq!(
            parse("BDAT 1 EXTRA", false),
            Err(ParseError::Syntax("BDAT takes only LAST"))
        );
    }

    #[test]
    fn auth_mechanisms_are_known() {
        assert_eq!(
            ok("AUTH PLAIN AGhvbG8AcHc="),
            Command::Auth {
                mechanism: AuthMechanism::Plain,
                initial: Some("AGhvbG8AcHc=".into()),
            }
        );
        assert_eq!(
            ok("auth login"),
            Command::Auth {
                mechanism: AuthMechanism::Login,
                initial: None,
            }
        );
        assert_eq!(parse("AUTH CRAM-MD5", false), Err(ParseError::Mechanism));
    }

    #[test]
    fn rcpt_accepts_utf8_only_when_extended() {
        assert_eq!(
            parse("RCPT TO:<用户@例子.测试>", false),
            Err(ParseError::Path(MailboxError::NoUtf8))
        );
        assert!(parse("RCPT TO:<用户@例子.测试>", true).is_ok());
        // A MAIL path always parses under the ASCII alphabet: the SMTPUTF8
        // parameter arrives in the same line, so the state machine admits a
        // UTF-8 reverse-path only after it has read that flag.
        match parse("MAIL FROM:<用户@例子.测试> SMTPUTF8", false) {
            Ok(Command::Mail { smtputf8, path, .. }) => {
                assert!(smtputf8);
                assert!(matches!(path, Mailbox::Address { utf8: true, .. }));
            }
            other => panic!("expected a SMTPUTF8 MAIL, got {other:?}"),
        }
    }
}
