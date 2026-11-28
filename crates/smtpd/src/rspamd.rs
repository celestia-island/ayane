//! The rspamd content scan: the one HTTP call the engine makes to a third
//! party, and the mapping from its answer to a transaction decision.
//!
//! The integration shape comes from the repository's own rule that a third
//! party is a network peer — never a linked library. rspamd's normal worker
//! speaks HTTP, so the whole conversation is one `POST /scan` whose body is
//! the message exactly as received (streamed out of the staged spool file,
//! never held in memory), plus one JSON answer whose `action` decides what
//! the transaction's final reply is.
//!
//! # What this module decides, and what it deliberately does not
//!
//! [`RspamdClient::scan`] turns a response into a [`ScanOutcome`]; the
//! driver ( [`crate::server`] ) turns the outcome into a reply line and a
//! queue action. The split is the crate's usual one: this layer computes,
//! that layer refuses.
//!
//! # Failure is fail-open, on purpose
//!
//! An unreachable, slow, or unintelligible scanner must not decide whether
//! mail flows: the SPF/DKIM/DMARC verdicts ([`crate::verify`]) run in this
//! process and do not depend on rspamd, so a dead scanner only loses the
//! content score — a [`ScanOutcome::Failed`] is counted
//! ([`crate::metrics::Counter::SpamScanErrors`]), logged at warn, and the
//! message continues as if no scan had run. The `451` codes are reserved
//! for the scanner's *own* explicit `soft reject` / `greylist` actions, so
//! a scanner restart cannot roll into a site-wide retry storm.

use std::fmt;
use std::net::IpAddr;
use std::path::Path;
use std::time::Duration;

use tokio_util::io::ReaderStream;

/// The connection-establishment timeout. The scanner sits on the same host
/// or bridge; a connect that takes longer is a dead service, and waiting
/// longer only holds the sender's `DATA`-end open.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(1);

/// The port a normal worker listens on when the URL names none.
const DEFAULT_PORT: u16 = 11333;

/// The path scanned when the URL names none.
const DEFAULT_PATH: &str = "/scan";

/// How many symbol names at most go into the rendered `tests=` list.
const MAX_TESTS: usize = 20;

/// How many bytes at most the rendered `tests=` list may span.
const MAX_TESTS_BYTES: usize = 500;

/// How many bytes at most a borrowed `smtp_message` may span as an SMTP
/// reply line's text.
const MAX_SMTP_MESSAGE_BYTES: usize = 200;

/// The actions rspamd's classic schema returns.
///
/// The six short phrases are the documented set; `quarantine` and `discard`
/// were added in rspamd 1.9. An answer whose `action` is none of these is
/// [`ScanOutcome::UnknownAction`] — never silently accepted and never
/// silently rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RspamdAction {
    /// Nothing flagged; deliver.
    NoAction,
    /// Temporarily refuse so the sender retries (greylisting modules).
    Greylist,
    /// Flag the message with a header; deliver.
    AddHeader,
    /// Flag the message by rewriting its subject; delivered as `add header`
    /// here — the engine only ever prepends (see [`SpamVerdict`]).
    RewriteSubject,
    /// Temporarily refuse ("try again later").
    SoftReject,
    /// Permanently refuse.
    Reject,
    /// Flag and quarantine; delivered as `add header` here (the routing
    /// snapshot owns the quarantine decision at delivery time).
    Quarantine,
    /// Accept then silently drop; mapped to [`RspamdAction::Reject`] here —
    /// answering `250` and then discarding would be the engine losing an
    /// accepted message, which is the one thing the queue must never do.
    Discard,
}

impl RspamdAction {
    /// The action string rspamd sends, as the fixed enum renders it back.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NoAction => "no action",
            Self::Greylist => "greylist",
            Self::AddHeader => "add header",
            Self::RewriteSubject => "rewrite subject",
            Self::SoftReject => "soft reject",
            Self::Reject => "reject",
            Self::Quarantine => "quarantine",
            Self::Discard => "discard",
        }
    }

    /// Parses an answer's `action` string. Exact phrases: the schema is a
    /// protocol, and tolerating near-misses here would render an operator's
    /// typo in the scanner's configuration invisible.
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "no action" => Some(Self::NoAction),
            "greylist" => Some(Self::Greylist),
            "add header" => Some(Self::AddHeader),
            "rewrite subject" => Some(Self::RewriteSubject),
            "soft reject" => Some(Self::SoftReject),
            "reject" => Some(Self::Reject),
            "quarantine" => Some(Self::Quarantine),
            "discard" => Some(Self::Discard),
            _ => None,
        }
    }

    /// Whether the message is flagged: the rendered `X-Spam-Status` says
    /// `Yes` for exactly these, `No` for [`RspamdAction::NoAction`]. The
    /// refusal actions never reach the header renderer — their messages are
    /// abandoned, not queued.
    #[must_use]
    pub fn marks_spam(self) -> bool {
        matches!(
            self,
            Self::AddHeader | Self::RewriteSubject | Self::Quarantine
        )
    }

    /// Whether the transaction continues to the queue (`true`) or is refused
    /// with the policy's own reply (`false`).
    #[must_use]
    pub fn continues(self) -> bool {
        !matches!(
            self,
            Self::Reject | Self::Discard | Self::SoftReject | Self::Greylist
        )
    }
}

impl fmt::Display for RspamdAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One scan's decision: the action plus the numbers the rendered status
/// header quotes.
#[derive(Debug, Clone, PartialEq)]
pub struct SpamVerdict {
    /// What rspamd decided.
    pub action: RspamdAction,
    /// The message's score (`0` when the answer omitted it).
    pub score: f64,
    /// The score that would have been required (`0` when omitted).
    pub required_score: f64,
    /// The symbol names that fired, capped at [`MAX_TESTS`] names and
    /// [`MAX_TESTS_BYTES`] for the header. Only names: a symbol's `options`
    /// are arbitrary scanner text and never leave this module.
    pub tests: Vec<String>,
    /// The scanner's suggestion for the SMTP reply text (`messages.smtp_
    /// message`), taken only for a refusal and sanitized before use.
    pub smtp_message: Option<String>,
}

/// What one scan ended with.
#[derive(Debug, Clone, PartialEq)]
pub enum ScanOutcome {
    /// The scanner answered with a known action.
    Action(SpamVerdict),
    /// The scanner answered but the `action` was missing or unrecognized:
    /// the conservative mapping (add the header, deliver) plus an error
    /// count, so a scanner that grows a new action is visible instead of
    /// silently opening the gate.
    UnknownAction(SpamVerdict, String),
    /// The scan could not be completed — unreachable, timed out, non-200,
    /// or an unparseable answer. The message continues unscanned.
    Failed(ScanError),
}

/// Why a scan produced no verdict.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ScanError {
    /// The scanner's port refused the connection or the connection broke.
    #[error("rspamd unreachable: {0}")]
    Unreachable(String),
    /// The scan ran past the configured total timeout.
    #[error("rspamd scan timed out")]
    TimedOut,
    /// The scanner answered with a non-200 status.
    #[error("rspamd answered HTTP {0}")]
    Status(u16),
    /// The answer was not the JSON shape this client reads.
    #[error("rspamd answer is not a readable scan result: {0}")]
    Response(String),
}

/// Why a configured scan endpoint is not usable.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RspamdUrlError {
    /// The URL is not a plain `http://` endpoint (https, another scheme, or
    /// no scheme at all): the scan rides a loopback or bridge in plain text,
    /// and a TLS-facing endpoint is a different deployment decision.
    #[error("not a plain `http://host[:port][/path]` URL")]
    NotHttp,
    /// The authority part is empty, carries credentials, or the host has
    /// characters no host can have.
    #[error("the authority is not a `host[:port]` pair")]
    Authority,
    /// The port is not a `u16`.
    #[error("the port is not a port number")]
    Port,
}

/// Where a scan request goes: an authority and a path parsed out of the
/// configured URL. Only what the client needs — no scheme field, because
/// only `http` parses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    /// The authority exactly as configured (`127.0.0.1:11333`), minus any
    /// credentials (rejected) — re-rendered into the request URL.
    authority: String,
    /// The request path (`/scan` by default).
    path: String,
}

impl Endpoint {
    /// The full request URL.
    fn url(&self) -> String {
        format!("http://{}{}", self.authority, self.path)
    }
}

/// Parses a scan endpoint out of a configured URL: `http://host[:port][/path]`.
///
/// A missing port means the normal worker's standard one ([`DEFAULT_PORT`]),
/// and a missing path means [`DEFAULT_PATH`] — the two defaults a scan URL
/// is about, so `http://127.0.0.1` scans the same place as the spelled-out
/// form. Everything else (userinfo, other schemes, an unparsable port) is a
/// configuration error: a silently misparsed filter endpoint is a filter
/// that quietly scans nothing.
pub fn parse_endpoint(raw: &str) -> Result<Endpoint, RspamdUrlError> {
    let rest = raw.strip_prefix("http://").ok_or(RspamdUrlError::NotHttp)?;
    let (authority, path) = match rest.split_once('/') {
        Some((authority, path)) => (authority, format!("/{path}")),
        None => (rest, DEFAULT_PATH.to_owned()),
    };
    if authority.contains(['@', '?', '#', '/']) {
        return Err(RspamdUrlError::Authority);
    }
    // A bracketed IPv6 literal keeps its brackets through the authority (the
    // request URL needs them back); the port rides outside them.
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) if !host.is_empty() => (host, Some(port)),
        _ => (authority, None),
    };
    let mut ipv6 = false;
    if host.starts_with('[') {
        if !(host.ends_with(']') && host.len() > 2) {
            return Err(RspamdUrlError::Authority);
        }
        ipv6 = true;
    } else if host.is_empty() {
        return Err(RspamdUrlError::Authority);
    }
    // A host is letters, digits and the punctuation names use — anything
    // else (spaces, controls) is not a name this client will put on a
    // request line.
    let host_characters = host.trim_matches(['[', ']']);
    let host_legal = !host_characters.is_empty()
        && host_characters.chars().all(|character| {
            character.is_ascii_alphanumeric()
                || matches!(character, '.' | '-' | '_')
                || (character == ':' && ipv6)
        });
    if !host_legal {
        return Err(RspamdUrlError::Authority);
    }
    if port.is_some_and(|port| port.parse::<u16>().is_err()) {
        return Err(RspamdUrlError::Port);
    }
    // A URL that names no port scans the normal worker's standard one.
    let authority = if port.is_some() {
        authority.to_owned()
    } else {
        format!("{authority}:{DEFAULT_PORT}")
    };
    Ok(Endpoint { authority, path })
}

/// Everything a scan needs that is not the message itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanRequest<'a> {
    /// The spool id this message will carry (`Queue-Id`).
    pub queue_id: &'a str,
    /// The reverse-path address (`From`; empty for the null sender).
    pub from: &'a str,
    /// The accepted recipients, one `Rcpt` header each.
    pub recipients: &'a [String],
    /// The connecting client's address (`IP`).
    pub ip: IpAddr,
    /// The EHLO/HELO name (`Helo`, and `Hostname`, which the engine does not
    /// resolve separately).
    pub helo: &'a str,
}

/// A client for one configured scan endpoint. Small and `Clone`: every
/// listener copy holds one, and only an inbound listener gets one.
///
/// The [`reqwest::Client`] inside is an `Arc` — cloning this type copies the
/// handle, not a connection pool. The configured password is held here and
/// kept out of the `Debug` output, exactly like every other credential-ish
/// field in this crate.
#[derive(Clone)]
pub struct RspamdClient {
    http: reqwest::Client,
    endpoint: Endpoint,
    timeout: Duration,
    password: Option<String>,
}

impl fmt::Debug for RspamdClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RspamdClient")
            .field("url", &self.endpoint.url())
            .field("timeout", &self.timeout)
            .field("password", &self.password.is_some())
            .finish()
    }
}

impl RspamdClient {
    /// Parses a configured endpoint into a client.
    ///
    /// # Errors
    ///
    /// Returns [`RspamdUrlError`] when the URL is not a plain `http://`
    /// endpoint, or [`RspamdUrlError::Port`] when its port is not a port —
    /// the same class of startup-time refusal a malformed listener line is.
    pub fn parse(
        raw: &str,
        timeout: Duration,
        password: Option<String>,
    ) -> Result<Self, RspamdUrlError> {
        let endpoint = parse_endpoint(raw)?;
        let http = reqwest::Client::builder()
            .connect_timeout(CONNECT_TIMEOUT)
            .build()
            .map_err(|err| {
                tracing::warn!(%err, "the HTTP client for rspamd could not be built");
                RspamdUrlError::NotHttp
            })?;
        Ok(Self {
            http,
            endpoint,
            timeout,
            password,
        })
    }

    /// Scans the message staged at `path` (`size` octets, exactly as
    /// received) and reports what the scanner said.
    ///
    /// The body is streamed out of the file in fixed chunks, so a message
    /// never lives in memory because of the scan. One attempt, no retry: the
    /// sender is waiting at the `DATA`-end, and [`ScanOutcome::Failed`] is
    /// already the safe exit.
    pub async fn scan(&self, path: &Path, size: u64, request: ScanRequest<'_>) -> ScanOutcome {
        let file = match tokio::fs::File::open(path).await {
            Ok(file) => file,
            Err(err) => {
                return ScanOutcome::Failed(ScanError::Unreachable(format!(
                    "staged message unreadable: {err}"
                )));
            }
        };
        let mut builder = self
            .http
            .post(self.endpoint.url())
            // The message length is known exactly (it is the staged file's
            // size), and saying so lets the scanner read a bounded body
            // instead of decoding chunks. hyper respects an explicitly set
            // `Content-Length` over its own chunked framing.
            .header("Content-Length", size)
            .header("From", header_value(request.from))
            .header("Pass", "all")
            .header("Ip", request.ip.to_string())
            .header("Helo", header_value(request.helo))
            .header("Hostname", header_value(request.helo))
            .header("Queue-Id", header_value(request.queue_id));
        for recipient in request.recipients {
            builder = builder.header("Rcpt", header_value(recipient));
        }
        if let Some(password) = &self.password {
            builder = builder.header("Password", header_value(password));
        }
        builder = builder
            .timeout(self.timeout)
            .body(reqwest::Body::wrap_stream(ReaderStream::new(file)));
        let response = match builder.send().await {
            Ok(response) => response,
            Err(err) => {
                if err.is_timeout() {
                    return ScanOutcome::Failed(ScanError::TimedOut);
                }
                let detail = err
                    .status()
                    .map_or_else(|| err.to_string(), |status| format!("HTTP {status}"));
                return ScanOutcome::Failed(ScanError::Unreachable(detail));
            }
        };
        let status = response.status();
        if status != reqwest::StatusCode::OK {
            return ScanOutcome::Failed(ScanError::Status(status.as_u16()));
        }
        let body = match response.text().await {
            Ok(body) => body,
            Err(err) => return ScanOutcome::Failed(ScanError::Response(err.to_string())),
        };
        classify(&body)
    }
}

/// Turns a scan answer's text into an outcome. Sync and pure, so the JSON
/// shapes a scanner can send are testable without a socket.
#[must_use]
pub fn classify(body: &str) -> ScanOutcome {
    let answer: Answer = match serde_json::from_str(body) {
        Ok(answer) => answer,
        Err(err) => return ScanOutcome::Failed(ScanError::Response(err.to_string())),
    };
    let mut tests = answer
        .symbols
        .map(|symbols| symbols.keys().cloned().collect::<Vec<_>>())
        .unwrap_or_default();
    // Sorted, so the rendered header is a function of the *set* of symbols
    // and not of the order the scanner happened to serialize them in.
    tests.sort();
    tests.dedup();
    let smtp_message = answer.messages.and_then(|messages| messages.smtp_message);
    let verdict = SpamVerdict {
        score: answer.score.unwrap_or(0.0),
        required_score: answer.required_score.unwrap_or(0.0),
        tests,
        smtp_message,
        // Filled in below, once the action is known.
        action: RspamdAction::NoAction,
    };
    let Some(raw) = answer.action.as_deref() else {
        return ScanOutcome::UnknownAction(
            SpamVerdict {
                action: RspamdAction::AddHeader,
                ..verdict
            },
            "missing".to_owned(),
        );
    };
    match RspamdAction::parse(raw) {
        Some(action) => ScanOutcome::Action(SpamVerdict { action, ..verdict }),
        None => ScanOutcome::UnknownAction(
            SpamVerdict {
                action: RspamdAction::AddHeader,
                ..verdict
            },
            raw.to_owned(),
        ),
    }
}

/// The classic scan-answer schema, tolerant of everything it may omit.
#[derive(Debug, serde::Deserialize)]
struct Answer {
    /// What the scanner decided.
    action: Option<String>,
    /// The message's score.
    score: Option<f64>,
    /// The score that would have flagged it.
    required_score: Option<f64>,
    /// The fired symbols, by name. Their payloads (scores, and `options`
    /// with whatever text the modules put there) are deliberately not read:
    /// the names are the only part that reaches a header.
    symbols: Option<serde_json::Map<String, serde_json::Value>>,
    /// Free-form message texts the scanner suggests; only `smtp_message` is
    /// read, and only for a refusal.
    messages: Option<Messages>,
}

#[derive(Debug, serde::Deserialize)]
struct Messages {
    smtp_message: Option<String>,
}

/// Renders the `X-Spam-Status` field the queue prepends for a scanned,
/// accepted message. `Yes` for exactly the flagged actions, `No` for `no
/// action`; the numbers and the capped symbol-name list are the only
/// scanner-derived content, and the `action=` phrase comes from the fixed
/// enum — a scanner's free text (symbol options included) cannot reach the
/// header through here.
#[must_use]
pub fn spam_status_header(verdict: &SpamVerdict) -> Vec<u8> {
    let status = if verdict.action.marks_spam() {
        "Yes"
    } else {
        "No"
    };
    let mut tests = String::new();
    for (index, name) in verdict.tests.iter().enumerate() {
        if index >= MAX_TESTS || tests.len() + name.len() > MAX_TESTS_BYTES {
            break;
        }
        if index > 0 {
            tests.push(',');
        }
        tests.push_str(name);
    }
    format!(
        "X-Spam-Status: {}, score={:.1}, required={:.1}, tests={}, action={}\r\n",
        status,
        verdict.score,
        verdict.required_score,
        tests,
        verdict.action.as_str(),
    )
    .into_bytes()
}

/// Sanitizes a scanner-suggested SMTP reply text: one line, printable, at
/// most [`MAX_SMTP_MESSAGE_BYTES`] bytes. `None` when nothing usable is
/// left, so the caller falls back to its fixed wording.
#[must_use]
pub fn sanitize_smtp_message(raw: &str) -> Option<String> {
    let mut line = String::with_capacity(raw.len().min(MAX_SMTP_MESSAGE_BYTES));
    for character in raw.chars() {
        if character.is_ascii_graphic() || character == ' ' {
            line.push(character);
        } else {
            // Anything else — CR, LF, controls, non-ASCII — is dropped: an
            // SMTP reply line is one line of visible text.
            line.push(' ');
        }
    }
    let line = line.trim();
    if line.is_empty() {
        return None;
    }
    let mut end = line.len().min(MAX_SMTP_MESSAGE_BYTES);
    while !line.is_char_boundary(end) {
        end -= 1;
    }
    Some(line[..end].to_owned())
}

/// Reduces a header value to what an HTTP header may carry: printable ASCII
/// only. Envelope text (paths, the HELO name) has already passed the SMTP
/// parser, but a byte outside the printable range would make the request
/// fail at the header layer — the scan degrades instead, which is the wrong
/// failure for a value one sanitized copy would have carried fine.
fn header_value(raw: &str) -> String {
    let sanitized: String = raw
        .chars()
        .filter(|character| character.is_ascii_graphic())
        .collect();
    if sanitized.is_empty() {
        "unknown".to_owned()
    } else {
        sanitized
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_loopback_scan_url_parses_to_its_parts() {
        let endpoint = parse_endpoint("http://127.0.0.1:11333/scan").expect("parses");
        assert_eq!(endpoint.authority, "127.0.0.1:11333");
        assert_eq!(endpoint.path, "/scan");
        assert_eq!(endpoint.url(), "http://127.0.0.1:11333/scan");
    }

    #[test]
    fn missing_port_and_path_fall_to_the_scan_defaults() {
        let endpoint = parse_endpoint("http://rspamd").expect("parses");
        assert_eq!(endpoint.authority, "rspamd:11333");
        assert_eq!(endpoint.path, DEFAULT_PATH);
        assert_eq!(endpoint.url(), "http://rspamd:11333/scan");
    }

    #[test]
    fn an_ipv6_loopback_literal_parses_with_brackets_intact() {
        let endpoint = parse_endpoint("http://[::1]:11333/scan").expect("parses");
        assert_eq!(endpoint.url(), "http://[::1]:11333/scan");
    }

    #[test]
    fn urls_that_are_not_plain_http_scan_endpoints_are_refused() {
        for raw in [
            "",
            "https://127.0.0.1:11333/scan",
            "ftp://127.0.0.1/scan",
            "127.0.0.1:11333",
            "http://",
            "http://user:pass@127.0.0.1:11333",
            "http://127.0.0.1:scan",
            "http://127.0.0.1:99999",
            "http://[::1:11333",
            "http://host /scan",
        ] {
            assert!(
                parse_endpoint(raw).is_err(),
                "`{raw}` must be refused, not guessed at"
            );
        }
    }

    #[test]
    fn every_documented_action_parses_and_round_trips() {
        for raw in [
            "no action",
            "greylist",
            "add header",
            "rewrite subject",
            "soft reject",
            "reject",
            "quarantine",
            "discard",
        ] {
            let action = RspamdAction::parse(raw).unwrap_or_else(|| panic!("{raw}"));
            assert_eq!(action.as_str(), raw);
        }
        assert_eq!(RspamdAction::parse("reject "), None, "exact phrases only");
        assert_eq!(RspamdAction::parse("tempfail"), None);
    }

    #[test]
    fn flagged_actions_mark_spam_and_refusals_do_not_continue() {
        assert!(RspamdAction::AddHeader.marks_spam());
        assert!(RspamdAction::RewriteSubject.marks_spam());
        assert!(RspamdAction::Quarantine.marks_spam());
        assert!(!RspamdAction::NoAction.marks_spam());
        for action in [
            RspamdAction::Reject,
            RspamdAction::Discard,
            RspamdAction::SoftReject,
            RspamdAction::Greylist,
        ] {
            assert!(!action.continues(), "{action} refuses the message");
        }
        for action in [
            RspamdAction::NoAction,
            RspamdAction::AddHeader,
            RspamdAction::RewriteSubject,
            RspamdAction::Quarantine,
        ] {
            assert!(action.continues(), "{action} delivers");
        }
    }

    #[test]
    fn a_full_answer_classifies_to_its_action_and_numbers() {
        let body = r#"{
            "score": 12.3,
            "required_score": 6.0,
            "action": "add header",
            "symbols": {
                "GTUBE": {"name": "GTUBE", "score": 10.0,
                          "options": ["option text must never leak"]},
                "FREEMAIL_FROM": {"name": "FREEMAIL_FROM", "score": 0.5}
            },
            "message-id": "x@y",
            "messages": {"smtp_message": "rejected"}
        }"#;
        let ScanOutcome::Action(verdict) = classify(body) else {
            panic!("a full answer classifies: {body}");
        };
        assert_eq!(verdict.action, RspamdAction::AddHeader);
        assert!((verdict.score - 12.3).abs() < f64::EPSILON);
        assert!((verdict.required_score - 6.0).abs() < f64::EPSILON);
        assert_eq!(verdict.tests, vec!["FREEMAIL_FROM", "GTUBE"]);
        assert_eq!(verdict.smtp_message.as_deref(), Some("rejected"));
    }

    #[test]
    fn an_answer_is_read_with_every_optional_field_missing() {
        let ScanOutcome::UnknownAction(verdict, raw) = classify("{}") else {
            panic!("an empty object is still an answer, an unknown one");
        };
        assert_eq!(raw, "missing");
        assert_eq!(
            verdict.action,
            RspamdAction::AddHeader,
            "missing is unknown"
        );
        assert_eq!(verdict.score, 0.0);
        assert_eq!(verdict.required_score, 0.0);
        assert!(verdict.tests.is_empty());
        assert_eq!(verdict.smtp_message, None);
        assert!(matches!(
            classify("not json at all"),
            ScanOutcome::Failed(_)
        ));
    }

    #[test]
    fn an_unknown_action_is_conservative_and_names_what_arrived() {
        let ScanOutcome::UnknownAction(verdict, raw) = classify(r#"{"action":"new thing"}"#) else {
            panic!("an unknown action must classify as unknown");
        };
        assert_eq!(verdict.action, RspamdAction::AddHeader, "conservative");
        assert_eq!(raw, "new thing");
    }

    #[test]
    fn the_status_header_carries_numbers_and_names_only() {
        let verdict = SpamVerdict {
            action: RspamdAction::AddHeader,
            score: 12.3,
            required_score: 6.0,
            tests: vec!["GTUBE".to_owned(), "FREEMAIL_FROM".to_owned()],
            smtp_message: None,
        };
        let header = String::from_utf8(spam_status_header(&verdict)).expect("header");
        // `classify` sorts the names; the renderer keeps the order it is
        // given, which is what makes it a pure function of its input.
        assert_eq!(
            header,
            "X-Spam-Status: Yes, score=12.3, required=6.0, \
             tests=GTUBE,FREEMAIL_FROM, action=add header\r\n"
        );
        assert!(!header.contains("option text"), "options never enter");
    }

    #[test]
    fn a_clean_answer_renders_the_no_status() {
        let verdict = SpamVerdict {
            action: RspamdAction::NoAction,
            score: -0.5,
            required_score: 6.0,
            tests: Vec::new(),
            smtp_message: None,
        };
        let header = String::from_utf8(spam_status_header(&verdict)).expect("header");
        assert_eq!(
            header,
            "X-Spam-Status: No, score=-0.5, required=6.0, tests=, action=no action\r\n"
        );
    }

    #[test]
    fn the_tests_list_is_capped_by_count_and_bytes() {
        let tests: Vec<String> = (0..40).map(|index| format!("SYMBOL_{index:02}")).collect();
        let verdict = SpamVerdict {
            action: RspamdAction::AddHeader,
            score: 1.0,
            required_score: 1.0,
            tests,
            smtp_message: None,
        };
        let header = String::from_utf8(spam_status_header(&verdict)).expect("header");
        let rendered = header
            .split_once("tests=")
            .expect("tests list")
            .1
            .split(", ")
            .next()
            .expect("the list ends at `action=`")
            .to_owned();
        assert_eq!(rendered.split(',').count(), MAX_TESTS, "{rendered}");
        assert!(rendered.len() <= MAX_TESTS_BYTES, "{rendered}");
        // A byte cap also holds when a few names are long: no partial name.
        let long: Vec<String> = vec!["L".repeat(300), "M".repeat(300)];
        let verdict = SpamVerdict {
            tests: long,
            ..verdict
        };
        let header = String::from_utf8(spam_status_header(&verdict)).expect("header");
        let rendered = header.split_once("tests=").expect("tests list").1;
        let rendered = rendered.split(", action=").next().expect("list");
        assert!(rendered.len() <= MAX_TESTS_BYTES, "{rendered}");
        assert_eq!(
            rendered,
            "L".repeat(300),
            "a name that does not fit whole is dropped whole"
        );
    }

    #[test]
    fn a_borrowed_reply_text_is_santized_to_one_bounded_line() {
        let sanitized = sanitize_smtp_message("bad\r\n\r\ninjection\tattempt").expect("usable");
        assert_eq!(sanitized, "bad    injection attempt");
        assert!(!sanitized.contains(['\r', '\n', '\t']));
        let long = sanitize_smtp_message(&"x".repeat(400)).expect("usable");
        assert_eq!(long.len(), MAX_SMTP_MESSAGE_BYTES);
        assert_eq!(sanitize_smtp_message("\r\n \t"), None, "nothing usable");
    }

    #[test]
    fn header_values_carry_printable_ascii_only() {
        assert_eq!(header_value("a@b.example"), "a@b.example");
        assert_eq!(header_value("a@b\r\nX-Injected: 1"), "a@bX-Injected:1");
        assert_eq!(header_value(""), "unknown");
    }
}
