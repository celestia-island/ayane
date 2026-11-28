//! The rspamd integration, over real sockets: a fake normal worker (a
//! hand-written tokio server that can answer any shape the protocol allows,
//! including the broken ones), the real driver, and the real spool.
//!
//! Every behavioural case runs twice — once over `DATA` and once over a
//! `BDAT` chain — because the two transport paths converge on
//! [`ayane_smtpd::server`]'s one completion point, and a hook that reaches
//! only one of them is exactly the divergence this crate refuses to grow
//! back (the CVE-2023-51764 lesson, kept as a test).

mod support;

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ayane_smtpd::rspamd::RspamdClient;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

use support::{Harness, HarnessOptions, Reply};

/// The message every case sends: headers, a blank line, a body — with no
/// leading-dot line, so the `DATA` form is the message plus `.`.
const MESSAGE: &str = "From: <someone@remote.test>\r\nTo: <inbox@example.com>\r\n\
     Subject: scanned\r\n\r\nThe body of a scanned message.\r\n";

/// A classic-schema answer body with the given action and numbers.
fn action_body(action: &str) -> String {
    format!(r#"{{"action":"{action}","score":12.3,"required_score":6.0}}"#)
}

/// A request the fake scanner received.
#[derive(Debug, Clone)]
struct RecordedRequest {
    /// The request line's target (`/scan`).
    target: String,
    /// The header lines, as sent, in arrival order.
    headers: Vec<String>,
    /// How many body octets arrived.
    body_len: usize,
    /// How many reads brought them (the streaming assertion: a body streamed
    /// out of a file arrives in chunks, not in one write).
    body_reads: usize,
}

/// What the fake scanner does with every connection it accepts.
#[derive(Clone)]
enum FakeAnswer {
    /// An HTTP answer with a JSON body, after this delay.
    Json {
        status: u16,
        body: String,
        delay: Duration,
    },
    /// Accept the connection and drop it without answering (the "the
    /// scanner died mid-request" shape a timeout must cover).
    Silence,
}

impl FakeAnswer {
    fn json(status: u16, body: String) -> Self {
        Self::Json {
            status,
            body,
            delay: Duration::ZERO,
        }
    }

    /// A classic-schema answer with the given action and numbers.
    fn action(action: &str) -> Self {
        Self::json(200, action_body(action))
    }
}

/// A fake rspamd normal worker: accepts any number of connections, records
/// every request, and answers each with its [`FakeAnswer`].
struct FakeRspamd {
    addr: SocketAddr,
    requests: Arc<Mutex<Vec<RecordedRequest>>>,
}

impl FakeRspamd {
    /// Starts the fake and detaches its accept loop (it lives as long as the
    /// test's runtime, like the harness's listener task).
    async fn start(answer: FakeAnswer) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind fake rspamd");
        let addr = listener.local_addr().expect("fake addr");
        let requests = Arc::new(Mutex::new(Vec::new()));
        let recorded = requests.clone();
        tokio::spawn(async move {
            loop {
                let Ok((socket, _)) = listener.accept().await else {
                    break;
                };
                let answer = answer.clone();
                let recorded = recorded.clone();
                tokio::spawn(async move { answer_one(socket, answer, recorded).await });
            }
        });
        Self { addr, requests }
    }

    /// The requests it has seen so far.
    fn seen(&self) -> Vec<RecordedRequest> {
        self.requests.lock().expect("fake requests").clone()
    }

    /// The one request it has seen (the single-message cases).
    fn only(&self) -> RecordedRequest {
        let seen = self.seen();
        assert_eq!(seen.len(), 1, "one scan request: {seen:?}");
        seen.into_iter().next().expect("one request")
    }
}

/// Serves one connection: reads the request to its `Content-Length`, records
/// it, then writes the scripted answer to the socket — or, for
/// [`FakeAnswer::Silence`], writes nothing and drops the connection.
async fn answer_one(
    mut socket: tokio::net::TcpStream,
    answer: FakeAnswer,
    recorded: Arc<Mutex<Vec<RecordedRequest>>>,
) {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 4096];
    let header_end = loop {
        let Ok(read) = socket.read(&mut chunk).await else {
            return;
        };
        if read == 0 {
            return;
        }
        buffer.extend_from_slice(&chunk[..read]);
        if let Some(position) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
            break position + 4;
        }
        if buffer.len() > 128 * 1024 {
            return;
        }
    };
    let head = String::from_utf8_lossy(&buffer[..header_end]).into_owned();
    let mut lines = head.lines();
    let request_line = lines.next().unwrap_or_default().to_owned();
    let headers: Vec<String> = lines.map(str::to_owned).collect();
    let content_length: usize = headers
        .iter()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse().ok())?
        })
        .unwrap_or(0);
    let mut body = buffer[header_end..].to_vec();
    let mut body_reads = usize::from(!body.is_empty());
    while body.len() < content_length {
        let Ok(read) = socket.read(&mut chunk).await else {
            break;
        };
        if read == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..read]);
        body_reads += 1;
    }
    body.truncate(content_length);
    recorded
        .lock()
        .expect("fake requests")
        .push(RecordedRequest {
            target: request_line
                .split_whitespace()
                .nth(1)
                .unwrap_or_default()
                .to_owned(),
            headers,
            body_len: body.len(),
            body_reads: body_reads.max(1),
        });
    let FakeAnswer::Json {
        status,
        body: reply,
        delay,
    } = answer
    else {
        // Silence: the connection drops with nothing written.
        return;
    };
    tokio::time::sleep(delay).await;
    let response = format!(
        "HTTP/1.1 {status} Answer\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n{reply}",
        reply.len()
    );
    let _ = socket.write_all(response.as_bytes()).await;
    let _ = socket.shutdown().await;
}

/// A client for one fake's address.
fn scanner(fake: &FakeRspamd, timeout_ms: u64) -> RspamdClient {
    RspamdClient::parse(
        &format!("http://{}", fake.addr),
        Duration::from_millis(timeout_ms),
        None,
    )
    .expect("client")
}

/// One case's world: a fake scanner, a listener configured with it, and a
/// connected client.
async fn case(tag: &str, answer: FakeAnswer) -> (Harness, FakeRspamd, support::Client) {
    let fake = FakeRspamd::start(answer).await;
    let harness = Harness::start(
        tag,
        HarnessOptions {
            rspamd: Some(scanner(&fake, 2_000)),
            metrics: true,
            ..HarnessOptions::inbound()
        },
    )
    .await;
    let client = harness.client();
    (harness, fake, client)
}

/// Whether a message goes out over `DATA` or a `BDAT` chain.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Mode {
    Data,
    Bdat,
}

const MODES: [Mode; 2] = [Mode::Data, Mode::Bdat];

/// Sends one message over `mode` and returns the transaction's final reply.
fn send(client: &mut support::Client, mode: Mode, message: &str) -> Reply {
    client.ehlo("client.test");
    client.expect("MAIL FROM:<someone@remote.test>", 250);
    client.expect("RCPT TO:<inbox@example.com>", 250);
    match mode {
        Mode::Data => {
            client.expect("DATA", 354);
            client.send_raw(format!("{message}.\r\n").as_bytes());
            client.read_reply()
        }
        Mode::Bdat => {
            // The split falls mid-header on purpose: chunks are raw octets.
            let (first, second) = message.split_at(message.len() / 2);
            client.pending(first.as_bytes());
            client.expect(&format!("BDAT {}", first.len()), 250);
            client.pending(second.as_bytes());
            // The LAST chunk's reply is the transaction's answer.
            client.command(&format!("BDAT {} LAST", second.len()))
        }
    }
}

/// The spool's `tmp/` directory, emptied by every refusal.
fn staged_leftovers(harness: &Harness) -> Vec<std::path::PathBuf> {
    std::fs::read_dir(harness.dir.path().join("spool/tmp"))
        .expect("spool tmp")
        .flatten()
        .map(|entry| entry.path())
        .collect()
}

// ── 1 + 3: the refusing actions ─────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn reject_refuses_the_message_and_leaves_no_file() {
    for mode in MODES {
        let (harness, fake, mut client) = case("rspamd-reject", FakeAnswer::action("reject")).await;
        let reply = send(&mut client, mode, MESSAGE);
        assert_eq!(reply.code, 554, "{mode:?}: {reply:?}");
        assert!(
            reply.text.contains("5.7.1 Message rejected by spam filter"),
            "{mode:?}: {reply:?}"
        );
        // The staged file was abandoned: nothing in `new/`, nothing in
        // `tmp/` — the refusal is the message's whole afterlife.
        assert!(harness.queued().is_empty(), "{mode:?}");
        assert!(staged_leftovers(&harness).is_empty(), "{mode:?}");
        let metrics = harness.metrics.as_ref().expect("metrics");
        assert_eq!(metrics.total(ayane_smtpd::Counter::SpamRejected), 1);
        assert_eq!(metrics.total(ayane_smtpd::Counter::SpamScanned), 1);
        assert_eq!(metrics.total(ayane_smtpd::Counter::MessagesIn), 0);
        assert_eq!(fake.only().target, "/scan");
        harness.stop();
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn discard_is_mapped_to_the_refusal_not_to_a_silent_drop() {
    let (harness, _fake, mut client) = case("rspamd-discard", FakeAnswer::action("discard")).await;
    let reply = send(&mut client, Mode::Data, MESSAGE);
    assert_eq!(reply.code, 554, "{reply:?}");
    assert!(reply.text.contains("5.7.1"), "{reply:?}");
    assert!(harness.queued().is_empty());
    harness.stop();
}

#[tokio::test(flavor = "multi_thread")]
async fn soft_reject_and_greylist_answer_their_own_451_lines() {
    for (action, text) in [
        ("soft reject", "4.3.2 Try again later (content filter)"),
        ("greylist", "4.3.2 Greylisted, try again later"),
    ] {
        let (harness, _fake, mut client) = case("rspamd-451", FakeAnswer::action(action)).await;
        let reply = send(&mut client, Mode::Data, MESSAGE);
        assert_eq!(reply.code, 451, "{action}: {reply:?}");
        assert_eq!(reply.text, text, "{action}: {reply:?}");
        assert!(harness.queued().is_empty(), "{action}");
        harness.stop();
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_reject_borrows_the_scanners_smtp_message_one_line_at_a_time() {
    let answer = FakeAnswer::json(
        200,
        r#"{"action":"reject","score":12.3,"required_score":6.0,
            "messages":{"smtp_message":"gone\r\n\r\naway\tfor good"}}"#
            .to_owned(),
    );
    let (harness, _fake, mut client) = case("rspamd-smtp-message", answer).await;
    let reply = send(&mut client, Mode::Data, MESSAGE);
    assert_eq!(reply.code, 554, "{reply:?}");
    // One line, no controls, the scanner's words kept where they are legal.
    assert_eq!(reply.text, "5.7.1 gone    away for good", "{reply:?}");
    assert!(harness.queued().is_empty());
    harness.stop();
}

// ── 2 + 4: the flagging actions ─────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn add_header_flags_the_message_on_both_transports() {
    for mode in MODES {
        let answer = FakeAnswer::json(
            200,
            r#"{"action":"add header","score":12.3,"required_score":6.0,
                "symbols":{"GTUBE":{"name":"GTUBE","score":10.0,
                                     "options":["scanner option text"]},
                           "FREEMAIL_FROM":{"name":"FREEMAIL_FROM","score":0.5}}}"#
                .to_owned(),
        );
        let (harness, fake, mut client) = case("rspamd-add-header", answer).await;
        let reply = send(&mut client, mode, MESSAGE);
        assert_eq!(reply.code, 250, "{mode:?}: {reply:?}");
        let stored = String::from_utf8_lossy(&harness.only_message()).into_owned();
        let expected = "X-Spam-Status: Yes, score=12.3, required=6.0, \
                        tests=FREEMAIL_FROM,GTUBE, action=add header\r\n";
        assert!(stored.contains(expected), "{mode:?}: {stored:?}");
        // The trace field stays on top; the status rides behind it.
        let received = stored.find("Received: ").expect("trace field");
        let status = stored.find("X-Spam-Status: ").expect("status field");
        assert!(received < status, "{mode:?}: {stored:?}");
        // MUT:M5 — the scanner's free text (a symbol's options) reaching the
        // spooled message is exactly the mutant this assertion killed.
        assert!(
            !stored.contains("scanner option text"),
            "{mode:?}: {stored:?}"
        );
        assert_eq!(fake.only().body_len, MESSAGE.len());
        harness.stop();
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn no_action_delivers_with_the_no_status() {
    for mode in MODES {
        let (harness, _fake, mut client) = case(
            "rspamd-no-action",
            FakeAnswer::json(
                200,
                r#"{"action":"no action","score":-0.5,"required_score":6.0}"#.to_owned(),
            ),
        )
        .await;
        let reply = send(&mut client, mode, MESSAGE);
        assert_eq!(reply.code, 250, "{mode:?}: {reply:?}");
        let stored = String::from_utf8_lossy(&harness.only_message()).into_owned();
        assert!(
            stored.contains(
                "X-Spam-Status: No, score=-0.5, required=6.0, tests=, action=no action\r\n"
            ),
            "{mode:?}: {stored:?}"
        );
        harness.stop();
    }
}

// ── 5 + 6: fail-open ────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn broken_scanner_answers_fail_open_without_a_status_header() {
    for (tag, answer) in [
        ("rspamd-http500", FakeAnswer::json(500, "boom".to_owned())),
        (
            "rspamd-bad-json",
            FakeAnswer::json(200, "not json".to_owned()),
        ),
    ] {
        let (harness, _fake, mut client) = case(tag, answer).await;
        let reply = send(&mut client, Mode::Data, MESSAGE);
        assert_eq!(reply.code, 250, "{tag}: {reply:?}");
        let stored = String::from_utf8_lossy(&harness.only_message()).into_owned();
        assert!(
            !stored.contains("X-Spam-Status"),
            "{tag}: a failed scan leaves no header: {stored:?}"
        );
        let metrics = harness.metrics.as_ref().expect("metrics");
        assert_eq!(
            metrics.total(ayane_smtpd::Counter::SpamScanErrors),
            1,
            "{tag}"
        );
        assert_eq!(metrics.total(ayane_smtpd::Counter::SpamScanned), 0, "{tag}");
        harness.stop();
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn an_answer_without_a_known_action_is_conservative_and_counted() {
    let (harness, _fake, mut client) = case(
        "rspamd-unknown",
        FakeAnswer::json(200, r#"{"score":1.0}"#.to_owned()),
    )
    .await;
    let reply = send(&mut client, Mode::Data, MESSAGE);
    assert_eq!(reply.code, 250, "{reply:?}");
    let stored = String::from_utf8_lossy(&harness.only_message()).into_owned();
    assert!(
        stored.contains("action=add header"),
        "unknown is conservative: {stored:?}"
    );
    let metrics = harness.metrics.as_ref().expect("metrics");
    assert_eq!(metrics.total(ayane_smtpd::Counter::SpamScanErrors), 1);
    assert_eq!(metrics.total(ayane_smtpd::Counter::SpamScanned), 1);
    harness.stop();
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unreachable_scanner_fails_open_and_counts() {
    // A port that will refuse: bound, then dropped.
    let closed = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let closed_addr = closed.local_addr().expect("addr");
    drop(closed);
    let harness = Harness::start(
        "rspamd-refused",
        HarnessOptions {
            rspamd: Some(
                RspamdClient::parse(
                    &format!("http://{closed_addr}"),
                    Duration::from_millis(2_000),
                    None,
                )
                .expect("client"),
            ),
            metrics: true,
            ..HarnessOptions::inbound()
        },
    )
    .await;
    let mut client = harness.client();
    let reply = send(&mut client, Mode::Data, MESSAGE);
    assert_eq!(reply.code, 250, "{reply:?}");
    assert_eq!(harness.queued().len(), 1);
    let metrics = harness.metrics.as_ref().expect("metrics");
    assert_eq!(metrics.total(ayane_smtpd::Counter::SpamScanErrors), 1);
    harness.stop();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_scanner_past_its_timeout_fails_open_and_counts() {
    // Two half-dead shapes, one answer: a scanner that accepts and stalls
    // past the timeout, and one that drops the connection mid-request. Both
    // are fail-open within the timeout, not the fake's own schedule.
    for (tag, answer) in [
        (
            "rspamd-timeout",
            FakeAnswer::Json {
                status: 200,
                body: action_body("no action"),
                delay: Duration::from_secs(2),
            },
        ),
        ("rspamd-silence", FakeAnswer::Silence),
    ] {
        let fake = FakeRspamd::start(answer).await;
        let harness = Harness::start(
            tag,
            HarnessOptions {
                // MUT:M2 — the timeout is the knob under test: shorter than
                // the fake's stall, so the answer can never arrive in time;
                // inverting fail-open for scan failures kills this test.
                rspamd: Some(scanner(&fake, 200)),
                metrics: true,
                ..HarnessOptions::inbound()
            },
        )
        .await;
        let mut client = harness.client();
        let started = std::time::Instant::now();
        let reply = send(&mut client, Mode::Data, MESSAGE);
        assert_eq!(reply.code, 250, "{tag}: {reply:?}");
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "{tag}: the timeout, not the fake's schedule, bounds the wait: {:?}",
            started.elapsed()
        );
        assert_eq!(harness.queued().len(), 1, "{tag}");
        let metrics = harness.metrics.as_ref().expect("metrics");
        assert_eq!(
            metrics.total(ayane_smtpd::Counter::SpamScanErrors),
            1,
            "{tag}"
        );
        harness.stop();
    }
}

// ── 8 + 9: the configuration gate ───────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn an_unconfigured_listener_connects_nowhere_and_changes_nothing() {
    // The fake is running, but no client is configured: if the driver scans
    // anyway, this fake is where it would show up. The role gate (submission
    // never holds a client at all) is the assembly's —
    // comment-gate-ok: assembly coverage lives in the engine role tests
    // (crates/core/src/engine.rs::only_an_inbound_listener_is_given_the_
    // content_scanner, plus a_configured_engine_scans_inbound… in this
    // workspace's core e2e); at this layer the same None means the same
    // nothing.
    let fake = FakeRspamd::start(FakeAnswer::action("no action")).await;
    let harness = Harness::start("rspamd-unset", HarnessOptions::inbound()).await;
    let mut client = harness.client();
    let reply = send(&mut client, Mode::Data, MESSAGE);
    assert_eq!(reply.code, 250, "{reply:?}");
    let stored = String::from_utf8_lossy(&harness.only_message()).into_owned();
    assert!(!stored.contains("X-Spam-Status"), "{stored:?}");
    assert!(stored.contains("Received: "), "{stored:?}");
    assert!(
        fake.seen().is_empty(),
        "no scan request may be made: {:?}",
        fake.seen()
    );
    harness.stop();
}

/// Every value one request carried for a header name, in arrival order.
fn header(request: &RecordedRequest, name: &str) -> Vec<String> {
    request
        .headers
        .iter()
        .filter_map(|line| line.split_once(": "))
        .filter(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.to_owned())
        .collect()
}

// ── 10: the request's own shape ─────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn the_scan_request_carries_the_whole_envelope() {
    let (harness, fake, mut client) = case("rspamd-request", FakeAnswer::action("no action")).await;
    client.ehlo("client.test");
    client.expect("MAIL FROM:<someone@remote.test>", 250);
    client.expect("RCPT TO:<inbox@example.com>", 250);
    client.expect("RCPT TO:<ops@example.com>", 250);
    client.expect("DATA", 354);
    client.send_raw(format!("{MESSAGE}.\r\n").as_bytes());
    let reply = client.read_reply();
    assert_eq!(reply.code, 250, "{reply:?}");
    let queued = harness.queued();
    assert_eq!(queued.len(), 1);
    let request = fake.only();
    assert_eq!(request.target, "/scan");
    assert_eq!(
        header(&request, "From"),
        vec!["someone@remote.test"],
        "{:?}",
        request.headers
    );
    assert_eq!(
        header(&request, "Rcpt"),
        vec!["inbox@example.com", "ops@example.com"],
        "one header per recipient: {:?}",
        request.headers
    );
    assert_eq!(header(&request, "Ip"), vec!["127.0.0.1"]);
    assert_eq!(header(&request, "Helo"), vec!["client.test"]);
    assert_eq!(header(&request, "Hostname"), vec!["client.test"]);
    assert_eq!(
        header(&request, "Queue-Id"),
        vec![queued[0].id.as_str()],
        "the spool id"
    );
    assert_eq!(header(&request, "Pass"), vec!["all"]);
    assert!(
        header(&request, "Password").is_empty(),
        "no password without one configured: {:?}",
        request.headers
    );
    // The message length is announced, not chunked: the scanner can read a
    // bounded body.
    assert_eq!(
        header(&request, "Content-Length"),
        vec![MESSAGE.len().to_string()]
    );
    assert!(
        !request
            .headers
            .iter()
            .any(|line| line.to_ascii_lowercase().starts_with("transfer-encoding")),
        "streamed with Content-Length, not chunked: {:?}",
        request.headers
    );
    // The body is the message exactly as received — no engine prepend.
    harness.stop();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_null_reverse_path_travels_as_an_empty_from() {
    // `MAIL FROM:<>` is the bounce/DSN path: the envelope's reverse-path is
    // the empty string, and that is exactly what the scanner must see — a
    // fabricated `unknown` would be an envelope no peer ever sent, and
    // sender-keyed scanner rules would share one bucket for all of them.
    let (harness, fake, mut client) =
        case("rspamd-null-sender", FakeAnswer::action("no action")).await;
    client.ehlo("client.test");
    client.expect("MAIL FROM:<>", 250);
    client.expect("RCPT TO:<inbox@example.com>", 250);
    client.expect("DATA", 354);
    client.send_raw(format!("{MESSAGE}.\r\n").as_bytes());
    assert_eq!(client.read_reply().code, 250);
    let request = fake.only();
    assert_eq!(
        header(&request, "From"),
        vec![""],
        "the null reverse-path is an empty From: {:?}",
        request.headers
    );
    assert_eq!(header(&request, "Rcpt"), vec!["inbox@example.com"]);
    harness.stop();
}

#[tokio::test(flavor = "multi_thread")]
async fn the_body_is_the_message_exactly_as_received() {
    let (harness, fake, mut client) = case("rspamd-body", FakeAnswer::action("no action")).await;
    let reply = send(&mut client, Mode::Data, MESSAGE);
    assert_eq!(reply.code, 250, "{reply:?}");
    let request = fake.only();
    assert_eq!(request.body_len, MESSAGE.len(), "raw octets, no prepend");
    harness.stop();
}

// ── 11: streaming ───────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn a_large_message_is_streamed_through_the_scan() {
    // ~24 MiB, just under the SIZE ceiling. What this test asserts,
    // mechanically: the fake records every `read` it serves; the body is
    // then expected to arrive with an exact `Content-Length` and in many
    // separate reads (>`100` for this size), i.e. forwarded incrementally
    // rather than as one write. It does not measure the scanner's memory —
    // socket reads would look chunked even if the client buffered first.
    // comment-gate-ok: explicitly disclaims what the test does not measure.
    let line = "a".repeat(900);
    let lines = 28_000;
    let message = format!(
        "Subject: big\r\n\r\n{}\r\n",
        format!("{line}\r\n").repeat(lines)
    );
    assert!(message.len() < 25 * 1024 * 1024);
    let (harness, fake, mut client) = case("rspamd-large", FakeAnswer::action("no action")).await;
    let reply = send(&mut client, Mode::Data, &message);
    assert_eq!(reply.code, 250, "{reply:?}");
    let request = fake.only();
    assert_eq!(request.body_len, message.len(), "every octet forwarded");
    assert!(
        request.body_reads > 100,
        "streamed in chunks, not in one write: {} reads for {} bytes",
        request.body_reads,
        request.body_len
    );
    assert_eq!(harness.queued().len(), 1);
    harness.stop();
}

// ── 6.3 M3: the scan decides *before* the queue commits ─────────────────

#[tokio::test(flavor = "multi_thread")]
async fn a_slow_refusal_still_leaves_no_spool_file() {
    // The scanner is slow enough that an implementation which committed
    // first and asked later would have the file in `new/` before the answer
    // arrives. The refusal must leave `new/` and `tmp/` empty all the same.
    let answer = FakeAnswer::Json {
        status: 200,
        body: action_body("reject"),
        delay: Duration::from_millis(300),
    };
    let (harness, _fake, mut client) = case("rspamd-slow-reject", answer).await;
    let reply = send(&mut client, Mode::Data, MESSAGE);
    assert_eq!(reply.code, 554, "{reply:?}");
    assert!(
        harness.queued().is_empty(),
        "nothing in new/: {:?}",
        harness.queued()
    );
    assert!(staged_leftovers(&harness).is_empty(), "nothing in tmp/");
    harness.stop();
}
