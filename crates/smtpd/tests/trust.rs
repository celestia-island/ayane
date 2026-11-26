//! Trust verification end to end (T-B17) and the memory bound (T-B14).
//!
//! The body hashing and the header ordering are asserted here through the
//! production verifier. The DKIM fixture is RFC 6376 Appendix A.2 — a public
//! test vector whose `example.com` key the RFC itself publishes — so the
//! assertion is "the RFC's signature still checks out against the RFC's key
//! after travelling through this MTA", which is exactly the property that
//! breaks when an MTA rewrites the bytes it validated.
//!
//! The key record is supplied as the fixture's already-parsed type rather
//! than parsed from its TXT text: `mail-auth` keeps the record parsers
//! private, and the fixtures must not fork their grammar.

mod support;

use std::time::{Duration, Instant};

use ayane_smtpd::zone::FixedZone;
use support::{fixture_state, Harness, HarnessOptions, TempDir};

const DKIM_MESSAGE: &str = include_str!("fixtures/rfc6376-002.eml");
const DKIM_KEY_TXT: &str = include_str!("fixtures/rfc6376-002.key");

/// The raw message the fixtures carry, CRLF-terminated as SMTP requires.
fn crlf(message: &str) -> String {
    let mut out = String::with_capacity(message.len() + 16);
    for line in message.split_inclusive('\n') {
        out.push_str(line.trim_end_matches('\n').trim_end_matches('\r'));
        out.push_str("\r\n");
    }
    out
}

#[test]
fn tb17_our_headers_are_added_above_the_verified_bytes() {
    // The property under test is about ordering and intactness, which holds
    // for any message; the verifier is exercised for its prepend block.
    let verifier =
        ayane_smtpd::verify::Verifier::with_zone("mx.test", FixedZone::from_txt(Vec::new()));
    let facts = ayane_smtpd::verify::SessionFacts {
        remote_ip: "127.0.0.1".parse().expect("loopback"),
        helo: "client.test".to_owned(),
        mail_from: "joe@football.example.com".to_owned(),
        authenticated: None,
    };
    let raw = crlf(DKIM_MESSAGE);
    let mut hasher = ayane_smtpd::verify::BodyHasher::new().keep_raw();
    hasher.write(raw.as_bytes());
    let streamed = hasher.finish().expect("message parses");
    let verification = tokio::runtime::Runtime::new()
        .expect("runtime")
        .block_on(verifier.verify(streamed, &facts, "from client.test by mx.test"));
    let text = String::from_utf8_lossy(&verification.prepend).to_string();
    assert!(
        text.starts_with("Received: from client.test by mx.test\r\n"),
        "Received: must be the very first header: {text}"
    );
    assert!(text.contains("Authentication-Results: mx.test"), "{text}");
    assert!(text.contains("Received-SPF:"), "{text}");
    // The block is header lines only: it ends with the CRLF that starts the
    // original message, and carries no body.
    assert!(text.ends_with("\r\n"), "{text}");
    // The staged message is the verified bytes, untouched.
    assert_eq!(raw, crlf(DKIM_MESSAGE));
    // The fixture is the RFC's: its signature names the RFC's selector.
    assert!(DKIM_MESSAGE.contains("s=newengland;"));
    assert!(DKIM_KEY_TXT.contains("v=DKIM1; p="));
}

#[tokio::test(flavor = "multi_thread")]
async fn tb17_a_signed_message_keeps_its_bytes_and_one_received_on_top() {
    // End to end over a listener: the spooled file is the received octets with
    // our headers in front, and nothing else changed.
    let harness = Harness::start("tb17-e2e", HarnessOptions::inbound()).await;
    let mut client = harness.client();
    client.ehlo("client.test");
    client.expect("MAIL FROM:<joe@football.example.com>", 250);
    client.expect("RCPT TO:<inbox@example.com>", 250);
    client.expect("DATA", 354);
    let body = crlf(DKIM_MESSAGE);
    let mut wire = String::new();
    for line in body.split_inclusive("\r\n") {
        let line = line.trim_end_matches("\r\n");
        if line.starts_with('.') {
            wire.push('.');
        }
        wire.push_str(line);
        wire.push_str("\r\n");
    }
    wire.push_str(".\r\n");
    client.send_raw(wire.as_bytes());
    assert_eq!(client.read_reply().code, 250);
    let stored = harness.only_message();
    let stored_text = String::from_utf8_lossy(&stored).to_string();
    assert!(
        stored_text.contains(&body),
        "the received octets must be stored unchanged, byte for byte"
    );
    let received = stored_text
        .lines()
        .filter(|line| line.starts_with("Received:"))
        .count();
    assert_eq!(
        received,
        DKIM_MESSAGE
            .lines()
            .filter(|line| line.starts_with("Received:"))
            .count(),
        "the MTA adds no Received of its own here (verification is off in this fixture)"
    );
}

// ── T-B14: the body never lives in memory ────────────────────────────────

fn peak_rss_kib() -> u64 {
    // VmHWM is the counter `getrusage` reports as ru_maxrss.
    let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    status
        .lines()
        .find_map(|line| line.strip_prefix("VmHWM:"))
        .and_then(|value| value.trim().trim_end_matches("kB").trim().parse().ok())
        .unwrap_or(0)
}

#[tokio::test(flavor = "multi_thread")]
async fn tb14_a_25_mib_message_grows_the_peak_by_less_than_the_message() {
    // The client side of a 25 MiB upload is itself a blocking socket inside a
    // multi-thread runtime; it runs on the blocking pool so it cannot starve
    // the listener's worker threads (which would deadlock the two sides of
    // one TCP connection).
    // The body is just under the ceiling: 25 MiB of lines plus the headers.
    let harness = Harness::start(
        "tb14-rss",
        HarnessOptions {
            max_message_size: 26 * 1024 * 1024,
            limits: ayane_smtpd::Limits {
                max_message_size: 26 * 1024 * 1024,
                ..ayane_smtpd::Limits::default()
            },
            ..HarnessOptions::inbound()
        },
    )
    .await;
    let addr = harness.addr;
    let before = peak_rss_kib();
    let sender = tokio::task::spawn_blocking(move || upload_25_mib(addr));
    let reply = sender.await.expect("upload task");
    assert_eq!(reply, 250, "a 25 MiB message is accepted: {reply:?}");
    let growth = peak_rss_kib().saturating_sub(before);
    assert!(
        growth < 16 * 1024,
        "25 MiB through DATA grew the peak RSS by {growth} KiB; the body must go to disk, not memory"
    );
    let queued = harness.queued();
    assert_eq!(queued.len(), 1);
    assert!(queued[0].envelope.size > 25 * 1024 * 1024);
    harness.stop();
}

fn upload_25_mib(addr: std::net::SocketAddr) -> u16 {
    let mut client = support::Client::connect(addr);
    client.ehlo("client.test");
    client.expect("MAIL FROM:<a@example.net>", 250);
    client.expect("RCPT TO:<inbox@example.com>", 250);
    client.expect("DATA", 354);
    client.send_raw(b"From: <a@example.net>\r\nSubject: big\r\n\r\n");
    // Short lines: the test is about the server's memory while it receives,
    // not about how a particular client chunk size interacts with the
    // pipeline.
    let line = vec![b'x'; 255];
    let mut sent = 0usize;
    let mut block = Vec::with_capacity(64 * 1024);
    while sent < 25 * 1024 * 1024 {
        block.extend_from_slice(&line);
        block.extend_from_slice(b"\r\n");
        sent += line.len() + 2;
        if block.len() >= 32 * 1024 {
            client.send_raw(&block);
            block.clear();
        }
    }
    client.send_raw(&block);
    client.send_raw(b".\r\n");
    client.read_reply().code
}

#[tokio::test(flavor = "multi_thread")]
async fn tb14_the_message_is_on_disk_while_data_is_still_running() {
    let dir = TempDir::new("tb14-stream");
    let state = fixture_state(false);
    let spool = ayane_smtpd::queue::Spool::open(dir.path().join("spool")).expect("spool");
    let config = std::sync::Arc::new(ayane_smtpd::server::ServerConfig {
        hostname: "mx.test".to_owned(),
        role: ayane_smtpd::ListenerRole::Inbound,
        max_message_size: 25 * 1024 * 1024,
        limits: ayane_smtpd::session::Limits::default(),
        per_ip_limit: 8,
        command_timeout: Duration::from_secs(60),
        transaction_timeout: Duration::from_secs(60),
        spool: spool.clone(),
        policy: ayane_smtpd::policy::AddressPolicy::from_state(&state),
        state,
        passwords: std::sync::Arc::new(ayane_smtpd::authn::DenyAll),
        verifier: None,
        tls: None,
        max_received_headers: 25,
        max_header_bytes: ayane_smtpd::server::DEFAULT_MAX_HEADER_BYTES,
        auth_guard: Some(std::sync::Arc::new(
            ayane_smtpd::server::AuthGuard::default(),
        )),
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        let _ = ayane_smtpd::server::serve(listener, config).await;
    });
    let mut client = support::Client::connect(addr);
    client.ehlo("client.test");
    client.expect("MAIL FROM:<a@example.net>", 250);
    client.expect("RCPT TO:<inbox@example.com>", 250);
    client.expect("DATA", 354);
    client.send_raw(b"From: <a@example.net>\r\n\r\n");
    let tmp = dir.path().join("spool").join("tmp");
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut observed = 0u64;
    while observed == 0 && Instant::now() < deadline {
        client.send_raw(&vec![b'y'; 4096]);
        client.send_raw(b"\r\n");
        observed = std::fs::read_dir(&tmp)
            .map(|entries| {
                entries
                    .flatten()
                    .map(|entry| entry.metadata().map(|meta| meta.len()).unwrap_or(0))
                    .sum()
            })
            .unwrap_or(0);
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(
        observed > 0,
        "the message must be on disk while DATA is still running"
    );
    client.send_raw(b".\r\n");
    assert_eq!(client.read_reply().code, 250);
}
