//! The header-section bound, over real sockets.
//!
//! The streaming verifier buffers the **whole** header section — it cannot
//! tell where the body starts until the blank line arrives — so a peer that
//! never sends that line makes the verifier hold everything it sent. The
//! driver is the only layer that can bound it, which is why
//! [`ServerConfig::max_header_bytes`] is a driver setting and why these tests
//! drive the driver rather than the verifier.
//!
//! What each test asserts is the observable contract: a header section over
//! the bound is refused with `552 5.3.4`, the transaction ends there, and
//! **nothing is queued**. The zero-queue assertion is the one that matters —
//! a refusal that still spooled the message would be a refusal in name only.

mod support;

use std::time::Duration;

use ayane_smtpd::server::DEFAULT_MAX_HEADER_BYTES;
use support::{Client, Harness, HarnessOptions};

/// The bound these tests run with: small enough that crossing it is quick
/// over loopback, large enough that a real header section fits.
const LIMIT: u64 = 4 * 1024;

fn bounded() -> HarnessOptions {
    HarnessOptions {
        max_header_bytes: LIMIT,
        transaction_timeout: Duration::from_secs(20),
        ..HarnessOptions::inbound()
    }
}

/// A message whose header section is `field_count` copies of a short field
/// followed by the blank line, and a body after it.
fn headers(field_count: usize) -> String {
    let mut out = String::new();
    for index in 0..field_count {
        out.push_str(&format!("X-Pad-{index}: {}\r\n", "p".repeat(64)));
    }
    out
}

/// Opens a transaction to the fixture's own mailbox and returns the client.
fn transaction(harness: &Harness) -> Client {
    let mut client = harness.client();
    client.ehlo("client.test");
    client.expect("MAIL FROM:<a@example.net>", 250);
    client.expect("RCPT TO:<inbox@example.com>", 250);
    client
}

#[tokio::test(flavor = "multi_thread")]
async fn a_header_section_under_the_bound_is_accepted() {
    // The control: the same shape as the refusal test, one field group short
    // of the bound. If this failed, the refusal below would prove nothing.
    let harness = Harness::start("header-under", bounded()).await;
    let mut client = transaction(&harness);
    client.expect("DATA", 354);
    let mut body = String::from("From: <a@example.net>\r\nSubject: fits\r\n");
    body.push_str(&headers(40));
    body.push_str("\r\nbody\r\n.\r\n");
    assert!(
        body.len() < LIMIT as usize,
        "the fixture must stay under the bound: {} vs {LIMIT}",
        body.len()
    );
    client.send_raw(body.as_bytes());
    let reply = client.read_reply();
    assert_eq!(reply.code, 250, "{reply:?}");
    assert_eq!(harness.queued().len(), 1, "the message is queued");
    harness.stop();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_header_section_with_no_blank_line_is_refused_with_552() {
    // The case the bound exists for: no blank line at all, so the header
    // section is *the whole message* and the verifier would buffer all of it.
    let harness = Harness::start("header-none", bounded()).await;
    let mut client = transaction(&harness);
    client.expect("DATA", 354);
    let mut body = String::from("From: <a@example.net>\r\n");
    body.push_str(&headers(200));
    body.push_str(".\r\n");
    client.send_raw(body.as_bytes());
    let reply = client.read_reply();
    assert_eq!(
        reply.code, 552,
        "an unbounded header section is a processing error: {reply:?}"
    );
    assert_eq!(reply.text, "5.3.4 Header section too large", "{reply:?}");
    assert!(
        harness.queued().is_empty(),
        "a refused message is never queued"
    );
    harness.stop();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_header_section_over_the_bound_is_refused_at_the_crossing_line() {
    // Headers that end properly but are too large: the refusal has to arrive
    // once the head outgrows the bound, not after the whole body is uploaded.
    let harness = Harness::start("header-over", bounded()).await;
    let mut client = transaction(&harness);
    client.expect("DATA", 354);
    let mut body = String::from("From: <a@example.net>\r\n");
    body.push_str(&headers(200));
    body.push_str("\r\nbody\r\n.\r\n");
    client.send_raw(body.as_bytes());
    let reply = client.read_reply();
    assert_eq!(
        reply.code, 552,
        "the head outgrew the bound before its blank line: {reply:?}"
    );
    assert_eq!(reply.text, "5.3.4 Header section too large", "{reply:?}");
    assert!(harness.queued().is_empty(), "nothing is queued");
    harness.stop();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_large_body_after_a_small_head_is_still_accepted() {
    // The bound is on the hedge, not on the message: a head over many lines
    // is fine as long as the blank line arrives before the limit, whatever the
    // body behind it weighs. A body of the same size as the bound, well past
    // it, must still go through.
    let harness = Harness::start("header-body", bounded()).await;
    let mut client = transaction(&harness);
    client.expect("DATA", 354);
    let mut body = String::from("From: <a@example.net>\r\nSubject: big\r\n\r\n");
    for _ in 0..200 {
        body.push_str(&"b".repeat(64));
        body.push_str("\r\n");
    }
    body.push_str(".\r\n");
    assert!(
        body.len() > LIMIT as usize * 2,
        "the body must dwarf the header bound: {} vs {LIMIT}",
        body.len()
    );
    client.send_raw(body.as_bytes());
    let reply = client.read_reply();
    assert_eq!(
        reply.code, 250,
        "a big body under a small head fits: {reply:?}"
    );
    assert_eq!(harness.queued().len(), 1);
    harness.stop();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_bdat_message_over_the_header_bound_is_refused() {
    // The chunked path has no line structure until the chain is whole, so the
    // bound is charged once, on the reassembled message. The refusal is still
    // a single `552` to the `LAST` chunk — the transaction's answer, not a
    // second reply to a command that already had one — and nothing is queued.
    let harness = Harness::start("header-bdat", bounded()).await;
    let mut client = transaction(&harness);
    let mut chunk = String::from("From: <a@example.net>\r\n");
    chunk.push_str(&headers(200));
    // No blank line anywhere: the whole chunk is header section.
    let bytes = chunk.into_bytes();
    client.pending(&bytes);
    let reply = client.command(&format!("BDAT {} LAST", bytes.len()));
    assert_eq!(reply.code, 552, "a chunked head over the bound: {reply:?}");
    assert_eq!(reply.text, "5.3.4 Header section too large", "{reply:?}");
    assert!(harness.queued().is_empty(), "nothing is queued");
    harness.stop();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_bdat_message_under_the_header_bound_is_accepted() {
    // The control for the chunked path: same client shape, a head that ends
    // properly before the bound.
    let harness = Harness::start("header-bdat-ok", bounded()).await;
    let mut client = transaction(&harness);
    let first = b"From: <a@example.net>\r\nCon".to_vec();
    let second = b"tent-Type: text/plain\r\n\r\nbody from chunks\r\n".to_vec();
    client.pending(&first);
    assert_eq!(client.command(&format!("BDAT {}", first.len())).code, 250);
    client.pending(&second);
    let reply = client.command(&format!("BDAT {} LAST", second.len()));
    assert_eq!(reply.code, 250, "{reply:?}");
    let queued = harness.queued();
    assert_eq!(queued.len(), 1);
    let stored = String::from_utf8_lossy(&harness.only_message()).to_string();
    assert!(stored.contains("\r\n\r\nbody from chunks\r\n"), "{stored}");
    harness.stop();
}

#[tokio::test(flavor = "multi_thread")]
async fn the_bound_applies_without_a_verifier() {
    // The bound is the driver's, not the verifier's `Option`. A listener
    // without a verifier still refuses a head over the limit — a header
    // section that large is not something to accept into a mailbox either, and
    // a bound that disappeared with a misconfigured `None` would be one an
    // operator can lose silently. The harness fixture has no verifier.
    let harness = Harness::start("header-noverifier", bounded()).await;
    assert!(
        !HarnessOptions::inbound().verify,
        "the fixture listener runs without a verifier"
    );
    let mut client = transaction(&harness);
    client.expect("DATA", 354);
    let mut body = String::from("From: <a@example.net>\r\n");
    body.push_str(&headers(200));
    body.push_str(".\r\n");
    client.send_raw(body.as_bytes());
    assert_eq!(client.read_reply().code, 552);
    assert!(harness.queued().is_empty());
    harness.stop();
}

/// The two transports refuse the same message, which is what makes the bound
/// a policy instead of a per-transport accident.
///
/// The shape is the one an earlier version got wrong: a **small** header
/// section (a blank line a hundred octets in) on top of a body far larger
/// than the bound. Charged line by line over `DATA` that is obviously fine —
/// the blank line ends the section and the body is never counted. Charged as
/// one blob over `BDAT`, where the chain is raw octets with no line structure
/// left, the same message became "a header section the size of the message"
/// and was refused with `552`. Same limit, same message, two answers: a
/// difference a sender can probe for, and a refusal a legitimate chunking
/// client cannot act on.
///
/// Both transports are driven here, over one `max_header_bytes`, so the
/// assertion is that the answers **match** — not that each is whatever it was
/// last time.
#[tokio::test(flavor = "multi_thread")]
async fn both_transports_answer_the_same_message_the_same_way() {
    const SMALL_HEAD: &str = "From: <a@example.net>\r\nSubject: dual\r\n\r\n";

    /// A body several times the header bound, as a string.
    fn big_body() -> String {
        let mut body = String::new();
        for _ in 0..200 {
            body.push_str(&"b".repeat(64));
            body.push_str("\r\n");
        }
        body
    }

    let head_len = SMALL_HEAD.len();
    let body = big_body();
    assert!(
        (head_len as u64) <= LIMIT,
        "the section must fit under the bound: {head_len} vs {LIMIT}"
    );
    assert!(
        body.len() as u64 > 2 * LIMIT,
        "the body must dwarf the bound: {} vs {LIMIT}",
        body.len()
    );

    // DATA: a hundred-octet head, then a body several times the bound.
    let data_harness = Harness::start("dual-data", bounded()).await;
    let mut client = transaction(&data_harness);
    client.expect("DATA", 354);
    client.send_raw(format!("{SMALL_HEAD}{body}.\r\n").as_bytes());
    let over_data = client.read_reply().code;
    let queued_over_data = data_harness.queued().len();
    data_harness.stop();

    // BDAT: the same octets, one chunk, `LAST`.
    let bdat_harness = Harness::start("dual-bdat", bounded()).await;
    let mut client = transaction(&bdat_harness);
    let message = format!("{SMALL_HEAD}{body}").into_bytes();
    client.pending(&message);
    let over_bdat = client.command(&format!("BDAT {} LAST", message.len())).code;
    let queued_over_bdat = bdat_harness.queued().len();
    bdat_harness.stop();

    assert_eq!(
        over_data, 250,
        "a small head over DATA is accepted, whatever the body weighs"
    );
    assert_eq!(
        over_bdat, 250,
        "and over BDAT: the blank line ends the section there too"
    );
    assert_eq!(
        over_bdat, over_data,
        "the two transports must not disagree about the same message"
    );
    assert_eq!(queued_over_data, 1, "the DATA copy is queued");
    assert_eq!(queued_over_bdat, 1, "the BDAT copy is queued");
}

/// The same pair, on the refusing side: **no blank line at all** past the
/// bound is a header section over the bound over either transport.
///
/// This is the other half of the duality — the fix above must not have made
/// `BDAT` permissive, only *symmetric*. A message whose head never ends is
/// refused by `DATA` for the reason the bound exists (the verifier would hold
/// it whole), and `BDAT` has to say the same.
#[tokio::test(flavor = "multi_thread")]
async fn both_transports_refuse_a_head_that_never_ends() {
    let mut endless = String::from("From: <a@example.net>\r\n");
    endless.push_str(&headers(200));
    assert!(
        endless.len() as u64 > LIMIT,
        "the head must outgrow the bound: {} vs {LIMIT}",
        endless.len()
    );

    let data_harness = Harness::start("dual-refuse-data", bounded()).await;
    let mut client = transaction(&data_harness);
    client.expect("DATA", 354);
    client.send_raw(format!("{endless}.\r\n").as_bytes());
    let over_data = client.read_reply();
    data_harness.stop();

    let bdat_harness = Harness::start("dual-refuse-bdat", bounded()).await;
    let mut client = transaction(&bdat_harness);
    let message = endless.into_bytes();
    client.pending(&message);
    let over_bdat = client.command(&format!("BDAT {} LAST", message.len()));
    bdat_harness.stop();

    for (transport, reply) in [("DATA", &over_data), ("BDAT", &over_bdat)] {
        assert_eq!(reply.code, 552, "{transport}: {reply:?}");
        assert_eq!(
            reply.text, "5.3.4 Header section too large",
            "{transport}: {reply:?}"
        );
    }
    assert_eq!(over_bdat.code, over_data.code, "same answer, both ways");
}

/// One chunk that is *itself* larger than the bound, holding a short head and
/// a long body, still goes through: the bound is on the section, and a single
/// chunk is not a section.
#[tokio::test(flavor = "multi_thread")]
async fn a_single_chunk_is_not_a_header_section() {
    let harness = Harness::start("dual-single-chunk", bounded()).await;
    let mut client = transaction(&harness);
    let mut message = String::from("From: <a@example.net>\r\nSubject: one chunk\r\n\r\n");
    message.push_str(&"c".repeat((LIMIT as usize) * 3));
    message.push_str("\r\n");
    let bytes = message.into_bytes();
    client.pending(&bytes);
    let reply = client.command(&format!("BDAT {} LAST", bytes.len()));
    assert_eq!(
        reply.code, 250,
        "a big body in one chunk is fine: {reply:?}"
    );
    assert_eq!(harness.queued().len(), 1);
    harness.stop();
}

#[test]
fn the_default_bound_is_one_mebibyte() {
    // The default a deployment gets unless it says otherwise. Keeping it here
    // rather than only in the docs is what makes a change to it a decision
    // someone has to make on purpose.
    assert_eq!(DEFAULT_MAX_HEADER_BYTES, 1024 * 1024);
    // It has to be smaller than the default message size, or it bounds nothing.
    const _: () = assert!(DEFAULT_MAX_HEADER_BYTES < 25 * 1024 * 1024);
}
