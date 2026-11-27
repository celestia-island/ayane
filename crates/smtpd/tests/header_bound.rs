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

/// One transport's answer to a message: the transaction's final reply and how
/// many messages the listener queued.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    /// The `250` of the transaction, the `554` of a failed one, or a `552` for
    /// a bound.
    pub code: u16,
    /// The reply text, empty for a reply that carried none.
    pub text: String,
    /// How many messages the listener spooled.
    pub queued: usize,
}

/// Sends `message` over both transports, on separate listeners with the same
/// bound, and returns what each transport answered.
///
/// Every test in this module that is about *agreement* goes through here, so
/// the two paths are exercised by the same octets, the same fixture and the
/// same limit — the only thing that differs is the transport. The whole reply
/// is kept, not just its code, because "same code" is the weaker half of the
/// duality: a `554 5.6.0 Transaction failed` and a `554 5.7.1 Sender rejected`
/// agree on the code and disagree about the reason, and only the text pair
/// shows it.
///
/// # What the two legs actually send
///
/// The `BDAT` leg sends `message` as one `LAST` chunk. The `DATA` leg sends
/// `message`, and a `.<CRLF>` terminator **only if the transfer does not
/// answer first**. That is deliberately not "the same octets go into both":
/// the compared thing is the message plus its terminator — one wire form of one
/// message — because `DATA` has a terminator and `BDAT` does not (see the
/// `server` module's "where the two transports genuinely differ"). Claiming
/// more than that would be wrong in two directions at once: a bare `.<CRLF>`
/// inside a chunk is body, and a bare `.<CRLF>` inside a `DATA` body is the
/// terminator.
///
/// The conditional terminator is also what makes the refusals comparable. A
/// transfer that fails on the octets does not answer at once: a **failed**
/// `DATA` transfer drains the rest of the upload before it replies, so a sender
/// that keeps its socket open with no terminator coming is answered only when
/// the drain ends — the transaction timer (20 s in this fixture). That is
/// measured, and it is why the first version of these tests reported a `554`
/// for the `DATA` leg: it had already appended the terminator before reading,
/// so the reply it read was the post-drain one. Without the terminator the same
/// transfer says nothing for 20 s and then answers `554 5.6.0 Transaction
/// failed` — not `421`: the timer bounds the drain, it does not close the
/// connection. The terminator supplied here ends the drain at once, so both
/// transports answer the same question ("what is wrong with these octets?")
/// instead of the same question one timer apart. `tb15` and
/// `a_terminator_after_a_bare_lf_does_not_resume_the_session` cover the drain
/// itself, where that timing is the thing under test.
async fn both_ways(tag: &str, message: &[u8]) -> (Verdict, Verdict) {
    let data_harness = Harness::start(&format!("{tag}-data"), bounded()).await;
    let mut client = transaction(&data_harness);
    client.expect("DATA", 354);
    // The message, then — if the transfer does not answer on its own — the
    // terminator that completes the wire form (see this function's doc).
    client.send_raw(message);
    let data_reply = client.try_read_reply_within(std::time::Duration::from_millis(500));
    let data_reply = match data_reply {
        Some(reply) => reply,
        None => {
            client.send_raw(b".\r\n");
            client.read_reply()
        }
    };
    let queued_over_data = data_harness.queued().len();
    data_harness.stop();

    let bdat_harness = Harness::start(&format!("{tag}-bdat"), bounded()).await;
    let mut client = transaction(&bdat_harness);
    client.pending(message);
    let bdat_reply = client.command(&format!("BDAT {} LAST", message.len()));
    let queued_over_bdat = bdat_harness.queued().len();
    bdat_harness.stop();

    (
        Verdict {
            code: data_reply.code,
            text: data_reply.text,
            queued: queued_over_data,
        },
        Verdict {
            code: bdat_reply.code,
            text: bdat_reply.text,
            queued: queued_over_bdat,
        },
    )
}

/// Asserts the duality every message in this module is supposed to have: the
/// two transports answer the same code with the same text, and queue the same
/// number of messages.
#[track_caller]
fn assert_duality(what: &str, data: &Verdict, bdat: &Verdict) {
    assert_eq!(
        (bdat.code, bdat.text.as_str()),
        (data.code, data.text.as_str()),
        "{what}: DATA answered {data:?} and BDAT answered {bdat:?} — one \
         answer per transport is the invariant, not merely one code"
    );
    assert_eq!(
        bdat.queued, data.queued,
        "{what}: the transports queued different numbers of messages: \
         DATA {data:?}, BDAT {bdat:?}"
    );
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
#[tokio::test(flavor = "multi_thread")]
async fn both_transports_answer_the_same_message_the_same_way() {
    /// A body several times the header bound, as a string.
    fn big_body() -> String {
        let mut body = String::new();
        for _ in 0..200 {
            body.push_str(&"b".repeat(64));
            body.push_str("\r\n");
        }
        body
    }

    let head = "From: <a@example.net>\r\nSubject: dual\r\n\r\n";
    let body = big_body();
    assert!(
        (head.len() as u64) <= LIMIT,
        "the section must fit under the bound: {} vs {LIMIT}",
        head.len()
    );
    assert!(
        body.len() as u64 > 2 * LIMIT,
        "the body must dwarf the bound: {} vs {LIMIT}",
        body.len()
    );

    let (data, bdat) = both_ways("dual", format!("{head}{body}").as_bytes()).await;
    assert_eq!(
        data.code, 250,
        "a small head over DATA is accepted, whatever the body weighs"
    );
    assert_eq!(
        bdat.code, 250,
        "and over BDAT: the blank line ends the section there too"
    );
    assert_duality("a small head and a big body", &data, &bdat);
    assert_eq!(data.queued, 1, "the DATA copy is queued");
    assert_eq!(bdat.queued, 1, "the BDAT copy is queued");
}

/// The empty-header message: the very first line is already the blank line.
///
/// This is the shape a `CRLFCRLF` search cannot size. `<CRLF><CRLF>` occurs at
/// offset 0 there — but the second of those CRLFs is the **body's first line
/// ending**, not a blank line, and taking it as one charges the section four
/// octets where `DATA` charges two. Every message with an empty header was
/// then charged two octets too much over `BDAT`, and the two transports
/// diverged for any bound within two octets of the real section.
///
/// Hence the **exact** body: `2 * limit - 4` octets, so the section plus the
/// body's first line lands two octets past the limit. A small body would make
/// this test pass under both readings — which is how the defect survived a
/// full suite the first time. Under the `CRLFCRLF` reading the charged
/// "section" is the blank line *plus* that first body line, which is
/// `limit + 2`: refused. Under the line rule it is two octets: accepted.
#[tokio::test(flavor = "multi_thread")]
async fn an_empty_header_is_the_same_two_octets_over_both_transports() {
    // `\r\n` (the whole section) + `q` repeated + `\r\n` (the body's first
    // line) + `tail\r\n`. The first body line must end `limit - 2` octets
    // into the body, so `4 + (limit - 2) = limit + 2` is what a `CRLFCRLF`
    // search would charge.
    let limit = LIMIT as usize;
    let mut message = b"\r\n".to_vec();
    message.extend(std::iter::repeat_n(b'q', limit + 2 - 4 - 2));
    message.extend_from_slice(b"\r\ntail\r\n");

    let (data, bdat) = both_ways("dual-empty", &message).await;
    assert_eq!(data.code, 250, "an empty header over DATA: {data:?}");
    assert_eq!(
        bdat.code, 250,
        "an empty header over BDAT — a `CRLFCRLF` search would charge the \
         body's first line as part of the section and answer 552: {bdat:?}"
    );
    assert_duality("an empty header", &data, &bdat);
    assert_eq!(data.queued, 1);
    assert_eq!(bdat.queued, 1);
}

/// The same, one line further in: `<CRLF>` (the empty first line ends the
/// section there) then a body whose first line is long enough that a
/// `CRLFCRLF` search would swallow it.
#[tokio::test(flavor = "multi_thread")]
async fn an_empty_header_over_a_long_first_body_line_agrees() {
    let limit = LIMIT as usize;
    let mut message = b"\r\n".to_vec();
    message.extend(std::iter::repeat_n(b'z', limit + 8));
    message.extend_from_slice(b"\r\nmore body\r\n");
    let (data, bdat) = both_ways("dual-short", &message).await;
    assert_eq!(data.code, 250, "two octets of head over DATA");
    assert_eq!(bdat.code, 250, "and over BDAT");
    assert_duality("an empty header over a long first line", &data, &bdat);
}

/// A head with a bare `LF` is refused by both transports, with the same code.
///
/// `DATA` refuses a bare `LF` outright rather than guessing at it — treating
/// it as a line break is the SMTP smuggling hole (CVE-2023-51764), so the
/// whole transfer fails with the transaction's `554 5.6.0`. A chained message
/// carrying the same octets has to be refused too, and for the same reason:
/// answering it `250` because the chunk arrived in one piece would make the
/// two transports disagree about whether the message is readable at all —
/// a larger disagreement than the size one, since here one of them would be
/// accepting octets the other will not parse.
///
/// The message is small on purpose (25 octets): the refusal must come from
/// the malformed line, not from any size bound.
#[tokio::test(flavor = "multi_thread")]
async fn a_bare_lf_in_the_head_is_refused_by_both_transports() {
    let message = b"Subject: x\nfake\r\n\r\nbody\r\n";
    assert_eq!(message.len(), 25, "small enough that no bound applies");
    let (data, bdat) = both_ways("dual-bare-lf", message).await;
    assert_eq!(
        data.code, 554,
        "DATA fails the transaction on a bare LF: {data:?}"
    );
    assert_eq!(
        bdat.code, 554,
        "and BDAT must not answer 250 to octets DATA refuses: {bdat:?}"
    );
    assert_duality("a bare LF in the head", &data, &bdat);
    assert_eq!(data.queued, 0, "nothing is queued over DATA");
    assert_eq!(bdat.queued, 0, "nothing is queued over BDAT");
}

/// The same, with the bare `LF` in a folded line rather than the first field:
/// the rejection cannot be a "the first line looks odd" shortcut.
#[tokio::test(flavor = "multi_thread")]
async fn a_bare_lf_in_a_folded_head_line_is_refused_by_both_transports() {
    let message = b"Subject: ok\r\n bad\nline\r\n\r\nbody\r\n";
    let (data, bdat) = both_ways("dual-bare-lf-fold", message).await;
    assert_eq!(data.code, 554, "DATA: {data:?}");
    assert_eq!(bdat.code, 554, "BDAT: {bdat:?}");
    assert_duality("a bare LF in a folded head line", &data, &bdat);
    assert_eq!(bdat.queued, 0);
}

/// The bound is **derived** rather than assumed: `limit` octets of section
/// is accepted and `limit + 1` is refused, over both transports.
///
/// A section of exactly `limit` is not over a bound of `limit` — the
/// comparison is strict — and the two transports have to agree about that
/// too. The earlier plan for this test pinned `limit` on the refusing side;
/// running it showed the boundary is one octet further out, which is the
/// reason a calibration test exists rather than a comment saying where the
/// line is.
///
/// The octets are asserted before the replies are: a fixture that is off by
/// one would quietly move the boundary the test is supposed to measure, and
/// the failure would look like a server bug.
#[tokio::test(flavor = "multi_thread")]
async fn the_bound_is_a_strict_inequality_on_both_transports() {
    /// A header section of exactly `section` octets: one field line, then the
    /// blank line, both counted.
    fn head_of(section: usize) -> Vec<u8> {
        // `X:` + padding + CRLF (the field), then the blank line's CRLF.
        let overhead = b"X:".len() + 2 + 2;
        assert!(section >= overhead, "a field and a blank line");
        let mut head = b"X:".to_vec();
        head.extend(std::iter::repeat_n(b'p', section - overhead));
        head.extend_from_slice(b"\r\n\r\n");
        assert_eq!(head.len(), section, "the fixture must be exact");
        head
    }

    let limit = LIMIT as usize;
    // `limit` fits; the octet after it does not.
    for (section, expected) in [(limit - 1, 250), (limit, 250), (limit + 1, 552)] {
        let mut message = head_of(section);
        message.extend_from_slice(b"body\r\n");
        let (data, bdat) = both_ways(&format!("edge-{section}"), &message).await;
        assert_eq!(
            data.code, expected,
            "a {section}-octet head over DATA (bound {limit}): \
             `section > limit` is the rule"
        );
        assert_eq!(
            bdat.code, expected,
            "a {section}-octet head over BDAT (bound {limit}): same rule"
        );
        assert_duality(&format!("a {section}-octet head"), &data, &bdat);
    }
}

/// The refusing side of the duality: **no blank line at all** past the bound
/// is a header section over the bound over either transport.
///
/// The fix above must not have made `BDAT` permissive, only *symmetric*. A
/// message whose head never ends is refused by `DATA` for the reason the bound
/// exists (the verifier would hold it whole), and `BDAT` has to say the same.
#[tokio::test(flavor = "multi_thread")]
async fn both_transports_refuse_a_head_that_never_ends() {
    let mut endless = String::from("From: <a@example.net>\r\n");
    endless.push_str(&headers(200));
    assert!(
        endless.len() as u64 > LIMIT,
        "the head must outgrow the bound: {} vs {LIMIT}",
        endless.len()
    );

    let (data, bdat) = both_ways("dual-refuse", endless.as_bytes()).await;
    for (transport, verdict) in [("DATA", &data), ("BDAT", &bdat)] {
        assert_eq!(verdict.code, 552, "{transport}: a head with no blank line");
    }
    assert_duality("a head that never ends", &data, &bdat);
    assert_eq!(data.queued, 0);
    assert_eq!(bdat.queued, 0);
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

// ── a bare LF in the BODY ────────────────────────────────────────────────
//
// The header tests above are about the *head*: `charge_message` sizes the
// section before the blank line and refuses one of its lines that does not end
// in `CRLF`. The body behind the blank line never reached that scan, so a
// chained record whose head was clean and whose body carried a bare `LF` was
// answered `250` — while the same octets over `DATA` were refused `554 5.6.0`,
// because `read_body_line` refuses a bare `LF` anywhere in the transfer.
//
// That is CVE-2023-51764 at the *BDAT* boundary: the body is where a smuggled
// envelope would be put (`\r\n\r\nfirst\r\n\n.\nMAIL FROM:…`), and answering
// `250` to it means the spool holds octets this server told the sender it
// would never accept. The three shapes below are the ones that were measured
// on the unfixed tree (first body line / deep in the body / a large body past
// the head), and each one went `DATA = 554`, `BDAT = 250` before the fix and
// `554`/`554` after it.

/// The three body shapes a bare `LF` was hiding in, as one list so the tests
/// below cannot quietly cover only the easy one.
///
/// Every message starts with a **clean** head (its own bare-`LF` scan does not
/// fire), so a failure here can only come from the body scan.
fn body_bare_lf_shapes() -> Vec<(&'static str, Vec<u8>)> {
    let head = b"From: <a@example.net>\r\nSubject: body bare lf\r\n\r\n";

    // 1. The very first line of the body, ending in a bare `LF`.
    let mut first_line = head.to_vec();
    first_line.extend_from_slice(b"first\r\nstill the body\nmore\r\n");

    // 2. Deep in the body: far past the blank line, dozens of well-formed
    //    lines in, so a scan that only looks at the start of the body misses
    //    it. The bare `LF` carries the smuggling shape of the classic attack:
    //    a `\n.\n` after it would be a second message to a server that reads
    //    `LF` as a line break.
    let mut deep = head.to_vec();
    for index in 0..64 {
        deep.extend_from_slice(format!("line {index}\r\n").as_bytes());
    }
    deep.extend_from_slice(b"before\r\n\n.\nMAIL FROM:<evil@example.net>\r\n");
    deep.extend_from_slice(b"after the smuggle attempt\r\n");

    // 3. A large body whose one bare `LF` sits past the header bound: the
    //    head fits, so this is not a size refusal, and it is the shape that
    //    says the scan has to cover the *whole* record rather than the part
    //    the header budget happened to look at.
    let mut large = head.to_vec();
    let filler = b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd\r\n";
    while large.len() < LIMIT as usize * 4 {
        large.extend_from_slice(filler);
    }
    large.extend_from_slice(b"tail\r\nsmuggled\n\r\n");

    vec![
        ("first-body-line", first_line),
        ("deep-in-the-body", deep),
        ("large-body", large),
    ]
}

/// The three measured body shapes, each refused by **both** transports with
/// the same `554 5.6.0 Transaction failed`, and nothing queued either way.
///
/// Before the fix this test failed on the `BDAT` half of every shape: the
/// head's bare-`LF` scan stopped at the blank line, so an unclean body behind
/// a clean head was spooled and answered `250`. The message below is the one
/// the fix has to make impossible to accept: the octets `DATA` refuses are the
/// octets a smuggled envelope would be built from.
#[tokio::test(flavor = "multi_thread")]
async fn a_bare_lf_in_the_body_is_refused_by_both_transports() {
    for (shape, message) in body_bare_lf_shapes() {
        // The head is clean: this is the body's check under test, not the
        // head's. The first `\r\n\r\n` is the blank line, and nothing before
        // it carries a bare `LF`.
        let section = message
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .expect("the fixture has a blank line")
            + 4;
        let clean = message[..section]
            .iter()
            .enumerate()
            .all(|(index, octet)| *octet != b'\n' || message[index - 1] == b'\r');
        assert!(
            clean,
            "{shape}: the head must be clean or this test is about the head"
        );

        let (data, bdat) = both_ways(&format!("body-{shape}"), &message).await;
        assert_eq!(
            data.code, 554,
            "{shape}: DATA fails the transaction on a body bare LF: {data:?}"
        );
        assert_eq!(
            data.text, "5.6.0 Transaction failed",
            "{shape}: the transaction's own refusal: {data:?}"
        );
        assert_eq!(
            bdat.code, 554,
            "{shape}: BDAT answered {bdat:?} to octets DATA refuses with 554 — \
             a chained record must not be spooled because its head was clean"
        );
        assert_eq!(
            bdat.text, "5.6.0 Transaction failed",
            "{shape}: the same refusal, not merely the same code: {bdat:?}"
        );
        assert_duality(shape, &data, &bdat);
        assert_eq!(data.queued, 0, "{shape}: nothing is queued over DATA");
        assert_eq!(bdat.queued, 0, "{shape}: nothing is queued over BDAT");
    }
}

/// The control for the body scan: a body with **only** `CRLF` line endings is
/// accepted by both transports, however many lines and how many octets it has.
///
/// Without this, a scan that refused every chained message would pass the test
/// above. The body here is several times the header bound and spans many
/// lines, so an over-eager "reject the whole record" would show up here.
#[tokio::test(flavor = "multi_thread")]
async fn a_body_of_only_crlf_is_accepted_by_both_transports() {
    let mut message = b"From: <a@example.net>\r\nSubject: clean body\r\n\r\n".to_vec();
    for index in 0..400 {
        message.extend_from_slice(format!("body line {index} with content\r\n").as_bytes());
    }
    // A trailing `CRLF` and a line that ends the body: nothing here is a bare
    // `LF`, and every `\n` is preceded by a `\r`.
    message.extend_from_slice(b"last line\r\n");
    assert!(
        message.len() as u64 > 2 * LIMIT,
        "the body must dwarf the header bound: {} vs {LIMIT}",
        message.len()
    );
    let (data, bdat) = both_ways("body-clean", &message).await;
    assert_eq!(data.code, 250, "a CRLF body over DATA: {data:?}");
    assert_eq!(
        bdat.code, 250,
        "a CRLF body over BDAT must stay accepted — the scan refuses bare LF, \
         not chunked messages: {bdat:?}"
    );
    assert_duality("a CRLF body", &data, &bdat);
    assert_eq!(data.queued, 1);
    assert_eq!(bdat.queued, 1);
}

/// A body whose **first** line is empty and whose `LF`s are all part of a
/// `CRLF`: the boundary of the rule.
///
/// The bare-`LF` test in the other direction (`\n` at the start of a line) is
/// what a naive `contains(&b'\n')` gets wrong: the octet after every legal line
/// ending *is* an `LF`, and a check that looked for `\n` at a line start
/// without looking behind it would refuse every message with a blank line in
/// it. This message is mostly blank lines.
#[tokio::test(flavor = "multi_thread")]
async fn a_body_of_blank_lines_agrees_both_ways() {
    let mut message = b"From: <a@example.net>\r\n\r\n".to_vec();
    for _ in 0..64 {
        message.extend_from_slice(b"\r\n");
    }
    message.extend_from_slice(b"after the blanks\r\n");
    let (data, bdat) = both_ways("body-blank-lines", &message).await;
    assert_eq!(
        data.code, 250,
        "blank lines are `CRLF`-terminated lines, not bare LFs: {data:?}"
    );
    assert_eq!(bdat.code, 250, "and over BDAT: {bdat:?}");
    assert_duality("a body of blank lines", &data, &bdat);
    assert_eq!(bdat.queued, 1);
}

/// A `DKIM-Signature` carrying an `l=` (body-length, RFC 6376 §3.5) tag does
/// not change the answer: a bare `LF` behind the blank line is still refused by
/// both transports.
///
/// `l=` is the one signature form that *invites* a sender to append octets past
/// what was signed, so it is exactly where a smuggled envelope would be put.
/// The transport refusal is upstream of DKIM — it has to fire before any body
/// hash is taken, whatever the signature says about how much of the body it
/// covers — and the two transports have to agree that it does.
#[tokio::test(flavor = "multi_thread")]
async fn a_body_length_signature_does_not_excuse_a_body_bare_lf() {
    use base64::Engine;
    use mail_auth::crypto::{HashContext, HashImpl, Sha256};
    use mail_auth::headers::Writable;

    // The signed prefix and the `bh=` it hashes to, under `simple`
    // canonicalization (the prefix, then one CRLF).
    let signed_body = b"this part is signed\r\n";
    let signed = signed_body.len() as u64;
    let canonical = [signed_body.as_slice(), b"\r\n"].concat();
    let mut hasher = <Sha256 as HashImpl>::hasher();
    canonical.as_slice().write(&mut hasher);
    let bh = base64::engine::general_purpose::STANDARD.encode(hasher.complete().as_ref());

    let head = format!(
        "From: <a@example.net>\r\nSubject: l tag\r\n\
         DKIM-Signature: v=1; a=rsa-sha256; c=simple/simple; d=example.net; \
         s=s1; l={signed}; h=From:Subject; bh={bh}; b=AAAA\r\n\r\n"
    );

    // The unsigned tail carries the bare `LF`: the shape a sender would use to
    // append a second envelope under a signature that covers only the prefix.
    let mut message = head.into_bytes();
    message.extend_from_slice(signed_body);
    message.extend_from_slice(b"unsigned tail\r\nsmuggled\nMAIL FROM:<evil@example.net>\r\n");

    // The signature must really be in the message, or this test proves nothing
    // about `l=`.
    let text = String::from_utf8_lossy(&message);
    assert!(text.contains("; l="), "the fixture must carry the l= tag");
    assert!(
        text.contains(&format!("l={signed};")),
        "the fixture must carry the limit it hashes: {signed}"
    );

    let (data, bdat) = both_ways("body-l-signature", &message).await;
    assert_eq!(
        data.code, 554,
        "DATA refuses the bare LF in the unsigned tail: {data:?}"
    );
    assert_eq!(
        bdat.code, 554,
        "and BDAT: an `l=` signature is not a licence to append octets: {bdat:?}"
    );
    assert_duality("a body-length signature", &data, &bdat);
    assert_eq!(data.queued, 0);
    assert_eq!(bdat.queued, 0);
}

// ── S1: the `.<CRLF>` line a bare `LF` puts in reach ─────────────────────
//
// A bare `LF` is not a terminator, and this server does not read one as a
// line break — but the octets that follow it are still in the stream, and one
// of them can be a real `.<CRLF>` line. Data refused mid-transfer is drained
// up to the next terminator before the `554` goes out (a client that has
// uploaded a failed message must not have its upload re-read as commands), so
// the question this section pins is: *where does that drain stop, and what
// happens to what it walked over?*
//
// The answer used to be "it stops at the `.<CRLF>` the sender put after the
// bare `LF`, discards everything up to there, and executes the rest".
// Measured on the unfixed tree, `…\r\n\r\nprompt\r\n.\r\nMAIL FROM:<evil@…>\r\n
// …\r\nDATA\r\nsecond\r\n.\r\n` written in one piece produced **two queued
// messages**: the refused transfer's clean prefix, and a second message with
// `mail_from = evil@example.net` from a transaction the sender wrote behind its
// own terminator. That is a smuggled envelope, not a protocol difference — a
// real `DATA` transfer has exactly one terminator and everything after it is
// commands the client only sends once it has been answered.

/// The data this section is about, as one transfer: a clean head, then `body`,
/// then a forged transaction behind a terminator the sender chose.
///
/// `body` is written exactly as given, so it ends where the caller says it
/// ends — a body that ends in a bare `LF` leaves the `.<CRLF>` on the *next*
/// line to be a "line" only to a reader that guessed at the `LF`.
fn smuggled_transaction_behind(body: &[u8]) -> Vec<u8> {
    let mut wire = b"From: <a@example.net>\r\nSubject: s1\r\n\r\n".to_vec();
    wire.extend_from_slice(body);
    wire.extend_from_slice(b".\r\n");
    wire.extend_from_slice(b"MAIL FROM:<evil@example.net>\r\n");
    wire.extend_from_slice(b"RCPT TO:<inbox@example.com>\r\n");
    wire.extend_from_slice(b"DATA\r\nsecond\r\n.\r\n");
    wire
}

/// Every octet a client sends after a failed transfer's drain must be thrown
/// away, whatever the client got away with before it.
///
/// The drain stops at the first `.<CRLF>` in the stream because that is what a
/// client means by "end of message" — but a transfer that is already failing
/// has no terminator worth trusting: the sender chose those octets, and the
/// upload was never acknowledged. So everything the drain walks over, and
/// anything behind it, is discarded — never executed, never queued.
/// How a client writes the wire matters for this rule, so both writes are
/// tested: one piece, and split across two writes with a pause between them.
///
/// The split is not a variant for coverage's sake. A `DATA` transfer that fails
/// is drained up to the client's terminator *before* the `554` goes out, so the
/// only octets the drain does not already hold are the ones a sender writes
/// **after** its terminator — which a single `write` never produces, because
/// they arrive together with the terminator. A sender that splits its upload
/// produces them, and that is the sender the discard rule exists for. A test
/// that only writes the wire in one piece proves nothing about it: it passed
/// against a build that was still smuggling.
#[tokio::test(flavor = "multi_thread")]
async fn a_terminator_after_a_bare_lf_does_not_resume_the_session() {
    // Two prefixes, both failing before the terminator: a bare `LF` on the
    // body's first line (the shape that was measured), and a bare `LF` deep
    // in the body after clean lines.
    let mut deep = Vec::new();
    for index in 0..32 {
        deep.extend_from_slice(format!("line {index}\r\n").as_bytes());
    }
    deep.extend_from_slice(b"tail\n");
    for (shape, body) in [
        // The measured shape: the body's first line ends in a bare `LF`, so
        // the `.<CRLF>` after it is a "line" only to a reader that accepts the
        // bare `LF` as a line break — which this server does not.
        ("bare-lf-first-line", b"prompt\n".to_vec()),
        ("bare-lf-deep", deep),
    ] {
        let harness = Harness::start(&format!("s1-{shape}"), bounded()).await;
        let mut client = transaction(&harness);
        client.expect("DATA", 354);
        // One write: the whole thing is on the wire before the server can
        // answer anything, which is the shape that used to desynchronise.
        // (`Client::send_raw_pieces` writes it in one go: a `write_all` of this
        // much can block on a loopback socket whose reader is still uploading,
        // and a test that then waits for a fixed time gets a timing race
        // dressed up as a server behaviour.)
        client.send_raw_pieces(&smuggled_transaction_behind(&body));
        // The one-piece write above is the shape that reaches the drain
        // already complete; `a_tail_split_across_writes_is_discarded_too`
        // covers the one that does not.

        let first = client
            .try_read_reply_within(Duration::from_secs(5))
            .unwrap_or_else(|| panic!("{shape}: the transfer must be answered"));
        assert_eq!(
            (first.code, first.text.as_str()),
            (554, "5.6.0 Transaction failed"),
            "{shape}: a bare LF fails the transfer: {first:?}"
        );
        // The forged transaction must not be answered as a transaction: no
        // `250 Sender OK`, no `354`, no second `250`.
        let mut answers = Vec::new();
        while let Some(reply) = client.try_read_reply_within(Duration::from_millis(300)) {
            answers.push(format!("{} {}", reply.code, reply.text));
        }
        assert!(
            answers.is_empty(),
            "{shape}: nothing behind a failed transfer's drain may be executed, \
             and the server answered {answers:?}"
        );
        // The one thing that must be true either way: the forged envelope is
        // not in the queue.
        let queued = harness.queued();
        let senders: Vec<String> = queued
            .iter()
            .map(|m| m.envelope.mail_from.clone())
            .collect();
        assert!(
            !senders.iter().any(|from| from == "evil@example.net"),
            "{shape}: a forged envelope was queued: {senders:?}"
        );
        harness.stop();
    }
}

/// The shape where a sender picks the terminator: a bare `LF` on the last
/// body line, then a `.<CRLF>` line behind it, then a forged transaction.
///
/// `…\r\n\r\nprompt\n.\r\nMAIL FROM:<evil@…>\r\n…\r\nDATA\r\nsecond\r\n.\r\n`
///
/// The `LF` after `prompt` is bare, so this transfer fails — but a failing
/// transfer is still drained up to the first `.<CRLF>` in the stream, and the
/// sender is the one who wrote that `.<CRLF>`. Handing the octets behind it
/// back to the command reader makes the *refused* transfer a channel for a
/// whole forged transaction (measured under the loose drain as two queued
/// messages, the second from `evil@example.net`). So the drain's octets, and
/// everything behind the line it stops at, are body: discarded, never
/// executed, never queued.
#[tokio::test(flavor = "multi_thread")]
async fn octets_behind_a_terminator_in_a_failed_transfer_are_discarded() {
    let wire = smuggled_transaction_behind(b"prompt\n");
    let harness = Harness::start("s1-terminator", bounded()).await;
    let mut client = transaction(&harness);
    client.expect("DATA", 354);
    client.send_raw_pieces(&wire);

    let first = client
        .try_read_reply_within(Duration::from_secs(5))
        .expect("a refused transfer is answered");
    assert_eq!(
        (first.code, first.text.as_str()),
        (554, "5.6.0 Transaction failed"),
        "the transfer that wrote the bare LF is the one refused: {first:?}"
    );
    // Nothing behind it runs: no `250 Sender OK`, no `354`, no second `250`.
    let mut answers = Vec::new();
    while let Some(reply) = client.try_read_reply_within(Duration::from_millis(300)) {
        answers.push(format!("{} {}", reply.code, reply.text));
    }
    assert!(
        answers.is_empty(),
        "octets behind a failed transfer's terminator are body, never commands: \
         the server answered {answers:?}"
    );
    // The refused transfer queued nothing — not its prefix, not the forgery.
    let senders: Vec<String> = harness
        .queued()
        .iter()
        .map(|m| m.envelope.mail_from.clone())
        .collect();
    assert!(
        senders.is_empty(),
        "a refused transfer queues nothing, and certainly not a forged envelope: {senders:?}"
    );
    harness.stop();
}

/// The same failure, written in **two** pieces: the failing octets and the
/// sender's own terminator, then — after a pause the server can see — the
/// transaction forged behind it.
///
/// This is the shape that got through when the drain's own bookkeeping was the
/// only thing discarding: the drain consumed the terminator and returned with
/// the read buffer empty, so the octets that arrived afterwards were read by
/// the command loop as if the client had waited for the `554` and then started
/// a new transaction. Measured before the fix: `554 5.6.0`, then
/// `250 Sender OK` / `250 Recipient OK` / `354` / `250`, with
/// `evil@example.net` in the queue.
#[tokio::test(flavor = "multi_thread")]
async fn a_tail_split_across_writes_is_discarded_too() {
    let harness = Harness::start("s1-split-write", bounded()).await;
    let mut client = transaction(&harness);
    client.expect("DATA", 354);

    // First piece: everything up to and including the terminator the sender
    // wrote. This is what the drain consumes.
    let mut first = b"From: <a@example.net>\r\nSubject: s1\r\n\r\n".to_vec();
    first.extend_from_slice(b"prompt\n.\r\n");
    client.send_raw(&first);

    // The pause is what makes the second piece arrive *after* the drain: with
    // one write both pieces are in the kernel buffer together and the drain
    // discards them there, which is why the one-piece test cannot see this.
    tokio::time::sleep(Duration::from_millis(20)).await;

    // Second piece: the forged transaction, written by a sender that has not
    // read the `554` yet.
    client.send_raw_pieces(
        b"MAIL FROM:<evil@example.net>\r\nRCPT TO:<inbox@example.com>\r\nDATA\r\nsecond\r\n.\r\n",
    );

    let first_reply = client
        .try_read_reply_within(Duration::from_secs(5))
        .expect("the refused transfer is answered");
    assert_eq!(
        (first_reply.code, first_reply.text.as_str()),
        (554, "5.6.0 Transaction failed"),
        "{first_reply:?}"
    );
    // The tail is answered — a server that goes silent on it is a server that
    // has stopped talking to its client — but answered as what it is: the
    // commands a refused transfer carried. `MAIL FROM` opens nothing (`503`),
    // and nothing after it can run without an envelope.
    while let Some(reply) = client.try_read_reply_within(Duration::from_millis(300)) {
        assert_ne!(
            reply.code, 250,
            "no step of a forged transaction may be accepted: {reply:?}"
        );
        assert!(
            !reply.text.contains("Sender OK") && !reply.text.contains("Recipient OK"),
            "a forged envelope must not be honoured: {reply:?}"
        );
    }
    let senders: Vec<String> = harness
        .queued()
        .iter()
        .map(|m| m.envelope.mail_from.clone())
        .collect();
    assert!(
        senders.is_empty(),
        "nothing is queued from a refused transfer, however its writes were \
         split: {senders:?}"
    );
    harness.stop();
}

/// The same tail, written **after** the client has read the `554`.
///
/// A sender that was told its transfer failed cannot then continue that
/// transfer: what it writes next begins from wherever the server left the
/// conversation. The connection is still open (a `554` is not a `421`), so the
/// next bytes must be a new command — and the octets of a forged transaction
/// are not ones this server will run as a consequence of the transfer it just
/// refused.
#[tokio::test(flavor = "multi_thread")]
async fn a_forged_tail_sent_after_the_refusal_is_not_executed() {
    let harness = Harness::start("s1-after-reply", bounded()).await;
    let mut client = transaction(&harness);
    client.expect("DATA", 354);
    let mut first = b"From: <a@example.net>\r\nSubject: s1\r\n\r\n".to_vec();
    first.extend_from_slice(b"prompt\n.\r\n");
    client.send_raw(&first);

    let reply = client
        .try_read_reply_within(Duration::from_secs(5))
        .expect("the refused transfer is answered");
    assert_eq!(
        (reply.code, reply.text.as_str()),
        (554, "5.6.0 Transaction failed")
    );

    tokio::time::sleep(Duration::from_secs(3)).await;
    client.send_raw_pieces(
        b"MAIL FROM:<evil@example.net>\r\nRCPT TO:<inbox@example.com>\r\nDATA\r\nsecond\r\n.\r\n",
    );
    while let Some(reply) = client.try_read_reply_within(Duration::from_millis(300)) {
        assert_ne!(
            reply.code, 250,
            "nothing written after a refusal may resume the refused upload: \
             {reply:?}"
        );
    }
    let senders: Vec<String> = harness
        .queued()
        .iter()
        .map(|m| m.envelope.mail_from.clone())
        .collect();
    assert!(senders.is_empty(), "nothing is queued: {senders:?}");
    harness.stop();
}

/// R1's exact wire, pinned as **not** a defect — the terminator is where a
/// `DATA` transfer says it is, bare `LF`s after it are commands, and the
/// transaction they belong to was never refused.
///
/// `…\r\n\r\n.\r\n\nMAIL FROM:<evil@…>\r\n…`
///
/// Read as `DATA`, the `.<CRLF>` right after the blank line **is** the
/// terminator: the message is the empty body above it, and it is valid. The
/// bare `LF` that follows lands in the command stream, where a line ending in a
/// bare `LF` is an empty command (`500`) — a protocol fact, not a smuggling
/// hole, because the sender wrote those octets *after* its own terminator and
/// behind a message the server accepted. The rest of the wire is a normal
/// pipelined transaction.
///
/// **What this test pins is that those octets are executed as commands** — not
/// when they are answered. Measured, the answers do not come back in the order
/// they were caused: the `250` for the accepted message and the `500` for the
/// empty line arrive first, and the pipelined transaction's replies arrive only
/// after the drain has been asked for and has ended — a transfer is drained
/// before its answer goes out, and on this wire the drain has nothing to stop
/// at until the transaction timer, so the forge is answered *after* it. The
/// bytes are executed either way, which is why this is a legitimate pipelining
/// client and not a refusal being resumed. (An earlier version of this comment
/// said the pipeline ran "as it always has", which reads as a claim about
/// timing; it was not.)
///
/// R1's construction is therefore a `DATA` transfer whose forge lives behind
/// an **acknowledged** message, not one whose forge lives behind a **refused**
/// one; the smuggling case is the two tests above.
#[tokio::test(flavor = "multi_thread")]
async fn a_forge_behind_an_acknowledged_terminator_is_plain_pipelining() {
    let wire = concat!(
        "From: <a@example.net>\r\nSubject: s1\r\n\r\n",
        ".\r\n\n",
        "MAIL FROM:<evil@example.net>\r\n",
        "RCPT TO:<inbox@example.com>\r\n",
        "DATA\r\nsecond\r\n.\r\n",
    );
    let harness = Harness::start("s1-r1-wire", bounded()).await;
    let mut client = transaction(&harness);
    client.expect("DATA", 354);
    client.send_raw_pieces(wire.as_bytes());

    // The acknowledged empty message.
    let first = client
        .try_read_reply_within(Duration::from_secs(5))
        .expect("the empty message is answered");
    assert_eq!(
        (first.code, first.text.as_str()),
        (250, "2.0.0 OK: queued"),
        "the `.<CRLF>` after the blank line is the terminator: {first:?}"
    );
    // The bare `LF` after it is a command line that is empty. (This one *is*
    // in order; the transaction behind it is not — see this test's doc.)
    let empty = client
        .try_read_reply_within(Duration::from_secs(5))
        .expect("the empty command line is answered");
    assert_eq!(
        empty.code, 500,
        "a bare `LF` in the command stream is an empty command: {empty:?}"
    );
    // Then the pipelined transaction runs, exactly as it would for any client
    // that sent its commands early.
    for expected in [
        (250, "2.1.0 Sender OK"),
        (250, "2.1.5 Recipient OK"),
        (354, "Start mail input; end with <CRLF>.<CRLF>"),
        (250, "2.0.0 OK: queued"),
    ] {
        let reply = client
            .try_read_reply_within(Duration::from_secs(5))
            .expect("the pipelined transaction is answered");
        assert_eq!((reply.code, reply.text.as_str()), expected, "{reply:?}");
    }
    let senders: Vec<String> = harness
        .queued()
        .iter()
        .map(|m| m.envelope.mail_from.clone())
        .collect();
    assert_eq!(
        senders,
        vec!["a@example.net".to_owned(), "evil@example.net".to_owned()],
        "both messages are queued: the acknowledged one and the pipelined one"
    );
    harness.stop();
}

/// The same wire, one octet of difference: **no** bare `LF` in the prefix, a
/// clean body, then the `.<CRLF>` and a forged transaction behind it.
///
/// This is the control the rule has to leave alone. Here the `.<CRLF>` **is**
/// the message's terminator, the transfer succeeds (the message is queued), and
/// the octets behind it are the client's next commands — pipelining, which the
/// server has always accepted and which is exactly what a client that wrote
/// its commands in one piece expects.
#[tokio::test(flavor = "multi_thread")]
async fn a_valid_transfer_still_allows_pipelining_behind_its_terminator() {
    let harness = Harness::start("s1-control", bounded()).await;
    let mut client = transaction(&harness);
    client.expect("DATA", 354);
    client.send_raw_pieces(&smuggled_transaction_behind(b"prompt\r\n"));
    // The answers the server owes for octets it was sent in one piece: the
    // transfer's `250`, then the pipelined transaction's `250 Sender OK`,
    // `250 Recipient OK`, `354`, and its own `250`.
    let expected = [
        (250, "2.0.0 OK: queued"),
        (250, "2.1.0 Sender OK"),
        (250, "2.1.5 Recipient OK"),
        (354, "Start mail input; end with <CRLF>.<CRLF>"),
        (250, "2.0.0 OK: queued"),
    ];
    for (code, text) in expected {
        let reply = client
            .try_read_reply_within(Duration::from_secs(5))
            .unwrap_or_else(|| panic!("a valid transfer and its pipeline are answered: {code}"));
        assert_eq!((reply.code, reply.text.as_str()), (code, text), "{reply:?}");
    }
    // Both messages are queued, each from the sender that wrote it: the first
    // is the transfer, the second is the transaction the client pipelined
    // behind its own terminator — which is a client sending early, not a
    // sender smuggling octets past a refusal.
    let senders: Vec<String> = harness
        .queued()
        .iter()
        .map(|m| m.envelope.mail_from.clone())
        .collect();
    assert_eq!(
        senders,
        vec!["a@example.net".to_owned(), "evil@example.net".to_owned()],
        "both messages are queued, in the order the client wrote them"
    );
    harness.stop();
}

/// The trade the refusal makes, from the client's side: **one `503`, then the
/// client is back to normal.**
///
/// The server cannot tell a refused transfer's tail from a new command at the
/// byte level — both are `MAIL FROM:`-style lines — so the first command after
/// a refusal is refused (`503`) and the next one is served. The decision is of
/// 2026-11-26, and it exists so that a legitimate client that had nothing to do
/// with the tail pays one retry and never loses its connection.
///
/// This is the contract the previous test protects from the other side: that
/// test proves a forged tail can never open a transaction; this one proves the
/// cost of that protection is exactly one `503` and nothing more.
#[tokio::test(flavor = "multi_thread")]
async fn a_refusal_costs_one_503_and_a_retry_recovers() {
    let harness = Harness::start("s1-retry", bounded()).await;
    let mut client = transaction(&harness);
    client.expect("DATA", 354);
    let mut first = b"From: <a@example.net>\r\nSubject: s1\r\n\r\n".to_vec();
    first.extend_from_slice(b"prompt\n.\r\n");
    client.send_raw(&first);
    let refusal = client
        .try_read_reply_within(Duration::from_secs(5))
        .expect("the refused transfer is answered");
    assert_eq!(
        (refusal.code, refusal.text.as_str()),
        (554, "5.6.0 Transaction failed")
    );

    // The client tries to start a new message straight after the `554`: the
    // server is still discarding the tail and answers `503` — it is not
    // pretending the command was garbage, and it is not closing the socket.
    client.send("MAIL FROM:<a@example.net>");
    let first_after = client
        .try_read_reply_within(Duration::from_secs(5))
        .expect("the command after a refusal is answered");
    assert_eq!(
        (first_after.code, first_after.text.as_str()),
        (503, "5.5.1 Bad sequence of commands"),
        "one command, one answer, connection still open: {first_after:?}"
    );

    // The retry is served in full: a complete transaction and a message that
    // queues. This is what "a client that retries once is back to normal"
    // means, and it is what the `503` above must not cost.
    client.expect("MAIL FROM:<a@example.net>", 250);
    client.expect("RCPT TO:<inbox@example.com>", 250);
    client.expect("DATA", 354);
    let mut body = b"From: <a@example.net>\r\nSubject: retry\r\n\r\n".to_vec();
    body.extend_from_slice(b"a clean retry\r\n.\r\n");
    client.send_raw(&body);
    let queued_reply = client
        .try_read_reply_within(Duration::from_secs(5))
        .expect("the retried message is answered");
    assert_eq!(
        (queued_reply.code, queued_reply.text.as_str()),
        (250, "2.0.0 OK: queued"),
        "{queued_reply:?}"
    );
    let senders: Vec<String> = harness
        .queued()
        .iter()
        .map(|m| m.envelope.mail_from.clone())
        .collect();
    assert_eq!(
        senders,
        vec!["a@example.net".to_owned()],
        "the retried message is the only one queued: {senders:?}"
    );
    harness.stop();
}
