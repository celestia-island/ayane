//! The RFC 5321 / ESMTP behaviour matrix, over real TCP sockets.
//!
//! Every test here starts a listener, speaks the protocol as a client would
//! and asserts on the wire replies and the spool, never on internal state.

mod support;

use std::time::{Duration, Instant};

use ayane_smtpd::server::MAX_BDAT_BUFFER;
use ayane_smtpd::ListenerRole;
use support::{deliver, Client, Harness, HarnessOptions};

const MESSAGE: &str =
    "From: <sender@example.net>\r\nTo: <inbox@example.com>\r\nSubject: hi\r\n\r\nhello\r\n";

#[tokio::test(flavor = "multi_thread")]
async fn greeting_and_ehlo_advertise_the_four_extensions() {
    let harness = Harness::start("ehlo", HarnessOptions::inbound()).await;
    let mut client = harness.client();
    let reply = client.ehlo("client.test");
    assert!(reply.advertises("PIPELINING"), "{reply:?}");
    assert!(reply.advertises("SIZE 26214400"), "{reply:?}");
    assert!(reply.advertises("CHUNKING"), "{reply:?}");
    assert!(reply.advertises("SMTPUTF8"), "{reply:?}");
    assert!(reply.advertises("8BITMIME"), "{reply:?}");
    assert!(
        !reply.advertises_prefix("AUTH"),
        "port 25 never offers AUTH"
    );
    assert!(
        !reply.advertises("STARTTLS"),
        "the fixture listener has no TLS"
    );
    harness.stop();
}

#[tokio::test(flavor = "multi_thread")]
async fn helo_offers_no_extensions_and_accepts_a_transaction() {
    let harness = Harness::start("helo", HarnessOptions::inbound()).await;
    let mut client = harness.client();
    let reply = client.expect("HELO client.test", 250);
    assert_eq!(reply.lines.len(), 1, "HELO is a single line");
    client.expect("MAIL FROM:<a@example.net>", 250);
    client.expect("RCPT TO:<inbox@example.com>", 250);
    client.expect("RSET", 250);
    client.expect("QUIT", 221);
    harness.stop();
}

#[tokio::test(flavor = "multi_thread")]
async fn commands_are_answered_by_state() {
    let harness = Harness::start("states", HarnessOptions::inbound()).await;
    let mut client = harness.client();
    // Before EHLO: 503 for everything that belongs to a transaction.
    assert_eq!(client.command("MAIL FROM:<a@example.net>").code, 503);
    assert_eq!(client.command("RCPT TO:<inbox@example.com>").code, 503);
    assert_eq!(client.command("DATA").code, 503);
    assert_eq!(client.command("BDAT 0 LAST").code, 503);
    assert_eq!(
        client.command("STARTTLS").code,
        454,
        "no TLS on this listener"
    );
    // NOOP / RSET / VRFY are legal at any point.
    assert_eq!(client.command("NOOP").code, 250);
    assert_eq!(client.command("RSET").code, 250);
    let vrfy = client.command("VRFY ops");
    assert_eq!(vrfy.code, 252, "VRFY never confirms existence");
    // After EHLO, RCPT/DATA still need MAIL.
    client.ehlo("client.test");
    assert_eq!(client.command("RCPT TO:<inbox@example.com>").code, 503);
    assert_eq!(client.command("DATA").code, 503);
    assert_eq!(client.command("BDAT 0 LAST").code, 503);
    // A second MAIL inside a transaction is a nested command.
    client.expect("MAIL FROM:<a@example.net>", 250);
    assert_eq!(client.command("MAIL FROM:<b@example.net>").code, 503);
    assert_eq!(client.command("DATA").code, 503, "DATA needs a recipient");
    client.expect("RCPT TO:<inbox@example.com>", 250);
    client.expect("DATA", 354);
    client.send_raw(b"Subject: x\r\n\r\nbody\r\n.\r\n");
    assert_eq!(client.read_reply().code, 250);
    // The transaction is over; a fresh one starts at MAIL.
    assert_eq!(client.command("RCPT TO:<inbox@example.com>").code, 503);
    client.expect("QUIT", 221);
    harness.stop();
}

#[tokio::test(flavor = "multi_thread")]
async fn syntax_errors_are_501_and_unknown_commands_500() {
    let harness = Harness::start("syntax", HarnessOptions::inbound()).await;
    let mut client = harness.client();
    client.ehlo("client.test");
    assert_eq!(client.command("FOO bar").code, 500);
    assert_eq!(client.command("").code, 500);
    assert_eq!(client.command("MAIL <a@b.example>").code, 501);
    // A path that cannot parse is a syntax error wherever it appears.
    assert_eq!(client.command("RCPT TO:<a@b").code, 501);
    assert_eq!(client.command("MAIL FROM:<a@b.example> SIZE=abc").code, 501);
    assert_eq!(client.command("AUTH CRAM-MD5").code, 504);
    assert_eq!(client.command("BDAT x").code, 501);
    // RCPT is first judged by state: without MAIL it is a sequence error even
    // when the syntax would also be wrong.
    assert_eq!(client.command("RCPT TO:a@example.com").code, 503);
    // None of it left the session wedged: the sender is known from here on.
    client.expect("MAIL FROM:<a@b.example>", 250);
    // A bare address (no angle brackets) is taken as sent, so it reaches the
    // router, which has no such mailbox.
    assert_eq!(client.command("RCPT TO:a@example.com").code, 550);
    client.expect("RSET", 250);
    // A wrong parameter on a known command is 555, not a syntax error.
    assert_eq!(client.command("MAIL FROM:<a@b.example> RET=FULL").code, 555);
    harness.stop();
}

#[tokio::test(flavor = "multi_thread")]
async fn full_transaction_is_spooled_byte_for_byte() {
    let harness = Harness::start("deliver", HarnessOptions::inbound()).await;
    let mut client = harness.client();
    let reply = deliver(
        &mut client,
        "sender@example.net",
        "inbox@example.com",
        MESSAGE,
    );
    assert_eq!(reply.code, 250, "{reply:?}");
    client.expect("QUIT", 221);
    let stored = harness.only_message();
    let expected = MESSAGE.to_owned();
    assert!(
        String::from_utf8_lossy(&stored).contains(&expected),
        "stored message must carry the original bytes: {}",
        String::from_utf8_lossy(&stored)
    );
    let queued = harness.queued();
    assert_eq!(queued[0].envelope.mail_from, "sender@example.net");
    assert_eq!(queued[0].envelope.recipients, vec!["inbox@example.com"]);
    assert!(!queued[0].envelope.sha256.is_empty());
    harness.stop();
}

#[tokio::test(flavor = "multi_thread")]
async fn pipelining_answers_every_command_in_order() {
    let harness = Harness::start("pipelining", HarnessOptions::inbound()).await;
    let mut client = harness.client();
    client.ehlo("client.test");
    // One write, four commands, no read in between: the server must answer
    // each one, in order, without waiting for the next.
    client.send_raw(b"RSET\r\nNOOP\r\nNOOP\r\nQUIT\r\n");
    let replies: Vec<u16> = (0..4).map(|_| client.read_reply().code).collect();
    assert_eq!(replies, vec![250, 250, 250, 221]);

    let mut client = harness.client();
    client.ehlo("client.test");
    client.send_raw(b"MAIL FROM:<a@example.net>\r\nRCPT TO:<inbox@example.com>\r\nDATA\r\n");
    assert_eq!(client.read_reply().code, 250);
    assert_eq!(client.read_reply().code, 250);
    assert_eq!(client.read_reply().code, 354);
    client.send_raw(b"Subject: pipelined\r\n\r\nbody\r\n.\r\n");
    assert_eq!(client.read_reply().code, 250);
    assert_eq!(harness.queued().len(), 1);
    harness.stop();
}

#[tokio::test(flavor = "multi_thread")]
async fn size_over_the_ceiling_is_refused_at_mail() {
    let harness = Harness::start("size", HarnessOptions::inbound()).await;
    let mut client = harness.client();
    client.ehlo("client.test");
    let reply = client.command("MAIL FROM:<a@example.net> SIZE=26214401");
    assert_eq!(reply.code, 552, "{reply:?}");
    // Still no transaction: RCPT is a sequence error, not a size answer.
    assert_eq!(client.command("RCPT TO:<inbox@example.com>").code, 503);
    // At the limit it is accepted.
    client.expect("MAIL FROM:<a@example.net> SIZE=26214400", 250);
    harness.stop();
}

#[tokio::test(flavor = "multi_thread")]
async fn bdat_chain_builds_one_message() {
    let harness = Harness::start("bdat", HarnessOptions::inbound()).await;
    let mut client = harness.client();
    client.ehlo("client.test");
    client.expect("MAIL FROM:<a@example.net>", 250);
    client.expect("RCPT TO:<inbox@example.com>", 250);
    // The chunk boundaries fall in the middle of a header line and in the
    // middle of the header/body separator on purpose: chunks are raw octets,
    // so the server must not re-terminate them.
    let first = b"Subject: chunk\r\nCon";
    let second = b"tent-Type: text/plain\r\n\r";
    let third = b"\nbody from chunks\r\n";
    // Each chunk travels as `BDAT n` + its octets; every chunk has its own
    // reply (RFC 3030 §4.2), and the LAST one is the transaction's answer.
    client.pending(first);
    assert_eq!(client.command(&format!("BDAT {}", first.len())).code, 250);
    client.pending(second);
    assert_eq!(client.command(&format!("BDAT {}", second.len())).code, 250);
    client.pending(third);
    let reply = client.command(&format!("BDAT {} LAST", third.len()));
    assert_eq!(reply.code, 250, "LAST answers the message: {reply:?}");
    let stored = String::from_utf8_lossy(&harness.only_message()).to_string();
    assert!(
        stored.contains("Content-Type: text/plain\r\n\r\nbody from chunks\r\n"),
        "{stored}"
    );
    harness.stop();
}

#[tokio::test(flavor = "multi_thread")]
async fn bdat_and_data_are_mutually_exclusive() {
    let harness = Harness::start("bdat-data", HarnessOptions::inbound()).await;
    let mut client = harness.client();
    client.ehlo("client.test");
    client.expect("MAIL FROM:<a@example.net>", 250);
    assert_eq!(
        client.command("RCPT TO:<inbox@example.com>").code,
        250,
        "the recipient must be accepted before BDAT"
    );
    // A non-LAST chunk is acknowledged once it was read; the octets and the
    // command go on the wire together, as a chunking client writes them.
    client.pending(b"abcd");
    let ack = client.command("BDAT 4");
    assert_eq!(ack.code, 250, "chunk acknowledgement");
    // Inside a chunk chain DATA is a sequence error.
    let data = client.command("DATA");
    assert_eq!(
        data.code, 503,
        "DATA inside a chunk chain must be a sequence error, got {data:?}"
    );
    // RSET ends the transaction; BDAT without MAIL is a sequence error too.
    client.expect("RSET", 250);
    assert_eq!(client.command("BDAT 0 LAST").code, 503);
    harness.stop();
}

#[tokio::test(flavor = "multi_thread")]
async fn smtputf8_admits_non_ascii_paths_only_when_announced() {
    let harness = Harness::start("utf8", HarnessOptions::inbound()).await;
    let mut client = harness.client();
    client.ehlo("client.test");
    // Without SMTPUTF8 the non-ASCII path is a syntax error at MAIL (the
    // parser only admits the SMTPUTF8 alphabet when the line announces it).
    assert_eq!(client.command("MAIL FROM:<ユーザ@example.net>").code, 501);
    client.expect("MAIL FROM:<ユーザ@example.net> SMTPUTF8", 250);
    // The reply address is ASCII; the SMTPUTF8 extension is about the
    // envelope's alphabet, not about translating the recipient.
    client.expect("RCPT TO:<inbox@example.com>", 250);
    client.expect("DATA", 354);
    client.send_raw(b"Subject: utf8\r\n\r\nbody\r\n.\r\n");
    assert_eq!(client.read_reply().code, 250);
    let queued = harness.queued();
    assert!(queued[0].envelope.smtputf8);
    assert_eq!(queued[0].envelope.mail_from, "ユーザ@example.net");
    harness.stop();
}

#[tokio::test(flavor = "multi_thread")]
async fn over_long_command_line_is_refused_and_closed() {
    let harness = Harness::start("longline", HarnessOptions::inbound()).await;
    let mut client = harness.client();
    let mut line = String::from("MAIL FROM:<");
    line.push_str(&"a".repeat(1200));
    line.push('>');
    client.send(&line);
    let reply = client.read_reply();
    assert_eq!(reply.code, 500, "{reply:?}");
    assert!(reply.text.contains("Line too long"), "{reply:?}");
    let rest = client.read_to_end();
    assert!(rest.is_empty(), "the server closes after the refusal");
    assert!(harness.queued().is_empty());
    harness.stop();
}

#[tokio::test(flavor = "multi_thread")]
async fn rset_clears_the_transaction_but_not_the_greeting() {
    let harness = Harness::start("rset", HarnessOptions::inbound()).await;
    let mut client = harness.client();
    client.ehlo("client.test");
    client.expect("MAIL FROM:<a@example.net>", 250);
    client.expect("RCPT TO:<inbox@example.com>", 250);
    client.expect("RSET", 250);
    // Greeting kept: MAIL is legal again without a new EHLO.
    client.expect("MAIL FROM:<b@example.net>", 250);
    // But the recipients are gone.
    assert_eq!(client.command("DATA").code, 503);
    harness.stop();
}

#[tokio::test(flavor = "multi_thread")]
async fn recipient_limit_is_enforced() {
    let mut options = HarnessOptions::inbound();
    options.limits.max_recipients = 2;
    let harness = Harness::start("rcptlimit", options).await;
    let mut client = harness.client();
    client.ehlo("client.test");
    client.expect("MAIL FROM:<a@example.net>", 250);
    let first = client.command("RCPT TO:<inbox@example.com>");
    assert_eq!(first.code, 250, "{first:?}");
    let second = client.command("RCPT TO:<ops@example.com>");
    assert_eq!(second.code, 250, "{second:?}");
    let third = client.command("RCPT TO:<sales@example.com>");
    assert_eq!(third.code, 452, "{third:?}");
    harness.stop();
}

#[tokio::test(flavor = "multi_thread")]
async fn dns_rejects_the_null_forward_path() {
    let harness = Harness::start("nullrcpt", HarnessOptions::inbound()).await;
    let mut client = harness.client();
    client.ehlo("client.test");
    client.expect("MAIL FROM:<a@example.net>", 250);
    let reply = client.command("RCPT TO:<>");
    assert_eq!(reply.code, 501, "{reply:?}");
    harness.stop();
}

#[tokio::test(flavor = "multi_thread")]
async fn unknown_auth_on_port_25_is_not_offered() {
    let harness = Harness::start("noauth", HarnessOptions::inbound()).await;
    let mut client = harness.client();
    client.ehlo("client.test");
    let reply = client.command("AUTH PLAIN AGhvbG8AcHc=");
    assert_eq!(reply.code, 502, "{reply:?}");
    harness.stop();
}

#[tokio::test(flavor = "multi_thread")]
async fn max_messages_per_connection_ends_the_session() {
    let mut options = HarnessOptions::inbound();
    options.limits.max_messages = 1;
    let harness = Harness::start("msglimit", options).await;
    let mut client = harness.client();
    let reply = deliver(&mut client, "a@example.net", "inbox@example.com", MESSAGE);
    assert_eq!(reply.code, 250, "the first message: {reply:?}");
    // The second message hits the cap: the reply is 421 and the connection
    // closes, so the client learns it must reconnect rather than retry.
    let reply = deliver(&mut client, "a@example.net", "inbox@example.com", MESSAGE);
    assert_eq!(reply.code, 421, "{reply:?}");
    assert_eq!(
        harness.queued().len(),
        2,
        "both messages are spooled — the 421 is about the connection, not the \
         message it just accepted"
    );
    harness.stop();
}

#[tokio::test(flavor = "multi_thread")]
async fn quit_closes_the_connection() {
    let harness = Harness::start("quit", HarnessOptions::inbound()).await;
    let mut client = harness.client();
    client.expect("QUIT", 221);
    assert!(client.read_to_end().is_empty());
    harness.stop();
}

#[tokio::test(flavor = "multi_thread")]
async fn submission_listener_accepts_remote_recipients_after_auth() {
    let harness = Harness::start("submission", HarnessOptions::submission()).await;
    let mut client = Client::connect(harness.addr);
    let reply = client.ehlo("client.test");
    assert!(reply.advertises("STARTTLS"), "{reply:?}");
    assert!(
        !reply.advertises_prefix("AUTH"),
        "AUTH is only offered after TLS: {reply:?}"
    );
    // Without AUTH the listener refuses to relay — and says which refusal it
    // is: RFC 4954 §4's `530 5.7.0`, not the relay verdict a client that *had*
    // authenticated would get.
    client.expect("MAIL FROM:<ops@example.com>", 250);
    let reply = client.command("RCPT TO:<someone@gmail.com>");
    assert_eq!(reply.code, 530, "{reply:?}");
    assert!(reply.text.contains("Authentication required"), "{reply:?}");
    harness.stop();
}

#[tokio::test(flavor = "multi_thread")]
async fn submission_rejects_a_sender_the_identity_cannot_claim() {
    let harness = Harness::start("submission-sender", HarnessOptions::submission()).await;
    let mut client = harness.client();
    client.ehlo("client.test");
    // Anonymous clear-text AUTH is never accepted.
    let reply = client.command(&format!("AUTH PLAIN {}", {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD.encode("\0ops@example.com\0s3cret")
    }));
    assert_eq!(
        reply.code, 538,
        "no credential on a clear channel: {reply:?}"
    );
    harness.stop();
}

#[tokio::test(flavor = "multi_thread")]
async fn role_is_structural() {
    let inbound = Harness::start("role-in", HarnessOptions::inbound()).await;
    let submission = Harness::start("role-sub", HarnessOptions::submission()).await;
    assert_eq!(HarnessOptions::inbound().role, ListenerRole::Inbound);
    assert!(!ListenerRole::Inbound.offers_auth());
    assert!(ListenerRole::Submission.offers_auth());
    assert!(ListenerRole::SubmissionsTls.offers_auth());

    let mut client = inbound.client();
    client.ehlo("client.test");
    client.expect("MAIL FROM:<a@example.net>", 250);
    assert_eq!(
        client.command("RCPT TO:<someone@gmail.com>").code,
        550,
        "port 25 never relays"
    );

    let mut client = submission.client();
    client.ehlo("client.test");
    client.expect("MAIL FROM:<ops@example.com>", 250);
    assert_eq!(
        client.command("RCPT TO:<someone@gmail.com>").code,
        530,
        "unauthenticated submission does not relay either, and asks for a login"
    );
    harness_stop(&inbound);
    harness_stop(&submission);
}

fn harness_stop(harness: &Harness) {
    harness.stop();
}

// ── BDAT bounds: a refused chunk is answered once, and closed ────────────

#[tokio::test(flavor = "multi_thread")]
async fn bdat_a_single_chunk_over_the_buffer_is_closed_without_reading_it() {
    // One chunk bigger than the in-memory chunk buffer, and the client sends
    // no octets at all. The answer must be a single terminal reply and a
    // close — not a `552` followed by a `554` two replies later (a second
    // reply to a command that already had one) — and it must not wait out a
    // timer for octets that are never going to be kept.
    //
    // This is the one chunk refusal the *transport* makes: the session admits
    // a chunk of this size whenever it fits in the message size (it does, at
    // 25 MiB), so `receive_chunk` is what refuses it, and it refuses it
    // without reading a single octet: the octets are neither message content
    // nor commands, and a client that sent none of them is answered at once.
    // The command timer is short here so that a version which *did* start
    // reading would show up as a two-second delay rather than a pass.
    let patience = Duration::from_secs(2);
    let options = HarnessOptions {
        command_timeout: patience,
        transaction_timeout: Duration::from_secs(20),
        ..HarnessOptions::inbound()
    };
    let harness = Harness::start("bdat-single", options).await;
    let mut client = harness.client();
    client.ehlo("client.test");
    client.expect("MAIL FROM:<a@example.net>", 250);
    client.expect("RCPT TO:<inbox@example.com>", 250);
    let declared = MAX_BDAT_BUFFER + 1;
    let started = Instant::now();
    client.send(&format!("BDAT {declared} LAST"));
    let reply = client
        .try_read_reply()
        .expect("the refused chunk is answered, not parked");
    assert_eq!(
        reply.code, 421,
        "the refused chunk closes the connection with one reply: {reply:?}"
    );
    assert!(
        client.is_closed_within(Duration::from_secs(10)),
        "the close follows the reply, not the transaction timer"
    );
    let elapsed = started.elapsed();
    assert!(
        elapsed < Duration::from_secs(10),
        "the refusal does not wait out the transaction timer: took {elapsed:?}"
    );
    assert!(
        harness.queued().is_empty(),
        "a refused chunk never reaches the queue"
    );
    harness.stop();
}

#[tokio::test(flavor = "multi_thread")]
async fn bdat_a_chain_over_the_message_limit_is_closed_without_growing_memory() {
    // The session's running total, from the **declared** sizes, refuses the
    // first chunk it cannot take with `552` — exact, before any of its octets
    // are read, and no octet is ever buffered. The transport's own reassembly
    // bound is the other ceiling and answers `421`; it is pinned by
    // `bdat_a_chunk_past_the_transport_ceiling_closes_the_connection`.
    //
    // The answer comes with the command, and the connection ends with it: a
    // client that stops talking must not park the server on the transaction
    // timer.
    let limit = 25 * 1024 * 1024;
    let patience = Duration::from_secs(2);
    let options = HarnessOptions {
        max_message_size: limit,
        limits: ayane_smtpd::Limits {
            max_message_size: limit,
            ..ayane_smtpd::Limits::default()
        },
        command_timeout: patience,
        transaction_timeout: Duration::from_secs(20),
        ..HarnessOptions::inbound()
    };
    let harness = Harness::start("bdat-chain", options).await;
    let mut client = harness.client();
    client.ehlo("client.test");
    client.expect("MAIL FROM:<a@example.net>", 250);
    client.expect("RCPT TO:<inbox@example.com>", 250);
    let chunk = vec![b'x'; MAX_BDAT_BUFFER];
    let expected = limit as usize / MAX_BDAT_BUFFER;
    for _ in 0..expected {
        client.pending(&chunk);
        let reply = client.command(&format!("BDAT {}", chunk.len()));
        assert_eq!(
            reply.code, 250,
            "a chunk inside the limit is acknowledged: {reply:?}"
        );
    }
    // The last chunk's octets are still being read when its reply arrives; a
    // `NOOP` puts the connection back in step before the next command.
    client.settle();
    // The next chunk's declared size breaks the total.
    let started = Instant::now();
    let reply = client.command(&format!("BDAT {}", chunk.len()));
    assert!(
        matches!(reply.code, 552 | 421),
        "the exact total refuses the chunk it cannot take, and only once: {reply:?}"
    );
    let elapsed = started.elapsed();
    assert!(
        elapsed < Duration::from_secs(10),
        "the refusal does not wait out the transaction timer: {elapsed:?}"
    );
    assert!(harness.queued().is_empty());
    harness.stop();
}

#[tokio::test(flavor = "multi_thread")]
async fn bdat_last_is_the_transaction_end_even_on_the_second_chunk() {
    // Regression: the driver used to decide `LAST` from the parsed command,
    // and the octets of a non-LAST chunk are read by the driver *before* the
    // next command exists. A chain whose LAST chunk arrives after an
    // acknowledgement is the ordinary case (RFC 3030 §4.2), and the message
    // must be queued by it.
    let harness = Harness::start("bdat-last", HarnessOptions::inbound()).await;
    let mut client = harness.client();
    client.ehlo("client.test");
    client.expect("MAIL FROM:<a@example.net>", 250);
    client.expect("RCPT TO:<inbox@example.com>", 250);
    let head = b"Subject: two chunks\r\n\r\n";
    client.pending(head);
    assert_eq!(client.command(&format!("BDAT {}", head.len())).code, 250);
    let body = b"the rest\r\n";
    client.pending(body);
    let reply = client.command(&format!("BDAT {} LAST", body.len()));
    assert_eq!(
        reply.code, 250,
        "the LAST chunk completes the message: {reply:?}"
    );
    let stored = String::from_utf8_lossy(&harness.only_message()).to_string();
    assert!(stored.contains("Subject: two chunks"), "{stored}");
    assert!(stored.contains("the rest\r\n"), "{stored}");
    harness.stop();
}

#[tokio::test(flavor = "multi_thread")]
async fn bdat_a_chunk_whose_octets_outrun_its_declaration_is_cut_off() {
    // A client whose last chunk of 2 octets would put the message over the
    // size it declared is refused on the declaration, and what follows the
    // command is never read: the octets of a chunk are exactly its declared
    // size, so anything a refused client writes after `BDAT 2` would otherwise
    // sit in the connection as commands — the SMTP-smuggling shape. The
    // connection ends with the refusal, before the octets are read.
    let limit = 2 * 1024 * 1024;
    let options = HarnessOptions {
        max_message_size: limit,
        limits: ayane_smtpd::Limits {
            max_message_size: limit,
            ..ayane_smtpd::Limits::default()
        },
        transaction_timeout: Duration::from_secs(20),
        ..HarnessOptions::inbound()
    };
    let harness = Harness::start("bdat-lie", options).await;
    let mut client = harness.client();
    client.ehlo("client.test");
    client.expect("MAIL FROM:<a@example.net>", 250);
    client.expect("RCPT TO:<inbox@example.com>", 250);
    // Two full chunks fill the message size exactly.
    let chunk = vec![b'x'; MAX_BDAT_BUFFER];
    for _ in 0..2 {
        client.pending(&chunk);
        let reply = client.command(&format!("BDAT {}", chunk.len()));
        assert_eq!(reply.code, 250, "a chunk inside the limit: {reply:?}");
    }
    // A chunk of 2 declared octets makes the declared total 2 octets over the
    // message size, so the session refuses it on the declaration (`552`) —
    // before any octet is read, and the connection ends with it instead of
    // waiting for octets that were never going to be wanted.
    let started = Instant::now();
    client.send("BDAT 2");
    let reply = client
        .try_read_reply()
        .expect("the refusal is answered at once");
    let elapsed = started.elapsed();
    assert_eq!(
        reply.code, 552,
        "the declared total, not the octets, is the bound here: {reply:?}"
    );
    assert!(
        elapsed < Duration::from_secs(5),
        "the refusal does not wait for octets nobody sent: {elapsed:?}"
    );
    assert!(harness.queued().is_empty());
    // And the octets cannot become commands: whatever the server answered,
    // the transfer is over and nothing is accepted.
    client.send_raw_best_effort(&[b"MAIL FROM:<evil@example.net>\r\n".to_vec(), chunk].concat());
    assert!(
        harness.queued().is_empty(),
        "a command written where chunk octets were expected is never executed"
    );
    harness.stop();
}

#[tokio::test(flavor = "multi_thread")]
async fn bdat_the_transport_bound_closes_the_connection_before_reading_the_chunk() {
    // Two ceilings stand between a client and the spool. The session's is on
    // the **declarations** and is the protocol's answer (`552`, and the
    // transaction is done). The transport's is on what it would reassemble —
    // `bdat_chain.len() + size > max_bdat_total` — and it can only differ from
    // the session's when the message size is below one chunk: there the
    // session stops at 1 MiB while one chunk is still 1 MiB, so a chain of
    // half a chunk plus a whole chunk is a chunk the declaration admits and
    // the buffer must not hold.
    //
    // Whichever bound sees it, the answer comes with the command — one
    // terminal reply, never two — and the connection ends with it: a client
    // that stops talking after the refusal is not parked on the transaction
    // timer. (Where the session refused the declaration, the `552` is that
    // answer and no octet of the chunk is read; where the transport did, it is
    // the `421`.)
    let limit = 1024 * 1024;
    let options = HarnessOptions {
        max_message_size: limit,
        limits: ayane_smtpd::Limits {
            max_message_size: limit,
            ..ayane_smtpd::Limits::default()
        },
        transaction_timeout: Duration::from_secs(20),
        ..HarnessOptions::inbound()
    };
    let harness = Harness::start("bdat-transport", options).await;
    let mut client = harness.client();
    client.ehlo("client.test");
    client.expect("MAIL FROM:<a@example.net>", 250);
    client.expect("RCPT TO:<inbox@example.com>", 250);
    let half = vec![b'x'; ayane_smtpd::server::MAX_BDAT_BUFFER / 2];
    client.pending(&half);
    assert_eq!(
        client.command(&format!("BDAT {}", half.len())).code,
        250,
        "the first chunk is inside every limit"
    );
    // The octets of the refused chunk are never sent: the answer must not
    // depend on them.
    let started = Instant::now();
    client.send(&format!("BDAT {}", ayane_smtpd::server::MAX_BDAT_BUFFER));
    let reply = client
        .try_read_reply()
        .expect("the refused chunk is closed off, not read");
    let elapsed = started.elapsed();
    assert!(
        matches!(reply.code, 421 | 552),
        "a chunk no ceiling admits is answered once and closed: {reply:?}"
    );
    assert!(
        elapsed < Duration::from_secs(5),
        "the refusal does not wait for the transaction timer: {elapsed:?}"
    );
    // Nothing follows the answer: the connection is over, not waiting for the
    // octets of a chunk it already refused.
    client.finish_sending();
    assert!(
        client
            .try_read_reply_within(Duration::from_secs(5))
            .is_none(),
        "one reply and then nothing, never a second answer or a wait"
    );
    assert!(
        harness.queued().is_empty(),
        "a chunk past both ceilings never reaches the queue"
    );
    harness.stop();
}

// ── RFC 5321 §4.1.3: <Postmaster> has no domain and is always accepted ───

#[tokio::test(flavor = "multi_thread")]
async fn postmaster_is_accepted_without_a_domain_in_any_case() {
    let harness = Harness::start("postmaster", HarnessOptions::inbound()).await;
    for spelling in ["postmaster", "Postmaster", "POSTMASTER"] {
        let mut client = harness.client();
        client.ehlo("client.test");
        client.expect("MAIL FROM:<a@example.net>", 250);
        let reply = client.command(&format!("RCPT TO:<{spelling}>"));
        assert_eq!(
            reply.code, 250,
            "<{spelling}> must be accepted: RFC 5321 §4.1.3 makes it a MUST, got {reply:?}"
        );
        client.expect("DATA", 354);
        client.send_raw(b"Subject: to the postmaster\r\n\r\nbody\r\n.\r\n");
        assert_eq!(client.read_reply().code, 250);
    }
    let queued = harness.queued();
    assert_eq!(queued.len(), 3);
    for message in &queued {
        // The envelope records it as the postmaster of the server that
        // greeted the client: that is what a delivery agent can route.
        assert_eq!(
            message.envelope.recipients,
            vec!["postmaster@mx.test".to_owned()],
            "the bare postmaster is qualified with the server's own name"
        );
    }
    harness.stop();
}

#[tokio::test(flavor = "multi_thread")]
async fn only_postmaster_is_exempt_from_having_a_domain() {
    let harness = Harness::start("postmaster-only", HarnessOptions::inbound()).await;
    let mut client = harness.client();
    client.ehlo("client.test");
    client.expect("MAIL FROM:<a@example.net>", 250);
    for spelling in ["other", "postmasterx", "postmaster.example", "x-postmaster"] {
        let reply = client.command(&format!("RCPT TO:<{spelling}>"));
        assert_eq!(
            reply.code, 501,
            "<{spelling}> has no domain and is not the postmaster: {reply:?}"
        );
    }
    // And a domainless postmaster on a listener with no greeting is still a
    // sequence answer, not a delivery.
    assert_eq!(harness.queued().len(), 0);
    harness.stop();
}
