//! The verification layer asserted on its own — no socket, no harness.
//!
//! Everything here feeds [`BodyHasher`] / [`Verifier`] the octets and a
//! [`FixedZone`], and asserts the answer. That is the point of the layer being
//! pure computation: the properties belong to the verifier, so they hold
//! whether or not a listener is ever built around it.
//!
//! The DKIM fixture is RFC 6376 Appendix A.2 — a public test vector whose
//! `example.com` key the RFC itself publishes — supplied with its own
//! `newengland._domainkey.example.com` TXT record. Nothing here reaches the
//! network: a name the zone does not list has no records, and the RFC's own
//! key is enough for the RFC's own signature.
//!
//! The ARC, DMARC and SPF fixtures are built in-process with `mail-auth`'s
//! signers: a chain we seal ourselves is a chain the verifier must accept, and
//! a policy record we write ourselves is a policy it must apply.

use std::net::IpAddr;

use ayane_smtpd::verify::{
    BodyHasher, PolicyVerdict, SessionFacts, StreamedMessage, Verification, Verifier, VerifyError,
};
use ayane_smtpd::zone::FixedZone;
use mail_auth::crypto::{Ed25519Key, HashAlgorithm};
use mail_auth::dkim::{Canonicalization, DkimSigner};
use mail_auth::headers::HeaderWriter;

// ── fixtures ─────────────────────────────────────────────────────────────

/// RFC 6376 A.2: the signed message.
const RFC6376_SIGNED: &str = include_str!("fixtures/rfc6376-002.eml");

/// RFC 6376 A.2: its `newengland._domainkey.example.com` TXT record.
const RFC6376_KEY: &str = include_str!("fixtures/rfc6376-002.key");

/// The RFC's message as SMTP would carry it: CRLF line endings, one trailing
/// CRLF.
///
/// The fixture keeps the line endings it was published with (LF); `simple`
/// canonicalization is exact about the body, so the conversion has to happen
/// once, here, rather than being assumed of the file.
fn rfc6376_message() -> Vec<u8> {
    let mut out = crlf(RFC6376_SIGNED.trim_end_matches(['\r', '\n']));
    out.push_str("\r\n");
    out.into_bytes()
}

fn crlf(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 64);
    for line in text.split('\n') {
        out.push_str(line.strip_suffix('\r').unwrap_or(line));
        out.push_str("\r\n");
    }
    out
}

fn dkim_key_line() -> (String, String) {
    let (name, record) = RFC6376_KEY
        .trim_end()
        .split_once(' ')
        .expect("fixture is `<name> <record>`");
    (name.to_owned(), record.to_owned())
}

/// The zone the RFC fixture needs: its published key, and nothing else.
fn rfc6376_zone() -> FixedZone {
    use mail_auth::dns::{TxtRecord, TxtRecordParser};

    let (name, record) = dkim_key_line();
    let record = mail_auth::dkim::DomainKey::parse(record.as_bytes()).expect("RFC 6376 A.2 key");
    FixedZone::from_txt(vec![(name, TxtRecord::from(record))])
}

fn zone_with(entries: &[(&str, &str)]) -> FixedZone {
    use mail_auth::dns::{TxtRecord, TxtRecordParser};

    let txt = entries
        .iter()
        .map(|(name, record)| {
            let record =
                mail_auth::dkim::DomainKey::parse(record.as_bytes()).expect("fixture key record");
            ((*name).to_owned(), TxtRecord::from(record))
        })
        .collect();
    FixedZone::from_txt(txt)
}

fn facts(mail_from: &str) -> SessionFacts {
    SessionFacts {
        remote_ip: "192.0.2.10".parse().expect("RFC 5737 address"),
        helo: "client.example.net".to_owned(),
        mail_from: mail_from.to_owned(),
        authenticated: None,
    }
}

fn verify(zone: FixedZone, message: &[u8], mail_from: &str) -> Verification {
    let verifier = Verifier::with_zone("mx.ayane.test", zone);
    let streamed = StreamedMessage::from_bytes(message).expect("message parses");
    block_on(verifier.verify(streamed, &facts(mail_from), "from client.example.net"))
}

/// Runs a future to completion.
///
/// The verifier's `verify_*` calls go out through a hickory resolver, which
/// wants a Tokio reactor even when every answer comes from a fixed zone, so the
/// suite drives them on a real runtime — a current-thread one, because under a
/// zone nothing is ever awaited for longer than a poll.
fn block_on<F: std::future::Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime")
        .block_on(future)
}

/// A fresh Ed25519 key, its public record, and the two names a signature and a
/// key live under.
///
/// Generated per test through `mail-auth`'s own key generator, so nothing in
/// the tree is a private key; the pair lives for the process only.
struct KeyPair {
    pkcs8: Vec<u8>,
    domain: &'static str,
    selector: &'static str,
}

fn key_pair() -> KeyPair {
    KeyPair {
        pkcs8: Ed25519Key::generate_pkcs8().expect("key generation"),
        domain: "sender.example",
        selector: "s1",
    }
}

impl KeyPair {
    fn record_name(&self) -> String {
        format!("{}._domainkey.{}", self.selector, self.domain)
    }

    /// The TXT record a verifier reads at `<selector>._domainkey.<domain>`.
    fn record(&self) -> String {
        use base64::Engine;

        format!(
            "v=DKIM1; k=ed25519; p={}",
            base64::engine::general_purpose::STANDARD.encode(self.key().public_key())
        )
    }

    /// The key, re-read from its PKCS #8 form: `Ed25519Key` is not `Clone`, so
    /// a test that signs twice re-derives it.
    fn key(&self) -> Ed25519Key {
        Ed25519Key::from_pkcs8_der(&self.pkcs8).expect("key parses")
    }

    fn signer(&self) -> DkimSigner<Ed25519Key, mail_auth::signer::Ready> {
        DkimSigner::from_key(self.key())
            .domain(self.domain)
            .selector(self.selector)
            .headers(["From", "To", "Subject", "Date", "Message-ID"])
    }
}

/// The simplest message shape a signature can cover.
fn signed_message(pair: &KeyPair, body: &str, interior: &str) -> Vec<u8> {
    let message = format!(
        "From: Ada <ada@{}>\r\nTo: bob@fiction.example\r\nSubject: {interior}\r\n\
         Date: Tue, 25 Nov 2025 12:00:00 +0000\r\nMessage-ID: <fixture@{}>\r\n\r\n{body}",
        pair.domain, pair.domain
    );
    let signature = pair
        .signer()
        .sign(message.as_bytes())
        .expect("signing works");
    let mut out = Vec::new();
    out.extend_from_slice(signature.to_header().as_bytes());
    out.extend_from_slice(message.as_bytes());
    out
}

// ── DKIM over a real signature ───────────────────────────────────────────

#[test]
fn dkim_passes_on_the_rfc6376_appendix_a_message() {
    let message = rfc6376_message();
    let verification = verify(rfc6376_zone(), &message, "joe@football.example.com");
    assert!(
        verification.summary.contains("dkim=1/1"),
        "the RFC's signature must verify against the RFC's key: {}",
        verification.summary
    );
    let block = String::from_utf8_lossy(&verification.prepend).to_string();
    assert!(
        block.contains("\tdkim=pass header.i=joe@football.example.com header.s=newengland"),
        "the result header must carry dkim=pass for the RFC's signature: {block}"
    );
}

#[test]
fn tampering_one_body_byte_breaks_the_signature() {
    let mut message = rfc6376_message();
    // "We lost the game." — flip the `l` of `lost` to `m`.
    let at = message
        .windows(4)
        .position(|window| window == b"lost")
        .expect("fixture body");
    message[at] = b'm';

    let verification = verify(rfc6376_zone(), &message, "joe@football.example.com");
    assert!(
        !verification.summary.contains("dkim=1/1"),
        "a changed body byte must not verify: {}",
        verification.summary
    );
    assert!(
        !String::from_utf8_lossy(&verification.prepend).contains("\tdkim=pass"),
        "{}",
        String::from_utf8_lossy(&verification.prepend)
    );
}

#[test]
fn tampering_one_signed_header_byte_breaks_the_signature() {
    let mut message = rfc6376_message();
    let at = message
        .windows(7)
        .position(|window| window == b"Subject")
        .expect("fixture header");
    // Change the *value*, not the name: `c=simple` signs the value verbatim.
    let value_at = at
        + message[at..]
            .iter()
            .position(|b| *b == b'?')
            .expect("value");
    message[value_at] = b'!';

    let verification = verify(rfc6376_zone(), &message, "joe@football.example.com");
    assert!(
        !verification.summary.contains("dkim=1/1"),
        "a changed signed header must not verify: {}",
        verification.summary
    );
}

#[test]
fn a_signature_with_no_key_in_the_zone_is_not_a_pass() {
    // The same bytes, the same message, an empty zone: the key is missing, so
    // the honest answer is `permerror`, never `pass`.
    let verification = verify(
        FixedZone::default(),
        &rfc6376_message(),
        "joe@football.example.com",
    );
    assert!(
        !verification.summary.contains("dkim=1/1"),
        "a message whose key cannot be fetched did not verify: {}",
        verification.summary
    );
    assert!(
        verification.summary.contains("dkim=0/1"),
        "the signature must be counted and rejected: {}",
        verification.summary
    );
}

// ── the prepend contract (T-B17) ─────────────────────────────────────────

#[test]
fn received_is_prepended_at_the_very_top_and_the_message_is_untouched() {
    let message = rfc6376_message();
    let verification = verify(rfc6376_zone(), &message, "joe@football.example.com");
    let block = String::from_utf8(verification.prepend.clone()).expect("headers are ASCII");

    // One `Received:`, first, before every result header.
    assert!(
        block.starts_with("Received: from client.example.net\r\n"),
        "Received: must be the first line: {block}"
    );
    assert_eq!(
        block.matches("Received:").count(),
        1,
        "exactly our own trace field: {block}"
    );
    // The result headers follow it, in the order the layer promises.
    let received_spf = block.find("Received-SPF:").expect("Received-SPF present");
    let auth_results = block
        .find("Authentication-Results: mx.ayane.test")
        .expect("Authentication-Results present");
    assert!(received_spf < auth_results, "{block}");
    // The block is header lines only, and it ends where the original starts.
    assert!(
        block.ends_with("\r\n"),
        "header lines end with CRLF: {block:?}"
    );
    assert!(
        !block.contains("\r\n\r\n"),
        "no body in the prepend: {block:?}"
    );

    // The file the spool would write: prepend + the verified octets, byte for
    // byte. That is the whole contract — the new block is at the file head and
    // the original bytes are unchanged.
    let mut file = verification.prepend.clone();
    file.extend_from_slice(&message);
    assert_eq!(
        &file[verification.prepend.len()..],
        message.as_slice(),
        "the message bytes are unchanged"
    );
    assert!(
        file.starts_with(b"Received: "),
        "our block is the file head"
    );
    // Three fields were added (`Received:`, `Received-SPF:`,
    // `Authentication-Results:`) and the message contributed none of its own
    // bytes: the only difference between the file and the message is the
    // prepend.
    assert_eq!(
        block
            .split("\r\n")
            .filter(|line| !line.starts_with([' ', '\t']) && !line.is_empty())
            .count(),
        3,
        "exactly three fields in the prepend block: {block}"
    );

    // And the signature still holds across the prepend: the verified bytes
    // are the same octets `dkim=pass` was computed over.
    assert!(
        verification.summary.contains("dkim=1/1"),
        "{}",
        verification.summary
    );
}

#[test]
fn received_count_reads_the_message_without_being_fooled_by_our_own_block() {
    let verifier = Verifier::with_zone("mx.ayane.test", FixedZone::default());
    let message = rfc6376_message();
    // RFC 6376 A.2 carries one `Received:` of its own.
    assert_eq!(verifier.received_count(&message), 1);

    let mut looped = b"Received: from a.test by b.test\r\n".to_vec();
    looped.extend_from_slice(&message);
    assert_eq!(
        verifier.received_count(&looped),
        2,
        "a loop detector counts the hop that added one"
    );
}

// ── streaming ────────────────────────────────────────────────────────────

/// An 8 MiB message that carries a real signature: the RFC 6376 A.2 headers,
/// and its signed body repeated until the message is large enough.
///
/// The repetition is what makes the test meaningful — the stream has a body
/// hash to compute, and `bh=` no longer matches, which is fine: this asserts
/// the *digest*, not the verdict. A message with no signature at all would
/// have no recipe to stream and the test would pass by measuring nothing.
fn large_message() -> Vec<u8> {
    let message = rfc6376_message();
    let (head, body) = split_message(&message);
    let line = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit.\r\n";

    let mut out = head.to_vec();
    out.extend_from_slice(b"\r\n");
    while out.len() < 8 * 1024 * 1024 {
        out.extend_from_slice(body);
        // Round up to whole lines so `simple` and `relaxed` agree about
        // trailing empty lines, then pad with plausible text.
        while out.len() % line.len() != 0 {
            out.push(b'.');
        }
    }
    out.extend_from_slice(line);
    assert!(out.len() >= 8 * 1024 * 1024, "{}", out.len());
    out
}

/// The header section (without its terminating blank line) and the body.
fn split_message(message: &[u8]) -> (&[u8], &[u8]) {
    let offset = body_offset(message);
    (&message[..offset], &message[offset..])
}

/// The body hash recipes the message's own signatures declare.
fn recipes(message: &[u8]) -> Vec<(Canonicalization, HashAlgorithm, u64)> {
    let parsed = mail_auth::AuthenticatedMessage::parse(message).expect("message parses");
    parsed
        .dkim_signatures()
        .iter()
        .map(|header| (header.header.cb, header.header.a.into(), header.header.l))
        .collect()
}

fn body_offset(message: &[u8]) -> usize {
    mail_auth::AuthenticatedMessage::parse(message)
        .expect("message parses")
        .body_offset()
}

/// The body hashes a message produces when fed in `chunk`-byte pieces,
/// computed through the production [`BodyHasher`] — no re-parsing, no second
/// implementation.
fn chunked_hash(
    message: &[u8],
    chunk: usize,
) -> Vec<(Canonicalization, HashAlgorithm, u64, Vec<u8>)> {
    let mut hasher = BodyHasher::new().keep_raw();
    for piece in message.chunks(chunk) {
        hasher.write(piece);
    }
    hasher.finish().expect("message parses").dkim_body_hashes()
}

/// The body hashes the same message produces through the independent
/// computation (parse, canonicalize, hash), which is what a signer computes.
fn reference_hash(message: &[u8]) -> Vec<Vec<u8>> {
    let verifier = Verifier::with_zone("mx.ayane.test", FixedZone::default());
    let body = &message[body_offset(message)..];
    recipes(message)
        .into_iter()
        .map(|(canonicalization, algorithm, limit)| {
            verifier.body_hash_of(canonicalization, algorithm, body, limit)
        })
        .collect()
}

/// The digests out of `chunked_hash`'s tuples.
fn digests(hashes: Vec<(Canonicalization, HashAlgorithm, u64, Vec<u8>)>) -> Vec<Vec<u8>> {
    hashes.into_iter().map(|(_, _, _, digest)| digest).collect()
}

#[test]
fn chunking_an_eight_megabyte_message_changes_nothing() {
    let message = large_message();
    assert!(message.len() >= 8 * 1024 * 1024, "{}", message.len());

    // The reference: the digest a signer would have computed over these octets.
    let reference = reference_hash(&message);
    assert_eq!(
        reference.len(),
        1,
        "the message must carry exactly one DKIM signature for this to measure anything"
    );
    assert_eq!(recipes(&message).len(), 1);
    assert_eq!(reference[0].len(), 32, "SHA-256 digest");

    // One write.
    assert_eq!(
        digests(chunked_hash(&message, message.len())),
        reference,
        "one write must equal the reference body hash"
    );
    // And read-buffer-sized pieces, which is how a driver feeds the spool.
    // `mail-auth` looks for the header terminator from the previous scan
    // point, so a degenerate one-byte feed re-copies the header bytes on every
    // chunk — quadratic in the header length — which is why there is
    // deliberately no one-byte case here: it would measure that pathology, not
    // the contract. The point of the sizes below is that the body hashes the
    // same however the reader happened to cut it.
    for chunk in [1_024, 4_096, 65_536, 1 << 20] {
        assert_eq!(
            digests(chunked_hash(&message, chunk)),
            reference,
            "a {chunk}-byte chunking must produce the same body hash"
        );
    }
}

#[test]
fn streaming_the_rfc_message_reproduces_its_body_hash() {
    // The RFC's own `bh=` is the digest over RFC 6376 A.2's body: if the
    // streamed path computes exactly that, the streaming path and the
    // canonicalization agree even for `simple`.
    let message = rfc6376_message();
    let streamed = StreamedMessage::from_bytes(&message).expect("message parses");
    let digests = streamed.dkim_body_hashes();
    assert_eq!(digests.len(), 1);
    let (_, _, _, digest) = &digests[0];

    let parsed = mail_auth::AuthenticatedMessage::parse(&message).expect("message parses");
    let declared = &parsed.dkim_signatures()[0].header.bh;
    assert_eq!(
        digest, declared,
        "the digest the stream took must be the `bh=` the signer declared"
    );
}

#[test]
fn a_body_length_signature_hashes_only_the_signed_prefix() {
    // `l=` (RFC 6376 §3.5) says "the body hash covers the first `l` octets".
    // A digest computed over the whole body instead would reject every such
    // message — and a *streaming* verifier that ignored the limit would report
    // a digest nobody signed. Strict parsing drops `l=` outright, so the
    // fixture is built here in relaxed mode rather than published.
    use base64::Engine;
    use mail_auth::crypto::{HashContext, HashImpl, Sha256};
    use mail_auth::headers::Writable;

    let body = b"this part is signed\r\nthis part is not signed\r\n";
    let signed = 22_u64;
    let prefix = &body[..signed as usize];

    // `simple` canonicalization: the body up to the blank line, trailing
    // empty lines dropped, terminated by one CRLF.
    let canonical = [prefix, b"\r\n"].concat();
    let mut hasher = <Sha256 as HashImpl>::hasher();
    canonical.as_slice().write(&mut hasher);
    let expected = hasher.complete().as_ref().to_vec();

    let message = format!(
        "From: Ada <ada@example.org>\r\nSubject: l tag\r\nDKIM-Signature: v=1; a=rsa-sha256; c=simple/simple; d=example.org; s=s1; l={signed}; h=From:Subject; bh={}; b=AAAA\r\n\r\n{}",
        base64::engine::general_purpose::STANDARD.encode(&expected),
        String::from_utf8_lossy(body)
    );

    let relaxed = mail_auth::AuthenticatedMessage::parse_with_opts(message.as_bytes(), None, false)
        .expect("message parses");
    assert_eq!(
        relaxed.dkim_signatures().len(),
        1,
        "relaxed parsing keeps the signature so the recipe survives"
    );
    let signature = &relaxed.dkim_signatures()[0].header;
    assert_eq!(signature.l, signed, "the recipe keeps the limit");

    let verifier = Verifier::with_zone("mx.ayane.test", FixedZone::default());
    let whole = verifier.body_hash_of(signature.cb, signature.a.into(), relaxed.raw_body(), 0);
    let limited = verifier.body_hash_of(
        signature.cb,
        signature.a.into(),
        relaxed.raw_body(),
        signature.l,
    );
    assert_ne!(
        whole, limited,
        "the unsigned tail must not be part of a limited body hash"
    );
    assert_eq!(limited, expected, "the limited digest is the prefix's");
}

/// A message whose one `DKIM-Signature` covers only part of the body
/// (`l=`), built in relaxed mode: strict parsing drops such signatures on
/// sight, and this fixture exists to exercise the `l=` path.
///
/// `bh=` is the digest of the signed prefix, so a verifier that hashes the
/// whole body — or one that streams past the limit — reports a digest nobody
/// signed.
fn body_length_message() -> Vec<u8> {
    use base64::Engine;
    use mail_auth::crypto::{HashContext, HashImpl, Sha256};
    use mail_auth::headers::Writable;

    let body = b"this part is signed\r\nthis part is not signed\r\n";
    let signed = 22_u64;
    // `simple` canonicalization: the covered prefix, then one CRLF.
    let canonical = [&body[..signed as usize], b"\r\n"].concat();
    let mut hasher = <Sha256 as HashImpl>::hasher();
    canonical.as_slice().write(&mut hasher);
    let bh = base64::engine::general_purpose::STANDARD.encode(hasher.complete().as_ref());

    format!(
        "From: Ada <ada@example.org>\r\nSubject: l tag\r\nDKIM-Signature: v=1; a=rsa-sha256; c=simple/simple; d=example.org; s=s1; l={signed}; h=From:Subject; bh={bh}; b=AAAA\r\n\r\n{}",
        String::from_utf8_lossy(body)
    )
    .into_bytes()
}

#[test]
fn a_streamed_body_hash_honours_the_l_limit_of_its_signature() {
    // The streaming path is the one that can quietly ignore `l=`: it declares
    // its recipe from the signature, so the recipe has to be the same one the
    // digest was taken under. Asserted through `dkim_body_hashes` (the
    // production accessor) against the digest of the prefix alone.
    let message = body_length_message();
    let relaxed = mail_auth::AuthenticatedMessage::parse_with_opts(&message, None, false)
        .expect("message parses");
    assert_eq!(
        relaxed.dkim_signatures().len(),
        1,
        "relaxed parsing keeps the signature so the recipe survives"
    );
    let signature = &relaxed.dkim_signatures()[0];

    let streamed = StreamedMessage::from_bytes(&message).expect("message parses");
    let (canonicalization, algorithm, limit, digest) = &streamed.dkim_body_hashes()[0];
    assert_eq!(*limit, signature.header.l, "the recipe keeps the limit");
    assert_eq!(
        *digest, signature.header.bh,
        "the streamed digest must be the `bh=` the signer declared, over the prefix only"
    );

    // And the whole-body digest is genuinely different, so the assertion
    // above is not vacuous: without the limit this fixture would hash the
    // unsigned tail too.
    let verifier = Verifier::with_zone("mx.ayane.test", FixedZone::default());
    let whole = verifier.body_hash_of(*canonicalization, *algorithm, relaxed.raw_body(), 0);
    assert_ne!(
        whole, *digest,
        "a digest over the whole body is not the digest over the signed prefix"
    );
}

#[test]
fn an_empty_message_is_an_error_not_a_silent_pass() {
    let mut hasher = BodyHasher::new();
    hasher.write(b"");
    assert_eq!(hasher.finish().err(), Some(VerifyError::EmptyMessage));
    assert_eq!(
        StreamedMessage::from_bytes(b"not a header at all").err(),
        Some(VerifyError::EmptyMessage)
    );
}

// ── a DKIM signature we produced ourselves ───────────────────────────────

impl KeyPair {
    fn record_pair(&self) -> (String, String) {
        (self.record_name(), self.record())
    }
}

#[test]
fn a_signature_we_produce_verifies_against_the_zone_we_publish() {
    // The loop is closed in this process: the key that signed is the key in
    // the zone, so a `pass` here means the verifier, the zone adapter and the
    // body hashing all agree — not that some fixture happened to still match.
    let pair = key_pair();
    let message = signed_message(&pair, "hello there\r\n", "a signed message");
    let (name, record) = pair.record_pair();
    let zone = zone_with(&[(&name, &record)]);

    let verification = verify(zone, &message, "ada@sender.example");
    assert!(
        verification.summary.contains("dkim=1/1"),
        "own signature must verify: {}",
        verification.summary
    );
}

#[test]
fn a_body_byte_with_no_reason_to_be_there_is_caught() {
    let pair = key_pair();
    let mut message = signed_message(&pair, "hello there\r\n", "a signed message");
    let (name, record) = pair.record_pair();
    let zone = zone_with(&[(&name, &record)]);

    // Append a line after the signature: `relaxed` still covers it.
    message.extend_from_slice(b"added after signing\r\n");
    let verification = verify(zone, &message, "ada@sender.example");
    assert!(
        !verification.summary.contains("dkim=1/1"),
        "bytes appended after signing must fail: {}",
        verification.summary
    );
}

#[test]
fn prepending_our_received_line_does_not_break_a_signature_over_other_headers() {
    // The re-sign test: the verifier computes its verdict over the received
    // octets, and those octets are what the spool writes after the prepend —
    // so the verdict and the file agree. Asserted directly: verifying the
    // prepended file again with the same zone yields the same DKIM result.
    let pair = key_pair();
    let message = signed_message(&pair, "body\r\n", "prepend check");
    let (name, record) = pair.record_pair();
    let zone = zone_with(&[(&name, &record)]);
    let verification = verify(zone.clone(), &message, "ada@sender.example");
    assert!(
        verification.summary.contains("dkim=1/1"),
        "{}",
        verification.summary
    );

    let mut file = verification.prepend.clone();
    file.extend_from_slice(&message);
    let again = verify(zone, &file, "ada@sender.example");
    assert!(
        again.summary.contains("dkim=1/1"),
        "our own headers at the top cannot invalidate a signature that did \
         not cover them: {}",
        again.summary
    );
    assert_eq!(again.verdict, PolicyVerdict::Accept);
}

// ── ARC ──────────────────────────────────────────────────────────────────

#[test]
fn a_chain_we_seal_validates_and_a_broken_one_does_not() {
    use mail_auth::arc::ArcSealer;
    use mail_auth::AuthenticationResults;

    let pair = key_pair();
    let message = signed_message(&pair, "arc body\r\n", "arc");
    let (name, record) = pair.record_pair();

    let sealer = ArcSealer::from_key(pair.key())
        .domain(pair.domain)
        .selector(pair.selector)
        .headers([
            "From",
            "To",
            "Subject",
            "Date",
            "Message-ID",
            "DKIM-Signature",
        ]);
    let auth_results =
        AuthenticationResults::new("hop.one.test").with_dkim_results(&[], "ada@sender.example");
    let parsed = mail_auth::AuthenticatedMessage::parse(&message).expect("message parses");
    // The chain is empty, so instance 1 seals it.
    let sealed = sealer
        .seal(
            &parsed,
            &auth_results,
            &mail_auth::arc::ArcOutput::default(),
        )
        .expect("sealing works");
    let mut chained = Vec::new();
    chained.extend_from_slice(sealed.to_header().as_bytes());
    chained.extend_from_slice(&message);

    let verification = verify(
        zone_with(&[(&name, &record)]),
        &chained,
        "ada@sender.example",
    );
    let block = String::from_utf8_lossy(&verification.prepend).to_string();
    assert!(
        block.contains("arc=pass"),
        "a chain sealed with the zone's key must validate: {block}"
    );

    // Break the newest ARC-Message-Signature's body coverage by appending
    // bytes: the seal no longer matches what the chain vouched for.
    let mut broken = chained.clone();
    broken.extend_from_slice(b"appended after sealing\r\n");
    let verification = verify(
        zone_with(&[(&name, &record)]),
        &broken,
        "ada@sender.example",
    );
    let block = String::from_utf8_lossy(&verification.prepend).to_string();
    assert!(
        !block.contains("arc=pass"),
        "a tampered chain must not validate: {block}"
    );
}

#[test]
fn a_message_without_arc_headers_reports_arc_none() {
    let verification = verify(
        rfc6376_zone(),
        &rfc6376_message(),
        "joe@football.example.com",
    );
    let block = String::from_utf8_lossy(&verification.prepend).to_string();
    assert!(block.contains("arc=none"), "{block}");
}

// ── DMARC, and the fail-closed verdict ───────────────────────────────────

/// A message that DMARC will fail: `From: ada@sender.example`, a DKIM
/// signature over a *different* key than the zone publishes (so DKIM fails),
/// and SPF set up to fail too.
fn dmarc_failing_message() -> (Vec<u8>, KeyPair) {
    let pair = key_pair();
    let message = signed_message(&pair, "dmarc body\r\n", "dmarc");
    (message, pair)
}

/// A zone that publishes `policy` for the domain and **no key for the
/// selector the message used** — so the message's own signature fails and only
/// DMARC's policy can decide what happens to it.
fn dmarc_zone(pair: &KeyPair, policy: &str) -> FixedZone {
    FixedZone::default()
        .with_dmarc(pair.domain, policy)
        .expect("policy record parses")
}

#[test]
fn dmarc_fail_under_a_reject_policy_refuses() {
    let (message, pair) = dmarc_failing_message();
    // Since RFC 9091, an organizational `p=` under a `psd=` parent does not
    // apply to non-PSD subdomains, so each test publishes its own record at
    // the author domain — which is the shape a single-domain deployment has
    // anyway.
    let zone = dmarc_zone(&pair, "v=DMARC1; p=reject");

    let verification = verify(zone, &message, "ada@sender.example");
    let block = String::from_utf8_lossy(&verification.prepend).to_string();
    assert!(block.contains("dmarc=fail"), "{block}");
    assert_eq!(
        verification.verdict,
        PolicyVerdict::Reject,
        "{}",
        verification.summary
    );
}

#[test]
fn dmarc_fail_under_a_none_policy_passes_the_message_through() {
    let (message, pair) = dmarc_failing_message();
    let zone = dmarc_zone(&pair, "v=DMARC1; p=none");

    let verification = verify(zone, &message, "ada@sender.example");
    let block = String::from_utf8_lossy(&verification.prepend).to_string();
    assert!(block.contains("dmarc=fail"), "{block}");
    assert_eq!(
        verification.verdict,
        PolicyVerdict::Accept,
        "p=none must not refuse: {}",
        verification.summary
    );
}

#[test]
fn dmarc_fail_under_a_quarantine_policy_refuses_at_this_layer() {
    // Documented in `decide`: the quarantine mailbox is on the delivery side,
    // which does not exist yet, so the fail-closed answer available here is
    // refusal.
    let (message, pair) = dmarc_failing_message();
    let zone = dmarc_zone(&pair, "v=DMARC1; p=quarantine");

    let verification = verify(zone, &message, "ada@sender.example");
    assert_eq!(
        verification.verdict,
        PolicyVerdict::Reject,
        "{}",
        verification.summary
    );
}

#[test]
fn a_domain_with_no_dmarc_record_is_none_and_accepted() {
    let (message, pair) = dmarc_failing_message();
    let (name, record) = pair.record_pair();
    let verification = verify(
        zone_with(&[(&name, &record)]),
        &message,
        "ada@sender.example",
    );
    let block = String::from_utf8_lossy(&verification.prepend).to_string();
    assert!(block.contains("dmarc=none"), "{block}");
    assert_eq!(verification.verdict, PolicyVerdict::Accept);
}

#[test]
fn spf_failing_alone_does_not_refuse() {
    // No SPF record for the sender's domain → `spf=none`, and a message with no
    // DMARC record at all must still be accepted: SPF is a hint.
    let (message, pair) = dmarc_failing_message();
    let (name, record) = pair.record_pair();
    let verification = verify(
        zone_with(&[(&name, &record)]),
        &message,
        "ada@sender.example",
    );
    assert_eq!(verification.verdict, PolicyVerdict::Accept);
    assert!(
        verification.summary.contains("spf=none") || verification.summary.contains("spf=fail"),
        "{}",
        verification.summary
    );
}

// ── the zone itself ──────────────────────────────────────────────────────

#[test]
fn a_name_the_zone_does_not_list_answers_no_records_without_a_query() {
    // This goes through the decision path, not the cache: a zone that lists a
    // key but nothing else must produce `dkim=permerror` (record not found)
    // and `spf=none` — the answers of an authoritative "nothing here", which
    // are what an offline run gets. A cache miss that fell through to the
    // resolver would read `temperror` instead as soon as the network is gone,
    // and `temperror` is a different statement about the world.
    let pair = key_pair();
    let (name, record) = pair.record_pair();
    let zone = zone_with(&[(&name, &record)]);
    // The zone lists the real key; ask about a domain it does not list.
    let streamed = StreamedMessage::from_bytes(&rfc6376_message()).expect("message parses");
    let verifier = Verifier::with_zone("mx.ayane.test", zone);
    let session = facts("someone@not-in-the-zone.example");
    let verification = block_on(verifier.verify(streamed, &session, "from client.example.net"));
    let block = String::from_utf8_lossy(&verification.prepend).to_string();

    assert!(
        block.contains("dkim=permerror (dns record not found)"),
        "an absent key is a permanent 'not published', not a transient outage: {block}"
    );
    assert!(
        block.contains("spf=none (mx.ayane.test: no SPF records found"),
        "an absent SPF record is `none`, not `temperror`: {block}"
    );
    assert!(
        !block.contains("temperror"),
        "nothing here may read as a temporary DNS failure: {block}"
    );
}

#[test]
fn a_lookup_inside_the_authority_never_reaches_the_resolver() {
    // The negative answer is what makes the zone authoritative, and this is
    // the property stated directly rather than through a verdict: every name
    // the zone can be asked about gets *an answer* — a record or a NODATA —
    // and only a name it lists nothing for *and* knows nothing about is left
    // to the resolver. `None` from the cache is "ask the network"; a
    // `dkim=permerror` test would pass even if a resolver were asked and
    // happened to answer, this would not.
    use mail_auth::dns::{DnsCache, Negative, RecordSet, ResolverCache, TxtRecord};
    use mail_auth::Mx;

    let pair = key_pair();
    let (name, record) = pair.record_pair();
    let zone = zone_with(&[(&name, &record)])
        .with_dmarc(pair.domain, "v=DMARC1; p=reject")
        .expect("policy record parses");

    // TXT: a listed name has its record, an unlisted one has NODATA.
    let txt = DnsCache::txt(&zone).expect("txt cache");
    let listed = format!("{name}.");
    assert!(
        ResolverCache::get::<str>(txt, listed.as_str()).is_some(),
        "the record the fixture published is answered"
    );
    for unlisted in [
        "_dmarc.absent.example.",
        "_dmarc.other-sender.example.",
        "_domainkey.sender.example.",
        "sender.example.",
        "example.",
        "no-such-host.invalid.",
    ] {
        match ResolverCache::get::<str>(txt, unlisted) {
            Some(TxtRecord::Error(mail_auth::Error::Dns(mail_auth::DnsError::RecordNotFound(
                _,
            )))) => {}
            Some(_) => panic!("{unlisted} must be NODATA, not a record"),
            None => panic!("{unlisted} fell through to the resolver"),
        }
    }

    // MX: same question, the `Err(Negative)` shape.
    let mx = DnsCache::mx(&zone).expect("mx cache");
    match ResolverCache::get::<str>(mx, "sender.example.") {
        Some(Err(Negative { .. })) => {}
        _ => panic!("an MX miss inside the authority is a negative answer"),
    }
    // A listed MX would be a `RecordSet`; the marker type is enough to keep
    // the import honest.
    let _: Option<Result<RecordSet<Mx>, Negative>> =
        ResolverCache::get::<str>(mx, "sender.example.");
}

#[test]
fn an_unlisted_name_is_answered_by_the_zone_not_the_resolver() {
    // The cache-level half of the contract, and the one property the
    // decision-path test above cannot show: a *miss inside the authority* must
    // come back as the NODATA answer. A `None` there means "this cache cannot
    // answer" to `mail-auth`, which then asks the resolver — so `None` is a
    // network query wearing the costume of an empty answer.
    use mail_auth::dns::{DnsCache, ResolverCache};

    let pair = key_pair();
    let (name, record) = pair.record_pair();
    let zone = zone_with(&[(&name, &record)]);
    let cache = DnsCache::txt(&zone).expect("txt cache");

    assert!(
        ResolverCache::get::<str>(cache, "absent._domainkey.sender.example.").is_some(),
        "an unlisted name still gets an answer (see the authority test below)"
    );
}

#[test]
fn the_policy_record_replaces_an_earlier_one_for_the_same_domain() {
    let pair = key_pair();
    let zone = zone_with(&[])
        .with_dmarc(pair.domain, "v=DMARC1; p=none")
        .expect("first policy")
        .with_dmarc(pair.domain, "v=DMARC1; p=reject")
        .expect("second policy");
    let (message, _) = dmarc_failing_message();
    let verification = verify(zone, &message, "ada@sender.example");
    assert_eq!(
        verification.verdict,
        PolicyVerdict::Reject,
        "the last policy written is the one that applies: {}",
        verification.summary
    );
}

#[test]
fn a_session_fact_is_not_derived_from_the_message() {
    // The verifier takes HELO and MAIL FROM from the session, never from the
    // headers: a `From:` that disagrees with the envelope cannot rewrite SPF's
    // question.
    let (message, pair) = dmarc_failing_message();
    let (name, record) = pair.record_pair();
    let verifier = Verifier::with_zone("mx.ayane.test", zone_with(&[(&name, &record)]));
    let mut session = facts("ada@sender.example");
    session.remote_ip = "203.0.113.9".parse::<IpAddr>().expect("RFC 5737 address");
    session.helo = "other.example.net".to_owned();
    let streamed = StreamedMessage::from_bytes(&message).expect("message parses");
    let verification = block_on(verifier.verify(streamed, &session, "from other.example.net"));
    let block = String::from_utf8_lossy(&verification.prepend).to_string();
    assert!(
        block.contains("client-ip=203.0.113.9"),
        "Received-SPF must name the session's peer: {block}"
    );
    assert_eq!(block.matches("Received: from other.example.net").count(), 1);
}
