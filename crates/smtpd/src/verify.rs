//! Trust verification: SPF, DKIM, ARC and DMARC over the bytes as received.
//!
//! # The order, and why it is that order
//!
//! ```text
//! SPF  ──►  DKIM  ──►  ARC (informational)  ──►  DMARC  ──►  local policy
//! (envelope)  (message)                       (needs both)    (the driver)
//! ```
//!
//! 1. **SPF** answers an *envelope* question (`MAIL FROM` / `HELO` against the
//!    connecting IP) and needs nothing from the headers, so it can start before
//!    the message is read.
//! 2. **DKIM** answers a *message* question (the signature covers headers and
//!    the body hash covers the octets), so it runs once the body has been
//!    streamed.
//! 3. **ARC** is evaluated beside DKIM, not after it: it is evidence *about
//!    earlier hops*, and it never changes the DKIM result.
//! 4. **DMARC** consumes SPF and DKIM — a mechanism result cannot be computed
//!    before the mechanisms — and is therefore last.
//! 5. **Local policy** is the driver's. This layer stops at [`Verification`];
//!    [`PolicyVerdict`] is the fail-closed default the driver may apply, not a
//!    refusal it performs here.
//!
//! Three hard rules shape the rest of the module:
//!
//! 1. **Only the raw octets are verified.** The body is hashed by
//!    [`BodyHasher`] while it is written to the spool file, so a 25 MiB
//!    message never exists in memory; the `Received:` and
//!    `Authentication-Results:` lines come back as [`Verification::prepend`]
//!    and are written when the spool file is opened, *after* the hashes were
//!    taken, so they cannot disturb them.
//! 2. **`Received:` is only ever prepended, at the top.** RFC 5321 §4.4 makes
//!    each hop responsible for its own trace field in front of everything that
//!    arrived; and a DKIM signature may itself sign `Received:` (RFC 6376
//!    Appendix A.2 does), so inserting anywhere else or rewriting an existing
//!    field would invalidate a signature that was valid on the wire.
//! 3. **The decision is fail-closed, and its judgement point is the driver.**
//!    A DMARC failure under `p=reject` (and, per MAP §四, under
//!    `p=quarantine`) yields [`PolicyVerdict::Reject`], but refusing the
//!    message — a reply code on the `DATA`-end — is the driver's act. A DNS
//!    timeout keeps the message (a temporary failure must not lose mail) but
//!    records `dmarc=temperror`, so nothing is silently treated as passing.
//!
//! Everything here is pure computation over bytes plus the DNS answers an
//! injected [`crate::zone::FixedZone`] hands back: no listener, no file, no
//! clock read of its own.

use std::net::IpAddr;

use mail_auth::dmarc::Policy;
use mail_auth::headers::HeaderWriter;
use mail_auth::spf::verify::SpfParameters;
use mail_auth::stream::MessageStream;
use mail_auth::{
    AuthenticationResults, DmarcResult, MessageAuthenticator, Parameters, ReceivedSpf, SpfResult,
};

use crate::zone::FixedZone;

/// What the queue is allowed to do with a verified message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyVerdict {
    /// Accept and spool into `new/`.
    Accept,
    /// The message must not reach a mailbox: refused at the end of DATA.
    Reject,
}

/// The verdict plus the header lines the spool must prepend, top first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verification {
    /// Accept or refuse.
    pub verdict: PolicyVerdict,
    /// The `Received:` and result headers, in the order they must appear at
    /// the very top of the spooled file (`Received:` first).
    pub prepend: Vec<u8>,
    /// A one-line human summary for logs and the envelope metadata.
    pub summary: String,
}

/// Everything the verifiers need that is not in the message itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionFacts {
    /// The client's IP address, as the TCP peer reported it.
    pub remote_ip: IpAddr,
    /// The HELO/EHLO name the client sent.
    pub helo: String,
    /// The MAIL FROM address (`""` for the null reverse-path).
    pub mail_from: String,
    /// The authenticated identity, when the session ran AUTH.
    pub authenticated: Option<String>,
}

/// One body hash a message carries: the body canonicalization and algorithm
/// its signature named, the `l=` length it covered (`0` for the whole body),
/// and the digest.
pub type BodyDigest = (
    mail_auth::dkim::Canonicalization,
    mail_auth::crypto::HashAlgorithm,
    u64,
    Vec<u8>,
);

/// Hashes a message while it is streamed, to be finished once the whole
/// message has been written to the spool.
///
/// ## What it holds
///
/// The **body** is never kept: it is canonicalized and hashed chunk by chunk
/// as it arrives, which is what lets a large message be verified without
/// living in memory (T-B14). The **header section** is buffered in full —
/// [`mail_auth::stream::MessageStream`] holds octets until it finds the blank
/// line that ends it — so the bound here is "body, not headers"; a message
/// with no blank line at all is buffered whole before [`BodyHasher::finish`]
/// can tell it has no body. The driver's own size limit is what bounds that,
/// not this type.
pub struct BodyHasher {
    stream: MessageStream,
    // The received octets, only when `keep_raw` asked for them.
    raw: Vec<u8>,
    keep_raw: bool,
}

impl BodyHasher {
    /// Starts a stream. Call [`BodyHasher::write`] with every raw octet of the
    /// message exactly as received.
    #[must_use]
    pub fn new() -> Self {
        Self {
            stream: MessageStream::new(),
            raw: Vec::new(),
            keep_raw: false,
        }
    }

    /// Also keeps the received octets, for the callers that can parse a whole
    /// message (the `Received:` loop count, and the tests that feed a signed
    /// message by hand). Production never turns this on: the point of the
    /// stream is that the body does not live in memory.
    #[must_use]
    pub fn keep_raw(mut self) -> Self {
        self.keep_raw = true;
        self
    }

    /// Feeds a chunk.
    ///
    /// The chunk boundary carries no meaning: [`MessageStream`] holds back the
    /// three bytes that could straddle the header terminator, so the outcome is
    /// the same for any split of the same octets.
    pub fn write(&mut self, chunk: &[u8]) {
        self.stream.write(chunk);
        if self.keep_raw {
            self.raw.extend_from_slice(chunk);
        }
    }

    /// Ends the stream, returning a [`StreamedMessage`] whose body hashes can
    /// be used by the verifiers.
    ///
    /// # Errors
    ///
    /// Returns [`VerifyError::EmptyMessage`] when no header field could be
    /// parsed (the message is not RFC 5322 at all).
    pub fn finish(self) -> Result<StreamedMessage, VerifyError> {
        let raw = self.keep_raw.then_some(self.raw);
        self.stream
            .finish()
            .map(|streamed| StreamedMessage { streamed, raw })
            .map_err(|_| VerifyError::EmptyMessage)
    }
}

impl Default for BodyHasher {
    fn default() -> Self {
        Self::new()
    }
}

/// A message hashed during streaming; verifiable without the body.
pub struct StreamedMessage {
    streamed: mail_auth::stream::StreamedMessage,
    raw: Option<Vec<u8>>,
}

impl StreamedMessage {
    /// Hashes the whole message at once, through the same stream.
    ///
    /// Exists so a caller that already holds the bytes (a replay tool, a test)
    /// does not have to spell the three steps out. Production streams: the body
    /// must not be buffered.
    ///
    /// # Errors
    ///
    /// Returns [`VerifyError::EmptyMessage`] when no header field could be
    /// parsed.
    pub fn from_bytes(message: &[u8]) -> Result<Self, VerifyError> {
        let mut hasher = BodyHasher::new().keep_raw();
        hasher.write(message);
        hasher.finish()
    }

    /// The octets the stream was fed, when the caller asked to keep them.
    #[must_use]
    pub fn raw(&self) -> Option<&[u8]> {
        self.raw.as_deref()
    }

    /// One body hash per `DKIM-Signature` the streamed header section
    /// carried, in message order: the body canonicalization it names, the hash
    /// algorithm its `a=` implies, the `l=` it covers, and the digest of the
    /// body the stream consumed.
    ///
    /// This is the streaming contract in one value: **the digest is the one
    /// the stream took while the body went past**, and comparing it with
    /// [`Verifier::body_hash_of`] on the same octets is asserting that the
    /// chunking changed nothing. The signature's own `bh=` is returned beside
    /// it rather than compared here, because comparing is the verifier's job
    /// (and needs the key to finish the story).
    ///
    /// Empty when no caller kept the raw octets: the streamed form has no
    /// header section to match recipes against.
    #[must_use]
    pub fn dkim_body_hashes(&self) -> Vec<BodyDigest> {
        let Some(raw) = self.raw.as_deref() else {
            return Vec::new();
        };
        // Deliberately **relaxed**: strict parsing refuses `l=` signatures
        // (RFC 6376 §8.2) and the production path never sees them, but the
        // digest a signature *declares* is a property of its tags, and a
        // caller asking for it is asking about the recipe, not the verdict.
        let Some(message) = mail_auth::AuthenticatedMessage::parse_with_opts(raw, None, false)
        else {
            return Vec::new();
        };
        let body = message.raw_body();
        message
            .dkim_signatures()
            .iter()
            .map(|header| &header.header)
            .map(|signature| {
                (
                    signature.cb,
                    signature.a.into(),
                    signature.l,
                    body_digest(signature.cb, signature.a.into(), body, signature.l),
                )
            })
            .collect()
    }
}

/// The verifier, holding the DNS resolver shared by every connection.
#[derive(Clone)]
pub struct Verifier {
    authenticator: MessageAuthenticator,
    hostname: String,
    /// Answers DNS from a fixed zone instead of the network (tests, and a
    /// deployment that pins its own records).
    zone: Option<FixedZone>,
}

/// Why verification could not run at all.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum VerifyError {
    /// No header field parsed: not a message.
    #[error("message has no parsable header field")]
    EmptyMessage,
    /// The system resolver configuration could not be read.
    #[error("DNS resolver unavailable: {0}")]
    Resolver(String),
}

impl Verifier {
    /// A verifier over a fixed zone: every lookup the verifiers make is
    /// answered from `zone`, and a name the zone does not list has no
    /// records.
    #[must_use]
    pub fn with_zone(hostname: impl Into<String>, zone: FixedZone) -> Self {
        Self::from_parts(hostname.into(), Some(zone))
    }

    /// Builds a verifier on the system resolver configuration.
    ///
    /// # Errors
    ///
    /// Returns [`VerifyError::Resolver`] when `/etc/resolv.conf` or the nsswitch
    /// configuration cannot be read.
    pub fn with_system_resolver(hostname: impl Into<String>) -> Result<Self, VerifyError> {
        Ok(Self {
            authenticator: Self::system_resolver()?,
            hostname: hostname.into(),
            zone: None,
        })
    }

    /// Builds a verifier on Cloudflare's resolver (used by tests and by
    /// deployments without a usable local resolver).
    ///
    /// # Errors
    ///
    /// Returns [`VerifyError::Resolver`] when the resolver cannot be built.
    pub fn with_cloudflare_resolver(hostname: impl Into<String>) -> Result<Self, VerifyError> {
        let authenticator = MessageAuthenticator::new_cloudflare()
            .map_err(|err| VerifyError::Resolver(err.to_string()))?;
        Ok(Self {
            authenticator,
            hostname: hostname.into(),
            zone: None,
        })
    }

    /// The `authserv-id` this verifier stamps into `Authentication-Results`.
    #[must_use]
    pub fn hostname(&self) -> &str {
        &self.hostname
    }

    fn system_resolver() -> Result<MessageAuthenticator, VerifyError> {
        MessageAuthenticator::new_system_conf()
            .map_err(|err| VerifyError::Resolver(err.to_string()))
    }

    /// A verifier with (or without) a fixed zone.
    ///
    /// The resolver is always built even when every lookup is answered from
    /// the zone (a zone miss is an empty answer, not a query): `mail-auth`'s
    /// verifiers are methods on the resolver type. The parse and signing work
    /// — which is what a test exercises — never reaches it.
    ///
    /// # Panics
    ///
    /// Panics on a host with neither Cloudflare's addresses nor a readable
    /// system resolver configuration; there is no third way to build the type.
    #[must_use]
    pub(crate) fn from_parts(hostname: String, zone: Option<FixedZone>) -> Self {
        let authenticator = MessageAuthenticator::new_cloudflare()
            .or_else(|_| MessageAuthenticator::new_system_conf())
            .expect("a DNS resolver is needed to build the verifier type");
        Self {
            authenticator,
            hostname,
            zone,
        }
    }

    /// Runs SPF, DKIM, ARC and DMARC over a streamed message and decides.
    ///
    /// `received` is the `Received:` line to prepend (without its own CRLF or
    /// the `Received: ` field name); it is part of the output only, never of
    /// the verified bytes.
    pub async fn verify(
        &self,
        message: StreamedMessage,
        facts: &SessionFacts,
        received: &str,
    ) -> Verification {
        let StreamedMessage { streamed, raw } = message;
        // The raw octets win when the caller kept them: `AuthenticatedMessage`
        // can then be parsed as a whole message, which is what the `Received:`
        // loop count needs. Otherwise the streamed form is used and the body
        // is only ever present as hashes.
        let parsed = raw
            .as_deref()
            .and_then(mail_auth::AuthenticatedMessage::parse);
        let streamed_message = streamed.message();
        let message = parsed.as_ref().unwrap_or(&streamed_message);
        let helo = facts.helo.as_str();
        let hostname = self.hostname.as_str();
        let spf_params = SpfParameters::helo_and_mail_from(
            facts.remote_ip,
            helo,
            hostname,
            facts.mail_from.as_str(),
        );
        let mail_from_domain = if facts.mail_from.is_empty() {
            helo
        } else {
            facts
                .mail_from
                .rsplit_once('@')
                .map_or(helo, |(_, domain)| domain)
        };

        let zone = self.zone.as_ref();
        let (dkim, spf, arc, dmarc) = match zone {
            Some(zone) => {
                let dkim = self
                    .authenticator
                    .verify_dkim(Parameters::new(message).with_cache(zone))
                    .await;
                let spf = self
                    .authenticator
                    .verify_spf(Parameters::new(spf_params).with_cache(zone))
                    .await;
                let arc = self
                    .authenticator
                    .verify_arc(Parameters::new(message).with_cache(zone))
                    .await;
                let dmarc = self
                    .authenticator
                    .verify_dmarc(
                        Parameters::new(mail_auth::dmarc::verify::DmarcParameters {
                            message,
                            dkim_output: &dkim,
                            dkim2_output: None,
                            mail_from_domain,
                            spf_output: &spf,
                        })
                        .with_cache(zone),
                    )
                    .await;
                (dkim, spf, arc, dmarc)
            }
            None => {
                let dkim = self.authenticator.verify_dkim(message).await;
                let spf = self.authenticator.verify_spf(spf_params).await;
                let arc = self.authenticator.verify_arc(message).await;
                let dmarc = self
                    .authenticator
                    .verify_dmarc(mail_auth::dmarc::verify::DmarcParameters {
                        message,
                        dkim_output: &dkim,
                        dkim2_output: None,
                        mail_from_domain,
                        spf_output: &spf,
                    })
                    .await;
                (dkim, spf, arc, dmarc)
            }
        };

        let header_from = message.first_from_address().to_owned();
        let auth_results = AuthenticationResults::new(hostname)
            .with_dkim_results(&dkim, &header_from)
            .with_spf_result(&spf, &spf_params)
            .with_arc_result(&arc, facts.remote_ip)
            .with_dmarc_result(&dmarc)
            .to_header();
        let received_spf = ReceivedSpf::new(&spf, &spf_params).to_header();

        let verdict = decide(&dmarc);
        let summary = summarize(&dkim, &spf, &dmarc, verdict);

        let mut prepend = Vec::with_capacity(received.len() + auth_results.len() + 128 + 64);
        // `Received:` is the topmost header, by position in the prepend block
        // and therefore by position in the file (RFC 5321 §4.4).
        prepend.extend_from_slice(b"Received: ");
        prepend.extend_from_slice(received.as_bytes());
        prepend.extend_from_slice(b"\r\n");
        for field in [received_spf.as_str(), auth_results.as_str()] {
            prepend.extend_from_slice(field.trim_end_matches("\r\n").as_bytes());
            prepend.extend_from_slice(b"\r\n");
        }

        Verification {
            verdict,
            prepend,
            summary,
        }
    }

    /// The body digest `body` produces under one signature recipe, computed
    /// with the same code the verifier's DKIM leg uses.
    ///
    /// Exists so a caller holding both the octets and a streamed message can
    /// assert the streaming contract arithmetically — "the digest the stream
    /// took equals the digest of the bytes" — instead of trusting that it did.
    #[must_use]
    pub fn body_hash_of(
        &self,
        canonicalization: mail_auth::dkim::Canonicalization,
        algorithm: mail_auth::crypto::HashAlgorithm,
        body: &[u8],
        limit: u64,
    ) -> Vec<u8> {
        body_digest(canonicalization, algorithm, body, limit)
    }

    /// The `Received:` count a whole message carries, when the verifier was
    /// given the raw octets.
    #[must_use]
    pub fn received_count(&self, head: &[u8]) -> usize {
        mail_auth::AuthenticatedMessage::parse(head)
            .map(|message| message.received_headers_count())
            .unwrap_or(0)
    }
}

/// The fail-closed policy: which outcomes refuse the message.
///
/// - DMARC `pass` / `none` → accept.
/// - DMARC `fail` with `p=reject` or `p=quarantine` → **reject** (the
///   quarantine mailbox lives on the delivery side, which does not exist yet,
///   so the only fail-closed answer available is refusal).
/// - DMARC `temperror` / `permerror` → accept (a DNS outage must not discard
///   mail) but the result is recorded; it never reads as `pass`.
/// - SPF `fail` alone never refuses: SPF is an authorisation hint and the
///   envelope sender is trivially forgeable.
#[must_use]
pub fn decide(dmarc: &mail_auth::DmarcOutput) -> PolicyVerdict {
    match dmarc.result() {
        DmarcResult::Fail(_) => match dmarc.policy() {
            Policy::Reject | Policy::Quarantine => PolicyVerdict::Reject,
            Policy::None | Policy::Unspecified => PolicyVerdict::Accept,
        },
        DmarcResult::Pass
        | DmarcResult::None
        | DmarcResult::TempError(_)
        | DmarcResult::PermError(_) => PolicyVerdict::Accept,
    }
}

fn summarize(
    dkim: &[mail_auth::DkimOutput<'_>],
    spf: &mail_auth::SpfOutput,
    dmarc: &mail_auth::DmarcOutput,
    verdict: PolicyVerdict,
) -> String {
    let dkim_pass = dkim
        .iter()
        .filter(|output| output.result() == &mail_auth::DkimResult::Pass)
        .count();
    let spf_text = match spf.result() {
        SpfResult::Pass => "pass",
        SpfResult::Fail => "fail",
        SpfResult::SoftFail => "softfail",
        SpfResult::Neutral => "neutral",
        SpfResult::None => "none",
        SpfResult::TempError => "temperror",
        SpfResult::PermError => "permerror",
    };
    format!(
        "spf={spf_text} dkim={dkim_pass}/{} dmarc={} verdict={:?}",
        dkim.len(),
        dmarc.result(),
        verdict
    )
}

/// Writes the body hash input of RFC 6376 §3.4.3–4 — `body` canonicalized
/// with `canonicalization`, truncated to `limit` octets when it is not `0` —
/// into `out`.
///
/// The *signature* of a message never needs this from outside `mail-auth`
/// (its verifiers canonicalize as they go). This is the reverse direction: a
/// caller that already holds the octets recomputing the digest a signature
/// declares, so that "the streamed body hash equals the hash of the bytes" can
/// be an assertion instead of a belief.
///
/// `simple` and `relaxed` differ only in whitespace handling and trailing
/// empty lines (RFC 6376 §3.4.3 and §3.4.4), and the difference is exactly what
/// this implements: `simple` keeps the body as it is after dropping trailing
/// empty lines and ending with CRLF; `relaxed` additionally collapses runs of
/// whitespace, strips trailing whitespace per line and drops the CRLF of empty
/// lines at the end.
fn canonicalize_body(
    canonicalization: mail_auth::dkim::Canonicalization,
    body: &[u8],
    limit: u64,
    out: &mut Vec<u8>,
) {
    use mail_auth::dkim::Canonicalization;

    let cut = if limit == 0 {
        body
    } else {
        &body[..(limit.min(body.len() as u64) as usize)]
    };

    // Trailing empty lines go away in both canonicalizations, and the body
    // ends with a single CRLF (an empty body becomes a single CRLF).
    let mut end = cut.len();
    while end > 0 && matches!(cut[end - 1], b'\r' | b'\n') {
        end -= 1;
    }
    let body = &cut[..end];

    if canonicalization == Canonicalization::Simple {
        out.extend_from_slice(body);
        out.extend_from_slice(b"\r\n");
        return;
    }

    // `relaxed`: strip trailing whitespace per line, collapse interior runs to
    // one space, drop empty lines.
    for line in body.split(|byte| *byte == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let line: Vec<u8> =
            line.iter()
                .copied()
                .fold(Vec::with_capacity(line.len()), |mut acc, byte| {
                    if byte.is_ascii_whitespace() {
                        if acc.last() != Some(&b' ') {
                            acc.push(b' ');
                        }
                    } else {
                        acc.push(byte);
                    }
                    acc
                });
        let line = match line.strip_suffix(b" ") {
            Some(stripped) => stripped,
            None => line.as_slice(),
        };
        out.extend_from_slice(line);
        out.extend_from_slice(b"\r\n");
    }
}

/// The body digest of a whole message under one signature recipe.
///
/// `body` must be the octets after the header section that a verifier sees,
/// i.e. [`mail_auth::AuthenticatedMessage::raw_body`]. See
/// [`canonicalize_body`] for what "one signature recipe" means.
///
/// Used by [`StreamedMessage::dkim_body_hashes`] and by
/// [`Verifier::body_hash_of`], so there is one implementation of "the digest a
/// signature declares", not two that agree by inspection.
fn body_digest(
    canonicalization: mail_auth::dkim::Canonicalization,
    algorithm: mail_auth::crypto::HashAlgorithm,
    body: &[u8],
    limit: u64,
) -> Vec<u8> {
    use mail_auth::crypto::{HashImpl, Sha1, Sha256};

    let mut canonical = Vec::with_capacity(body.len() + 2);
    canonicalize_body(canonicalization, body, limit, &mut canonical);
    match algorithm {
        mail_auth::crypto::HashAlgorithm::Sha256 => {
            Sha256::digest(canonical.as_slice()).as_ref().to_vec()
        }
        mail_auth::crypto::HashAlgorithm::Sha1 => {
            Sha1::digest(canonical.as_slice()).as_ref().to_vec()
        }
        // SHA-512 exists for DKIM2 only, which this layer does not verify.
        mail_auth::crypto::HashAlgorithm::Sha512 => Vec::new(),
    }
}
