//! The outbound transport: where a message for a domain this instance does not
//! host actually goes.
//!
//! [`crate::deliver`] decides that a recipient is `Remote` — not hosted here,
//! so the outbound transport owns it — and leaves the entry in the queue. This
//! module is that transport. It answers three questions in the order RFC 5321
//! §5.1 asks them:
//!
//! ```text
//! which host?          ── MX (priority order, RFC 7505 null MX, A/AAAA fallback)
//!   ↓
//! how does it talk?    ── connect :25, EHLO, opportunistic STARTTLS (RFC 3207)
//!   ↓
//! what does it receive? ── MAIL/RCPT/DATA with SIZE and dot-stuffing, signed (DKIM)
//! ```
//!
//! and it answers them from a [`Resolver`] the caller hands in, so the whole
//! ladder is testable with no network: [`crate::zone::FixedZone`] is a
//! [`DnsCache`] adapted by [`ZoneResolver`], and [`StaticResolver`] is a map.
//!
//! # Which host: the MX ladder
//!
//! | What the zone says | What is tried |
//! |---|---|
//! | MX records | one host per preference, **ascending** (RFC 5321 §5.1: "lowest number first") |
//! | one MX `0 .` (RFC 7505) | **nothing** — the domain says it takes no mail, and a sender that falls back to A violates the record |
//! | no MX, but an A or AAAA | the domain itself, as the implicit MX (RFC 5321 §5.1) |
//! | no MX and no address | a **permanent** failure: the domain does not resolve |
//! | the query failed | a **temporary** failure: an unavailable resolver loses no mail |
//!
//! The two "no" answers are deliberately different codes, because they have
//! different fixes on the sending side: a domain with no records is a bounce
//! (there will never be a host), and a resolver that did not answer is a
//! retry (there is a host; we could not ask).
//!
//! # How it talks: opportunistic TLS
//!
//! MTA-to-MTA TLS is **opportunistic**, which is Postfix's
//! `smtp_tls_security_level = may` and RFC 3207 §4's "a client MAY use TLS if
//! the server advertises it": if the server lists `STARTTLS` the connection is
//! upgraded and the certificate is verified (`webpki-roots`, server name = the
//! MX host); if the handshake fails, the delivery **falls back to cleartext**
//! rather than failing, and the receiver is told — the `Received:` field's
//! `with` protocol word is `ESMTPS` for an upgraded connection and `ESMTP` for
//! a plaintext one, which is how the recipient can tell.
//!
//! Falling back is the right answer here and only here: an MTA handshake that
//! is stricter than the receiver's means every MX with a broken certificate is
//! unreachable, which is a denial of service the *sender* inflicts on its own
//! users. (MTA-STS and DANE make it strict where the receiver published a
//! policy; neither is implemented — see the receipt for the map entry.)
//!
//! **No credential ever crosses this connection.** Outbound is unauthenticated
//! by construction: there is no `AUTH` command in this client, and its absence
//! means a downgrade cannot leak a password — only the message, which would
//! have gone in cleartext anyway if the receiver had not offered TLS.
//!
//! # What it sends
//!
//! The client speaks the RFC 1869/5321 subset that matters on the wire:
//! `SIZE` (honoured: a message past the receiver's declared limit is a
//! permanent failure, and the limit travels on `MAIL FROM`), `8BITMIME` (the
//! body is sent as `-BODY=8BITMIME` when the receiver offers it), `PIPELINING`
//! (the `MAIL`/`RCPT` batch is written before the first reply is read),
//! and dot-stuffing on the sending side (a line whose first octet is `.` gets
//! a second one; the transfer ends with `.<CRLF>`).
//!
//! `SMTPUTF8` is **not** forwarded: a recipient whose address is not ASCII is
//! bounced rather than relayed, which is the documented simplification for
//! this layer (RFC 6531's extension is orthogonal to MX resolution and needs
//! the whole downstream chain to negotiate it).
//!
//! # What arrives: one `Received:` per hop
//!
//! Every hop owes its own trace field (RFC 5321 §4.4), and the final delivery
//! hop is a hop: [`ReceivedField`] renders `from <us> by <them> with ESMTP{,S}
//! id <id>` and [`receive`] puts it on top of the octets the queue holds. That
//! is also where the signature lands, and the order matters: the `Received:`
//! field is written **first**, then the `DKIM-Signature` header above it, so
//! the signed message is exactly the message the receiver's verifier sees.

use std::collections::BTreeMap;
use std::fmt;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use ayane_proto::DesiredState;
use mail_auth::dns::{DnsCache, Mx, Negative, RecordSet, ResolverCache};
use mail_auth::DnsError;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

/// The port an MTA listens on for inbound mail (RFC 5321 §4.5.3.1: the
/// default, and the one MX records mean).
pub const SMTP_PORT: u16 = 25;

/// The longest a `Received:` value may be before it is folded: RFC 5322 §2.1.1
/// caps a line at 998 octets and RFC 5321 §4.5.3.1.6 asks a server to *accept*
/// 1000, so a value near that is a field the next hop may already refuse.
pub const RECEIVED_LINE_LIMIT: usize = 998;

// ── the resolver seam ────────────────────────────────────────────────────

/// Where MX and address records come from.
///
/// The transport asks this and nothing else: it never opens a resolver itself,
/// which is what makes the whole MX ladder a table in a test. [`SystemResolver`]
/// is the production implementation (hickory, over `/etc/resolv.conf`) and
/// [`StaticResolver`] is a map; [`FixedZone`](crate::zone::FixedZone) is a
/// [`DnsCache`] and is adapted with [`ZoneResolver`].
///
/// Implementations are `async` behind `Pin<Box<dyn Future>>` rather than a
/// native async trait because the crate has no `async-trait` dependency for one
/// seam and a boxed future costs one allocation per message, not per octet.
pub trait Resolver: Send + Sync {
    /// The MX records of `domain`, sorted by ascending preference.
    ///
    /// # Errors
    ///
    /// Returns [`LookupError::Temporary`] when the query could not be answered
    /// (an unreachable resolver, a timeout) and [`LookupError::NoRecords`] when
    /// the domain provably has none of this type.
    fn mx<'a>(
        &'a self,
        domain: &'a str,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Vec<Mx>, LookupError>> + Send + 'a>,
    >;

    /// The addresses of `host`, A and AAAA together.
    ///
    /// # Errors
    ///
    /// Same split as [`Resolver::mx`]; a host with an A but no AAAA is not an
    /// error, it is a one-family answer.
    fn addresses<'a>(
        &'a self,
        host: &'a str,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Vec<IpAddr>, LookupError>> + Send + 'a>,
    >;
}

/// Why a lookup could not be used.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LookupError {
    /// The name provably has no records of the type asked for (NXDOMAIN, or
    /// NOERROR with an empty answer).
    #[error("no records")]
    NoRecords,
    /// The query could not be answered: a resolver that is down, a timeout, a
    /// malformed reply. A temporary failure — mail must not be lost to it.
    #[error("the resolver did not answer: {0}")]
    Temporary(String),
}

impl LookupError {
    /// Whether waiting could change this answer.
    #[must_use]
    pub fn is_temporary(&self) -> bool {
        matches!(self, Self::Temporary(_))
    }
}

/// The production resolver: hickory, over whatever the host's resolver
/// configuration says.
pub struct SystemResolver {
    authenticator: mail_auth::MessageAuthenticator,
}

impl fmt::Debug for SystemResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SystemResolver(..)")
    }
}

impl SystemResolver {
    /// Builds a resolver from `/etc/resolv.conf` (and the nsswitch
    /// configuration on hosts that have one).
    ///
    /// # Errors
    ///
    /// Returns [`LookupError::Temporary`] when the host has no usable resolver
    /// configuration. It is the same answer the transport gives a message when
    /// the resolver is unreachable, because it is the same situation: there is
    /// a host to deliver to and no way to ask where it is.
    pub fn system() -> Result<Self, LookupError> {
        mail_auth::MessageAuthenticator::new_system_conf()
            .or_else(|err| {
                // A host with no resolv.conf (a container with a mounted one
                // missing) still has a working provider table; refusing every
                // message would be worse than asking a public resolver.
                tracing::warn!(%err, "no system resolver configuration; using the built-in one");
                mail_auth::MessageAuthenticator::new_cloudflare()
            })
            .map(|authenticator| Self { authenticator })
            .map_err(|err| LookupError::Temporary(err.to_string()))
    }
}

/// What `mail_auth::Error` means for a lookup.
fn classify(error: &mail_auth::Error) -> LookupError {
    match error {
        mail_auth::Error::Dns(DnsError::RecordNotFound(_)) => LookupError::NoRecords,
        other => LookupError::Temporary(other.to_string()),
    }
}

impl Resolver for SystemResolver {
    fn mx<'a>(
        &'a self,
        domain: &'a str,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Vec<Mx>, LookupError>> + Send + 'a>,
    > {
        use mail_auth::dns::ToFqdn;
        Box::pin(async move {
            self.authenticator
                .mx_lookup(domain.to_fqdn(), None::<&mail_auth::dns::NoCache>)
                .await
                .map(|set| set.records.to_vec())
                .map_err(|err| classify(&err))
        })
    }

    fn addresses<'a>(
        &'a self,
        host: &'a str,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Vec<IpAddr>, LookupError>> + Send + 'a>,
    > {
        use mail_auth::dns::ToFqdn;
        Box::pin(async move {
            let mut out = Vec::new();
            let mut saw_records = false;
            let mut hard_failure = None;
            for family in 0..2 {
                let result = if family == 0 {
                    self.authenticator
                        .ipv4_lookup(host.to_fqdn(), None::<&mail_auth::dns::NoCache>)
                        .await
                        .map(|set| {
                            set.records
                                .iter()
                                .copied()
                                .map(IpAddr::V4)
                                .collect::<Vec<_>>()
                        })
                } else {
                    self.authenticator
                        .ipv6_lookup(host.to_fqdn(), None::<&mail_auth::dns::NoCache>)
                        .await
                        .map(|set| {
                            set.records
                                .iter()
                                .copied()
                                .map(IpAddr::V6)
                                .collect::<Vec<_>>()
                        })
                };
                match result {
                    Ok(addresses) => {
                        saw_records = true;
                        out.extend(addresses);
                    }
                    // One family missing is not an error: the host may publish
                    // only A, or only AAAA (RFC 5321 §5.1 does not require
                    // both), and the other family is still an answer.
                    Err(mail_auth::Error::Dns(DnsError::RecordNotFound(_))) => {}
                    Err(err) => hard_failure = Some(classify(&err)),
                }
            }
            match (out.is_empty(), saw_records, hard_failure) {
                (false, ..) => Ok(out),
                (true, _, Some(err)) => Err(err),
                (true, true, None) | (true, false, None) => Err(LookupError::NoRecords),
            }
        })
    }
}

/// A resolver answering from a map: the test and pinned-zone form.
#[derive(Debug, Clone, Default)]
pub struct StaticResolver {
    mx: BTreeMap<String, Result<Vec<Mx>, LookupError>>,
    addrs: BTreeMap<String, Result<Vec<IpAddr>, LookupError>>,
}

impl StaticResolver {
    /// A resolver that answers "no records" to everything.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Publishes `records` at `domain`, in ascending preference order as the
    /// MX ladder expects.
    #[must_use]
    pub fn with_mx(mut self, domain: &str, records: Vec<(u16, &str)>) -> Self {
        self.mx.insert(
            domain.to_ascii_lowercase(),
            Ok(group_mx(
                records
                    .into_iter()
                    .map(|(preference, host)| (preference, host.to_owned())),
            )),
        );
        self
    }

    /// Publishes a null MX (`0 .`) at `domain`: RFC 7505's "this domain
    /// accepts no mail".
    #[must_use]
    pub fn with_null_mx(mut self, domain: &str) -> Self {
        self.mx.insert(
            domain.to_ascii_lowercase(),
            Ok(vec![Mx {
                exchanges: Box::new([".".into()]),
                preference: 0,
            }]),
        );
        self
    }

    /// Makes the MX query for `domain` fail temporarily.
    #[must_use]
    pub fn with_mx_failure(mut self, domain: &str, reason: &str) -> Self {
        self.mx.insert(
            domain.to_ascii_lowercase(),
            Err(LookupError::Temporary(reason.to_owned())),
        );
        self
    }

    /// Publishes `addresses` for `host`.
    #[must_use]
    pub fn with_addresses(mut self, host: &str, addresses: &[IpAddr]) -> Self {
        self.addrs
            .insert(host.to_ascii_lowercase(), Ok(addresses.to_vec()));
        self
    }

    /// Makes the address query for `host` fail temporarily.
    #[must_use]
    pub fn with_address_failure(mut self, host: &str, reason: &str) -> Self {
        self.addrs.insert(
            host.to_ascii_lowercase(),
            Err(LookupError::Temporary(reason.to_owned())),
        );
        self
    }
}

impl Resolver for StaticResolver {
    fn mx<'a>(
        &'a self,
        domain: &'a str,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Vec<Mx>, LookupError>> + Send + 'a>,
    > {
        Box::pin(async move {
            self.mx
                .get(&domain.to_ascii_lowercase())
                .cloned()
                .unwrap_or(Err(LookupError::NoRecords))
        })
    }

    fn addresses<'a>(
        &'a self,
        host: &'a str,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Vec<IpAddr>, LookupError>> + Send + 'a>,
    > {
        Box::pin(async move {
            self.addrs
                .get(&host.to_ascii_lowercase())
                .cloned()
                .unwrap_or(Err(LookupError::NoRecords))
        })
    }
}

/// A [`crate::zone::FixedZone`] seen as a [`Resolver`].
///
/// The zone is the [`DnsCache`] the verifiers already use, and the wrappers
/// around it are the same `ResolverCache` interface, so the MX the transport
/// asks for and the MX a verifier would see come from one table. The zone is
/// authoritative: a name it does not list answers "no records" and never falls
/// through to the network, which is what keeps an offline run measuring the
/// transport instead of an outage.
#[derive(Clone)]
pub struct ZoneResolver {
    zone: Arc<dyn DnsCacheDyn>,
}

/// The dynamic half of [`DnsCache`]: a zone is generic over its five caches,
/// and the transport only needs MX and both address families. The blanket
/// implementation below covers every concrete `DnsCache`, so `ZoneResolver`
/// holds a trait object and not a type parameter — which is what lets one
/// `Outbound` be shared without naming the zone's associated types.
trait DnsCacheDyn: Send + Sync {
    fn mx_lookup(&self, name: &str) -> Option<Result<RecordSet<Mx>, Negative>>;
    fn v4_lookup(&self, name: &str) -> Option<Result<RecordSet<Ipv4Addr>, Negative>>;
    fn v6_lookup(&self, name: &str) -> Option<Result<RecordSet<Ipv6Addr>, Negative>>;
}

impl<Z> DnsCacheDyn for Z
where
    Z: DnsCache + Send + Sync,
{
    fn mx_lookup(&self, name: &str) -> Option<Result<RecordSet<Mx>, Negative>> {
        self.mx()?.get::<str>(name)
    }

    fn v4_lookup(&self, name: &str) -> Option<Result<RecordSet<Ipv4Addr>, Negative>> {
        self.ipv4()?.get::<str>(name)
    }

    fn v6_lookup(&self, name: &str) -> Option<Result<RecordSet<Ipv6Addr>, Negative>> {
        self.ipv6()?.get::<str>(name)
    }
}

impl ZoneResolver {
    /// Wraps any [`DnsCache`] — in practice a [`crate::zone::FixedZone`] — as
    /// the transport's resolver.
    #[must_use]
    pub fn new<Z: DnsCache + Send + Sync + 'static>(zone: Z) -> Self {
        Self {
            zone: Arc::new(zone),
        }
    }
}

impl fmt::Debug for ZoneResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ZoneResolver(..)")
    }
}

impl Resolver for ZoneResolver {
    fn mx<'a>(
        &'a self,
        domain: &'a str,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Vec<Mx>, LookupError>> + Send + 'a>,
    > {
        use mail_auth::dns::ToFqdn;
        Box::pin(async move {
            let name = domain.to_fqdn().into_owned();
            match self.zone.mx_lookup(&name) {
                Some(Ok(set)) => Ok(set.records.to_vec()),
                Some(Err(_)) | None => Err(LookupError::NoRecords),
            }
        })
    }

    fn addresses<'a>(
        &'a self,
        host: &'a str,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Vec<IpAddr>, LookupError>> + Send + 'a>,
    > {
        use mail_auth::dns::ToFqdn;
        Box::pin(async move {
            let name = host.to_fqdn().into_owned();
            let mut out = Vec::new();
            for (v4, v6) in [(true, false), (false, true)] {
                let answer = if v4 {
                    self.zone.v4_lookup(&name).map(|answer| {
                        answer.map(|set| {
                            set.records
                                .iter()
                                .copied()
                                .map(IpAddr::V4)
                                .collect::<Vec<_>>()
                        })
                    })
                } else if v6 {
                    self.zone.v6_lookup(&name).map(|answer| {
                        answer.map(|set| {
                            set.records
                                .iter()
                                .copied()
                                .map(IpAddr::V6)
                                .collect::<Vec<_>>()
                        })
                    })
                } else {
                    None
                };
                if let Some(Ok(addresses)) = answer {
                    out.extend(addresses);
                }
            }
            if out.is_empty() {
                Err(LookupError::NoRecords)
            } else {
                Ok(out)
            }
        })
    }
}

/// Whether an MX exchange names the root — RFC 7505's null MX (`0 .`).
///
/// A resolver may render the root name as `.` or as the empty string, and both
/// mean the same record.
fn is_root_name(exchange: &str) -> bool {
    let trimmed = exchange.trim_end_matches('.');
    trimmed.is_empty()
}

/// Groups `(preference, host)` pairs into [`Mx`] records, ascending.
///
/// `mail-auth`'s own `mx_lookup` groups this way; a [`StaticResolver`] and a
/// [`FixedZone`](crate::zone::FixedZone) have to, too, so a test's zone reads
/// like a resolver's answer.
#[must_use]
pub fn group_mx(pairs: impl Iterator<Item = (u16, String)>) -> Vec<Mx> {
    let mut records: Vec<(u16, Vec<Box<str>>)> = Vec::new();
    for (preference, host) in pairs {
        let host: Box<str> = host.to_ascii_lowercase().into_boxed_str();
        match records
            .iter_mut()
            .find(|(existing, _)| *existing == preference)
        {
            Some((_, hosts)) => hosts.push(host),
            None => records.push((preference, vec![host])),
        }
    }
    records.sort_unstable_by_key(|(preference, _)| *preference);
    records
        .into_iter()
        .map(|(preference, exchanges)| Mx {
            exchanges: exchanges.into_boxed_slice(),
            preference,
        })
        .collect()
}

// ── the MX ladder ────────────────────────────────────────────────────────

/// One host the transport may try, in the order the zone asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MxTarget {
    /// The host name — what the connection is made to and what the TLS
    /// certificate must be valid for.
    pub host: String,
    /// The MX preference, or `None` for the implicit MX of an A/AAAA fallback
    /// (RFC 5321 §5.1: "if an empty list of MXs is returned … use the A").
    pub preference: Option<u16>,
}

/// Where mail for a domain goes, or why it cannot go anywhere.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MxPlan {
    /// Try these hosts, in this order.
    Hosts(Vec<MxTarget>),
    /// The domain publishes a null MX (RFC 7505): it accepts no mail, and
    /// falling back to its address records would be a protocol violation, so
    /// the recipient is failed **permanently** and at once.
    Null,
    /// The domain does not resolve: no MX and no address. Permanent — there
    /// will never be a host to deliver to.
    NoHost,
    /// The resolver did not answer. Transient: try again later.
    Unavailable(String),
}

impl MxPlan {
    /// The hosts to try, in order.
    #[must_use]
    pub fn hosts(&self) -> &[MxTarget] {
        match self {
            Self::Hosts(hosts) => hosts,
            _ => &[],
        }
    }
}

/// Resolves the MX ladder for `domain` (RFC 5321 §5.1 + RFC 7505).
///
/// The address fallback is only consulted when the MX query answered **"no
/// records"** — never when it *failed*. A timeout during the MX query is not
/// evidence that the domain has no MX, and treating it as one would let a
/// resolver outage mail a message to a host the zone never named.
pub async fn resolve_mx(resolver: &dyn Resolver, domain: &str) -> MxPlan {
    match resolver.mx(domain).await {
        Ok(records) if records.is_empty() => fall_back_to_address(resolver, domain).await,
        Ok(records) => {
            // RFC 7505 §3: an MX with preference 0 and a single "." exchange
            // says the domain accepts no mail. A zone that publishes that
            // *and* real MX records is malformed; the null wins, because
            // honouring the other records would deliver mail a domain said it
            // does not want.
            let null = records.iter().any(|record| {
                record
                    .exchanges
                    .iter()
                    .any(|exchange| is_root_name(exchange))
            });
            if null {
                return MxPlan::Null;
            }
            let mut hosts = Vec::new();
            for record in &records {
                for exchange in record.exchanges.iter() {
                    let host = exchange.trim_end_matches('.').to_ascii_lowercase();
                    // An empty exchange is the same null MX in a resolver that
                    // rendered the root name as the empty string; never a host.
                    if host.is_empty() || is_root_name(&host) {
                        continue;
                    }
                    hosts.push(MxTarget {
                        host,
                        preference: Some(record.preference),
                    });
                }
            }
            if hosts.is_empty() {
                return MxPlan::Null;
            }
            hosts.sort_by_key(|target| target.preference);
            MxPlan::Hosts(hosts)
        }
        Err(LookupError::NoRecords) => fall_back_to_address(resolver, domain).await,
        Err(err @ LookupError::Temporary(_)) => MxPlan::Unavailable(err.to_string()),
    }
}

/// The implicit MX: the domain's own address (RFC 5321 §5.1).
async fn fall_back_to_address(resolver: &dyn Resolver, domain: &str) -> MxPlan {
    match resolver.addresses(domain).await {
        Ok(addresses) if !addresses.is_empty() => MxPlan::Hosts(vec![MxTarget {
            host: domain.to_ascii_lowercase(),
            preference: None,
        }]),
        Ok(_) | Err(LookupError::NoRecords) => MxPlan::NoHost,
        Err(err @ LookupError::Temporary(_)) => MxPlan::Unavailable(err.to_string()),
    }
}

// ── what a delivery attempt produced ─────────────────────────────────────

/// The TLS outcome of one connection, which is what the trace field records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TlsOutcome {
    /// The receiver did not advertise `STARTTLS`: the connection was plaintext
    /// from the first octet and nothing was lost by trying.
    NotOffered,
    /// `STARTTLS` was advertised and the handshake completed with a verified
    /// certificate.
    Upgraded,
    /// `STARTTLS` was advertised and the handshake failed (a bad certificate,
    /// an unimplemented protocol, a server that hung up). The connection
    /// continues in cleartext — the opportunistic fallback.
    Downgraded(String),
}

impl TlsOutcome {
    /// The RFC 3848 `with` protocol word this outcome puts in the trace field.
    #[must_use]
    pub fn protocol(&self) -> &'static str {
        match self {
            Self::Upgraded => "ESMTPS",
            Self::NotOffered | Self::Downgraded(_) => "ESMTP",
        }
    }
}

/// Why one host did not take the message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttemptError {
    /// The connection could not be made, or broke. Temporary.
    Transport(String),
    /// The receiver answered, and its answer says the message may arrive later
    /// (a `4yz` reply). Temporary, and the receiver's code is kept for the DSN.
    Deferred(Reply),
    /// The receiver answered, and its answer says it never will (a `5yz`
    /// reply). Permanent.
    Refused(Reply),
}

impl fmt::Display for AttemptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport(message) => f.write_str(message),
            Self::Deferred(reply) | Self::Refused(reply) => f.write_str(&reply.text()),
        }
    }
}

impl AttemptError {
    /// Whether waiting could change this answer.
    #[must_use]
    pub fn is_temporary(&self) -> bool {
        matches!(self, Self::Transport(_) | Self::Deferred(_))
    }

    /// The receiver's reply, when there was one.
    #[must_use]
    pub fn reply(&self) -> Option<&Reply> {
        match self {
            Self::Deferred(reply) | Self::Refused(reply) => Some(reply),
            Self::Transport(_) => None,
        }
    }

    /// The failure as a DSN `Diagnostic-Code` and operator log line: the
    /// remote code and text where there is one, the transport error otherwise.
    #[must_use]
    pub fn diagnostic(&self) -> String {
        match self {
            Self::Transport(message) => format!("X-ayane; {message}"),
            Self::Deferred(reply) | Self::Refused(reply) => {
                format!("smtp; {}", reply.text())
            }
        }
    }
}

/// One SMTP reply: a code and the (possibly multi-line) text behind it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    /// The three-digit code.
    pub code: u16,
    /// Every text line the reply carried, in order, without the code and the
    /// `-`/space separator.
    pub lines: Vec<String>,
}

impl Reply {
    /// The reply as a `Diagnostic-Code` value: `<code> <last line>`.
    #[must_use]
    pub fn text(&self) -> String {
        format!(
            "{} {}",
            self.code,
            self.lines.last().map_or("", String::as_str)
        )
    }

    /// Whether the code is a `2yz` (success) reply.
    #[must_use]
    pub fn is_ok(&self) -> bool {
        (200..300).contains(&self.code)
    }

    /// Whether the code is an intermediate `3yz` reply (`DATA`'s `354`).
    #[must_use]
    pub fn is_intermediate(&self) -> bool {
        (300..400).contains(&self.code)
    }

    /// Whether the code is a `4yz` (transient) reply.
    #[must_use]
    pub fn is_temporary(&self) -> bool {
        (400..500).contains(&self.code)
    }

    /// Whether the code is a `5yz` (permanent) reply.
    #[must_use]
    pub fn is_permanent(&self) -> bool {
        (500..600).contains(&self.code)
    }
}

impl fmt::Display for Reply {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text())
    }
}

/// What one recipient's fate was on one connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecipientResult {
    /// The recipient address as it was sent.
    pub recipient: String,
    /// `None` when the recipient was accepted and the message delivered,
    /// `Some(reason)` otherwise.
    pub error: Option<AttemptError>,
}

/// What one transaction did, per recipient.
///
/// The two halves are disjoint and together cover the recipient set the
/// transaction offered: `delivered` are the ones the receiver accepted (its
/// `250` at the end of `DATA` covers exactly those), `refused` the ones whose
/// own `RCPT` it declined — each carrying the reply so the retry ladder and the
/// DSN can use the receiver's own words.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    /// The host that was talked to.
    pub host: String,
    /// The TLS outcome, for the trace field and the operator's log.
    pub tls: TlsOutcome,
    /// The recipients the receiver accepted.
    pub delivered: Vec<String>,
    /// The recipients whose `RCPT` it refused, with each refusal.
    pub refused: Vec<RecipientResult>,
}

impl Outcome {
    /// The trace field's `with` protocol word.
    #[must_use]
    pub fn protocol(&self) -> &'static str {
        self.tls.protocol()
    }
}

// ── the ESMTP client ─────────────────────────────────────────────────────

/// The transport-level bounds of one outbound connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientLimits {
    /// How long the TCP connect may take.
    pub connect_timeout: Duration,
    /// How long any single SMTP reply may take.
    pub command_timeout: Duration,
    /// How long the TLS handshake may take.
    pub handshake_timeout: Duration,
}

impl Default for ClientLimits {
    /// The RFC 5321 §4.5.3.2 order of magnitude for an MTA, cut shorter
    /// because an outbound connection has other hosts to try: a receiver that
    /// takes a minute to greet is not going to take this message today.
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(30),
            command_timeout: Duration::from_secs(60),
            handshake_timeout: Duration::from_secs(30),
        }
    }
}

/// How the client was asked to reach a host: the address it may be redirected
/// to by a test, and the certificate policy it verifies against.
#[derive(Debug, Clone)]
pub struct Endpoint {
    /// Where to connect. Production resolves `host:25`; a test points this at
    /// a loopback listener while keeping `host` as the name the certificate
    /// must cover.
    pub address: SocketAddr,
    /// The name the connection presents itself as (EHLO) and the name the
    /// certificate must be valid for.
    pub host: String,
}

/// The trust policy of the outbound client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsPolicy {
    /// Verify the certificate against the web roots for the MX host name —
    /// the production policy.
    Verified,
    /// Accept any certificate. **Tests only**, for a fixture with a
    /// self-signed certificate; a deployment must never select it.
    InsecureForTests,
}

/// A client configuration: the name it presents, the bounds and the policy.
#[derive(Debug, Clone)]
pub struct ClientConfig {
    /// The name this instance presents in `EHLO`.
    pub hostname: String,
    /// The transport bounds.
    pub limits: ClientLimits,
    /// The certificate policy.
    pub tls: TlsPolicy,
}

/// What the receiver said it can do (`EHLO`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Capabilities {
    /// `SIZE <n>`: the largest message accepted, or `Some(0)` for an unbounded
    /// `SIZE`, or `None` when the receiver did not list `SIZE`.
    pub size: Option<u64>,
    /// `8BITMIME`: the body may carry octets above 127 without re-encoding.
    pub eight_bit_mime: bool,
    /// `SMTPUTF8`: UTF-8 addresses are accepted (not used — see the module
    /// docs).
    pub smtp_utf8: bool,
    /// `PIPELINING`: commands may be batched.
    pub pipelining: bool,
    /// `STARTTLS`: the connection may be upgraded.
    pub starttls: bool,
}

impl Capabilities {
    /// Reads the extension lines of an `EHLO` reply.
    #[must_use]
    pub fn parse(lines: &[String]) -> Self {
        let mut caps = Self::default();
        for line in lines {
            let mut words = line.split_ascii_whitespace();
            let Some(verb) = words.next() else { continue };
            let verb = verb.to_ascii_uppercase();
            match verb.as_str() {
                "STARTTLS" => caps.starttls = true,
                "8BITMIME" => caps.eight_bit_mime = true,
                "SMTPUTF8" => caps.smtp_utf8 = true,
                "PIPELINING" => caps.pipelining = true,
                "SIZE" => {
                    caps.size = Some(
                        words
                            .next()
                            .and_then(|limit| limit.parse().ok())
                            .unwrap_or(0),
                    );
                }
                _ => {}
            }
        }
        caps
    }
}

/// A plaintext or upgraded connection.
enum Stream {
    Plain(TcpStream),
    Tls(Box<tokio_rustls::client::TlsStream<TcpStream>>),
}

impl AsyncRead for Stream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(stream) => std::pin::Pin::new(stream).poll_read(cx, buf),
            Self::Tls(stream) => std::pin::Pin::new(stream.as_mut()).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for Stream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Plain(stream) => std::pin::Pin::new(stream).poll_write(cx, buf),
            Self::Tls(stream) => std::pin::Pin::new(stream.as_mut()).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(stream) => std::pin::Pin::new(stream).poll_flush(cx),
            Self::Tls(stream) => std::pin::Pin::new(stream.as_mut()).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(stream) => std::pin::Pin::new(stream).poll_shutdown(cx),
            Self::Tls(stream) => std::pin::Pin::new(stream.as_mut()).poll_shutdown(cx),
        }
    }
}

/// Dot-stuffs `body` for a `DATA` transfer and appends the terminator.
///
/// RFC 5321 §4.5.2: a line whose first octet is `.` is sent with one more, so
/// that the only `.<CRLF>` on the wire is the terminator. The transformation
/// is on **line starts only** — a `.` after the first octet of a line is
/// message content and is left alone — and the terminator is `.<CRLF>` after
/// the body's own final CRLF, which is why a body already ending in `CRLF`
/// gets one `<CRLF>` between its last line and the dot.
#[must_use]
pub fn dot_stuff(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len() + body.len() / 64 + 8);
    let mut at_line_start = true;
    for &byte in body {
        if at_line_start && byte == b'.' {
            out.push(b'.');
        }
        out.push(byte);
        at_line_start = byte == b'\n';
    }
    // The terminator is a line of its own: a body that does not end in CRLF
    // needs one before the dot, and a body that does is already there.
    if !body.ends_with(b"\r\n") {
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b".\r\n");
    out
}

/// One outbound connection: greet, negotiate, upgrade, transact.
pub struct Session {
    /// `None` only while a `STARTTLS` upgrade holds the socket: the handshake
    /// consumes the stream and hands back a different one, and dropping the
    /// reader first is what guarantees nothing an earlier server wrote is
    /// replayed into the session that follows (VU#555316).
    stream: Option<BufReader<Stream>>,
    capabilities: Capabilities,
    hostname: String,
    limits: ClientLimits,
    tls_policy: TlsPolicy,
    tls: TlsOutcome,
}

impl Session {
    /// Connects to `endpoint` and performs the greeting and `EHLO`.
    ///
    /// # Errors
    ///
    /// Returns [`AttemptError::Transport`] for a connect, greeting or `EHLO`
    /// failure — all temporary — and [`AttemptError::Refused`] when the
    /// receiver greets with a `5yz` (it will not talk to this sender at all).
    pub async fn connect(config: &ClientConfig, endpoint: &Endpoint) -> Result<Self, AttemptError> {
        let socket = tokio::time::timeout(
            config.limits.connect_timeout,
            TcpStream::connect(endpoint.address),
        )
        .await
        .map_err(|_| {
            AttemptError::Transport(format!(
                "connect to {} timed out after {:?}",
                endpoint.address, config.limits.connect_timeout
            ))
        })?
        .map_err(|err| AttemptError::Transport(format!("connect {}: {err}", endpoint.address)))?;
        let _ = socket.set_nodelay(true);
        let mut session = Self {
            stream: Some(BufReader::new(Stream::Plain(socket))),
            capabilities: Capabilities::default(),
            hostname: config.hostname.clone(),
            limits: config.limits,
            tls_policy: config.tls,
            tls: TlsOutcome::NotOffered,
        };
        let greeting = session.read_reply().await?;
        if !greeting.is_ok() {
            return Err(session.refusal(greeting));
        }
        session.ehlo().await?;
        Ok(session)
    }

    /// The capabilities the receiver listed.
    #[must_use]
    pub fn capabilities(&self) -> &Capabilities {
        &self.capabilities
    }

    /// The TLS outcome so far.
    #[must_use]
    pub fn tls(&self) -> &TlsOutcome {
        &self.tls
    }

    async fn ehlo(&mut self) -> Result<(), AttemptError> {
        let reply = self.command(&format!("EHLO {}", self.hostname)).await?;
        if reply.is_ok() {
            self.capabilities = Capabilities::parse(&reply.lines);
            return Ok(());
        }
        // RFC 5321 §4.1.4: a server that does not know EHLO answers 500/502/504
        // and the client falls back to HELO — with no extensions at all.
        if matches!(reply.code, 500 | 502 | 504) {
            let fallback = self.command(&format!("HELO {}", self.hostname)).await?;
            if fallback.is_ok() {
                self.capabilities = Capabilities::default();
                return Ok(());
            }
            return Err(self.refusal(fallback));
        }
        Err(self.refusal(reply))
    }

    /// Upgrades the connection when the receiver offers `STARTTLS` (RFC 3207),
    /// and records what happened either way.
    ///
    /// A failed handshake is **not** a failed delivery: the connection goes
    /// back to cleartext and the trace field will say `ESMTP`. See the module
    /// docs for why that is the right trade for MTA-to-MTA mail.
    ///
    /// # Errors
    ///
    /// Returns [`AttemptError::Transport`] when the `STARTTLS` command itself
    /// cannot be written or read. A receiver that *refuses* `STARTTLS` (a
    /// `454`/`5yz`) leaves the connection usable in cleartext, so that is not
    /// an error either — it is a downgrade, recorded as one.
    pub async fn start_tls(&mut self, server_name: &str) -> Result<(), AttemptError> {
        if !self.capabilities.starttls {
            self.tls = TlsOutcome::NotOffered;
            return Ok(());
        }
        let reply = self.command("STARTTLS").await?;
        if !reply.is_intermediate() && !reply.is_ok() {
            // Offered and then refused. Not an error: the RFC 3207 §4 answer
            // to a refused upgrade is to continue unprotected, and the trace
            // field will say so.
            self.tls = TlsOutcome::Downgraded(format!("STARTTLS refused: {}", reply.text()));
            return Ok(());
        }
        let connector = match self.connector() {
            Ok(connector) => connector,
            Err(err) => {
                self.tls = TlsOutcome::Downgraded(err);
                return Ok(());
            }
        };
        let name = match rustls::pki_types::ServerName::try_from(server_name.to_owned()) {
            Ok(name) => name,
            Err(err) => {
                self.tls = TlsOutcome::Downgraded(format!("unusable server name: {err}"));
                return Ok(());
            }
        };
        // The upgrade consumes the socket and the buffered reader owns it, so
        // the reader is taken out and unwrapped. Anything it holds past the
        // `220` is dropped with it: the client must not act on octets a server
        // wrote before the handshake (VU#555316's shape, the same discipline
        // the inbound driver documents).
        let Some(buffered) = self.stream.take() else {
            self.tls = TlsOutcome::Downgraded("the connection is already upgrading".to_owned());
            return Ok(());
        };
        let plain = buffered.into_inner();
        let Stream::Plain(socket) = plain else {
            // Only reachable when a second upgrade is attempted; the caller
            // never does, and the safe answer is not to pretend it worked.
            self.tls = TlsOutcome::Downgraded("the connection is already upgraded".to_owned());
            self.stream = None;
            return Ok(());
        };
        match tokio::time::timeout(
            self.limits.handshake_timeout,
            connector.connect(name, socket),
        )
        .await
        {
            Ok(Ok(stream)) => {
                self.stream = Some(BufReader::new(Stream::Tls(Box::new(stream))));
                self.tls = TlsOutcome::Upgraded;
                // RFC 3207 §4.2: the server forgets what it knew, so the
                // extension list is asked again on the upgraded connection.
                self.ehlo().await?;
                Ok(())
            }
            Ok(Err(err)) => {
                // The socket is gone with the failed handshake. The caller
                // must open a new plaintext connection to continue, which is
                // exactly what a downgrade means here.
                Err(AttemptError::Transport(format!(
                    "the TLS handshake failed and the connection ended: {err}"
                )))
            }
            Err(_) => Err(AttemptError::Transport(
                "the TLS handshake timed out".to_owned(),
            )),
        }
    }

    fn connector(&self) -> Result<TlsConnector, String> {
        let provider = rustls::crypto::ring::default_provider();
        let config = match self.tls_policy {
            TlsPolicy::InsecureForTests => {
                let verifier = Arc::new(AcceptAnyCertificate {
                    provider: provider.clone(),
                });
                rustls::ClientConfig::builder_with_provider(Arc::new(provider))
                    .with_safe_default_protocol_versions()
                    .map_err(|err| format!("TLS versions: {err}"))?
                    .dangerous()
                    .with_custom_certificate_verifier(verifier)
                    .with_no_client_auth()
            }
            TlsPolicy::Verified => {
                // The family's root store: the same webpki-roots the
                // workspace already trusts (`mail-auth`'s `webpki-roots`
                // feature is one consumer, `reqwest`'s rustls-tls is another).
                let mut roots = rustls::RootCertStore::empty();
                roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
                let verifier = rustls::client::WebPkiServerVerifier::builder_with_provider(
                    Arc::new(roots),
                    Arc::new(provider.clone()),
                )
                .build()
                .map_err(|err| format!("TLS roots: {err}"))?;
                rustls::ClientConfig::builder_with_provider(Arc::new(provider))
                    .with_safe_default_protocol_versions()
                    .map_err(|err| format!("TLS versions: {err}"))?
                    .with_webpki_verifier(verifier)
                    .with_no_client_auth()
            }
        };
        Ok(TlsConnector::from(Arc::new(config)))
    }

    /// Runs one transaction: `MAIL FROM` with `SIZE=`, `RCPT` for every
    /// recipient, `DATA`, the stuffed body, `QUIT`.
    ///
    /// A recipient the receiver refuses does not abort the transaction: SMTP
    /// lets one connection carry several recipients with different fates
    /// (RFC 5321 §4.1.1.3), and retrying a good recipient because a bad one
    /// bounced is how one message becomes two copies. So the result is
    /// **per recipient** — [`Outcome`] — and the transaction-level failure is
    /// reserved for the two replies that concern the message itself: a refused
    /// `MAIL FROM` and a refused end of `DATA`.
    ///
    /// # Errors
    ///
    /// Returns [`AttemptError::Refused`] when the `MAIL FROM` or the end of
    /// `DATA` is answered `5yz`, [`AttemptError::Deferred`] when it is answered
    /// `4yz`, and [`AttemptError::Transport`] when the connection breaks. In
    /// each of those cases the whole recipient set shares the failure.
    pub async fn deliver(
        &mut self,
        target: &str,
        sender: &str,
        recipients: &[String],
        message: &[u8],
    ) -> Result<Outcome, AttemptError> {
        if let Some(limit) = self.capabilities.size {
            // `SIZE 0` is RFC 1870 §4's "no fixed maximum".
            if limit > 0 && message.len() as u64 > limit {
                return Err(AttemptError::Refused(Reply {
                    code: 552,
                    lines: vec![format!(
                        "5.3.4 message is {} octets; the receiver accepts at most {limit}",
                        message.len()
                    )],
                }));
            }
        }
        let sender = if sender.is_empty() {
            "<>".to_owned()
        } else {
            format!("<{sender}>")
        };
        let mut mail = format!("MAIL FROM:{sender}");
        if self.capabilities.size.is_some() {
            mail.push_str(&format!(" SIZE={}", message.len()));
        }
        if self.capabilities.eight_bit_mime && message.iter().any(|byte| *byte >= 0x80) {
            mail.push_str(" BODY=8BITMIME");
        }
        let reply = self.command(&mail).await?;
        if !reply.is_ok() {
            return Err(self.refusal(reply));
        }

        // PIPELINING (RFC 2920): the whole `RCPT` batch goes out before the
        // first reply is read, so a five-recipient message costs one round trip
        // and not five. Without it each `RCPT` waits for its own reply.
        let mut answers: Vec<Reply> = Vec::with_capacity(recipients.len());
        if self.capabilities.pipelining {
            let mut batch = String::new();
            for recipient in recipients {
                batch.push_str(&format!("RCPT TO:<{recipient}>\r\n"));
            }
            self.write(batch.as_bytes()).await?;
            for _ in recipients {
                answers.push(self.read_reply().await?);
            }
        } else {
            for recipient in recipients {
                answers.push(self.command(&format!("RCPT TO:<{recipient}>")).await?);
            }
        }
        let accepted: Vec<String> = recipients
            .iter()
            .zip(answers.iter())
            .filter(|(_, reply)| reply.is_ok())
            .map(|(recipient, _)| recipient.clone())
            .collect();
        let refused: Vec<RecipientResult> = recipients
            .iter()
            .zip(answers.iter())
            .filter(|(_, reply)| !reply.is_ok())
            .map(|(recipient, reply)| RecipientResult {
                recipient: recipient.clone(),
                error: Some(if reply.is_temporary() {
                    AttemptError::Deferred(reply.clone())
                } else {
                    AttemptError::Refused(reply.clone())
                }),
            })
            .collect();

        if accepted.is_empty() {
            // Nothing to send: the transaction is over and every recipient
            // carries the reason its own `RCPT` was refused. A missing `RSET`
            // is harmless — the `QUIT` closes the connection anyway — but it
            // is sent so a server that logs the transaction sees it cancelled
            // rather than abandoned.
            let _ = self.command("RSET").await;
            let _ = self.command("QUIT").await;
            return Ok(Outcome {
                host: target.to_owned(),
                tls: self.tls.clone(),
                delivered: Vec::new(),
                refused,
            });
        }

        let reply = self.command("DATA").await?;
        if !reply.is_intermediate() {
            return Err(self.refusal(reply));
        }
        let body = dot_stuff(message);
        self.write(&body).await?;
        let reply = self.read_reply().await?;
        if !reply.is_ok() {
            return Err(self.refusal(reply));
        }
        let _ = self.command("QUIT").await;
        Ok(Outcome {
            host: target.to_owned(),
            tls: self.tls.clone(),
            delivered: accepted,
            refused,
        })
    }

    /// Writes one command, flushes, and reads its reply.
    async fn command(&mut self, line: &str) -> Result<Reply, AttemptError> {
        let mut wire = Vec::with_capacity(line.len() + 2);
        wire.extend_from_slice(line.as_bytes());
        wire.extend_from_slice(b"\r\n");
        self.write(&wire).await?;
        self.read_reply().await
    }

    async fn write(&mut self, bytes: &[u8]) -> Result<(), AttemptError> {
        let Some(stream) = self.stream.as_mut() else {
            return Err(AttemptError::Transport(
                "the connection is upgrading".to_owned(),
            ));
        };
        let write = async {
            stream.get_mut().write_all(bytes).await?;
            stream.get_mut().flush().await
        };
        tokio::time::timeout(self.limits.command_timeout, write)
            .await
            .map_err(|_| AttemptError::Transport("write timed out".to_owned()))?
            .map_err(|err| AttemptError::Transport(format!("write: {err}")))
    }

    /// Reads one reply, following `250-` continuation lines until the
    /// `250 ` that ends it (RFC 5321 §4.2.1).
    async fn read_reply(&mut self) -> Result<Reply, AttemptError> {
        let mut lines = Vec::new();
        loop {
            let Some(stream) = self.stream.as_mut() else {
                return Err(AttemptError::Transport(
                    "the connection is upgrading".to_owned(),
                ));
            };
            let mut line = String::new();
            let read =
                tokio::time::timeout(self.limits.command_timeout, stream.read_line(&mut line))
                    .await
                    .map_err(|_| AttemptError::Transport("read timed out".to_owned()))?;
            match read {
                Ok(0) => {
                    return Err(AttemptError::Transport(
                        "the receiver closed the connection mid-reply".to_owned(),
                    ))
                }
                Ok(_) => {}
                Err(err) => return Err(AttemptError::Transport(format!("read: {err}"))),
            }
            let trimmed = line.trim_end_matches(['\r', '\n']);
            if trimmed.len() < 4 || !trimmed.is_char_boundary(4) {
                // Not a reply at all. A server that speaks no SMTP is a
                // transport failure, not a permanent refusal: the message may
                // be fine and the server broken.
                return Err(AttemptError::Transport(format!(
                    "malformed reply line: {trimmed:?}"
                )));
            }
            let (code, rest) = trimmed.split_at(3);
            let Ok(code) = code.parse::<u16>() else {
                return Err(AttemptError::Transport(format!(
                    "malformed reply code: {trimmed:?}"
                )));
            };
            let continuation = rest.starts_with('-');
            lines.push(rest[1..].to_owned());
            if !continuation {
                return Ok(Reply { code, lines });
            }
        }
    }

    /// Turns a non-success reply into the attempt error its code names.
    fn refusal(&self, reply: Reply) -> AttemptError {
        if reply.is_temporary() {
            AttemptError::Deferred(reply)
        } else {
            AttemptError::Refused(reply)
        }
    }
}

/// A verifier that accepts every certificate: the test policy of
/// [`TlsPolicy::InsecureForTests`].
#[derive(Debug)]
struct AcceptAnyCertificate {
    provider: rustls::crypto::CryptoProvider,
}

impl rustls::client::danger::ServerCertVerifier for AcceptAnyCertificate {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

// ── the trace field a delivery hop writes ────────────────────────────────

/// The `Received:` field the final delivery hop writes (RFC 5321 §4.4).
///
/// The value is assembled here, pure, and the octets go on top of the message
/// by [`receive`]. What it carries is what the next hop cannot otherwise know:
/// who sent it (`from`, this instance), to whom (`by`, the MX host), with which
/// protocol (`with` — `ESMTPS` when the connection was upgraded, `ESMTP` when
/// it was not), and when.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceivedField {
    /// The host this instance calls itself in `EHLO`.
    pub from: String,
    /// The MX host the message went to.
    pub by: String,
    /// RFC 3848's protocol word: `ESMTPS` upgraded, `ESMTP` not.
    pub protocol: &'static str,
    /// Whether the connection *offered* TLS and the upgrade failed.
    ///
    /// The two `ESMTP` cases are different facts about the same wire: a
    /// receiver that never advertised `STARTTLS` says nothing about the
    /// sender, and one that advertised it and then failed the handshake does.
    /// The protocol word is the same (`ESMTP` — the connection really was
    /// plaintext), and this is what keeps them apart: a downgrade says so in
    /// the field, because the operator's next question after "was this
    /// encrypted?" is "why wasn't it?".
    pub starttls_failed: bool,
    /// The queue id, so the field joins an operator's log to the message.
    pub id: String,
    /// The RFC 5322 date.
    pub date: String,
}

/// The `Received:` comment that records a failed opportunistic upgrade.
///
/// RFC 5321 §4.4 permits a comment in a trace field, and this is the one this
/// crate writes: `with ESMTP (starttls-failed)` says the peer offered TLS and
/// the handshake did not complete. A connection where that happened is still
/// `ESMTP` — it was never `ESMTPS` — and the comment is the difference between
/// "the peer does not do TLS" and "the peer does, and something is wrong with
/// it".
pub const STARTTLS_FAILED_NOTE: &str = "(starttls-failed)";

impl ReceivedField {
    /// The value that follows `Received: ` (no field name, no CRLF).
    #[must_use]
    pub fn value(&self) -> String {
        let protocol = if self.starttls_failed {
            format!("{} {}", self.protocol, STARTTLS_FAILED_NOTE)
        } else {
            self.protocol.to_owned()
        };
        format!(
            "from {from} (ayane) by {by} with {protocol} id {id}; {date}",
            from = sanitize(&self.from, 255),
            by = sanitize(&self.by, 255),
            protocol = protocol,
            id = sanitize(&self.id, 255),
            date = sanitize(&self.date, 64),
        )
    }

    /// The whole field, folded where it would break the 998-octet line bound.
    #[must_use]
    pub fn header(&self) -> String {
        fold_received(&self.value())
    }
}

/// Folds a `Received:` value so no line exceeds RFC 5322 §2.1.1's octet cap.
///
/// The value is inserted at whitespace only, and each continuation line starts
/// with a single space — the RFC's folding rule — so the unfolded value a
/// reader reconstructs is the value that was written. A value already short
/// enough comes back untouched, which is the normal case: a real
/// `Received:` value is a few hundred octets.
#[must_use]
pub fn fold_received(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 16);
    out.push_str("Received: ");
    let mut column = "Received: ".len();
    for (index, word) in value.split(' ').enumerate() {
        let extra = if index == 0 { 0 } else { 1 };
        // A line may hold at most `RECEIVED_LINE_LIMIT` octets, and the
        // continuation's own leading space counts.
        if index > 0 && column + extra + word.len() > RECEIVED_LINE_LIMIT {
            out.push_str("\r\n ");
            column = 1;
        } else if index > 0 {
            out.push(' ');
            column += 1;
        }
        out.push_str(word);
        column += word.len();
    }
    out.push_str("\r\n");
    out
}

/// Replaces the octets a header value cannot hold.
///
/// A host name, a queue id and a date are produced by this crate, but two of
/// them travel through a resolver answer, and a CR or LF in one would end the
/// field and start another — header injection into the message the next hop
/// keeps. (The inbound driver's `sanitize_header_token` is the same rule, one
/// layer up.)
fn sanitize(value: &str, max: usize) -> String {
    let cleaned: String = value
        .chars()
        .map(|ch| if ch.is_control() { '?' } else { ch })
        .take(max)
        .collect();
    if cleaned.is_empty() {
        "unknown".to_owned()
    } else {
        cleaned
    }
}

/// The octets that go on the wire: this hop's `Received:` field, then whatever
/// the queue holds.
///
/// The trace field is written **here, once, per hop** and not stored: the queue
/// entry keeps the octets it received, so a retry either writes one field per
/// delivery or none at all. It goes
/// first because the octets below it are exactly what the receiver's DKIM
/// verifier hashes — the signature this crate adds covers the `Received:` field
/// it was computed over, so the order is `Received:` then `DKIM-Signature` then
/// the stored message, and nothing may be inserted between them.
#[must_use]
pub fn receive(field: &ReceivedField, body: &[u8]) -> Vec<u8> {
    let header = field.header();
    let mut out = Vec::with_capacity(header.len() + body.len());
    out.extend_from_slice(header.as_bytes());
    out.extend_from_slice(body);
    out
}

// ── DKIM signing ─────────────────────────────────────────────────────────

/// The header fields outbound mail is signed over (RFC 6376 §5.4).
///
/// `From` is mandatory (§5.4.1: a signature without it is invalid). The rest
/// are the ones a signature is *for*: `To`, `Subject`, `Date` and
/// `Message-ID` are what a receiver's disposition rules read, and an unsigned
/// one of them is an octet a relay could rewrite. `MIME-Version` and
/// `Content-Type` are added when present because a body that changes type after
/// signing is a body whose hash means something else.
pub const SIGNED_HEADERS: &[&str] = &[
    "From",
    "To",
    "Cc",
    "Subject",
    "Date",
    "Message-ID",
    "MIME-Version",
    "Content-Type",
    "Reply-To",
];

/// Why a message could not be signed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SignError {
    /// The configured key is not a PKCS #8 (or PKCS #1) PEM an RSA signer can
    /// load.
    #[error("the DKIM key for `{domain}` cannot be loaded: {reason}")]
    Key {
        /// The signing domain.
        domain: String,
        /// What the parser said.
        reason: String,
    },
    /// `mail-auth` refused to sign (no headers, an unsupported algorithm).
    #[error("DKIM signing failed: {0}")]
    Sign(String),
}

/// One domain's signer, built from the state's selector and the key the
/// consumer read from its own out-of-band source.
///
/// The key never travels in the state snapshot (see
/// [`ayane_proto::DkimSigningConfig`]): this type is what turns "the selector
/// says `ayane`" and "the process was given this PEM" into a signature, and it
/// is built once per pass, not once per message.
pub struct Signer {
    domain: String,
    inner: mail_auth::dkim::DkimSigner<
        mail_auth::crypto::RsaKey<mail_auth::crypto::Sha256>,
        mail_auth::signer::Ready,
    >,
}

impl fmt::Debug for Signer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Signer")
            .field("domain", &self.domain)
            .finish_non_exhaustive()
    }
}

impl Signer {
    /// Builds a signer for `domain` from a PEM private key.
    ///
    /// RSA-SHA256 is the algorithm every receiver understands; `relaxed` on
    /// both header and body (RFC 6376 §3.4.2 and §3.4.4) is the one that
    /// survives a hop that rewrites whitespace, which is most of them.
    ///
    /// # Errors
    ///
    /// Returns [`SignError::Key`] when the PEM cannot be read as a key.
    pub fn rsa(domain: &str, selector: &str, pem: &str) -> Result<Self, SignError> {
        use rustls::pki_types::pem::PemObject as _;

        let der =
            rustls::pki_types::PrivateKeyDer::from_pem_slice(pem.as_bytes()).map_err(|err| {
                SignError::Key {
                    domain: domain.to_owned(),
                    reason: err.to_string(),
                }
            })?;
        let key = mail_auth::crypto::RsaKey::<mail_auth::crypto::Sha256>::from_key_der(der)
            .map_err(|err| SignError::Key {
                domain: domain.to_owned(),
                reason: err.to_string(),
            })?;
        let inner = mail_auth::dkim::DkimSigner::from_key(key)
            .domain(domain)
            .selector(selector)
            .headers(SIGNED_HEADERS.iter().copied())
            .header_canonicalization(mail_auth::dkim::Canonicalization::Relaxed)
            .body_canonicalization(mail_auth::dkim::Canonicalization::Relaxed);
        Ok(Self {
            domain: domain.to_owned(),
            inner,
        })
    }

    /// The domain this signer speaks for.
    #[must_use]
    pub fn domain(&self) -> &str {
        &self.domain
    }

    /// Signs `message` and returns its `DKIM-Signature` field, CRLF included.
    ///
    /// # Errors
    ///
    /// Returns [`SignError::Sign`] when `mail-auth` refuses; the caller must
    /// not send the message unsigned in that case without saying so.
    pub fn sign(&self, message: &[u8]) -> Result<String, SignError> {
        use mail_auth::headers::HeaderWriter as _;

        let signature = self
            .inner
            .sign(message)
            .map_err(|err| SignError::Sign(err.to_string()))?;
        Ok(signature.to_header())
    }
}

/// Builds the signers a state and an environment describe.
///
/// For every enabled domain with a DKIM selector in the state, the private key
/// is read from the environment variable `template` names — `{domain}` stands
/// for the domain, so `AYANE_DKIM_KEY_{domain}` is one variable per domain.
///
/// Three things this deliberately does:
///
/// - **A domain with a selector and no key is logged and left unsigned.** The
///   alternative — refusing to deliver — turns a missing signature into a mail
///   outage; DMARC's `p=` is the receiver's policy to enforce, not a reason to
///   hold the message.
/// - **A key that will not load is a hard error.** A domain that says it signs
///   and then ships a message with no signature, or with a broken one, is a
///   worse answer than stopping: an operator who moved a key should find out at
///   start-up.
/// - **The template is read from the environment, never from the state.** The
///   state names the selector (which is public); the environment delivers the
///   key. Nothing this function touches is ever written back.
///
/// # Errors
///
/// Returns [`SignError::Key`] when a key the environment does supply cannot be
/// parsed.
pub fn signers_from_env(
    state: &DesiredState,
    template: &str,
) -> Result<BTreeMap<String, Signer>, SignError> {
    let mut signers = BTreeMap::new();
    for (domain, config) in Outbound::signers_for(state) {
        // The variable name is `template` with the domain substituted. A
        // domain is a DNS name and an environment variable name is not: a dot
        // is legal in the first and — on a POSIX shell — not in the second, so
        // the domain is spelled in the variable the way an operator can write
        // it. See [`dkim_env_name`].
        let variable = dkim_env_name(template, &domain);
        match std::env::var(&variable) {
            Ok(pem) if !pem.trim().is_empty() => {
                // The key is the domain's, and the domain is the one the
                // message will claim. A second format check here is depth, not
                // belief: `state.validate()` already refused a malformed
                // hosted name, and a key configured for a name a sender could
                // not claim is a signature nobody verifies.
                if let Err(err) = ayane_proto::check_domain(&domain) {
                    tracing::warn!(
                        domain = %domain,
                        error = %err,
                        "a DKIM key is configured for a name that is not a domain:                          refusing to sign for it"
                    );
                    continue;
                }
                signers.insert(
                    domain.clone(),
                    Signer::rsa(&domain, &config.selector, &pem)?,
                );
            }
            _ => {
                tracing::warn!(
                    domain = %domain,
                    variable,
                    "a DKIM selector is configured but its key is not in the environment: \
                     mail from this domain leaves unsigned"
                );
            }
        }
    }
    Ok(signers)
}

/// The environment variable holding `domain`'s DKIM key, from a template.
///
/// `{domain}` is replaced by the domain with every octet outside
/// `[A-Za-z0-9_]` turned into `_`, because a POSIX environment variable name
/// may not contain a dot: `example.com` becomes `example_com`, so
/// `AYANE_DKIM_KEY_{domain}` names `AYANE_DKIM_KEY_example_com`.
///
/// A template that already contains the sanitised spelling is honoured as
/// written (no double substitution), so an operator who wrote
/// `AYANE_DKIM_KEY_example_com` by hand and an operator who wrote the template
/// get the same variable.
#[must_use]
pub fn dkim_env_name(template: &str, domain: &str) -> String {
    let sanitised: String = domain
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '_' {
                ch
            } else {
                '_'
            }
        })
        .collect();
    template.replace("{domain}", &sanitised)
}

/// Puts a `DKIM-Signature` field on top of `message`.
///
/// The signature is computed over the message **including** this hop's
/// `Received:` field (which is why the field is written first) and covers every
/// occurrence of each signed header name, so `h=` lists them from the bottom
/// up — the RFC's rule, and `mail-auth` writes it.
#[must_use]
pub fn sign_bytes(signature_header: &str, message: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(signature_header.len() + message.len());
    out.extend_from_slice(signature_header.as_bytes());
    out.extend_from_slice(message);
    out
}

// ── the transport configuration ──────────────────────────────────────────

/// The outbound transport: everything a delivery pass needs to put a message
/// on another host's disk.
///
/// One instance is shared by every pass (it holds the resolver and the TLS
/// policy, not per-message state), and its [`Outbound::deliver_group`] is what
/// [`crate::deliver`] calls once per destination domain.
pub struct Outbound {
    resolver: Arc<dyn Resolver>,
    client: ClientConfig,
    /// The port every host is connected to. `25` in a deployment; a test binds
    /// a listener on a random port and says so, and an operator on a network
    /// that requires a relay port can too.
    port: u16,
    /// Overrides for where a host connects. Tests use it to point a
    /// certificate-checked connection at a loopback listener while keeping the
    /// MX name as the name the certificate must cover; a deployment never sets
    /// one, and the field is a map so a pinned host can be redirected by an
    /// operator on a network with a split-horizon resolver.
    addresses: BTreeMap<String, SocketAddr>,
    /// The DKIM keys, by signing domain.
    signers: BTreeMap<String, Arc<Signer>>,
}

impl fmt::Debug for Outbound {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Outbound")
            .field("hostname", &self.client.hostname)
            .field("port", &self.port)
            .field("tls", &self.client.tls)
            .field("signing_domains", &self.signers.keys().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

impl Outbound {
    /// A transport over `resolver` that presents `hostname` in `EHLO` and
    /// connects to port 25.
    #[must_use]
    pub fn new(resolver: Arc<dyn Resolver>, hostname: impl Into<String>) -> Self {
        Self {
            resolver,
            client: ClientConfig {
                hostname: hostname.into(),
                limits: ClientLimits::default(),
                tls: TlsPolicy::Verified,
            },
            port: SMTP_PORT,
            addresses: BTreeMap::new(),
            signers: BTreeMap::new(),
        }
    }

    /// Replaces the transport bounds (tests and an operator on a slow link).
    #[must_use]
    pub fn with_limits(mut self, limits: ClientLimits) -> Self {
        self.client.limits = limits;
        self
    }

    /// Replaces the certificate policy. [`TlsPolicy::InsecureForTests`] exists
    /// for a fixture with a self-signed certificate and for nothing else.
    #[must_use]
    pub fn with_tls_policy(mut self, tls: TlsPolicy) -> Self {
        self.client.tls = tls;
        self
    }

    /// Connects to `port` on every host instead of 25.
    #[must_use]
    pub fn with_port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }

    /// Pins `host`'s address instead of resolving it.
    #[must_use]
    pub fn with_address(mut self, host: &str, address: SocketAddr) -> Self {
        self.addresses.insert(host.to_ascii_lowercase(), address);
        self
    }

    /// Adds a signer for `domain`: mail whose `From` domain is `domain` leaves
    /// with its `DKIM-Signature`.
    #[must_use]
    pub fn with_signer(mut self, signer: Signer) -> Self {
        self.signers
            .insert(signer.domain().to_ascii_lowercase(), Arc::new(signer));
        self
    }

    /// The transport configuration (the `EHLO` name and the bounds).
    #[must_use]
    pub fn client_config(&self) -> &ClientConfig {
        &self.client
    }

    /// The signer for `domain`, when one is configured.
    #[must_use]
    pub fn signer(&self, domain: &str) -> Option<&Arc<Signer>> {
        self.signers.get(&domain.to_ascii_lowercase())
    }

    /// Everything a delivery pass knows about the state: the signers it names.
    ///
    /// A domain with a selector in the state and no key in the process is a
    /// configuration mistake the operator must see, so it is a warning here and
    /// the message leaves unsigned — refusing to deliver a message because a
    /// *signature* is missing would turn an authentication problem into a mail
    /// outage.
    #[must_use]
    pub fn signers_for(state: &DesiredState) -> BTreeMap<String, ayane_proto::DkimSigningConfig> {
        state
            .domains
            .iter()
            .filter(|domain| domain.enabled)
            .filter_map(|domain| {
                domain
                    .dkim
                    .as_ref()
                    .map(|dkim| (domain.name.clone(), dkim.clone()))
            })
            .collect()
    }

    /// Delivers one message to every host `domain` names, in MX order.
    ///
    /// The result is one [`GroupResult`] per recipient: a delivery that reached
    /// a host is `Ok` for the recipients that host accepted, and the reason a
    /// recipient did not go through otherwise — each with the code the retry
    /// ladder and the DSN need. The MX ladder is walked **only** past hosts
    /// that did not answer at the transport level: a host that answered `5yz`
    /// about a recipient has answered about *that recipient*, and asking the
    /// next MX would just make a second server refuse it.
    pub async fn deliver_group(
        &self,
        domain: &str,
        sender: &str,
        recipients: &[String],
        message: &[u8],
        id: &str,
        now_epoch: u64,
    ) -> GroupResult {
        let plan = resolve_mx(self.resolver.as_ref(), domain).await;
        match &plan {
            MxPlan::Null => {
                return GroupResult::uniform(
                    recipients,
                    AttemptError::Refused(Reply {
                        code: 556,
                        lines: vec![format!(
                            "5.1.6 {domain} publishes a null MX (RFC 7505): it accepts no mail"
                        )],
                    }),
                );
            }
            MxPlan::NoHost => {
                return GroupResult::uniform(
                    recipients,
                    AttemptError::Refused(Reply {
                        code: 550,
                        lines: vec![format!(
                            "5.1.2 {domain} does not resolve: no MX and no address"
                        )],
                    }),
                );
            }
            MxPlan::Unavailable(why) => {
                return GroupResult::uniform(
                    recipients,
                    AttemptError::Transport(format!("the MX lookup for {domain} failed: {why}")),
                );
            }
            MxPlan::Hosts(hosts) if hosts.is_empty() => {
                return GroupResult::uniform(
                    recipients,
                    AttemptError::Refused(Reply {
                        code: 556,
                        lines: vec![format!("5.1.6 {domain} names no host")],
                    }),
                );
            }
            MxPlan::Hosts(_) => {}
        }

        let mut results: Vec<(String, Result<String, AttemptError>)> = Vec::new();
        let mut pending: Vec<String> = recipients.to_vec();
        // What the last attempt said about each recipient, so a recipient
        // every host failed on keeps the *reason* and not just "failed".
        let mut last: BTreeMap<String, AttemptError> = BTreeMap::new();
        'hosts: for target in plan.hosts() {
            if pending.is_empty() {
                break;
            }
            let endpoint = match self.endpoint(&target.host).await {
                Ok(endpoint) => endpoint,
                Err(err) => {
                    for recipient in &pending {
                        last.insert(recipient.clone(), err.clone());
                    }
                    continue;
                }
            };
            let outcome = self
                .transmit(&endpoint, sender, &pending, message, id, now_epoch)
                .await;
            match outcome {
                Ok(outcome) => {
                    for recipient in outcome.delivered {
                        last.remove(&recipient);
                        results.push((recipient.clone(), Ok(target.host.clone())));
                        pending.retain(|left| left != &recipient);
                    }
                    for refusal in outcome.refused {
                        let Some(error) = refusal.error else {
                            continue;
                        };
                        // A `5yz` is the receiver's final answer about *this
                        // recipient*: asking another MX would merely get a
                        // second server to say the same thing. A `4yz` is a
                        // "later", and the next MX may take it now.
                        if !error.is_temporary() {
                            results.push((refusal.recipient.clone(), Err(error)));
                            pending.retain(|left| left != &refusal.recipient);
                        } else {
                            last.insert(refusal.recipient, error);
                        }
                    }
                }
                Err(err) => {
                    // The whole transaction failed: no host took anything, so
                    // every pending recipient carries this host's refusal.
                    for recipient in &pending {
                        last.insert(recipient.clone(), err.clone());
                    }
                    // A receiver that refuses this sender outright will refuse
                    // it on every host, so walking the rest of the ladder only
                    // costs connections. A transport failure is exactly the
                    // case the ladder exists for.
                    if matches!(err, AttemptError::Refused(_)) {
                        break 'hosts;
                    }
                }
            }
        }
        for recipient in pending {
            let error = last.remove(&recipient).unwrap_or_else(|| {
                AttemptError::Transport(
                    "every MX host for the domain was tried and none answered".to_owned(),
                )
            });
            results.push((recipient, Err(error)));
        }
        GroupResult { results }
    }

    /// Where `host` is connected to.
    async fn endpoint(&self, host: &str) -> Result<Endpoint, AttemptError> {
        if let Some(address) = self.addresses.get(&host.to_ascii_lowercase()) {
            return Ok(Endpoint {
                address: *address,
                host: host.to_owned(),
            });
        }
        let addresses = self
            .resolver
            .addresses(host)
            .await
            .map_err(|err| AttemptError::Transport(format!("{host}: {err}")))?;
        let with_port = |ip: &IpAddr| SocketAddr::new(*ip, self.port);
        // IPv4 first: a mail host reachable both ways is reached the way the
        // operator's egress is more likely to have an address for, and a
        // failure on one family is what the next MX host is for.
        let address = addresses
            .iter()
            .find(|ip| ip.is_ipv4())
            .or_else(|| addresses.first())
            .map(with_port)
            .ok_or_else(|| AttemptError::Transport(format!("{host} has no address")))?;
        Ok(Endpoint {
            address,
            host: host.to_owned(),
        })
    }

    /// One connection to one host: greet, upgrade if offered, sign, send.
    async fn transmit(
        &self,
        endpoint: &Endpoint,
        sender: &str,
        recipients: &[String],
        message: &[u8],
        id: &str,
        now_epoch: u64,
    ) -> Result<Outcome, AttemptError> {
        let mut session = Session::connect(&self.client, endpoint).await?;
        // Opportunistic upgrade (RFC 3207, Postfix's `security_level = may`).
        // A handshake that fails takes the socket with it — rustls consumes the
        // stream — so falling back to cleartext means opening a second
        // connection that does not offer to upgrade again, which is what a
        // real MTA does after a failed `STARTTLS`. The message is what would
        // have gone in cleartext had the server not advertised TLS at all, and
        // the trace field says `ESMTP` rather than claiming a session that
        // died.
        let tls = match session.start_tls(&endpoint.host).await {
            // Upgraded, or the server never offered it: the session knows.
            Ok(()) => session.tls().clone(),
            Err(err) => {
                tracing::info!(
                    host = %endpoint.host,
                    %err,
                    "STARTTLS failed; delivering over a plaintext connection"
                );
                drop(session);
                let plain = Session::connect(&self.client, endpoint).await?;
                session = plain;
                TlsOutcome::Downgraded(err.to_string())
            }
        };
        let field = ReceivedField {
            from: self.client.hostname.clone(),
            by: endpoint.host.clone(),
            protocol: tls.protocol(),
            starttls_failed: matches!(tls, TlsOutcome::Downgraded(_)),
            id: id.to_owned(),
            date: crate::server::format_rfc5322(now_epoch),
        };
        let received = receive(&field, message);
        let wire = self.sign(&received)?;
        session
            .deliver(&endpoint.host, sender, recipients, &wire)
            .await
    }

    /// Signs the octets when the `From` header's domain has a signer.
    ///
    /// The signing domain is the `From` header's, not the envelope's: RFC 6376
    /// §5.4 signs what the reader sees, and a signature over a domain the
    /// message does not claim addresses nobody. See [`FromDomain`] for which
    /// `From` that is and why an ambiguous message is never signed.
    fn sign(&self, received: &[u8]) -> Result<Vec<u8>, AttemptError> {
        let domain = match from_domain(received) {
            FromDomain::One(domain) => domain,
            // Two `From` fields: malformed, and a signature would say "this is
            // genuinely from" about a message whose own author is unclear. The
            // receiver decides what to do with it; this crate does not vouch
            // for it.
            FromDomain::Ambiguous { domains } => {
                tracing::warn!(
                    domains = %domains.join(","),
                    "the message carries more than one From field: not signing it"
                );
                return Ok(received.to_vec());
            }
            FromDomain::NoDomain => {
                // Either no `From` at all or none with a domain. Unsigned is
                // the right answer for both: there is no domain to claim.
                return Ok(received.to_vec());
            }
        };
        let Some(signer) = self.signer(&domain) else {
            return Ok(received.to_vec());
        };
        let header = signer
            .sign(received)
            .map_err(|err| AttemptError::Transport(format!("cannot sign for {domain}: {err}")))?;
        Ok(sign_bytes(&header, received))
    }
}

/// The domain a message is signed for, from its `From` header field(s).
///
/// # Which `From` — the last one, and why
///
/// RFC 5322 §3.6 says a message has exactly one `From` field, but a message on
/// the wire may carry several, and when it does, **readers and DMARC take the
/// last one** — the one nearest the body, which is the one a chain of relays
/// most recently added. A signer that picked the first would sign
/// `example.test` for a message whose reader sees `victim.test`: the receiver
/// would report DKIM `pass` for a domain the message does not claim, which is
/// the exact combination a forger wants. So the *last* `From` field's domain
/// is what this returns.
///
/// # Multiple `From` is a refusal, not a choice
///
/// Taking the last one is already the safer reading, but a message with two
/// `From` fields is malformed, and signing it would lend a valid signature to
/// a shape that receivers handle inconsistently (some read the first, some the
/// last, DMARC reads the last). So [`from_domain`] returns the analysis rather
/// than a bare `Option`, and a second `From` field is a [`FromDomain::Ambiguous`]
/// that the transport refuses to sign and logs. A message nobody signed is
/// worse than one signed for the wrong domain only for the sender; an ambiguous
/// one is worse for everybody.
///
/// # Failing on one field never silences the others
///
/// The header section is scanned field by field. A field name that is not
/// UTF-8, or is not `From`, is **skipped** — not a reason to give up on the
/// fields after it. Only a `From` field whose *own* value yields no domain
/// makes the answer `NoDomain`, and even then the scan continues, so
/// `From: nobody` followed by `From: Alice <alice@example.test>` still signs
/// for `example.test`. That distinction is the difference between "this message
/// has no usable `From`" and "the first thing I looked at confused me": the
/// former is a fact about the message, the latter was a bug that let one
/// throwaway header line suppress signing for a whole domain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FromDomain {
    /// Exactly one `From` field, naming this signing domain.
    One(String),
    /// Two or more `From` fields: malformed, and never signed for.
    Ambiguous {
        /// Every domain those fields named, in message order. Empty when none
        /// of them yielded a domain.
        domains: Vec<String>,
    },
    /// No `From` field carries a usable domain.
    NoDomain,
}

/// The signing domain a message's `From` field names.
///
/// Deliberately literal: the header section ends at the first blank line, the
/// field name is matched case-insensitively, and the domain is the part of the
/// last address in the field after its last `@`. See [`FromDomain`] for what
/// "last field" and "ambiguous" mean here.
#[must_use]
pub fn from_domain(message: &[u8]) -> FromDomain {
    let head_len = message
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .unwrap_or(message.len());
    let head = &message[..head_len];
    let mut domains: Vec<String> = Vec::new();
    let mut seen = 0usize;
    for field in head.split(|byte| *byte == b'\n') {
        let field = field.strip_suffix(b"\r").unwrap_or(field);
        let Some(colon) = field.iter().position(|byte| *byte == b':') else {
            // A folded continuation line, or a line that is not a field at
            // all. Neither can be a `From` field's *start*, and neither is a
            // reason to stop looking.
            continue;
        };
        // A field name outside ASCII is a field no SMTP server this crate talks
        // to writes, and it is skipped rather than ending the search: one
        // junk line must not decide whether the message below it is signed.
        let Ok(name) = std::str::from_utf8(&field[..colon]) else {
            continue;
        };
        if !name.eq_ignore_ascii_case("from") {
            continue;
        }
        seen += 1;
        // A `From` field that yields no domain does not end the scan either:
        // the *next* one may be the real one. `None` from this field only
        // means this field contributed nothing.
        if let Some(domain) = value_domain(&field[colon + 1..]) {
            domains.push(domain);
        }
    }
    if seen > 1 {
        return FromDomain::Ambiguous { domains };
    }
    match domains.into_iter().next() {
        Some(domain) => FromDomain::One(domain),
        None => FromDomain::NoDomain,
    }
}

/// The domain of the last address in one `From` field's value, when it has
/// one.
fn value_domain(value: &[u8]) -> Option<String> {
    let value = String::from_utf8_lossy(value);
    let at = value.rfind('@')?;
    let rest = &value[at + 1..];
    let domain: String = rest
        .chars()
        .take_while(|ch| ch.is_ascii_alphanumeric() || *ch == '-' || *ch == '.')
        .collect();
    let domain = domain.trim_matches('.').to_ascii_lowercase();
    (!domain.is_empty()).then_some(domain)
}

/// The delivery layer's view of [`Outbound`].
///
/// [`crate::deliver`] is synchronous — it is a file-consuming state machine
/// whose whole crash story is about the order of two writes — and the SMTP
/// client is asynchronous. This adapter is the seam: it runs one destination's
/// group on a runtime of its own and hands the result back as a blocking call.
///
/// # Why the group runs on a thread of its own
///
/// Entering a runtime does not make `block_on` legal from a thread that is
/// *already* driving another one — tokio panics with "cannot start a runtime
/// from within a runtime", and the delivery consumer usually runs inside a
/// runtime (the binary's `#[tokio::main]`, a test's). So the group is moved to
/// a thread that owns nothing else, which is also where a blocking network
/// client belongs: it parks that thread, not the consumer's worker. The cost
/// is one thread per destination group, bounded by however many groups are
/// being delivered at once, and the alternative — an async delivery layer —
/// would put the spool's crash ordering behind an `await`.
pub struct SyncedTransport {
    outbound: Arc<Outbound>,
}

impl SyncedTransport {
    /// Wraps an [`Outbound`].
    ///
    /// # Errors
    ///
    /// Returns [`io::Error`] only for a failure to build a runtime, which is a
    /// host with no I/O driver and which no deployment has.
    pub fn new(outbound: Outbound) -> io::Result<Self> {
        Ok(Self {
            outbound: Arc::new(outbound),
        })
    }

    /// The transport underneath.
    #[must_use]
    pub fn outbound(&self) -> &Arc<Outbound> {
        &self.outbound
    }
}

impl fmt::Debug for SyncedTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SyncedTransport")
            .field("outbound", &self.outbound)
            .finish()
    }
}

impl crate::deliver::RemoteTransport for SyncedTransport {
    fn deliver_group(
        &self,
        request: &crate::deliver::RemoteRequest<'_>,
    ) -> io::Result<Vec<crate::deliver::RemoteReport>> {
        // Everything the thread needs, owned: the request borrows the caller's
        // message and recipient list, and the thread outlives this frame only
        // because it is joined before the frame ends.
        let outbound = Arc::clone(&self.outbound);
        let id = request.id.to_owned();
        let domain = request.domain.to_owned();
        let sender = request.sender.to_owned();
        let recipients = request.recipients.to_vec();
        let message = request.message.to_vec();
        let now_epoch = request.now_epoch;
        let worker = std::thread::Builder::new()
            .name("ayane-outbound".to_owned())
            .spawn(move || {
                // The runtime is built *here* and dropped at the end of this
                // closure, on the thread that ran it: a runtime dropped from an
                // async context panics ("cannot drop a runtime in a context
                // where blocking is not allowed"), and being owned by this
                // thread is what keeps that impossible.
                let Ok(runtime) = tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(1)
                    .enable_all()
                    .build()
                else {
                    return Vec::new();
                };
                let result = runtime.block_on(outbound.deliver_group(
                    &domain,
                    &sender,
                    &recipients,
                    &message,
                    &id,
                    now_epoch,
                ));
                result
                    .results
                    .into_iter()
                    .map(|(recipient, reply)| crate::deliver::RemoteReport {
                        recipient,
                        reply: match reply {
                            Ok(host) => crate::deliver::RemoteReply::Delivered { host },
                            Err(error) => {
                                let reason = error.diagnostic();
                                if error.is_temporary() {
                                    crate::deliver::RemoteReply::Deferred { reason }
                                } else {
                                    crate::deliver::RemoteReply::Refused { reason }
                                }
                            }
                        },
                    })
                    .collect::<Vec<_>>()
            })
            .map_err(|err| io::Error::other(format!("outbound thread: {err}")))?;
        worker
            .join()
            .map_err(|_| io::Error::other("the outbound thread panicked"))
    }
}

/// One destination's result: every recipient the group carried, with its fate.
///
/// `Err` is the recipient's own last reason (the receiver's code, or the
/// transport's words), never a shared "something failed": the retry ladder and
/// the DSN both quote it, and an operator reads it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GroupResult {
    /// One entry per recipient, in the order they were offered.
    pub results: Vec<(String, Result<String, AttemptError>)>,
}

impl GroupResult {
    /// Every recipient in the set failed for the same reason.
    #[must_use]
    pub fn uniform(recipients: &[String], error: AttemptError) -> Self {
        Self {
            results: recipients
                .iter()
                .map(|recipient| (recipient.clone(), Err(error.clone())))
                .collect(),
        }
    }

    /// The host that took each delivered recipient.
    pub fn delivered(&self) -> impl Iterator<Item = (&str, &str)> {
        self.results.iter().filter_map(|(recipient, result)| {
            result
                .as_ref()
                .ok()
                .map(|host| (recipient.as_str(), host.as_str()))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The signing-test key: the same throwaway RSA-2048 pair `tests/outbound.rs`
    /// uses, registered in `_ledger/tool-exemptions.md`. It authenticates
    /// nothing outside these tests.
    const FIXTURE_KEY: &str = include_str!("../tests/fixtures/dkim-private.pem");

    fn ip(raw: &str) -> IpAddr {
        raw.parse().expect("fixture address")
    }

    // ── the MX ladder ────────────────────────────────────────────────────

    #[tokio::test]
    async fn mx_records_are_tried_lowest_preference_first() {
        // RFC 5321 §5.1: the lowest preference is tried first. Two places make
        // that true — [`group_mx`] sorts a resolver's answer and
        // [`resolve_mx`] sorts what a [`Resolver`] hands back — so the test
        // drives a resolver that answers *unsorted*, which is what a zone or a
        // test double is free to do, and asserts the order the transport uses.
        /// A resolver whose MX answer is deliberately in the wrong order.
        struct Unsorted;
        impl Resolver for Unsorted {
            fn mx<'a>(
                &'a self,
                _domain: &'a str,
            ) -> std::pin::Pin<
                Box<dyn std::future::Future<Output = Result<Vec<Mx>, LookupError>> + Send + 'a>,
            > {
                Box::pin(async {
                    Ok(vec![
                        Mx {
                            exchanges: Box::new(["backup.example.com".into()]),
                            preference: 20,
                        },
                        Mx {
                            exchanges: Box::new(["primary.example.com".into()]),
                            preference: 10,
                        },
                    ])
                })
            }

            fn addresses<'a>(
                &'a self,
                _host: &'a str,
            ) -> std::pin::Pin<
                Box<dyn std::future::Future<Output = Result<Vec<IpAddr>, LookupError>> + Send + 'a>,
            > {
                Box::pin(async { Err(LookupError::NoRecords) })
            }
        }
        let plan = resolve_mx(&Unsorted, "example.com").await;
        assert_eq!(
            plan.hosts()
                .iter()
                .map(|t| t.host.as_str())
                .collect::<Vec<_>>(),
            vec!["primary.example.com", "backup.example.com"],
            "the transport orders by preference even when the answer does not"
        );
        // And a `StaticResolver` (which groups through [`group_mx`]) answers
        // in the same order, so the fixture a test uses reads like a resolver.
        let resolver = StaticResolver::empty().with_mx(
            "example.com",
            vec![(20, "backup.example.com"), (10, "primary.example.com")],
        );
        let plan = resolve_mx(&resolver, "example.com").await;
        assert_eq!(
            plan.hosts()
                .iter()
                .map(|t| t.host.as_str())
                .collect::<Vec<_>>(),
            vec!["primary.example.com", "backup.example.com"]
        );
        assert_eq!(
            plan.hosts(),
            &[
                MxTarget {
                    host: "primary.example.com".to_owned(),
                    preference: Some(10)
                },
                MxTarget {
                    host: "backup.example.com".to_owned(),
                    preference: Some(20)
                },
            ],
            "{plan:?}"
        );
    }

    #[test]
    fn an_mx_answer_is_grouped_and_sorted_by_preference() {
        // `mail-auth`'s own `mx_lookup` groups a zone's answer this way, so a
        // fixture that does not would read like a resolver that answers in a
        // shape the transport never sees. The sort is pinned here directly:
        // `resolve_mx` sorts again, so a test that only went through it would
        // pass with this function unsorted.
        let grouped = group_mx(
            [
                (30u16, "third.example".to_owned()),
                (10, "a.first.example".to_owned()),
                (10, "b.first.example".to_owned()),
                (20, "second.example".to_owned()),
            ]
            .into_iter(),
        );
        assert_eq!(
            grouped.iter().map(|mx| mx.preference).collect::<Vec<_>>(),
            vec![10, 20, 30],
            "ascending preference"
        );
        assert_eq!(
            grouped[0].exchanges.as_ref(),
            &["a.first.example".into(), "b.first.example".into()],
            "one preference groups its exchanges in answer order"
        );
    }

    #[tokio::test]
    async fn a_null_mx_is_permanent_and_never_falls_back_to_a() {
        // RFC 7505: `0 .` says "this domain accepts no mail". A sender that
        // then looks up the A record delivers mail the domain explicitly
        // refused.
        //
        // The null record is the *only* MX here, so a plan that honoured it as
        // an ordinary exchange would produce no usable host and fall into the
        // "names no host" arm — a different answer with a different code. The
        // test therefore drives the RFC 7505 arm specifically, and the A
        // record is published to prove the fallback is not taken.
        let resolver = StaticResolver::empty()
            .with_null_mx("example.com")
            .with_addresses("example.com", &[ip("192.0.2.1")]);
        let plan = resolve_mx(&resolver, "example.com").await;
        assert_eq!(plan, MxPlan::Null);
        assert!(plan.hosts().is_empty(), "no host may be tried");

        // A null MX beside a real one is a malformed zone: the null wins,
        // because honouring the other exchange would deliver mail the domain
        // said it refuses. `StaticResolver` holds one answer per name, so the
        // mixed one is built by hand.
        struct Mixed;
        impl Resolver for Mixed {
            fn mx<'a>(
                &'a self,
                _domain: &'a str,
            ) -> std::pin::Pin<
                Box<dyn std::future::Future<Output = Result<Vec<Mx>, LookupError>> + Send + 'a>,
            > {
                Box::pin(async {
                    Ok(vec![
                        Mx {
                            exchanges: Box::new([".".into()]),
                            preference: 0,
                        },
                        Mx {
                            exchanges: Box::new(["mx.example.com".into()]),
                            preference: 20,
                        },
                    ])
                })
            }

            fn addresses<'a>(
                &'a self,
                _host: &'a str,
            ) -> std::pin::Pin<
                Box<dyn std::future::Future<Output = Result<Vec<IpAddr>, LookupError>> + Send + 'a>,
            > {
                Box::pin(async { Err(LookupError::NoRecords) })
            }
        }
        assert_eq!(
            resolve_mx(&Mixed, "example.com").await,
            MxPlan::Null,
            "a null MX in the answer wins over a real exchange"
        );
    }

    #[tokio::test]
    async fn no_mx_falls_back_to_the_domains_a_record() {
        // RFC 5321 §5.1: an empty MX answer means the domain itself is the
        // implicit MX.
        let resolver = StaticResolver::empty().with_addresses("example.com", &[ip("192.0.2.7")]);
        let plan = resolve_mx(&resolver, "example.com").await;
        assert_eq!(
            plan.hosts(),
            &[MxTarget {
                host: "example.com".to_owned(),
                preference: None
            }],
            "{plan:?}"
        );
    }

    #[tokio::test]
    async fn a_domain_with_neither_mx_nor_address_does_not_resolve() {
        let plan = resolve_mx(&StaticResolver::empty(), "nowhere.example").await;
        assert_eq!(plan, MxPlan::NoHost);
    }

    #[tokio::test]
    async fn a_resolver_that_cannot_answer_is_temporary_and_not_a_fallback() {
        // The critical distinction: a *failed* MX query is not "no MX". A
        // resolver outage must never send mail to an A record nobody asked
        // about.
        let resolver = StaticResolver::empty()
            .with_mx_failure("example.com", "resolver unreachable")
            .with_addresses("example.com", &[ip("192.0.2.50")]);
        let plan = resolve_mx(&resolver, "example.com").await;
        match plan {
            MxPlan::Unavailable(reason) => {
                assert!(reason.contains("resolver unreachable"), "{reason}")
            }
            other => panic!("a failed MX query must not become a host list: {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_failed_address_query_after_no_mx_is_temporary_too() {
        let resolver = StaticResolver::empty().with_address_failure("example.com", "timed out");
        let plan = resolve_mx(&resolver, "example.com").await;
        assert!(matches!(plan, MxPlan::Unavailable(_)), "{plan:?}");
    }

    #[tokio::test]
    async fn exchange_names_lose_their_trailing_dot_and_are_lowercased() {
        let resolver =
            StaticResolver::empty().with_mx("example.com", vec![(10, "MX.Example.COM.")]);
        let plan = resolve_mx(&resolver, "example.com").await;
        assert_eq!(plan.hosts()[0].host, "mx.example.com");
    }

    // ── dot-stuffing ─────────────────────────────────────────────────────

    #[test]
    fn a_leading_dot_is_doubled_and_nothing_else_is() {
        let stuffed = dot_stuff(b".first\r\nmid.dle\r\nlast.\r\n");
        assert_eq!(
            String::from_utf8(stuffed).expect("utf8"),
            "..first\r\nmid.dle\r\nlast.\r\n.\r\n",
            "only a line-leading dot is doubled; the terminator is its own line"
        );
    }

    #[test]
    fn a_body_that_does_not_end_in_crlf_still_gets_a_terminator() {
        let stuffed = dot_stuff(b"no trailing newline");
        assert_eq!(
            String::from_utf8(stuffed).expect("utf8"),
            "no trailing newline\r\n.\r\n"
        );
    }

    #[test]
    fn a_line_of_a_single_dot_is_stuffed_to_two() {
        // The shape that ends a transfer early if it is not stuffed.
        let stuffed = dot_stuff(b"body\r\n.\r\nafter\r\n");
        assert_eq!(
            String::from_utf8(stuffed).expect("utf8"),
            "body\r\n..\r\nafter\r\n.\r\n"
        );
    }

    #[test]
    fn an_empty_body_is_just_a_terminator() {
        assert_eq!(
            String::from_utf8(dot_stuff(b"")).expect("utf8"),
            "\r\n.\r\n"
        );
    }

    // ── the trace field ──────────────────────────────────────────────────

    #[test]
    fn the_received_field_names_both_sides_and_the_protocol() {
        let field = ReceivedField {
            from: "mx.example.com".to_owned(),
            by: "mx.destination.example".to_owned(),
            protocol: "ESMTPS",
            starttls_failed: false,
            id: "abc123".to_owned(),
            date: "Tue, 14 Jul 2026 03:33:20 +0000".to_owned(),
        };
        let value = field.value();
        assert!(value.starts_with("from mx.example.com"), "{value}");
        assert!(
            value.contains("by mx.destination.example with ESMTPS"),
            "{value}"
        );
        assert!(value.contains("id abc123"), "{value}");
        assert!(value.contains("Tue, 14 Jul 2026"), "{value}");
        let header = field.header();
        assert!(header.starts_with("Received: from"), "{header}");
        assert!(header.ends_with("\r\n"), "{header}");
        assert!(
            !header.contains("\r\n\r\n"),
            "one field, one blank line never"
        );
    }

    #[test]
    fn a_hostile_host_name_cannot_inject_a_header() {
        // Both names travel from the resolver into the field. A CR or LF in
        // one would end the field and start another.
        let field = ReceivedField {
            from: "mx.example.com".to_owned(),
            by: "evil\r\nX-Injected: yes".to_owned(),
            protocol: "ESMTP",
            starttls_failed: false,
            id: "abc".to_owned(),
            date: "Tue, 14 Jul 2026 03:33:20 +0000".to_owned(),
        };
        let header = field.header();
        assert!(!header.contains("\r\nX-Injected"), "{header}");
        assert!(
            header.contains("X-Injected: yes") || header.contains("X-Injected"),
            "{header}"
        );
        assert_eq!(
            header.matches("Received:").count(),
            1,
            "one field: {header}"
        );
    }

    #[test]
    fn a_long_received_value_is_folded_within_the_line_limit() {
        let field = ReceivedField {
            from: "mx.example.com".to_owned(),
            by: format!("{}.example", "a".repeat(400)),
            protocol: "ESMTPS",
            starttls_failed: false,
            id: "b".repeat(400),
            date: "Tue, 14 Jul 2026 03:33:20 +0000".to_owned(),
        };
        let header = field.header();
        for line in header.split("\r\n") {
            assert!(
                line.len() <= RECEIVED_LINE_LIMIT,
                "a line of {} octets is over the bound: {line}",
                line.len()
            );
        }
        // Folding at whitespace means the unfolded value is the value written.
        let unfolded = header
            .replace("\r\n ", " ")
            .replace("Received: ", "")
            .trim_end()
            .to_owned();
        assert_eq!(unfolded, field.value());
    }

    #[test]
    fn a_downgraded_connection_says_so_in_the_trace_field() {
        // Both are `ESMTP` — the connection really was plaintext — and the
        // comment is the only thing that separates "the peer does not do TLS"
        // from "the peer does and the handshake broke".
        let plaintext = ReceivedField {
            from: "mx.example.com".to_owned(),
            by: "mx.dest.example".to_owned(),
            protocol: "ESMTP",
            starttls_failed: false,
            id: "abc".to_owned(),
            date: "Tue, 14 Jul 2026 03:33:20 +0000".to_owned(),
        };
        let downgraded = ReceivedField {
            starttls_failed: true,
            ..plaintext.clone()
        };
        assert!(
            plaintext.value().contains("with ESMTP id "),
            "{}",
            plaintext.value()
        );
        assert!(
            !plaintext.value().contains("starttls-failed"),
            "{}",
            plaintext.value()
        );
        let value = downgraded.value();
        assert!(
            value.contains("with ESMTP (starttls-failed) id "),
            "{value}"
        );
        assert!(
            !value.contains("ESMTPS"),
            "a failed upgrade is never reported as a successful one: {value}"
        );
    }

    #[test]
    fn the_dkim_environment_variable_name_has_no_dot_in_it() {
        // A POSIX environment variable name may not contain a dot, and every
        // hosted domain has one.
        assert_eq!(
            dkim_env_name("AYANE_DKIM_KEY_{domain}", "example.com"),
            "AYANE_DKIM_KEY_example_com"
        );
        assert_eq!(
            dkim_env_name("AYANE_DKIM_KEY_{domain}", "mail.example.co.uk"),
            "AYANE_DKIM_KEY_mail_example_co_uk"
        );
        // The sanitised spelling is not substituted again.
        assert_eq!(
            dkim_env_name("AYANE_DKIM_KEY_example_com", "example.com"),
            "AYANE_DKIM_KEY_example_com"
        );
        // A template with no placeholder is used as written.
        assert_eq!(
            dkim_env_name("SOME_CONSTANT", "example.com"),
            "SOME_CONSTANT"
        );
    }

    #[test]
    fn a_short_value_is_not_folded() {
        let field = ReceivedField {
            from: "mx.example.com".to_owned(),
            by: "mx.dest.example".to_owned(),
            protocol: "ESMTP",
            starttls_failed: false,
            id: "abc".to_owned(),
            date: "Tue, 14 Jul 2026 03:33:20 +0000".to_owned(),
        };
        assert!(!field.header().contains("\r\n "), "{}", field.header());
    }

    #[test]
    fn receive_puts_the_trace_field_above_the_stored_octets() {
        let field = ReceivedField {
            from: "mx.example.com".to_owned(),
            by: "mx.dest.example".to_owned(),
            protocol: "ESMTPS",
            starttls_failed: false,
            id: "abc".to_owned(),
            date: "Tue, 14 Jul 2026 03:33:20 +0000".to_owned(),
        };
        let body = b"Subject: hi\r\n\r\nbody\r\n";
        let out = receive(&field, body);
        let text = String::from_utf8(out.clone()).expect("utf8");
        assert!(text.starts_with("Received: "), "{text}");
        assert!(text.ends_with("Subject: hi\r\n\r\nbody\r\n"), "{text}");
        assert_eq!(
            &out[out.len() - body.len()..],
            body,
            "the stored octets are untouched"
        );
    }

    // ── capability parsing ───────────────────────────────────────────────

    #[test]
    fn ehlo_extensions_are_read_from_the_reply_lines() {
        let caps = Capabilities::parse(&[
            "mail.example.com".to_owned(),
            "SIZE 35882577".to_owned(),
            "8BITMIME".to_owned(),
            "STARTTLS".to_owned(),
            "PIPELINING".to_owned(),
            "SMTPUTF8".to_owned(),
            "CHUNKING".to_owned(),
        ]);
        assert_eq!(caps.size, Some(35_882_577));
        assert!(caps.eight_bit_mime);
        assert!(caps.starttls);
        assert!(caps.pipelining);
        assert!(caps.smtp_utf8);
        // `SIZE` without a number is RFC 1870's "no fixed maximum".
        assert_eq!(Capabilities::parse(&["SIZE".to_owned()]).size, Some(0));
        // An extension nobody knows is ignored, not an error.
        assert_eq!(Capabilities::parse(&["CHUNKING".to_owned()]).size, None);
    }

    // ── the signing domain ───────────────────────────────────────────────

    fn one(domain: &str) -> FromDomain {
        FromDomain::One(domain.to_owned())
    }

    #[test]
    fn the_signing_domain_comes_from_the_from_header() {
        assert_eq!(
            from_domain(b"From: Alice <alice@example.com>\r\nTo: x@y\r\n\r\nbody"),
            one("example.com")
        );
        // Case folds, a display name is skipped, and a field listed later in
        // the section still counts.
        assert_eq!(
            from_domain(b"To: x@y\r\nFrom: \"A, B\" <A@EXAMPLE.COM>\r\n\r\nbody"),
            one("example.com")
        );
        // No `From` at all: nothing to sign for.
        assert_eq!(from_domain(b"To: x@y\r\n\r\nbody"), FromDomain::NoDomain);
        // A `From` without a domain cannot name a key.
        assert_eq!(
            from_domain(b"From: nobody\r\n\r\nbody"),
            FromDomain::NoDomain
        );
        // A body that mentions `From:` is not a header.
        assert_eq!(
            from_domain(b"Subject: s\r\n\r\nFrom: a@example.com\r\n"),
            FromDomain::NoDomain
        );
    }

    #[test]
    fn a_malformed_field_before_the_from_does_not_suppress_signing() {
        // The defect this pins: a header line whose *name* is not UTF-8 (or is
        // not `From`) used to abort the whole scan with `?`, so one throwaway
        // line above the real `From` left every message from the domain
        // unsigned — silently.
        let mut message = Vec::new();
        message.extend_from_slice(b"X-Junk-\xff\xfe: not a field name\r\n");
        message.extend_from_slice(b"From: nobody-at-all\r\n"); // no `@`
        message.extend_from_slice(b"From: Alice <alice@example.test>\r\n");
        message.extend_from_slice(b"\r\nbody\r\n");
        // Two `From` fields is now `Ambiguous` by design (see below), so the
        // assertion is about the *scan*: the real domain was still found.
        assert_eq!(
            from_domain(&message),
            FromDomain::Ambiguous {
                domains: vec!["example.test".to_owned()]
            },
            "the non-UTF-8 name and the domainless From must not hide the real one"
        );

        // One junk field and one real `From` — the shape that used to go out
        // unsigned.
        let mut message = Vec::new();
        message.extend_from_slice(b"X-Junk-\xff: junk\r\n");
        message.extend_from_slice(b"From: Alice <alice@example.test>\r\n");
        message.extend_from_slice(b"\r\nbody\r\n");
        assert_eq!(from_domain(&message), one("example.test"));

        // A `From` with no `@` and then a real one is the same story with a
        // domainless field instead of a bad name.
        let message = b"From: nobody\r\nFrom: Alice <alice@example.test>\r\n\r\nbody";
        assert_eq!(
            from_domain(message),
            FromDomain::Ambiguous {
                domains: vec!["example.test".to_owned()]
            }
        );
    }

    #[test]
    fn two_from_fields_are_ambiguous_and_never_signed() {
        // The reader and DMARC take the *last* `From` (RFC 5322 §3.6 says
        // there is exactly one, so this is malformed input). Signing the first
        // one would let a forger obtain "DKIM pass" for a domain the message
        // does not claim, so a second `From` is a refusal, not a choice.
        let message = b"From: Alice <alice@example.test>\r\n\
                        From: Bank <security@victim.test>\r\n\
                        \r\nbody\r\n";
        assert_eq!(
            from_domain(message),
            FromDomain::Ambiguous {
                domains: vec!["example.test".to_owned(), "victim.test".to_owned()]
            }
        );
        // The `Outbound` built with a signer for the first domain must still
        // leave the message unsigned: a signature for `example.test` on a
        // message whose last `From` is `victim.test` is the dangerous half.
        let signer = Signer::rsa("example.test", "ayane", FIXTURE_KEY).expect("the fixture key");
        let outbound =
            Outbound::new(Arc::new(StaticResolver::empty()), "mx.origin.test").with_signer(signer);
        let signed = outbound.sign(message).expect("signing does not fail");
        assert_eq!(
            signed, message,
            "an ambiguous message must go out unsigned, not signed for one of its From fields"
        );
    }

    #[test]
    fn a_single_from_is_signed_for_its_own_domain() {
        // The positive control for the refusal above: one `From` is signed,
        // so the test cannot pass by signing nothing ever.
        let signer = Signer::rsa("example.test", "ayane", FIXTURE_KEY).expect("the fixture key");
        let outbound =
            Outbound::new(Arc::new(StaticResolver::empty()), "mx.origin.test").with_signer(signer);
        let message = b"From: Alice <alice@example.test>\r\n\r\nbody\r\n";
        let signed = outbound.sign(message).expect("signing works");
        let text = String::from_utf8_lossy(&signed);
        assert!(text.starts_with("DKIM-Signature: "), "{text}");
        assert!(text.contains("d=example.test"), "{text}");
    }
}
