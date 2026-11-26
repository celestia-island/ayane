//! A fixed DNS zone for the verifiers: an **authoritative** answer source that
//! never lets a lookup reach the network.
//!
//! It exists for the tests, and for a deployment that already knows its
//! records. The zone is authoritative for **every name it is asked about** —
//! not scoped to the names it lists — and a name it does not list has
//! **no records**. That second half is the part worth being precise
//! about, because `mail-auth`'s cache seam is not a filter:
//!
//! > `ResolverCache::get` returning `None` means "this cache cannot answer",
//! > not "the answer is empty", and the lookup then asks the resolver — a
//! > network query.
//!
//! So the zone stores the negative answers explicitly:
//!
//! - TXT: [`TxtRecord::Error`] carrying `RecordNotFound`, which `txt_lookup`
//!   returns as the answer, and which DMARC's tree walk reads as "no policy at
//!   this name, keep walking".
//! - MX / A / AAAA / PTR: `Err(`[`Negative`]`)`, the same shape those lookups
//!   store for a NODATA answer.
//!
//! With that, every name inside the authority is answered in-process — the
//! positive ones with their records, the rest with a negative — and the policy
//! this layer implements (fail-closed, DNS-down-is-not-reject) is testable with
//! no network at all.
//!
//! A deployment that wants unknown names answered by the real resolver does
//! not use a fixed zone: build the [`crate::verify::Verifier`] without one.

use std::net::IpAddr;
use std::time::Instant;

use mail_auth::dns::{DnsCache, Negative, RecordSet, ResolverCache, ToFqdn, TxtRecord};
use mail_auth::{DnsError, Error, Mx};

/// A resolver cache over a fixed map, authoritative wherever the zone says so.
///
/// Every answer is valid until this process ends, so nothing expires.
///
/// A name absent from `entries` is answered with `miss` — an empty answer, not
/// a miss. `miss` is a value of the value type rather than something computed
/// on demand because this type is generic over `V` and cannot know which of
/// them spells "no records": `TxtRecord::Error(..)` for TXT, `Err(Negative)`
/// for the rest. The zone supplies it per cache when it is built.
pub struct FixedCache<K, V> {
    entries: Vec<(K, V)>,
    /// What a miss answers with. Built once, cloned per lookup (these values
    /// are small: an error enum and a response code).
    miss: Option<V>,
}

impl<K, V> Default for FixedCache<K, V> {
    fn default() -> Self {
        Self {
            entries: Vec::new(),
            miss: None,
        }
    }
}

impl<K, V> FixedCache<K, V> {
    /// A cache holding `entries`, authoritative: a name it does not list gets
    /// `miss`.
    #[must_use]
    pub fn new(entries: Vec<(K, V)>, miss: Option<V>) -> Self {
        Self { entries, miss }
    }

    /// Whether this cache answers at all. An empty zone answers "no records"
    /// to everything; a zone with no opinion does not.
    #[must_use]
    pub fn is_authoritative(&self) -> bool {
        !self.entries.is_empty() || self.miss.is_some()
    }
}

impl<K, V> ResolverCache<K, V> for FixedCache<K, V>
where
    K: std::hash::Hash + Eq + Clone,
    V: Clone,
{
    fn get<Q>(&self, name: &Q) -> Option<V>
    where
        K: std::borrow::Borrow<Q>,
        Q: std::hash::Hash + Eq + ?Sized,
    {
        if let Some((_, value)) = self
            .entries
            .iter()
            .find(|(key, _)| std::borrow::Borrow::<Q>::borrow(key) == name)
        {
            return Some(value.clone());
        }
        // Not listed: inside the authority that is a *negative answer*, and
        // returning it is what keeps the lookup from asking the resolver.
        self.miss.clone()
    }

    fn remove<Q>(&self, _name: &Q) -> Option<V>
    where
        K: std::borrow::Borrow<Q>,
        Q: std::hash::Hash + Eq + ?Sized,
    {
        None
    }

    fn insert(&self, _key: K, _value: V, _valid_until: Instant) {}
}

/// The negative TXT entry: "this name has no TXT records" (NODATA, code 0).
///
/// It is an `Error` variant so `txt_lookup` hands it back as the lookup's
/// result, which is exactly what a cache hit on a negative answer does.
fn no_txt() -> TxtRecord {
    TxtRecord::Error(Error::Dns(DnsError::RecordNotFound(no_error())))
}

/// The response code of a NODATA answer: `NOERROR` with an empty answer
/// section, `0`.
fn no_error() -> mail_auth::hickory_resolver::proto::op::ResponseCode {
    mail_auth::hickory_resolver::proto::op::ResponseCode::NoError
}

/// The negative MX / A / AAAA / PTR entry: `NOERROR`, no records.
fn no_records<T>() -> Result<RecordSet<T>, Negative> {
    Err(Negative { code: no_error() })
}

/// The zone: one cache per record type, exactly as [`DnsCache`] expects.
pub struct FixedZone {
    txt: FixedCache<Box<str>, TxtRecord>,
    mx: FixedCache<Box<str>, Result<RecordSet<Mx>, Negative>>,
    ipv4: FixedCache<Box<str>, Result<RecordSet<std::net::Ipv4Addr>, Negative>>,
    ipv6: FixedCache<Box<str>, Result<RecordSet<std::net::Ipv6Addr>, Negative>>,
    ptr: FixedCache<IpAddr, Result<RecordSet<Box<str>>, Negative>>,
}

impl Clone for FixedZone {
    fn clone(&self) -> Self {
        Self {
            txt: FixedCache::new(self.txt.entries.clone(), self.txt.miss.clone()),
            mx: FixedCache::new(self.mx.entries.clone(), self.mx.miss.clone()),
            ipv4: FixedCache::new(self.ipv4.entries.clone(), self.ipv4.miss.clone()),
            ipv6: FixedCache::new(self.ipv6.entries.clone(), self.ipv6.miss.clone()),
            ptr: FixedCache::new(self.ptr.entries.clone(), self.ptr.miss.clone()),
        }
    }
}

impl Default for FixedZone {
    /// An empty zone that is still **authoritative for everything** it is
    /// asked: "no records" is an answer, and the empty zone exists to say it.
    /// A caller that wants the network asks a [`Verifier`](crate::Verifier)
    /// built without a zone.
    fn default() -> Self {
        Self::empty_authority()
    }
}

impl DnsCache for FixedZone {
    type Txt = FixedCache<Box<str>, TxtRecord>;
    type Mx = FixedCache<Box<str>, Result<RecordSet<Mx>, Negative>>;
    type Ipv4 = FixedCache<Box<str>, Result<RecordSet<std::net::Ipv4Addr>, Negative>>;
    type Ipv6 = FixedCache<Box<str>, Result<RecordSet<std::net::Ipv6Addr>, Negative>>;
    type Ptr = FixedCache<IpAddr, Result<RecordSet<Box<str>>, Negative>>;

    fn txt(&self) -> Option<&Self::Txt> {
        Some(&self.txt)
    }

    fn mx(&self) -> Option<&Self::Mx> {
        Some(&self.mx)
    }

    fn ipv4(&self) -> Option<&Self::Ipv4> {
        Some(&self.ipv4)
    }

    fn ipv6(&self) -> Option<&Self::Ipv6> {
        Some(&self.ipv6)
    }

    fn ptr(&self) -> Option<&Self::Ptr> {
        Some(&self.ptr)
    }
}

impl FixedZone {
    /// A zone that answers "no records" to **every** lookup, whatever the
    /// name — it is not scoped to a set of domains.
    ///
    /// The difference from an unset zone is the whole point of this module: a
    /// verifier built on this one never touches the network, so a result of
    /// `dkim=permerror` here means "the key is not published", not "the query
    /// failed".
    ///
    /// # A warning, not a default
    ///
    /// Every message verified against this zone comes out with no DKIM
    /// signature able to pass, no DMARC record able to apply, and therefore
    /// [`PolicyVerdict::Accept`](crate::PolicyVerdict) by default — the
    /// fail-closed policy never fires. That is what a test wants and what a
    /// deployment must never get: an operator-facing verifier uses
    /// [`Verifier::with_system_resolver`](crate::Verifier::with_system_resolver)
    /// or a zone built from real records.
    #[must_use]
    pub fn empty_authority() -> Self {
        Self {
            txt: FixedCache::new(Vec::new(), Some(no_txt())),
            mx: FixedCache::new(Vec::new(), Some(no_records())),
            ipv4: FixedCache::new(Vec::new(), Some(no_records())),
            ipv6: FixedCache::new(Vec::new(), Some(no_records())),
            ptr: FixedCache::new(Vec::new(), Some(no_records())),
        }
    }

    /// Builds the zone from `(name, record)` pairs.
    ///
    /// Each record is what `mail-auth` itself holds after parsing a resolver
    /// answer ([`TxtRecord::Spf`], [`TxtRecord::DomainKey`],
    /// [`TxtRecord::Dmarc`], …). The record types that produce them are
    /// public (`mail_auth::spf::SpfRecord` and friends); only the parser
    /// functions are not, so a caller that builds a zone supplies the records
    /// it already parsed — which is what a test fixture and a deployment that
    /// pins its zone both do.
    ///
    /// Every name added this way is inside the zone's authority, and so is
    /// every parent of it: a name that is absent from the zone answers "no
    /// records" rather than falling through to the resolver.
    #[must_use]
    pub fn from_txt(entries: Vec<(String, TxtRecord)>) -> Self {
        let mut zone = Self::empty_authority();
        let txt = entries
            .into_iter()
            .map(|(name, record)| (name.to_fqdn().into_owned().into_boxed_str(), record))
            .collect();
        zone.txt = FixedCache::new(txt, Some(no_txt()));
        zone
    }

    /// Adds a TXT record (already parsed) at `name`, keeping the authority.
    #[must_use]
    pub fn with_txt(mut self, name: &str, record: TxtRecord) -> Self {
        let name = name.to_fqdn().into_owned().into_boxed_str();
        let mut entries: Vec<(Box<str>, TxtRecord)> = self
            .txt
            .entries
            .into_iter()
            .filter(|(existing, _)| *existing != name)
            .collect();
        entries.push((name, record));
        self.txt = FixedCache::new(entries, Some(no_txt()));
        self
    }

    /// Adds a DMARC policy record (RFC 9989) found at `_dmarc.<domain>`.
    ///
    /// Unlike [`FixedZone::from_txt`], this parses the record text here: a
    /// DMARC policy is the one record a verifier consults by a name it
    /// derives from the `From` header rather than one the caller sees, so a
    /// test that wants "this domain says `p=reject`" would otherwise have to
    /// reproduce `mail-auth`'s private parser to build the entry.
    ///
    /// # Errors
    ///
    /// Returns the parse error when `record` is not a `v=DMARC1` record.
    pub fn with_dmarc(self, domain: &str, record: &str) -> Result<Self, mail_auth::Error> {
        use mail_auth::dns::TxtRecordParser;

        let parsed = mail_auth::dmarc::DmarcRecord::parse(record.as_bytes())?;
        Ok(self.with_txt(&format!("_dmarc.{domain}"), TxtRecord::from(parsed)))
    }

    /// Adds an SPF record (`v=spf1 …`) at `domain`.
    ///
    /// # Errors
    ///
    /// Returns the parse error when `record` is not an SPF record.
    pub fn with_spf(self, domain: &str, record: &str) -> Result<Self, mail_auth::Error> {
        use mail_auth::dns::TxtRecordParser;

        let parsed = mail_auth::spf::SpfRecord::parse(record.as_bytes())?;
        Ok(self.with_txt(domain, TxtRecord::from(parsed)))
    }
}
