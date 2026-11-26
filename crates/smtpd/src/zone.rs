//! A fixed DNS zone for the verifiers, and the adapters that make the
//! `mail-auth` verifiers consult it before the network.
//!
//! It exists for the tests and for a deployment that already knows its
//! records: a lookup for a name the zone lists never leaves the process, and a
//! lookup for a name it does not list gets the empty answer instead of a
//! network query. That is what lets T-B17 verify a signed message byte for
//! byte without a zone we would have to publish first.

use std::net::IpAddr;
use std::time::Instant;

use mail_auth::dns::{DnsCache, Negative, RecordSet, ResolverCache, ToFqdn, TxtRecord};
use mail_auth::Mx;

/// A resolver cache over a fixed map: every answer is valid until this
/// process ends, so the map never expires.
#[derive(Clone)]
pub struct FixedCache<K, V> {
    entries: Vec<(K, V)>,
}

impl<K, V> Default for FixedCache<K, V> {
    fn default() -> Self {
        Self {
            entries: Vec::new(),
        }
    }
}

impl<K: PartialEq, V: Clone> FixedCache<K, V> {
    /// A cache holding `entries`.
    #[must_use]
    pub fn new(entries: Vec<(K, V)>) -> Self {
        Self { entries }
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
        self.entries
            .iter()
            .find(|(key, _)| std::borrow::Borrow::<Q>::borrow(key) == name)
            .map(|(_, value)| value.clone())
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

/// The zone: one cache per record type, exactly as [`DnsCache`] expects.
#[derive(Clone, Default)]
pub struct FixedZone {
    txt: FixedCache<Box<str>, TxtRecord>,
    mx: FixedCache<Box<str>, Result<RecordSet<Mx>, Negative>>,
    ipv4: FixedCache<Box<str>, Result<RecordSet<std::net::Ipv4Addr>, Negative>>,
    ipv6: FixedCache<Box<str>, Result<RecordSet<std::net::Ipv6Addr>, Negative>>,
    ptr: FixedCache<IpAddr, Result<RecordSet<Box<str>>, Negative>>,
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
    /// Builds the zone from `(name, record)` pairs.
    ///
    /// Each record is what `mail-auth` itself holds after parsing a resolver
    /// answer ([`TxtRecord::Spf`], [`TxtRecord::DomainKey`],
    /// [`TxtRecord::Dmarc`], …). The record types that produce them are
    /// public (`mail_auth::spf::SpfRecord` and friends); only the parser
    /// functions are not, so a caller that builds a zone supplies the records
    /// it already parsed — which is what a test fixture and a deployment that
    /// pins its zone both do.
    #[must_use]
    pub fn from_txt(entries: Vec<(String, TxtRecord)>) -> Self {
        let txt = entries
            .into_iter()
            .map(|(name, record)| (name.to_fqdn().into_owned().into_boxed_str(), record))
            .collect();
        Self {
            txt: FixedCache::new(txt),
            ..Self::default()
        }
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
        let name = format!("_dmarc.{domain}")
            .to_fqdn()
            .into_owned()
            .into_boxed_str();
        // A second policy for the same domain replaces the first: one name
        // has one DMARC record, and a fixture that re-declares it means it.
        let mut txt: Vec<(Box<str>, TxtRecord)> = self
            .txt
            .entries
            .into_iter()
            .filter(|(existing, _)| *existing != name)
            .collect();
        txt.push((name, TxtRecord::from(parsed)));
        Ok(Self {
            txt: FixedCache::new(txt),
            ..self
        })
    }
}
