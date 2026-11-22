//! Network-surface introspection: TLS certificate status and postfix
//! traffic aggregation (the 网络配置 pages' data sources).

use std::collections::BTreeMap;
use std::path::Path;

/// TLS certificate status parsed from the deployed PEM chain.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct CertStatus {
    /// Certificate subject (RFC 4514-ish, as x509-parser renders it).
    pub subject: String,
    /// Issuer subject.
    pub issuer: String,
    /// Not-after instant, Unix seconds (UTC).
    pub not_after: i64,
    /// Whole days of validity remaining (negative = already expired).
    pub days_left: i64,
}

/// Why the certificate status could not be produced.
#[derive(Debug, thiserror::Error)]
pub enum CertError {
    /// The configured path does not exist or is unreadable.
    #[error("certificate file unavailable: {0}")]
    Unavailable(String),
    /// The PEM/DER could not be parsed.
    #[error("certificate parse: {0}")]
    Parse(String),
}

/// Parse the leaf certificate of a PEM chain.
///
/// # Errors
///
/// Returns [`CertError`] when the file is missing/unreadable or holds no
/// parseable certificate.
pub fn cert_status(path: &Path) -> Result<CertStatus, CertError> {
    use x509_parser::prelude::*;

    let bytes = std::fs::read(path).map_err(|e| CertError::Unavailable(e.to_string()))?;
    let der = first_pem_block(&bytes)
        .ok_or_else(|| CertError::Parse("no CERTIFICATE PEM block".to_owned()))?;
    let (rem, first) =
        X509Certificate::from_der(&der).map_err(|e| CertError::Parse(e.to_string()))?;
    // A fullchain's first block is the leaf; a bare cert file is the leaf.
    let cert = if first.subject() == first.issuer() && !rem.is_empty() {
        // Self-signed first block = the ROOT (a CA bundle ordering); take
        // the next block as the leaf in that case.
        X509Certificate::from_der(rem)
            .map(|(_, c)| c)
            .unwrap_or(first)
    } else {
        first
    };
    let not_after = cert.validity().not_after.timestamp();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let days_left = (not_after - now) / 86_400;
    Ok(CertStatus {
        subject: cert.subject().to_string(),
        issuer: cert.issuer().to_string(),
        not_after,
        days_left,
    })
}

/// Decode the first CERTIFICATE PEM block of a chain to DER bytes.
fn first_pem_block(bytes: &[u8]) -> Option<Vec<u8>> {
    let text = std::str::from_utf8(bytes).ok()?;
    let start = text.find("-----BEGIN CERTIFICATE-----")? + "-----BEGIN CERTIFICATE-----".len();
    let end = text[start..].find("-----END CERTIFICATE-----")? + start;
    let b64: String = text[start..end]
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.decode(b64).ok()
}

/// One aggregated inbound peer.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct InboundPeer {
    /// `host[ip]` exactly as the log named it (`unknown` when no rDNS).
    pub peer: String,
    /// `connect from` lines seen from this peer.
    pub connects: u64,
}

/// One aggregated outbound destination.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct OutboundPeer {
    /// `relay=host[ip]:port` as the log named it.
    pub relay: String,
    /// Recipient domains delivered through this relay.
    pub domains: Vec<String>,
    /// `status=sent` deliveries.
    pub sent: u64,
    /// `status=deferred` deliveries (retried by the queue).
    pub deferred: u64,
    /// `status=bounced` deliveries.
    pub bounced: u64,
}

/// Traffic aggregation over postfix log lines.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct TrafficReport {
    /// Inbound SMTP connections by peer, busiest first.
    pub inbound: Vec<InboundPeer>,
    /// Outbound deliveries by relay, busiest first.
    pub outbound: Vec<OutboundPeer>,
}

/// Aggregate `lines` (postfix logs) into a [`TrafficReport`].
///
/// Recognised shapes (postfix default logging):
/// - `… connect from unknown[203.0.113.9]` / `connect from mail.example.org[203.0.113.9]`
/// - `… to=<a@b.example>, relay=mail.b.example[198.51.100.2]:25, status=sent …`
#[must_use]
pub fn traffic_from_lines(lines: &[String]) -> TrafficReport {
    let mut inbound: BTreeMap<String, u64> = BTreeMap::new();
    let mut outbound: BTreeMap<String, (Vec<String>, u64, u64, u64)> = BTreeMap::new();

    for line in lines {
        if let Some(rest) = line.split_once("connect from") {
            let peer = rest.1.split(']').next().unwrap_or("").to_owned() + "]";
            let peer = peer.trim_start_matches(' ').to_owned();
            if peer.ends_with(']') {
                *inbound.entry(peer).or_default() += 1;
            }
        }
        if line.contains("to=<") {
            if let Some(relay_part) = line.split_once("relay=") {
                let relay = relay_part
                    .1
                    .split(',')
                    .next()
                    .unwrap_or("")
                    .trim()
                    .to_owned();
                if relay.is_empty() {
                    continue;
                }
                let status = if line.contains("status=sent") {
                    0
                } else if line.contains("status=deferred") {
                    1
                } else if line.contains("status=bounced") {
                    2
                } else {
                    continue;
                };
                let domain = line
                    .split_once("to=<")
                    .and_then(|(_, r)| r.split_once('>'))
                    .map(|(addr, _)| {
                        addr.rsplit_once('@')
                            .map_or_else(|| addr.to_owned(), |(_, d)| d.to_owned())
                    })
                    .unwrap_or_default();
                let entry = outbound
                    .entry(relay)
                    .or_insert_with(|| (Vec::new(), 0, 0, 0));
                match status {
                    0 => entry.1 += 1,
                    1 => entry.2 += 1,
                    _ => entry.3 += 1,
                }
                if !domain.is_empty() && !entry.0.contains(&domain) {
                    entry.0.push(domain);
                }
            }
        }
    }

    let mut inbound_vec: Vec<_> = inbound
        .into_iter()
        .map(|(peer, connects)| InboundPeer { peer, connects })
        .collect();
    inbound_vec.sort_by(|a, b| b.connects.cmp(&a.connects).then(a.peer.cmp(&b.peer)));

    let mut outbound_vec: Vec<_> = outbound
        .into_iter()
        .map(|(relay, (domains, sent, deferred, bounced))| OutboundPeer {
            relay,
            domains,
            sent,
            deferred,
            bounced,
        })
        .collect();
    outbound_vec.sort_by(|a, b| {
        (b.sent + b.deferred + b.bounced)
            .cmp(&(a.sent + a.deferred + a.bounced))
            .then(a.relay.cmp(&b.relay))
    });

    TrafficReport {
        inbound: inbound_vec,
        outbound: outbound_vec,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inbound_peers_aggregate_with_unknown_rdns() {
        let lines = vec![
            "postfix/smtpd[1]: connect from unknown[203.0.113.9]".to_owned(),
            "postfix/smtpd[1]: connect from unknown[203.0.113.9]".to_owned(),
            "postfix/smtpd[2]: connect from mail.sender.example[198.51.100.7]".to_owned(),
        ];
        let report = traffic_from_lines(&lines);
        assert_eq!(report.inbound[0].peer, "unknown[203.0.113.9]");
        assert_eq!(report.inbound[0].connects, 2);
        assert_eq!(report.inbound[1].peer, "mail.sender.example[198.51.100.7]");
        assert_eq!(report.inbound[1].connects, 1);
    }

    #[test]
    fn outbound_statuses_and_domains_aggregate() {
        let lines = vec![
            "smtp 1 to=<a@dest.example>, relay=mx.dest.example[192.0.2.1]:25, status=sent"
                .to_owned(),
            "smtp 2 to=<b@dest.example>, relay=mx.dest.example[192.0.2.1]:25, status=deferred"
                .to_owned(),
            "smtp 3 to=<c@other.example>, relay=mx.other.example[192.0.2.9]:25, status=bounced"
                .to_owned(),
        ];
        let report = traffic_from_lines(&lines);
        assert_eq!(report.outbound.len(), 2);
        let first = &report.outbound[0];
        assert_eq!(first.relay, "mx.dest.example[192.0.2.1]:25");
        assert_eq!(first.sent, 1);
        assert_eq!(first.deferred, 1);
        assert_eq!(first.domains, vec!["dest.example".to_owned()]);
    }

    #[test]
    fn non_smtp_lines_are_ignored() {
        let lines = vec![
            "postfix/qmgr[1]: removed".to_owned(),
            "postfix/anvil[1]: statistics".to_owned(),
        ];
        assert_eq!(traffic_from_lines(&lines), TrafficReport::default());
    }
}
