//! Network-surface introspection: TLS certificate status and the traffic
//! aggregation the 网络配置 pages draw.
//!
//! Traffic used to be *parsed* here — `traffic_from_lines` read Postfix's log
//! text (`connect from …`, `relay=…, status=sent`) into the two tables. The
//! engine that wrote those lines is not in the path any more, and the numbers
//! now come from counters ([`ayane_smtpd::metrics`]), so this module only
//! **renders** them ([`traffic_reply`]) in the shape the page already knows.
//! The parser is gone rather than kept for a second engine: two sources of one
//! number is how the page came to disagree with itself.

use std::path::Path;

use ayane_smtpd::metrics::TrafficSnapshot;

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
    /// The connecting address, as the socket named it.
    pub peer: String,
    /// Connections accepted from it in the window.
    pub connects: u64,
    /// Messages it got queued in the window (additive field).
    pub messages: u64,
    /// Recipients accepted at `RCPT` (additive field).
    pub recipients: u64,
    /// Recipients refused at `RCPT` (additive field).
    pub refused: u64,
}

/// One aggregated outbound destination.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct OutboundPeer {
    /// The destination domain. The field the page drew this row under was
    /// `relay` — the MX host — and the native counters have the domain
    /// instead (see `net_traffic` in `rpc.rs` for why), so the *name* is kept
    /// and the value is the domain, whose one entry is also in `domains`.
    pub relay: String,
    /// The recipient domains this row is about (one, always).
    pub domains: Vec<String>,
    /// Deliveries a receiver accepted.
    pub sent: u64,
    /// Deliveries deferred (retried by the queue).
    pub deferred: u64,
    /// Deliveries that ended in a bounce.
    pub bounced: u64,
}

/// Traffic aggregation, in the shape the 网络配置 pages draw.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct TrafficReport {
    /// Inbound peers, busiest first.
    pub inbound: Vec<InboundPeer>,
    /// Outbound destinations, busiest first.
    pub outbound: Vec<OutboundPeer>,
}

/// Renders a [`TrafficSnapshot`] as the page's reply.
///
/// The audit-shaped part (`requested_seconds`, `window_seconds`, `totals`) is
/// carried alongside the two tables rather than folded into them: a caller that
/// wants "how far back does this actually reach" has to be able to see it, and
/// a caller written against the old shape must not have to care.
#[must_use]
pub fn traffic_reply(snapshot: &TrafficSnapshot) -> serde_json::Value {
    let inbound: Vec<InboundPeer> = snapshot
        .inbound
        .iter()
        .map(|row| InboundPeer {
            peer: row.peer.clone(),
            connects: row.connects,
            messages: row.messages,
            recipients: row.recipients,
            refused: row.refused,
        })
        .collect();
    let outbound: Vec<OutboundPeer> = snapshot
        .outbound
        .iter()
        .map(|row| OutboundPeer {
            relay: row.domain.clone(),
            domains: vec![row.domain.clone()],
            sent: row.sent,
            deferred: row.deferred,
            bounced: row.bounced,
        })
        .collect();
    let report = TrafficReport { inbound, outbound };
    let mut value = serde_json::to_value(&report).unwrap_or_else(|_| serde_json::json!({}));
    if let Some(map) = value.as_object_mut() {
        // Additive keys, same object: a consumer that never heard of them
        // ignores them, one that wants them has them.
        map.insert(
            "requested_seconds".to_owned(),
            serde_json::json!(snapshot.requested_seconds),
        );
        map.insert(
            "window_seconds".to_owned(),
            serde_json::json!(snapshot.window_seconds),
        );
        map.insert(
            "totals".to_owned(),
            serde_json::to_value(snapshot.totals).unwrap_or_else(|_| serde_json::json!({})),
        );
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_reply_keeps_the_shape_the_page_draws() {
        // The two tables the 网络配置 page has always drawn, from counters
        // instead of log lines: the fields the old parser produced are the
        // fields this renders, so a webui built before the change renders it
        // unchanged.
        use ayane_smtpd::metrics::{Counter, Metrics};
        let metrics = Metrics::new();
        let now = 1_700_000_000;
        metrics.record_peer("203.0.113.9", Counter::Connects, 2, now);
        metrics.record_peer("203.0.113.9", Counter::MessagesIn, 1, now);
        metrics.record_peer("203.0.113.9", Counter::RecipientsIn, 2, now);
        metrics.record_domain("dest.example", Counter::OutboundSent, 3, now);
        metrics.record_domain("dest.example", Counter::OutboundDeferred, 1, now);
        let reply = traffic_reply(&metrics.snapshot(now, 72 * 3600));

        // The shape the page reads: `inbound[].peer` / `.connects`,
        // `outbound[].relay` / `.domains` / `.sent` / `.deferred` / `.bounced`.
        assert_eq!(reply["inbound"][0]["peer"], "203.0.113.9");
        assert_eq!(reply["inbound"][0]["connects"], 2);
        assert_eq!(reply["outbound"][0]["relay"], "dest.example");
        assert_eq!(reply["outbound"][0]["domains"][0], "dest.example");
        assert_eq!(reply["outbound"][0]["sent"], 3);
        assert_eq!(reply["outbound"][0]["deferred"], 1);
        assert_eq!(reply["outbound"][0]["bounced"], 0);
        // The additive part: what the old shape had no room for.
        assert_eq!(reply["inbound"][0]["messages"], 1);
        assert_eq!(reply["inbound"][0]["recipients"], 2);
        assert_eq!(reply["inbound"][0]["refused"], 0);
        assert_eq!(reply["requested_seconds"], 72 * 3600);
        assert_eq!(reply["window_seconds"], 24 * 3600);
        assert_eq!(reply["totals"]["connects"], 2);
    }

    #[test]
    fn an_empty_engine_renders_empty_tables() {
        // "Nothing happened" is an empty table, not an error: the page draws
        // its empty state from it.
        let reply = traffic_reply(&TrafficSnapshot::default());
        assert_eq!(reply["inbound"], serde_json::json!([]));
        assert_eq!(reply["outbound"], serde_json::json!([]));
        assert_eq!(reply["totals"]["messages_in"], 0);
    }
}
