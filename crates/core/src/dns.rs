//! The DNS wizard: live checks for one hosted domain.
//!
//! Split in two halves so the verdict logic is pure and unit-tested: the
//! resolver side materialises a [`DnsSnapshot`] (one round of lookups), and
//! [`verdicts`] grades it against what a working mail domain needs — MX,
//! SPF, DKIM, DMARC required; PTR, MTA-STS and TLS-RPT graded with advice.

use std::net::IpAddr;

use hickory_resolver::proto::rr::rdata::{MX, TXT};
use hickory_resolver::proto::rr::RData;
use hickory_resolver::TokioResolver;
use serde::Serialize;

/// Everything the wizard looks at, after one resolver pass.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DnsSnapshot {
    /// MX exchanges (host names) at the apex.
    pub mx: Vec<String>,
    /// TXT records at the apex (SPF lives here).
    pub txt_apex: Vec<String>,
    /// TXT records at `<selector>._domainkey`.
    pub txt_dkim: Vec<String>,
    /// TXT at `_dmarc`.
    pub txt_dmarc: Vec<String>,
    /// A/AAAA answers for the mail host.
    pub mail_addrs: Vec<IpAddr>,
    /// PTR for the mail host's first address.
    pub ptr: Option<String>,
    /// TXT at `_mta-sts`.
    pub txt_mta_sts: Vec<String>,
    /// TXT at `_smtp._tls`.
    pub txt_tls_rpt: Vec<String>,
}

/// One graded check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DnsCheck {
    /// Which check this is (`mx`, `spf`, `dkim`, `dmarc`, `ptr`, `mta-sts`, `tls-rpt`).
    pub check: &'static str,
    /// `pass`, `warn` or `fail`.
    pub status: &'static str,
    /// What was found, in one line.
    pub detail: String,
}

/// Grade a snapshot for `domain` with mail host `mail_host` and DKIM
/// `selector`.
#[must_use]
pub fn verdicts(
    snapshot: &DnsSnapshot,
    domain: &str,
    mail_host: &str,
    selector: &str,
) -> Vec<DnsCheck> {
    let mut checks = Vec::new();

    // MX — required, must reference the mail host.
    let mx_ok = snapshot.mx.iter().any(|exchange| {
        exchange
            .trim_end_matches('.')
            .eq_ignore_ascii_case(mail_host)
    });
    checks.push(DnsCheck {
        check: "mx",
        status: if snapshot.mx.is_empty() {
            "fail"
        } else if mx_ok {
            "pass"
        } else {
            "warn"
        },
        detail: if snapshot.mx.is_empty() {
            format!("no MX record for {domain}")
        } else {
            format!("mx: {}", snapshot.mx.join(", "))
        },
    });

    // SPF — required at the apex, should include the mx mechanism.
    let spf = snapshot
        .txt_apex
        .iter()
        .find(|txt| txt.starts_with("v=spf1"));
    checks.push(DnsCheck {
        check: "spf",
        status: match spf {
            None => "fail",
            Some(spf)
                if spf.contains(" mx") || spf.ends_with(" mx") || *spf == "v=spf1 mx -all" =>
            {
                "pass"
            }
            Some(_) => "warn",
        },
        detail: match spf {
            None => format!("no SPF record at {domain}"),
            Some(spf) => format!("spf: {spf}"),
        },
    });

    // DKIM — required for the configured selector.
    let dkim_ok = snapshot
        .txt_dkim
        .iter()
        .any(|txt| txt.starts_with("v=DKIM1") && txt.contains("p="));
    checks.push(DnsCheck {
        check: "dkim",
        status: if dkim_ok { "pass" } else { "fail" },
        detail: if dkim_ok {
            format!("{selector}._domainkey.{domain} publishes a key")
        } else {
            format!("{selector}._domainkey.{domain} has no v=DKIM1 key")
        },
    });

    // DMARC — required for deliverability.
    let dmarc_ok = snapshot
        .txt_dmarc
        .iter()
        .any(|txt| txt.starts_with("v=DMARC1"));
    checks.push(DnsCheck {
        check: "dmarc",
        status: if dmarc_ok { "pass" } else { "fail" },
        detail: if dmarc_ok {
            "_dmarc publishes a policy".to_owned()
        } else {
            format!("_dmarc.{domain} has no v=DMARC1 policy")
        },
    });

    // PTR — strongly recommended for outbound reputation.
    checks.push(DnsCheck {
        check: "ptr",
        status: match snapshot.ptr.as_deref() {
            Some(ptr) if ptr.trim_end_matches('.').eq_ignore_ascii_case(mail_host) => "pass",
            _ => "warn",
        },
        detail: match &snapshot.ptr {
            Some(ptr) => format!("reverse of the mail IP is {ptr}"),
            None => "the mail IP has no reverse DNS (set it at the provider)".to_owned(),
        },
    });

    // MTA-STS / TLS-RPT — optional modern protections.
    let mta_sts_ok = snapshot
        .txt_mta_sts
        .iter()
        .any(|txt| txt.starts_with("v=STSv1"));
    checks.push(DnsCheck {
        check: "mta-sts",
        status: if mta_sts_ok { "pass" } else { "warn" },
        detail: if mta_sts_ok {
            "_mta-sts publishes a policy".to_owned()
        } else {
            "no MTA-STS policy (optional; enables TLS pinning for senders)".to_owned()
        },
    });
    let tls_rpt_ok = snapshot
        .txt_tls_rpt
        .iter()
        .any(|txt| txt.starts_with("v=TLSRPT"));
    checks.push(DnsCheck {
        check: "tls-rpt",
        status: if tls_rpt_ok { "pass" } else { "warn" },
        detail: if tls_rpt_ok {
            "_smtp._tls publishes a reporting address".to_owned()
        } else {
            "no TLS-RPT record (optional; brings TLS failure reports)".to_owned()
        },
    });

    checks
}

/// Run one live resolver pass for `domain` / `mail_host` / `selector`.
///
/// # Errors
///
/// Returns a human-readable error when the resolver cannot be built; each
/// individual lookup degrades to "absent" instead of failing the pass.
pub async fn snapshot(
    domain: &str,
    mail_host: &str,
    selector: &str,
) -> Result<DnsSnapshot, String> {
    let resolver = TokioResolver::builder_tokio()
        .map_err(|e| format!("resolver init: {e}"))?
        .build()
        .map_err(|e| format!("resolver build: {e}"))?;

    let txt = |name: String| {
        let resolver = &resolver;
        async move {
            resolver
                .txt_lookup(format!("{name}.")) // fully qualified: cheaper lookups
                .await
                .ok()
                .map(|lookup| txt_strings(&lookup))
                .unwrap_or_default()
        }
    };

    let mx = resolver
        .mx_lookup(format!("{domain}."))
        .await
        .map(|lookup| {
            lookup
                .answers()
                .iter()
                .filter_map(|record| match &record.data {
                    RData::MX(MX { exchange, .. }) => {
                        Some(exchange.to_string().trim_end_matches('.').to_owned())
                    }
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default();

    let txt_apex = txt(domain.to_owned()).await;
    let txt_dkim = txt(format!("{selector}._domainkey.{domain}")).await;
    let txt_dmarc = txt(format!("_dmarc.{domain}")).await;
    let txt_mta_sts = txt(format!("_mta-sts.{domain}")).await;
    let txt_tls_rpt = txt(format!("_smtp._tls.{domain}")).await;

    let mail_addrs: Vec<IpAddr> = resolver
        .lookup_ip(format!("{mail_host}."))
        .await
        .map(|lookup| lookup.iter().collect())
        .unwrap_or_default();

    let ptr = match mail_addrs.first() {
        Some(ip) => {
            let reverse = reverse_name(*ip);
            resolver
                .reverse_lookup(reverse)
                .await
                .ok()
                .and_then(|lookup| {
                    lookup
                        .answers()
                        .first()
                        .and_then(|record| match &record.data {
                            RData::PTR(ptrdname) => {
                                Some(ptrdname.to_string().trim_end_matches('.').to_owned())
                            }
                            _ => None,
                        })
                })
        }
        None => None,
    };

    Ok(DnsSnapshot {
        mx,
        txt_apex,
        txt_dkim,
        txt_dmarc,
        mail_addrs,
        ptr,
        txt_mta_sts,
        txt_tls_rpt,
    })
}

fn txt_strings(lookup: &hickory_resolver::lookup::Lookup) -> Vec<String> {
    lookup
        .answers()
        .iter()
        .filter_map(|record| match &record.data {
            RData::TXT(TXT { ref txt_data, .. }) => {
                let joined: Vec<u8> = txt_data.iter().flatten().copied().collect();
                Some(String::from_utf8_lossy(&joined).into_owned())
            }
            _ => None,
        })
        .collect()
}

/// `in-addr.arpa` / `ip6.arpa` name for an address.
fn reverse_name(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            format!("{}.{}.{}.{}.in-addr.arpa", o[3], o[2], o[1], o[0])
        }
        IpAddr::V6(_) => ip.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn healthy() -> DnsSnapshot {
        DnsSnapshot {
            mx: vec!["mail.example.test".to_owned()],
            txt_apex: vec!["v=spf1 mx -all".to_owned()],
            txt_dkim: vec!["v=DKIM1; k=rsa; p=MIIBI".to_owned()],
            txt_dmarc: vec!["v=DMARC1; p=quarantine".to_owned()],
            mail_addrs: vec!["192.0.2.10".parse().unwrap()],
            ptr: Some("mail.example.test".to_owned()),
            txt_mta_sts: vec!["v=STSv1; id=1".to_owned()],
            txt_tls_rpt: vec!["v=TLSRPT; rua=mailto:r@example.test".to_owned()],
        }
    }

    #[test]
    fn a_healthy_domain_passes_everything() {
        let checks = verdicts(&healthy(), "example.test", "mail.example.test", "ayane");
        assert!(checks.iter().all(|c| c.status == "pass"), "{checks:?}");
        assert_eq!(checks.len(), 7);
    }

    #[test]
    fn missing_required_records_fail() {
        let mut snapshot = healthy();
        snapshot.mx.clear();
        snapshot.txt_apex.clear();
        snapshot.txt_dkim.clear();
        snapshot.txt_dmarc.clear();
        let checks = verdicts(&snapshot, "example.test", "mail.example.test", "ayane");
        for check in ["mx", "spf", "dkim", "dmarc"] {
            assert!(
                checks
                    .iter()
                    .any(|c| c.check == check && c.status == "fail"),
                "{check} must fail"
            );
        }
    }

    #[test]
    fn mx_pointing_elsewhere_only_warns() {
        let mut snapshot = healthy();
        snapshot.mx = vec!["elsewhere.example".to_owned()];
        let checks = verdicts(&snapshot, "example.test", "mail.example.test", "ayane");
        assert!(checks.iter().any(|c| c.check == "mx" && c.status == "warn"));
    }

    #[test]
    fn spf_without_mx_mechanism_warns() {
        let mut snapshot = healthy();
        snapshot.txt_apex = vec!["v=spf1 ip4:192.0.2.1 -all".to_owned()];
        let checks = verdicts(&snapshot, "example.test", "mail.example.test", "ayane");
        assert!(checks
            .iter()
            .any(|c| c.check == "spf" && c.status == "warn"));
    }

    #[test]
    fn mismatched_ptr_warns_but_not_fails() {
        let mut snapshot = healthy();
        snapshot.ptr = Some("something.else.test".to_owned());
        let checks = verdicts(&snapshot, "example.test", "mail.example.test", "ayane");
        assert!(checks
            .iter()
            .any(|c| c.check == "ptr" && c.status == "warn"));
    }

    #[test]
    fn absent_optional_records_stay_warnings() {
        let mut snapshot = healthy();
        snapshot.txt_mta_sts.clear();
        snapshot.txt_tls_rpt.clear();
        let checks = verdicts(&snapshot, "example.test", "mail.example.test", "ayane");
        assert!(checks
            .iter()
            .any(|c| c.check == "mta-sts" && c.status == "warn"));
        assert!(checks
            .iter()
            .any(|c| c.check == "tls-rpt" && c.status == "warn"));
    }
}
