//! Phishing-link heuristics for the read path.
//!
//! Pure analysis: links in (extracted from the text and HTML bodies), a
//! verdict out. Every check is explainable — a warning the user cannot
//! reason about is noise — so each verdict carries the concrete reasons.
//! The module never blocks anything; the webmail renders warnings next to
//! the links and leaves the judgement to the human.

/// One analysed link.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct LinkVerdict {
    /// The URL as found.
    pub url: String,
    /// Human-readable reason strings (empty = no finding).
    pub reasons: Vec<&'static str>,
    /// `danger` (do not trust), `warn` (suspicious) or `ok`.
    pub verdict: &'static str,
}

/// Well-known URL shorteners (host suffixes).
const SHORTENERS: &[&str] = &[
    "bit.ly",
    "t.co",
    "goo.gl",
    "tinyurl.com",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "cutt.ly",
    "rebrand.ly",
    "shorturl.at",
    "t.ly",
    "rb.gy",
    "s.id",
    "linktr.ee",
];

/// Extract and score every link found in the two bodies.
#[must_use]
pub fn analyze(text: Option<&str>, html: Option<&str>) -> Vec<LinkVerdict> {
    let mut urls = Vec::new();
    if let Some(text) = text {
        urls.extend(scan_text(text));
    }
    if let Some(html) = html {
        urls.extend(scan_html(html));
    }

    let mut seen = std::collections::HashSet::new();
    urls.into_iter()
        .filter(|url| seen.insert(url.clone()))
        .map(|url| score(&url))
        .collect()
}

/// Pull `href="…"` values out of (already sanitised) HTML.
fn scan_html(html: &str) -> Vec<String> {
    let lower = html.to_ascii_lowercase();
    let mut out = Vec::new();
    let mut cursor = 0;
    while let Some(pos) = lower[cursor..].find("href=\"") {
        let start = cursor + pos + 6;
        let Some(end_rel) = lower[start..].find('"') else {
            break;
        };
        let end = start + end_rel;
        if end > start {
            out.push(html[start..end].to_owned());
        }
        cursor = end + 1;
    }
    out
}

/// Pull bare http(s) URLs out of plain text.
fn scan_text(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for word in text.split_whitespace() {
        let word = word.trim_matches(|c: char| c.is_ascii_punctuation() && c != '/' && c != ':');
        if word.starts_with("http://") || word.starts_with("https://") {
            out.push(word.to_owned());
        } else if let Some((scheme, _)) = word.split_once(':') {
            // Dangerous schemes hide in innocuous text; collect them so the
            // reader is warned even though a real browser would not follow.
            if matches!(scheme, "javascript" | "data" | "vbscript" | "file") {
                out.push(word.to_owned());
            }
        }
    }
    out
}

/// Score one URL.
fn score(url: &str) -> LinkVerdict {
    let mut reasons: Vec<&'static str> = Vec::new();
    let mut danger = false;

    let (scheme, rest) = match url.split_once(':') {
        Some((s, r)) if s.chars().all(|c| c.is_ascii_alphanumeric()) => {
            (s.to_ascii_lowercase(), r.trim_start_matches("//"))
        }
        _ => (String::new(), url),
    };
    match scheme.as_str() {
        "https" => {}
        "http" => reasons.push("cleartext http link"),
        "javascript" | "data" | "vbscript" | "file" => {
            reasons.push("embedded script/data scheme");
            danger = true;
        }
        "" => reasons.push("no scheme"),
        _ => reasons.push("unusual scheme"),
    }

    // Strip path: the host is everything up to / ? or #
    let host_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..host_end];
    let host_port = authority.rsplit('@').next().unwrap_or(authority);
    if authority.contains('@') {
        reasons.push("embedded credentials in URL");
        danger = true;
    }
    let (host, port) = host_port.split_once(':').unwrap_or((host_port, ""));
    let _ = port;

    if host.starts_with('[') || host.parse::<std::net::IpAddr>().is_ok() {
        reasons.push("raw IP address instead of a domain");
        danger = true;
    }
    if host.split('.').any(|label| label.starts_with("xn--")) {
        reasons.push("punycode label (possible homoglyph)");
        danger = true;
    }
    if let Some(domain) = host.strip_prefix("www.").or(Some(host)) {
        if SHORTENERS.contains(&domain) {
            reasons.push("URL shortener hides the destination");
        }
    }
    if mixed_scripts(host) {
        reasons.push("mixed scripts in domain (homoglyph lookalike)");
        danger = true;
    }

    let verdict = if danger {
        "danger"
    } else if reasons.is_empty() {
        "ok"
    } else {
        "warn"
    };

    LinkVerdict {
        url: url.to_owned(),
        reasons,
        verdict,
    }
}

/// True when the host mixes Latin with Cyrillic/Greek (classic homoglyph
/// attacks like `аpple.com` with a Cyrillic а).
fn mixed_scripts(host: &str) -> bool {
    let mut latin = false;
    let mut lookalike = false;
    for ch in host.chars() {
        match ch {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '.' | '-' => {
                latin = latin || ch.is_ascii_alphabetic()
            }
            '\u{0400}'..='\u{04FF}' => lookalike = true, // Cyrillic
            '\u{0370}'..='\u{03FF}' => lookalike = true, // Greek
            _ => {}
        }
    }
    latin && lookalike
}

#[cfg(test)]
mod tests {
    use super::*;

    fn verdicts(text: &str) -> Vec<LinkVerdict> {
        analyze(Some(text), None)
    }

    #[test]
    fn clean_https_link_is_ok() {
        let v = verdicts("see https://example.test/docs for details");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].verdict, "ok");
        assert!(v[0].reasons.is_empty());
    }

    #[test]
    fn http_link_warns() {
        let v = verdicts("go to http://example.test/x");
        assert_eq!(v[0].verdict, "warn");
        assert_eq!(v[0].reasons, ["cleartext http link"]);
    }

    #[test]
    fn raw_ip_and_javascript_are_danger() {
        let v = verdicts("https://192.0.2.7/login and javascript:alert(1)");
        assert!(v
            .iter()
            .any(|l| l.verdict == "danger"
                && l.reasons.contains(&"raw IP address instead of a domain")));
        assert!(v
            .iter()
            .any(|l| l.verdict == "danger" && l.reasons.contains(&"embedded script/data scheme")));
    }

    #[test]
    fn punycode_is_danger() {
        let v = verdicts("https://xn--pple-43d.com/login");
        assert_eq!(v[0].verdict, "danger");
        assert!(v[0]
            .reasons
            .contains(&"punycode label (possible homoglyph)"));
    }

    #[test]
    fn homoglyph_domain_is_danger() {
        // Cyrillic а + Latin rest.
        let v = verdicts("https://аpple.test/signin");
        assert_eq!(v[0].verdict, "danger");
        assert!(v[0]
            .reasons
            .contains(&"mixed scripts in domain (homoglyph lookalike)"));
    }

    #[test]
    fn shortener_warns() {
        let v = verdicts("visit https://bit.ly/3xYz");
        assert_eq!(v[0].verdict, "warn");
        assert!(v[0]
            .reasons
            .contains(&"URL shortener hides the destination"));
    }

    #[test]
    fn html_hrefs_are_extracted_and_deduped() {
        let html = r#"<a href="https://a.test/1">x</a> <a href="https://a.test/1">y</a> <a href="http://b.test">z</a>"#;
        let v = analyze(None, Some(html));
        assert_eq!(v.len(), 2);
        assert!(v
            .iter()
            .any(|l| l.url == "http://b.test" && l.verdict == "warn"));
    }

    #[test]
    fn credentials_in_url_are_danger() {
        let v = verdicts("https://user:pass@example.test/");
        assert_eq!(v[0].verdict, "danger");
        assert!(v[0].reasons.contains(&"embedded credentials in URL"));
    }
}
