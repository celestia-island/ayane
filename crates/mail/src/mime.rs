//! Message parsing for the read path.
//!
//! Raw RFC 5322 bytes in, one safe, structured view out: header summary,
//! the text body, an ammonia-sanitised HTML body (scripts, event handlers,
//! remote images and styles stripped — the webmail never renders untrusted
//! HTML raw), and attachment metadata where every attachment carries its
//! SHA-256 so the UI can display it hash-first without ever executing it.

use sha2::{Digest, Sha256};

/// One attachment's safe metadata (never its bytes).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct AttachmentMeta {
    /// File name from the part headers, or `unnamed` when absent.
    pub filename: String,
    /// Normalised `type/subtype` (`application/octet-stream` fallback).
    pub content_type: String,
    /// Decoded size in bytes.
    pub size: usize,
    /// SHA-256 of the decoded bytes, lowercase hex.
    pub sha256: String,
}

/// A parsed, sanitised message ready for the webmail read view.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct ParsedMessage {
    /// `Message-ID` header when present.
    pub message_id: Option<String>,
    /// First `From` address (envelope form, no display name).
    pub from: Option<String>,
    /// Joined `To` addresses.
    pub to: Vec<String>,
    /// `Subject` header.
    pub subject: Option<String>,
    /// Raw `X-Ayane-Draft-To` header — the composer's recipient input as
    /// the draft saved it (a half-typed address never becomes a real `To`).
    /// Only drafts carry it; the composer reads it back on "continue".
    pub draft_to: Option<String>,
    /// Plain-text body when the message has one.
    pub text: Option<String>,
    /// Ammonia-sanitised HTML body (safe to render; remote content removed).
    pub html: Option<String>,
    /// Attachment metadata, hash-first.
    pub attachments: Vec<AttachmentMeta>,
}

/// Parse and sanitise one raw message.
#[must_use]
pub fn parse(raw: &[u8]) -> Option<ParsedMessage> {
    let message = mail_parser::MessageParser::default().parse(raw)?;

    let from = message
        .from()
        .and_then(|list| list.first())
        .and_then(|addr| addr.address())
        .map(str::to_owned);

    let to = message
        .to()
        .map(|list| {
            list.mailboxes()
                .filter_map(|addr| addr.address())
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();

    let text = message.body_text(0).map(|t| t.into_owned());
    // Sanitise aggressively: no media/embed/form tags, no scripts, no
    // event handlers, and NO url schemes at all — every remote reference
    // (tracking pixels included) is dropped, so the read view loads
    // nothing from the network on the client's behalf. Only html_body
    // parts are rendered; body_html would synthesise HTML from plain text.
    let html = message
        .html_body()
        .find(|part| part.is_content_type("text", "html"))
        .and_then(|part| part.text())
        .map(|h| {
            ammonia::Builder::new()
                .rm_tags([
                    "img", "style", "iframe", "object", "embed", "form", "input", "button",
                    "video", "audio", "source",
                ])
                .url_schemes(std::collections::HashSet::new())
                .clean(&h)
                .to_string()
        });

    let mut attachments = Vec::new();
    for part in message.attachments() {
        let filename = part
            .attachment_name()
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .unwrap_or("unnamed")
            .to_owned();
        let content_type = part
            .content_type()
            .map(|ct| match ct.subtype() {
                Some(sub) => format!("{}/{}", ct.ctype(), sub),
                None => ct.ctype().to_owned(),
            })
            .unwrap_or_else(|| "application/octet-stream".to_owned());
        let bytes = part.decoded();
        let sha256 = Sha256::digest(bytes.as_ref());
        attachments.push(AttachmentMeta {
            filename,
            content_type,
            size: bytes.len(),
            sha256: format!("{sha256:x}"),
        });
    }

    Some(ParsedMessage {
        message_id: message.message_id().map(str::to_owned),
        from,
        to,
        subject: message.subject().map(str::to_owned),
        draft_to: message
            .headers()
            .value("X-Ayane-Draft-To")
            .and_then(|v| v.as_text())
            .map(str::to_owned),
        text,
        html,
        attachments,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const PLAIN: &str = "From: Alice <alice@example.test>\r\n\
        To: bob@example.test\r\n\
        Subject: Hello plain\r\n\
        Message-ID: <m1@example.test>\r\n\
        Content-Type: text/plain; charset=utf-8\r\n\
        \r\n\
        Just some text.\r\n";

    const MIXED: &str = "From: eve@evil.example\r\n\
        To: victim@example.test\r\n\
        Subject: click\r\n\
        MIME-Version: 1.0\r\n\
        Content-Type: multipart/mixed; boundary=\"XX\"\r\n\
        \r\n\
        --XX\r\n\
        Content-Type: text/html; charset=utf-8\r\n\
        \r\n\
        <p>hi <b>there</b><script>steal()</script>\
        <img src=\"https://track.example/pixel.gif\">\
        <a href=\"https://ok.example\">link</a></p>\r\n\
        --XX\r\n\
        Content-Type: application/pdf; name=\"invoice.pdf\"\r\n\
        Content-Disposition: attachment; filename=\"invoice.pdf\"\r\n\
        \r\n\
        PDFBYTES\r\n\
        --XX--\r\n";

    #[test]
    fn parses_plain_messages() {
        let parsed = parse(PLAIN.as_bytes()).expect("parse");
        assert_eq!(parsed.from.as_deref(), Some("alice@example.test"));
        assert_eq!(parsed.subject.as_deref(), Some("Hello plain"));
        assert_eq!(parsed.message_id.as_deref(), Some("m1@example.test"));
        assert!(parsed
            .text
            .as_deref()
            .is_some_and(|t| t.contains("Just some text")));
        assert!(parsed.html.is_none());
        assert!(parsed.attachments.is_empty());
    }

    #[test]
    fn sanitises_html_and_hashes_attachments() {
        let parsed = parse(MIXED.as_bytes()).expect("parse");
        let html = parsed.html.as_deref().expect("html");
        assert!(html.contains("<b>there</b>"));
        assert!(!html.contains("script"));
        assert!(!html.contains("pixel.gif"));
        assert!(!html.contains("https://ok.example")); // href stripped with remote refs

        assert_eq!(parsed.attachments.len(), 1);
        let att = &parsed.attachments[0];
        assert_eq!(att.filename, "invoice.pdf");
        assert_eq!(att.content_type, "application/pdf");
        assert_eq!(att.size, 8);
        assert_eq!(att.sha256.len(), 64);
        // Deterministic: same bytes, same digest.
        let again = parse(MIXED.as_bytes()).expect("again");
        assert_eq!(again.attachments[0].sha256, att.sha256);
    }

    #[test]
    fn unparsable_input_yields_none() {
        assert!(parse(b"\x00\x01 not a message").is_none());
    }
}
