//! Outgoing message construction.
//!
//! ayane is a client of the mail stack, never a server: the webmail and the
//! service's own notices hand a fully built message to Postfix over submission
//! (`127.0.0.1:587`, SASL as the sender). `lettre` builds the MIME envelope; the
//! queue, retries, DKIM signing and SPF alignment all stay in Postfix/rspamd.

use ayane_proto::Address;
use lettre::address::Envelope;
use lettre::message::header::{ContentType, HeaderName, HeaderValue};
use lettre::message::{Attachment, Mailbox, Message, MultiPart};
use lettre::Address as LettreAddress;

/// Why a message could not be built.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ComposeError {
    /// One of the addresses is not acceptable to the MIME builder.
    #[error("invalid address: {0}")]
    Address(String),
    /// The message builder rejected the headers or the body.
    #[error("invalid message: {0}")]
    Message(String),
    /// A header value contains CR/LF and would allow header injection.
    #[error("header injection attempt in {0}")]
    HeaderInjection(&'static str),
}

/// Build a plain-text message and serialise it for submission.
///
/// # Errors
///
/// Returns [`ComposeError`] when an address cannot be represented as a mailbox,
/// a header value contains a newline, or the builder rejects the message.
pub fn build_plain_message(
    from: &Address,
    from_name: &str,
    to: &Address,
    subject: &str,
    body: &str,
) -> Result<Message, ComposeError> {
    build_plain_message_as(from, from_name, from, to, subject, body)
}

/// [`build_plain_message`] with the From header and the envelope sender
/// chosen separately.
///
/// `from` is what the recipient reads; `envelope_from` is what `MAIL FROM`
/// carries, and it is the account — never a Gmail-style variant of it. The
/// two differ exactly when the administrator let a user send as
/// `alice+tag@d`: the header shows the tag, while SPF, DKIM alignment and
/// the bounce path stay on the address that actually exists.
///
/// # Errors
///
/// Returns [`ComposeError`] on the same conditions as [`build_plain_message`].
pub fn build_plain_message_as(
    from: &Address,
    from_name: &str,
    envelope_from: &Address,
    to: &Address,
    subject: &str,
    body: &str,
) -> Result<Message, ComposeError> {
    reject_newlines("from display name", from_name)?;
    reject_newlines("subject", subject)?;

    let from = Mailbox::new(Some(from_name.to_owned()), lettre_address(from)?);
    let to = Mailbox::new(None, lettre_address(to)?);

    let message = Message::builder()
        .from(from)
        .to(to.clone())
        .subject(subject.to_owned())
        .header(ContentType::TEXT_PLAIN)
        .envelope(envelope_of(envelope_from, &to)?)
        .body(body.to_owned())
        .map_err(|error| ComposeError::Message(error.to_string()))?;

    Ok(message)
}

/// The `MAIL FROM` / `RCPT TO` pair for one message: the sending account
/// and the recipient the headers name.
fn envelope_of(envelope_from: &Address, to: &Mailbox) -> Result<Envelope, ComposeError> {
    let recipients = vec![to.email.clone()];
    Envelope::new(Some(lettre_address(envelope_from)?), recipients)
        .map_err(|error| ComposeError::Address(error.to_string()))
}

/// Build a plain-text DRAFT and serialise it for the Drafts mailbox.
///
/// A draft is a work in progress: the recipient may be absent or not yet a
/// valid address (it is whatever the composer held when the user saved).
/// A parseable recipient becomes a real `To` header; anything else rides
/// `X-Ayane-Draft-To` verbatim (raw text, safe-encoded — a half-typed
/// address must still save, and the composer reads it back on "continue").
/// Nothing here is ever submitted — the bytes land in Drafts over IMAP
/// APPEND.
///
/// # Errors
///
/// Returns [`ComposeError`] when a header value contains a newline or the
/// builder rejects the message.
pub fn build_draft_message(
    from: &Address,
    from_name: &str,
    to: &str,
    subject: &str,
    body: &str,
) -> Result<Message, ComposeError> {
    reject_newlines("from display name", from_name)?;
    reject_newlines("subject", subject)?;
    reject_newlines("to", to)?;

    let from_mailbox = Mailbox::new(Some(from_name.to_owned()), lettre_address(from)?);
    let sender = lettre_address(from)?;
    let mut builder = Message::builder()
        .from(from_mailbox)
        .subject(subject.to_owned());
    let destination = if to.trim().is_empty() {
        None
    } else {
        Address::parse(to)
            .ok()
            .and_then(|parsed| lettre_address(&parsed).ok())
            .map(|addr| Mailbox::new(None, addr))
    };
    if let Some(mailbox) = destination {
        // A parseable recipient is a real To header.
        builder = builder.to(mailbox);
    } else {
        if !to.trim().is_empty() {
            // A half-typed recipient rides the draft header verbatim
            // (safe-encoded) — there is nothing valid to put in To.
            let name = HeaderName::new_from_ascii("X-Ayane-Draft-To".to_owned())
                .map_err(|_| ComposeError::Message("draft header name rejected".to_owned()))?;
            builder = builder.raw_header(HeaderValue::new(name, to.to_owned()));
        }
        // The builder refuses a message with no destination at all; a
        // draft is never submitted, so its envelope points at the author
        // (the rendered bytes carry no To header — headers stay truthful).
        builder =
            builder.envelope(Envelope::new(Some(sender.clone()), vec![sender]).map_err(
                |error| ComposeError::Message(format!("draft envelope rejected: {error}")),
            )?);
    }
    let message = builder
        .header(ContentType::TEXT_PLAIN)
        .body(body.to_owned())
        .map_err(|error| ComposeError::Message(error.to_string()))?;

    Ok(message)
}

/// One outgoing attachment: filename as it appears in the message,
/// `type/subtype` content type, raw bytes (the builder handles encoding).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutgoingAttachment {
    /// Filename in the MIME part.
    pub filename: String,
    /// `type/subtype` (e.g. `image/png`).
    pub content_type: String,
    /// Raw payload bytes.
    pub data: Vec<u8>,
}

/// Render markdown to sanitised HTML for the alternative part.
///
/// The markdown is OUR OWN render of the user's input, but the input may
/// contain raw HTML — ammonia still cleans the output (scripts and event
/// handlers never reach a recipient's reader).
#[must_use]
pub fn markdown_to_html(markdown: &str) -> String {
    use pulldown_cmark::{html, Options, Parser};

    let mut options = Options::empty();
    options.insert(Options::ENABLE_TABLES);
    options.insert(Options::ENABLE_STRIKETHROUGH);
    options.insert(Options::ENABLE_TASKLISTS);
    let parser = Parser::new_ext(markdown, options);
    let mut rendered = String::new();
    html::push_html(&mut rendered, parser);
    ammonia::Builder::new()
        .rm_tags(["img", "iframe", "object", "embed", "form", "input"])
        .url_schemes(std::collections::HashSet::from(["http", "https", "mailto"]))
        .clean(&rendered)
        .to_string()
}

fn parse_content_type(raw: &str) -> ContentType {
    let raw = raw.trim().to_ascii_lowercase();
    let (ty, sub) = raw
        .split_once('/')
        .unwrap_or(("application", "octet-stream"));
    match (ty, sub) {
        ("text", "plain") => ContentType::TEXT_PLAIN,
        ("text", "html") => ContentType::TEXT_HTML,
        _ => ContentType::parse(&raw).unwrap_or(ContentType::TEXT_PLAIN),
    }
}

/// Build a composed message: the markdown body rides a
/// `multipart/alternative` (markdown source as the plain part, the
/// sanitised HTML render as the rich part); attachments, when present,
/// wrap it in `multipart/mixed`.
///
/// # Errors
///
/// Returns [`ComposeError`] when an address cannot be represented, a
/// header value contains a newline, or the builder rejects the message.
pub fn build_composed_message(
    from: &Address,
    from_name: &str,
    to: &Address,
    subject: &str,
    markdown: &str,
    attachments: &[OutgoingAttachment],
) -> Result<Message, ComposeError> {
    build_composed_message_mode(from, from_name, to, subject, markdown, attachments, true)
}

/// [`build_composed_message`] with an explicit plain/markdown mode: a plain
/// body keeps its HTML part a faithful escaped render of the typed text.
///
/// # Errors
///
/// Returns [`ComposeError`] on the same conditions as the mode-less twin.
pub fn build_composed_message_mode(
    from: &Address,
    from_name: &str,
    to: &Address,
    subject: &str,
    body: &str,
    attachments: &[OutgoingAttachment],
    markdown: bool,
) -> Result<Message, ComposeError> {
    build_composed_message_as(
        from,
        from_name,
        from,
        to,
        subject,
        body,
        attachments,
        markdown,
    )
}

/// [`build_composed_message_mode`] with the From header and the envelope
/// sender chosen separately (see [`build_plain_message_as`]).
///
/// # Errors
///
/// Returns [`ComposeError`] on the same conditions as the twin above.
#[allow(clippy::too_many_arguments)]
pub fn build_composed_message_as(
    from: &Address,
    from_name: &str,
    envelope_from: &Address,
    to: &Address,
    subject: &str,
    body: &str,
    attachments: &[OutgoingAttachment],
    markdown: bool,
) -> Result<Message, ComposeError> {
    reject_newlines("from display name", from_name)?;
    reject_newlines("subject", subject)?;

    let from = Mailbox::new(Some(from_name.to_owned()), lettre_address(from)?);
    let to = Mailbox::new(None, lettre_address(to)?);

    let alternative = if markdown {
        MultiPart::alternative_plain_html(body.to_owned(), markdown_to_html(body))
    } else {
        // Escaped paragraph render: what the user typed is exactly what
        // an HTML reader sees.
        let html = format!(
            "<p>{}</p>",
            ammonia::clean_text(body)
                .replace("\r\n", "<br/>")
                .replace('\n', "<br/>")
        );
        MultiPart::alternative_plain_html(body.to_owned(), html)
    };
    // Attachments wrap the alternative in multipart/mixed; each one is a
    // singlepart built through the Attachment helper.
    let body = if attachments.is_empty() {
        alternative
    } else {
        let mut mixed = MultiPart::mixed().multipart(alternative);
        for attachment in attachments {
            let part = Attachment::new(attachment.filename.clone()).body(
                attachment.data.clone(),
                parse_content_type(&attachment.content_type),
            );
            mixed = mixed.singlepart(part);
        }
        mixed
    };

    let message = Message::builder()
        .from(from)
        .to(to.clone())
        .subject(subject.to_owned())
        .envelope(envelope_of(envelope_from, &to)?)
        .multipart(body)
        .map_err(|error| ComposeError::Message(error.to_string()))?;

    Ok(message)
}

/// Serialise a built message into RFC 5322 bytes (tests, logging, spooling).
#[must_use]
pub fn render(message: &Message) -> Vec<u8> {
    message.formatted()
}

fn lettre_address(address: &Address) -> Result<LettreAddress, ComposeError> {
    LettreAddress::new(address.local(), address.domain())
        .map_err(|error| ComposeError::Address(error.to_string()))
}

fn reject_newlines(field: &'static str, value: &str) -> Result<(), ComposeError> {
    if value.contains('\r') || value.contains('\n') {
        return Err(ComposeError::HeaderInjection(field));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(raw: &str) -> Address {
        Address::parse(raw).expect("fixture address")
    }

    #[test]
    fn builds_a_submittable_message() {
        let message = build_plain_message(
            &addr("noreply@example.com"),
            "ayane",
            &addr("ops@example.com"),
            "Quota warning",
            "Your mailbox is 90% full.",
        )
        .expect("message");

        let bytes = render(&message);
        let text = String::from_utf8_lossy(&bytes);
        assert!(text.contains("From: ayane <noreply@example.com>"));
        assert!(text.contains("To: ops@example.com"));
        assert!(text.contains("Subject: Quota warning"));
        assert!(text.contains("Your mailbox is 90% full."));
    }

    #[test]
    fn rejects_header_injection_in_the_subject() {
        let error = build_plain_message(
            &addr("noreply@example.com"),
            "ayane",
            &addr("ops@example.com"),
            "hello\r\nBcc: victim@example.com",
            "body",
        )
        .expect_err("injection must be rejected");
        assert_eq!(error, ComposeError::HeaderInjection("subject"));
    }

    #[test]
    fn rejects_header_injection_in_the_display_name() {
        let error = build_plain_message(
            &addr("noreply@example.com"),
            "ayane\nBcc: victim@example.com",
            &addr("ops@example.com"),
            "hello",
            "body",
        )
        .expect_err("injection must be rejected");
        assert_eq!(error, ComposeError::HeaderInjection("from display name"));
    }

    #[test]
    fn drafts_with_a_valid_recipient_get_a_real_to_header() {
        let message = build_draft_message(
            &addr("noreply@example.com"),
            "ayane",
            "ops@example.com",
            "Half-written note",
            "still typing",
        )
        .expect("draft");

        let bytes = render(&message);
        let text = String::from_utf8_lossy(&bytes);
        assert!(text.contains("To: ops@example.com"));
        assert!(!text.contains("X-Ayane-Draft-To"));
        assert!(text.contains("Subject: Half-written note"));
    }

    #[test]
    fn drafts_keep_a_half_typed_recipient_verbatim() {
        let message = build_draft_message(
            &addr("noreply@example.com"),
            "ayane",
            "ops@ (still looking up the domain)",
            "Half-written note",
            "still typing",
        )
        .expect("draft");

        let bytes = render(&message);
        let text = String::from_utf8_lossy(&bytes);
        // No real To header (nothing valid to put there), but the raw
        // input survives on the draft header for the composer to read back.
        assert!(!text.contains("\r\nTo:"));
        assert!(text.contains("X-Ayane-Draft-To"));
        assert!(text.contains("ops@ (still looking up the domain)"));
    }

    #[test]
    fn a_variant_from_header_keeps_the_account_as_the_envelope_sender() {
        // The From header shows the tag the user typed; `MAIL FROM` carries
        // the address that exists, so SPF, DKIM alignment and bounces stay
        // with the mailbox.
        let header_from = addr("alice+lists@example.com");
        let account = addr("alice@example.com");
        let to = addr("boss@example.com");
        let message = build_plain_message_as(&header_from, "Alice", &account, &to, "s", "b")
            .expect("message");
        let rendered = String::from_utf8(render(&message)).expect("utf8");
        assert!(
            rendered.contains("From: Alice <alice+lists@example.com>"),
            "{rendered}"
        );
        assert_eq!(
            message.envelope().from().map(ToString::to_string),
            Some("alice@example.com".to_owned())
        );
        assert_eq!(
            message
                .envelope()
                .to()
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            vec!["boss@example.com".to_owned()]
        );

        // The plain builder derives the envelope from the header; the `_as`
        // form is the one that splits them — and only the SENDER is split:
        // the recipient set still comes from the same headers.
        let derived = build_plain_message(&header_from, "Alice", &to, "s", "b").expect("message");
        assert_eq!(
            derived.envelope().to(),
            message.envelope().to(),
            "the explicit envelope must not change the recipients"
        );
        assert_eq!(
            derived.envelope().from().map(ToString::to_string),
            Some("alice+lists@example.com".to_owned())
        );

        // A multiline attachment body keeps the same split.
        let attachments = vec![OutgoingAttachment {
            filename: "a.txt".to_owned(),
            content_type: "text/plain".to_owned(),
            data: b"hi".to_vec(),
        }];
        let composed = build_composed_message_as(
            &header_from,
            "Alice",
            &account,
            &to,
            "s",
            "b",
            &attachments,
            true,
        )
        .expect("message");
        assert_eq!(
            composed.envelope().from().map(ToString::to_string),
            Some("alice@example.com".to_owned())
        );
        let rendered = String::from_utf8(render(&composed)).expect("utf8");
        assert!(rendered.contains("alice+lists@example.com"), "{rendered}");
    }

    #[test]
    fn drafts_never_carry_header_injection_from_the_recipient() {
        let error = build_draft_message(
            &addr("noreply@example.com"),
            "ayane",
            "ops@example.com\r\nBcc: victim@example.com",
            "hello",
            "body",
        )
        .expect_err("injection must be rejected");
        assert_eq!(error, ComposeError::HeaderInjection("to"));
    }

    #[test]
    fn markdown_renders_tables_and_strips_scripts() {
        let html = markdown_to_html(
            "# Hi\n\n<script>alert(1)</script>\n\n| a | b |\n| - | - |\n| 1 | 2 |",
        );
        assert!(html.contains("<h1>Hi</h1>"));
        assert!(html.contains("<table>"));
        assert!(!html.contains("<script>"));
        // The script TEXT survives as escaped prose, the tag never does.
        assert!(!html.contains("alert(1)</script>"));
    }

    #[test]
    fn markdown_links_keep_http_mailto_and_drop_javascript() {
        let html = markdown_to_html(
            "[ok](https://example.com) [mail](mailto:a@b.c) [bad](javascript:alert(1))",
        );
        assert!(html.contains("https://example.com"));
        assert!(html.contains("mailto:a@b.c"));
        assert!(!html.contains("javascript:"));
    }

    #[test]
    fn composed_message_carries_alternative_and_attachments() {
        let message = build_composed_message(
            &addr("noreply@example.com"),
            "ayane",
            &addr("ops@example.com"),
            "Report",
            "**bold** statement",
            &[OutgoingAttachment {
                filename: "logo.png".to_owned(),
                content_type: "image/png".to_owned(),
                data: vec![0x89, b'P', b'N', b'G'],
            }],
        )
        .expect("message");

        let bytes = render(&message);
        let text = String::from_utf8_lossy(&bytes);
        assert!(text.contains("multipart/mixed"));
        assert!(text.contains("multipart/alternative"));
        // The markdown source is the plain part; the render is the HTML part.
        assert!(text.contains("**bold** statement"));
        assert!(text.contains("<strong>bold</strong>"));
        assert!(text.contains("logo.png"));
    }

    #[test]
    fn composed_message_without_attachments_is_alternative_only() {
        let message = build_composed_message(
            &addr("noreply@example.com"),
            "ayane",
            &addr("ops@example.com"),
            "Note",
            "plain note",
            &[],
        )
        .expect("message");

        let bytes = render(&message);
        let text = String::from_utf8_lossy(&bytes);
        assert!(text.contains("multipart/alternative"));
        assert!(!text.contains("multipart/mixed"));
    }
}
