//! Outgoing message construction.
//!
//! ayane is a client of the mail stack, never a server: the webmail and the
//! service's own notices hand a fully built message to Postfix over submission
//! (`127.0.0.1:587`, SASL as the sender). `lettre` builds the MIME envelope; the
//! queue, retries, DKIM signing and SPF alignment all stay in Postfix/rspamd.

use ayane_proto::Address;
use lettre::address::Envelope;
use lettre::message::header::{ContentType, HeaderName, HeaderValue};
use lettre::message::{Mailbox, Message};
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
    reject_newlines("from display name", from_name)?;
    reject_newlines("subject", subject)?;

    let from = Mailbox::new(Some(from_name.to_owned()), lettre_address(from)?);
    let to = Mailbox::new(None, lettre_address(to)?);

    let message = Message::builder()
        .from(from)
        .to(to)
        .subject(subject.to_owned())
        .header(ContentType::TEXT_PLAIN)
        .body(body.to_owned())
        .map_err(|error| ComposeError::Message(error.to_string()))?;

    Ok(message)
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
}
