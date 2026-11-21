//! Outgoing message construction.
//!
//! ayane is a client of the mail stack, never a server: the webmail and the
//! service's own notices hand a fully built message to Postfix over submission
//! (`127.0.0.1:587`, SASL as the sender). `lettre` builds the MIME envelope; the
//! queue, retries, DKIM signing and SPF alignment all stay in Postfix/rspamd.

use ayane_proto::Address;
use lettre::message::{header::ContentType, Mailbox, Message};
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
}
