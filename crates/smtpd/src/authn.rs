//! SASL PLAIN / LOGIN decoding and the credential check.
//!
//! The passwords are compared by a [`PasswordVerifier`] the caller supplies —
//! this crate never hashes a password itself (MAP §四 rule 10) and never
//! stores one. `ayane-store` already owns the Dovecot-compatible hash and the
//! HTTP login path, so the verifier is a thin adapter over it.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;

/// Checks one `(identity, password)` pair. Async so the adapter can reach the
/// store; the future must not hold a blocking lock across an `.await` in the
/// caller's runtime.
pub trait PasswordVerifier: Send + Sync {
    /// Returns `true` when `password` unlocks `identity` (a bare mailbox
    /// address). Implementations should treat an unknown mailbox and a wrong
    /// password identically so timing does not reveal existence.
    fn verify<'a>(
        &'a self,
        identity: &'a str,
        password: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send + 'a>>;
}

/// A verifier that never accepts anything, for listeners without AUTH or for
/// tests that exercise the rejection path.
#[derive(Debug, Clone, Copy, Default)]
pub struct DenyAll;

impl PasswordVerifier for DenyAll {
    fn verify<'a>(
        &'a self,
        _identity: &'a str,
        _password: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send + 'a>> {
        Box::pin(async { false })
    }
}

/// Why a SASL response could not be decoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SaslError {
    /// The response is not valid base64 or not valid UTF-8.
    #[error("malformed SASL response")]
    Malformed,
    /// PLAIN needs exactly three NUL-separated fields.
    #[error("malformed PLAIN message")]
    BadPlain,
    /// The response is the `*` cancellation.
    #[error("authentication cancelled")]
    Cancelled,
}

/// Decodes an `AUTH PLAIN` message (RFC 4616 §2): `[authzid] NUL authcid NUL
/// passwd`.
///
/// **The `authzid` is deliberately discarded.** RFC 4616 lets a client ask to
/// act as another identity, and this server never honours that: an
/// authenticated session acts as the identity it proved, and nothing else.
/// That is a security default, not an omission — a proxy-identity path would
/// turn one valid credential into whatever mailbox the client names, which is
/// exactly what the submission sender binding exists to prevent. It is also
/// why the field is only *parsed* and never validated: whatever it says has no
/// effect, so no value of it can be an injection either.
///
/// # Errors
///
/// Returns [`SaslError::Malformed`] for bad base64/UTF-8,
/// [`SaslError::BadPlain`] for the wrong number of fields, and
/// [`SaslError::Cancelled`] for `*`.
pub fn decode_plain(response: &str) -> Result<(String, String), SaslError> {
    if response == "*" {
        return Err(SaslError::Cancelled);
    }
    let raw = STANDARD
        .decode(response.trim())
        .map_err(|_| SaslError::Malformed)?;
    let text = String::from_utf8(raw).map_err(|_| SaslError::Malformed)?;
    let mut parts = text.split('\0');
    let _authzid = parts.next().ok_or(SaslError::BadPlain)?;
    let authcid = parts.next().ok_or(SaslError::BadPlain)?;
    let passwd = parts.next().ok_or(SaslError::BadPlain)?;
    if parts.next().is_some() || authcid.is_empty() {
        return Err(SaslError::BadPlain);
    }
    Ok((authcid.to_owned(), passwd.to_owned()))
}

/// Whether `identity` is one this server will look up: a bare mailbox, judged
/// by exactly the rules [`crate::mailbox::Mailbox::parse`] judges a path by.
///
/// The identity is a mailbox the client names, so it is **parsed as one** —
/// not by a table of shapes kept in step with the parser by hand. A parallel
/// table drifts: the first version of this check accepted one `@` and refused
/// quoting, but knew nothing about a domain label that starts with a hyphen, an
/// empty label, or a trailing dot, so `a@-example.com` logged in (`235`) while
/// `MAIL FROM:<a@-example.com>` was a `501` — one server, two answers about
/// whether the same text is a mailbox. Deriving the answer from the parser
/// makes that disagreement impossible: whatever `MAIL FROM` accepts, AUTH
/// accepts, and whatever `MAIL FROM` refuses, AUTH reports as a syntax error.
///
/// The shape is the SMTPUTF8 one, which this server always advertises:
/// `用户@例子.测试` is as much a mailbox as `ops@example.com` is, and refusing
/// it here while the greeting offers `SMTPUTF8` would contradict the
/// extension. What the local part's UTF-8 means to the store is the store's
/// business; this function only says the text cannot be anything other than
/// one mailbox.
///
/// Two things the parser's job is *not* are checked here as well, because the
/// identity travels differently from a path:
///
/// - It is not between angle brackets, so it is not trimmed: ` ops@example.com`
///   is a path a client may have written carelessly inside `<…>`, and it is
///   not the mailbox the session will look up, so it is refused rather than
///   silently repaired into a login.
/// - It ends up in the `Received:` field of every message the session sends,
///   and no control octet may survive into a header. A control octet is not a
///   mailbox either, so nothing is lost by asking here and it is the same
///   `501` whether or not the password was right.
#[must_use]
pub fn valid_identity(identity: &str) -> bool {
    if identity.is_empty() || identity.len() > 254 || identity.trim() != identity {
        return false;
    }
    if identity
        .chars()
        .any(|ch| ch.is_control() || ch.is_whitespace())
    {
        return false;
    }
    match crate::mailbox::Mailbox::parse(identity, true) {
        // The null path is `< >`: no identity at all, not a mailbox to log in
        // as.
        Ok(mailbox) => mailbox != crate::mailbox::Mailbox::Null,
        Err(_) => false,
    }
}

/// Decodes one base64 field of the LOGIN exchange.
///
/// # Errors
///
/// Returns [`SaslError::Malformed`] for bad base64/UTF-8 and
/// [`SaslError::Cancelled`] for `*`.
pub fn decode_login_field(response: &str) -> Result<String, SaslError> {
    if response == "*" {
        return Err(SaslError::Cancelled);
    }
    let raw = STANDARD
        .decode(response.trim())
        .map_err(|_| SaslError::Malformed)?;
    let text = String::from_utf8(raw).map_err(|_| SaslError::Malformed)?;
    if text.is_empty() {
        return Err(SaslError::Malformed);
    }
    Ok(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn b64(text: &str) -> String {
        STANDARD.encode(text.as_bytes())
    }

    #[test]
    fn plain_decodes_identity_and_password() {
        assert_eq!(
            decode_plain(&b64("\0ops@example.com\0secret")),
            Ok(("ops@example.com".to_owned(), "secret".to_owned()))
        );
    }

    #[test]
    fn plain_rejects_malformed_messages() {
        assert_eq!(decode_plain("***"), Err(SaslError::Malformed));
        assert_eq!(decode_plain(&b64("only")), Err(SaslError::BadPlain));
        assert_eq!(decode_plain("*"), Err(SaslError::Cancelled));
    }

    #[test]
    fn authzid_is_ignored_by_design() {
        // Whatever the client asks to act as, the answer is the identity it
        // proved: the proxy identity is dropped, never returned.
        assert_eq!(
            decode_plain(&b64("someone-else@example.com\0ops@example.com\0secret")),
            Ok(("ops@example.com".to_owned(), "secret".to_owned()))
        );
    }

    #[test]
    fn identities_with_control_octets_are_refused() {
        assert!(valid_identity("ops@example.com"));
        assert!(!valid_identity("ops@exa\r\nmple.com"));
        assert!(!valid_identity(
            "ops@example.com\r\nBcc: victim@example.net"
        ));
        assert!(!valid_identity("ops@example.com\u{0}x"));
        assert!(!valid_identity("ops example.com"));
        assert!(!valid_identity("@example.com"));
        assert!(!valid_identity("ops@"));
        assert!(!valid_identity("plain"));
        assert!(!valid_identity(""));
        // Abbreviated, quoted or listed addresses are not one bare mailbox,
        // and a leading/trailing blank is not part of one either.
        assert!(!valid_identity(" ops@example.com"));
        assert!(!valid_identity("ops@example.com "));
        assert!(!valid_identity("<ops@example.com>"));
        assert!(!valid_identity("ops@example.com,evil@example.net"));
    }

    #[test]
    fn smtputf8_identities_are_mailboxes_and_are_accepted() {
        // The greeting advertises SMTPUTF8, so an identity in the extended
        // alphabet must be able to log in: refusing it here while MAIL and
        // RCPT accepted it would contradict the extension.
        assert!(valid_identity("用户@例子.测试"));
        assert!(valid_identity("ユーザ@example.net"));
        assert!(valid_identity("用户@example.com"));
        assert!(valid_identity("Jörg@example.com"));
        // The extended alphabet does not buy a way around the control check.
        assert!(!valid_identity("用户@例子.测试\r\nBcc: victim@example.net"));
        assert!(!valid_identity("用\u{0}户@例子.测试"));
        assert!(!valid_identity("用户 名@例子.测试"));
        assert!(!valid_identity("用户@例子@.测试"));
    }

    #[test]
    fn login_fields_decode() {
        assert_eq!(
            decode_login_field(&b64("ops@example.com")),
            Ok("ops@example.com".to_owned())
        );
        assert_eq!(decode_login_field("*"), Err(SaslError::Cancelled));
    }
}
