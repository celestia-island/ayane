//! Mailbox (path) parsing for the SMTP envelope.
//!
//! RFC 5321 §4.1.2 fixes the `<path>` shapes the envelope commands accept:
//! `<>` for the null reverse-path, `<a@b>`, and `<@relay1,@relay2:a@b>` for the
//! obsolete source route. This module turns the text between the angle
//! brackets into a [`Mailbox`], keeping the ASCII and SMTPUTF8 (RFC 6531)
//! alphabets apart so the caller can enforce extra rules.
//!
//! Deliberately lenient in one direction only: a *bare* address without the
//! angle brackets is accepted for HELO-style tolerance on `MAIL FROM`, because
//! some appliances send it, but no mailbox may contain a control character,
//! whitespace in the ASCII form, or more than one `@`.
//!
//! One path has no `@` at all and is still legal: RFC 5321 §4.1.3 requires
//! every SMTP server to accept `RCPT TO:<Postmaster>`, with no domain. Only
//! that one local part is exempt (case-insensitively); every other domainless
//! path stays a `501`. The exemption is recorded as an empty `domain` in
//! [`Mailbox::Address`], and [`Mailbox::postmaster_domain`] is how a consumer
//! tells the two apart.

use std::fmt;

/// The one mailbox RFC 5321 §4.1.3 accepts without a domain.
pub const POSTMASTER: &str = "postmaster";

/// The reverse-path of `MAIL FROM` or the forward-path of `RCPT TO`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mailbox {
    /// `<>` — a bounce or a notification. It never generates a DSN.
    Null,
    /// A `local@domain` mailbox.
    Address {
        /// Everything before the final `@`, as written.
        local: String,
        /// The domain, as written (case preserved; matching is done by the
        /// consumer, never here). **Empty only for the bare `postmaster`**
        /// RFC 5321 §4.1.3 requires every server to accept; see
        /// [`Mailbox::postmaster_domain`].
        domain: String,
        /// The address needed SMTPUTF8 (any non-ASCII octet).
        utf8: bool,
        /// The address carried an obsolete source route (`@a,@b:`), which was
        /// stripped from `local`/`domain`.
        routed: bool,
    },
}

impl Mailbox {
    /// Parses the text between the angle brackets (or a bare address).
    ///
    /// `allow_utf8` decides whether non-ASCII octets are acceptable; when it
    /// is false they make the address invalid, which keeps a plain
    /// `MAIL FROM` from smuggling a UTF-8 local part past the `SMTPUTF8`
    /// parameter.
    ///
    /// # Errors
    ///
    /// Returns the reason the text is not a usable mailbox.
    pub fn parse(text: &str, allow_utf8: bool) -> Result<Self, MailboxError> {
        let text = text.trim();
        if text.is_empty() {
            return Ok(Self::Null);
        }
        if let Some(rest) = text.strip_prefix('@') {
            // Obsolete source route: @relay1,@relay2:local@domain
            let (route, rest) = rest.split_once(':').ok_or(MailboxError::MalformedRoute)?;
            let mut relays = 0usize;
            for relay in route.split(',') {
                if relay.is_empty() || !is_relay(relay) {
                    return Err(MailboxError::MalformedRoute);
                }
                relays += 1;
            }
            if relays == 0 || relays > 8 {
                return Err(MailboxError::MalformedRoute);
            }
            let mut mailbox = Self::parse(rest, allow_utf8)?;
            if let Self::Address { routed, .. } = &mut mailbox {
                *routed = true;
            }
            return Ok(mailbox);
        }
        let utf8 = !text.is_ascii();
        if utf8 && !allow_utf8 {
            return Err(MailboxError::NoUtf8);
        }
        // `trim` above removed the outer whitespace; anything left inside is
        // checked here, so a control octet can never survive into a file name,
        // a header or a log line.
        if text.chars().any(|ch| ch.is_control() || ch.is_whitespace()) {
            return Err(MailboxError::Control);
        }
        if text.contains(['<', '>', '(', ')', ',', ';', ':', '\\', '"', '[', ']', ' ']) {
            return Err(MailboxError::IllegalCharacter);
        }
        let Some((local, domain)) = text.rsplit_once('@') else {
            // RFC 5321 §4.1.3: every server accepts `RCPT TO:<Postmaster>`
            // with no domain, and only that name. It is carried as an address
            // with an empty domain so `local@host` and the bare form stay one
            // type; the caller qualifies it (the session names it for the host
            // it greets for).
            if text.eq_ignore_ascii_case(POSTMASTER) {
                return Ok(Self::Address {
                    local: POSTMASTER.to_owned(),
                    domain: String::new(),
                    utf8,
                    routed: false,
                });
            }
            return Err(MailboxError::MissingAt);
        };
        if local.is_empty() || domain.is_empty() {
            return Err(MailboxError::EmptyPart);
        }
        if local.contains('@') {
            return Err(MailboxError::MultipleAt);
        }
        if local.len() > 64 || text.len() > 254 {
            return Err(MailboxError::TooLong);
        }
        if local.eq_ignore_ascii_case(POSTMASTER) && domain.eq_ignore_ascii_case(POSTMASTER) {
            // `RCPT TO:<postmaster>` means "the postmaster of the server
            // being talked to", never "the account named postmaster on some
            // third-party domain" (RFC 5321 §4.1.3). Refused rather than
            // silently re-pointed, so a receiver's behaviour is not made up.
            return Err(MailboxError::AmbiguousPostmaster);
        }
        if domain.starts_with('[') || !is_atext_domain(domain) {
            return Err(MailboxError::MalformedDomain);
        }
        if domain.len() > 253 {
            return Err(MailboxError::TooLong);
        }
        Ok(Self::Address {
            local: local.to_owned(),
            domain: domain.to_owned(),
            utf8,
            routed: false,
        })
    }

    /// The `local@domain` text, or `""` for the null path.
    #[must_use]
    pub fn as_text(&self) -> String {
        match self {
            Self::Null => String::new(),
            Self::Address { local, domain, .. } if domain.is_empty() => local.clone(),
            Self::Address { local, domain, .. } => format!("{local}@{domain}"),
        }
    }

    /// The local part, `""` for the null path.
    #[must_use]
    pub fn local(&self) -> &str {
        match self {
            Self::Null => "",
            Self::Address { local, .. } => local,
        }
    }

    /// The domain part, empty for the null path **and** for the bare
    /// `postmaster` RFC 5321 §4.1.3 exempts from having one.
    #[must_use]
    pub fn domain(&self) -> &str {
        match self {
            Self::Null => "",
            Self::Address { domain, .. } => domain,
        }
    }

    /// The domain to deliver a **domainless** `postmaster` to: the local name
    /// this server was configured with (its greeting hostname).
    ///
    /// `None` for every other path — an address that already has a domain
    /// keeps it, and the null path has nowhere to go. A mismatch with the
    /// configured host is a plain unknown mailbox rather than a second
    /// acceptance: the name in the greeting is the host's own, which is what
    /// "the postmaster of this server" means.
    #[must_use]
    pub fn postmaster_domain(&self) -> Option<&str> {
        match self {
            Self::Address { domain, .. }
                if domain.is_empty() && self.local().eq_ignore_ascii_case(POSTMASTER) =>
            {
                Some("")
            }
            _ => None,
        }
    }
}

impl fmt::Display for Mailbox {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self == &Self::Null {
            f.write_str("<>")
        } else {
            write!(f, "<{}>", self.as_text())
        }
    }
}

/// Why a path is not a usable mailbox.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum MailboxError {
    /// No `@` between the angle brackets.
    #[error("path has no `@`")]
    MissingAt,
    /// More than one `@` in the address proper.
    #[error("path has more than one `@`")]
    MultipleAt,
    /// Empty local part or domain.
    #[error("path has an empty local part or domain")]
    EmptyPart,
    /// A character that never appears in an unquoted SMTP mailbox.
    #[error("path contains an illegal character")]
    IllegalCharacter,
    /// A control octet (including CR/LF).
    #[error("path contains a control character")]
    Control,
    /// Non-ASCII octets without SMTPUTF8.
    #[error("path needs SMTPUTF8")]
    NoUtf8,
    /// The domain is not a dotted label sequence.
    #[error("path domain is malformed")]
    MalformedDomain,
    /// Over the RFC 5321 length limits (64 / 254 octets).
    #[error("path is too long")]
    TooLong,
    /// An obsolete source route that does not parse.
    #[error("path source route is malformed")]
    MalformedRoute,
    /// `postmaster@postmaster`: a reserved local name as a domain, which
    /// cannot be what the client meant for any recipient it could reach.
    #[error("path names the reserved postmaster mailbox as a domain")]
    AmbiguousPostmaster,
}

/// A source-route relay: a dotted label sequence written without the `@`.
fn is_relay(relay: &str) -> bool {
    // RFC 5321 §4.1.2 writes a hop as `@ domain`, and the path's own leading
    // `@` is already stripped when the hops are split, so the first hop has
    // no `@` and every later one does. Both spellings are the same hop.
    let domain = relay.strip_prefix('@').unwrap_or(relay);
    !domain.contains(':') && !domain.contains('@') && is_atext_domain(domain)
}

/// Dotted-label check: letters, digits, `-` and `.`, no leading/trailing dot
/// or hyphen per label. Non-ASCII is allowed for SMTPUTF8 domains (RFC 6531
/// leaves them to the punycode layer; this layer does not resolve names).
fn is_atext_domain(domain: &str) -> bool {
    if domain.is_empty() || domain.len() > 253 {
        return false;
    }
    domain.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .chars()
                .all(|ch| ch.is_alphanumeric() || ch == '-' || !ch.is_ascii())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(text: &str) -> Mailbox {
        Mailbox::parse(text, false).expect("fixture address")
    }

    #[test]
    fn source_route_hops_may_omit_the_at() {
        assert!(is_relay("relay.example.org"));
        assert!(is_relay("@relay2.example.org"));
        assert!(!is_relay("@"));
        assert!(!is_relay("relay:25"));
    }

    #[test]
    fn null_path_is_its_own_value() {
        assert_eq!(Mailbox::parse("", false), Ok(Mailbox::Null));
        assert_eq!(Mailbox::Null.to_string(), "<>");
    }

    #[test]
    fn plain_address_round_trips() {
        assert_eq!(addr("ops@example.com").as_text(), "ops@example.com");
    }

    #[test]
    fn address_literal_and_bare_ip_are_not_mailboxes() {
        // A domain literal is never a local mailbox: the brackets are refused
        // outright, which is checked on every path, not only for RELAY.
        assert_eq!(
            Mailbox::parse("user@[192.0.2.1]", false),
            Err(MailboxError::IllegalCharacter)
        );
        assert_eq!(
            Mailbox::parse("user@[IPv6:::1]", false),
            Err(MailboxError::IllegalCharacter)
        );
        // A dotted-quad domain is syntactically a label sequence; refusing to
        // relay it is the router's job (`Address::parse`), not this layer's.
        assert!(Mailbox::parse("user@192.0.2.1", false).is_ok());
    }

    #[test]
    fn source_route_is_stripped_but_flagged() {
        // RFC 5321 §4.1.2: the path's own `@`, then the hops, then
        // `:local@domain`.
        let mailbox = addr("@relay.example.org,@relay2.example.org:user@example.com");
        assert_eq!(mailbox.as_text(), "user@example.com");
        match mailbox {
            Mailbox::Address { routed, .. } => assert!(routed),
            Mailbox::Null => panic!("expected an address"),
        }
        // A single hop may omit its `@` — it is the one the path's own `@`
        // introduced.
        assert!(matches!(
            addr("@relay.example.org:user@example.com"),
            Mailbox::Address { routed: true, .. }
        ));
        // A route with no address after it, or a hop that is not a domain, is
        // malformed.
        assert_eq!(
            Mailbox::parse("@relay.example.org:", false),
            Ok(Mailbox::Null),
            "an empty path after the route is the null path"
        );
        assert_eq!(
            Mailbox::parse("@relay:25:user@example.com", false),
            Err(MailboxError::IllegalCharacter),
            "`relay` with no dot is not a hop, and `relay:25` is no domain"
        );
        // And the route is optional: a bare `local@domain` stays unrouted.
        assert!(matches!(
            addr("user@example.com"),
            Mailbox::Address { routed: false, .. }
        ));
    }

    #[test]
    fn utf8_requires_the_switch() {
        assert_eq!(
            Mailbox::parse("用户@例子.测试", false),
            Err(MailboxError::NoUtf8)
        );
        let mailbox = Mailbox::parse("用户@例子.测试", true).expect("utf8 address");
        assert_eq!(mailbox.domain(), "例子.测试");
    }

    #[test]
    fn only_postmaster_may_have_no_domain() {
        // RFC 5321 §4.1.3: every server accepts `RCPT TO:<Postmaster>`.
        for spelling in ["postmaster", "Postmaster", "POSTMASTER", "PostMaster"] {
            let mailbox = Mailbox::parse(spelling, false).expect("bare postmaster");
            assert_eq!(mailbox.local(), "postmaster");
            assert_eq!(mailbox.domain(), "", "the bare form has no domain");
            assert_eq!(
                mailbox.postmaster_domain(),
                Some(""),
                "it is the postmaster of whichever server was talked to"
            );
            assert_eq!(mailbox.as_text(), "postmaster");
        }
        // Nobody else is exempt.
        for spelling in [
            "other",
            "postmasterx",
            "postmaster.example",
            "x-postmaster",
            "root",
        ] {
            assert_eq!(
                Mailbox::parse(spelling, false),
                Err(MailboxError::MissingAt),
                "{spelling} has no domain and is not the postmaster"
            );
        }
        // A qualified postmaster keeps its domain, whatever the domain is.
        let qualified = addr("postmaster@example.com");
        assert_eq!(qualified.domain(), "example.com");
        assert_eq!(qualified.postmaster_domain(), None);
        // `postmaster@postmaster` names the reserved mailbox *as* a domain:
        // it cannot mean a mailbox on a reachable host.
        assert_eq!(
            Mailbox::parse("postmaster@postmaster", false),
            Err(MailboxError::AmbiguousPostmaster)
        );
    }

    #[test]
    fn injections_are_refused() {
        assert_eq!(Mailbox::parse("a@b x", false), Err(MailboxError::Control));
        assert_eq!(
            Mailbox::parse("a@b\u{0}", false),
            Err(MailboxError::Control),
            "a NUL is a control octet even when it is the last one"
        );
        assert_eq!(
            Mailbox::parse("a@b com", false),
            Err(MailboxError::Control),
            "an interior blank is refused before the alphabet is consulted"
        );
        assert_eq!(
            Mailbox::parse("<a@b>", false),
            Err(MailboxError::IllegalCharacter)
        );
        assert_eq!(Mailbox::parse("a@@b", false), Err(MailboxError::MultipleAt));
        assert_eq!(
            Mailbox::parse(&format!("{}@b", "x".repeat(100)), false),
            Err(MailboxError::TooLong)
        );
    }
}
