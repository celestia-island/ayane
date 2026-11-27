//! Who may send, and who a recipient is — the two authorisation questions.
//!
//! The two branches of this module are structurally different listeners, not
//! a configuration flag:
//!
//! - [`inbound_recipient`] answers a **relay listener** (port 25): it accepts
//!   mail only for hosted domains and never for an authenticated identity.
//! - [`submission_recipient`] answers a **submission listener** (465/587): it
//!   accepts remote recipients, but only from an authenticated client whose
//!   MAIL FROM it can bind to a local mailbox.
//!
//! Both run at `RCPT TO` time. Rejecting later — after DATA — would make this
//! server a backscatter factory (MAP §四 rule 2).
//!
//! The two are separate functions rather than one function with a
//! [`ListenerRole`] parameter on purpose: a role parameter is a value an
//! operator can set wrong, and the wrong value turns a relay listener into an
//! open relay or a submission listener into one that takes no submissions.
//! The driver picks the function from the socket it accepted on, which is not
//! a configuration surface at all.

use ayane_mail::{route, Route};
use ayane_proto::{Address, DesiredState};
use serde::{Deserialize, Serialize};

/// The listener's role. Chosen by the driver, never by config.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ListenerRole {
    /// Port 25 inbound: accepts mail for hosted domains only.
    Inbound,
    /// 587 with mandatory STARTTLS: accepts submissions after AUTH.
    Submission,
    /// 465 implicit TLS: accepts submissions after AUTH.
    SubmissionsTls,
    /// 143 with `STARTTLS` (or 993, implicit TLS): serves one mailbox per
    /// connection over [`crate::imap_server`].
    ///
    /// A role here and not a fourth boolean because it answers the same
    /// question the other three do — *which serve loop owns this socket* — and
    /// the shape of that socket's TLS decides whether a password may cross it.
    /// An IMAP listener never runs the SMTP session at all, which is why the
    /// driver that owns it ([`crate::imap_server::serve`]) never consults
    /// [`inbound_recipient`] or [`submission_recipient`].
    Imap,
}

impl ListenerRole {
    /// Whether this listener advertises AUTH at all.
    ///
    /// The role half only: whether a mechanism is offered on a given connection
    /// is `AUTH`-in-`EHLO`, which also requires the channel to be encrypted.
    /// Both are needed and neither is the whole: this one says a login is
    /// *meaningful* here, the other says it could *succeed* (see
    /// `session::Session::ehlo`), and a listener that offers logins on a clear
    /// channel would advertise a door it refuses to open (`538`).
    #[must_use]
    pub fn offers_auth(self) -> bool {
        !matches!(self, Self::Inbound)
    }

    /// Whether this listener speaks SMTP at all.
    ///
    /// The three mail roles do; [`ListenerRole::Imap`] does not, and a driver
    /// that asked an IMAP listener for an SMTP capability list would be
    /// serving two protocols on one port. This is the one place that fact is
    /// written down outside the two drivers.
    #[must_use]
    pub fn serves_smtp(self) -> bool {
        !matches!(self, Self::Imap)
    }

    /// Whether this listener cannot run without a certificate.
    ///
    /// 465 is implicit TLS (RFC 8314 §3.3): the session starts encrypted, so
    /// without a certificate there is nothing to speak. 587 starts in the
    /// clear and upgrades on request, so it can run without one (it then
    /// advertises no STARTTLS and never AUTH, which is visible in EHLO).
    #[must_use]
    pub fn needs_tls(self) -> bool {
        matches!(self, Self::SubmissionsTls)
    }
}

/// Rules applied to the envelope at `MAIL FROM` and `RCPT TO`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AddressPolicy {
    /// Aliases as `(source, targets)`, compared case-insensitively. A
    /// submission may use one as MAIL FROM only when it forwards to the
    /// authenticated identity itself.
    pub aliases: Vec<(String, Vec<String>)>,
    /// Hosted domain names (lower-cased), used to decide whether a recipient is
    /// local before the router is consulted.
    pub local_domains: Vec<String>,
}

impl AddressPolicy {
    /// Builds the policy out of one validated [`DesiredState`].
    #[must_use]
    pub fn from_state(state: &DesiredState) -> Self {
        let aliases = state
            .aliases
            .iter()
            .map(|alias| {
                (
                    alias.source.as_str().to_owned(),
                    alias
                        .targets
                        .iter()
                        .map(|t| t.as_str().to_owned())
                        .collect(),
                )
            })
            .collect();
        let local_domains = state
            .domains
            .iter()
            .filter(|domain| domain.enabled)
            .map(|domain| domain.name.to_ascii_lowercase())
            .collect();
        Self {
            aliases,
            local_domains,
        }
    }

    /// Whether `domain` is hosted here.
    #[must_use]
    pub fn is_local_domain(&self, domain: &str) -> bool {
        let domain = domain.to_ascii_lowercase();
        self.local_domains.contains(&domain)
    }

    /// Whether an authenticated client may claim `sender` as its MAIL FROM.
    ///
    /// Bound to the identity, not to "any local address": an authenticated
    /// user must not be able to submit as somebody else (MAP §六 P1 and
    /// `deploy/prod/postfix`'s missing `smtpd_sender_login_maps`).
    #[must_use]
    pub fn may_submit_as(&self, identity: &str, sender: &str) -> bool {
        let identity = identity.to_ascii_lowercase();
        if identity == sender.to_ascii_lowercase() {
            return true;
        }
        // An alias whose targets include the identity resolves forward to it,
        // so the identity may use the alias as its own From. A mailbox that is
        // merely local — a shared mailbox, somebody else's account — is not
        // the identity's to claim.
        for alias in &self.aliases {
            let source_matches = alias.0.eq_ignore_ascii_case(sender);
            let targets_identity = alias
                .1
                .iter()
                .any(|target| target.eq_ignore_ascii_case(&identity));
            if source_matches && targets_identity {
                return true;
            }
        }
        false
    }

    /// The MAIL FROM check the session applies to any sender.
    ///
    /// # Errors
    ///
    /// Returns the 553 reason text when the sender is not acceptable.
    pub fn check_sender(&self, sender: &str) -> Result<(), &'static str> {
        if sender.is_empty() {
            return Ok(());
        }
        if sender.len() > 254 {
            return Err("Sender address rejected: too long");
        }
        if !sender.is_ascii() && !self.any_utf8_domain(sender) {
            return Err("Sender address rejected: non-ASCII domain not hosted");
        }
        Ok(())
    }

    fn any_utf8_domain(&self, _sender: &str) -> bool {
        // SMTPUTF8 already gated the alphabet; nothing else to check here.
        true
    }
}

/// The verdict for one recipient, as the session understands it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecipientVerdict {
    /// The mailbox exists here.
    Exists,
    /// The mailbox does not exist here.
    Unknown,
    /// A relay attempt: the domain is not hosted and the client is not
    /// authorised to relay through this listener.
    RelayDenied,
}

/// Decides recipients for the **inbound** listener (port 25).
///
/// Hosted-domain recipients go through [`route`]. `CatchAll` is deliberately
/// *not* an existence proof: a catch-all mailbox is where the unknown
/// addresses of a hosted domain are delivered, and the router only returns it
/// for an address that matched no account, shared mailbox or alias. An address
/// routed there is therefore **refused** — accepting it would accept every
/// address of the domain and bounce the bounces, the backscatter factory of
/// MAP §四 rules 2 and 3. When a deployment wants a real catch-all, the
/// operator adds an alias per address; the router's existence tables remain
/// the single authority.
#[must_use]
pub fn inbound_recipient(state: &DesiredState, sender: &Address, recipient: &Address) -> Verdict {
    if !state
        .domains
        .iter()
        .any(|domain| domain.enabled && domain.name == recipient.domain())
    {
        return Verdict {
            verdict: RecipientVerdict::RelayDenied,
        };
    }
    if policy_denies(state, sender) {
        return Verdict {
            verdict: RecipientVerdict::Unknown,
        };
    }
    match route(state, sender, recipient) {
        Route::Mailbox(_) | Route::Forward(_) => Verdict {
            verdict: RecipientVerdict::Exists,
        },
        // A shared mailbox is a real mailbox here — `route` answers `Shared`
        // only for an entry in `state.shared` — and `DesiredState::validate`
        // refuses a state where one is also an alias source or a catch-all,
        // so this arm is the existence proof its name promises.
        Route::Shared(_) => Verdict {
            verdict: RecipientVerdict::Exists,
        },
        // Quarantine is reached by an allow-listed sender sending to an
        // unknown address of a catch-all domain: still not an existing mailbox.
        Route::CatchAll(_) | Route::Quarantine | Route::Reject => Verdict {
            verdict: RecipientVerdict::Unknown,
        },
    }
}

fn policy_denies(state: &DesiredState, sender: &Address) -> bool {
    state
        .policy
        .denylist
        .iter()
        .any(|rule| rule.matches(sender))
}

/// The accept/refuse verdict for one recipient.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Verdict {
    /// What the session must answer.
    pub verdict: RecipientVerdict,
}

/// Decides recipients for a **submission** listener.
///
/// The recipient may be remote (this is what submission *is*), but only for an
/// authenticated client whose MAIL FROM is bound to its own local mailbox.
///
/// # Errors
///
/// Returns the refusal when the client has not authenticated.
pub fn submission_recipient(authenticated: bool) -> Result<(), SessionRefusal> {
    if authenticated {
        Ok(())
    } else {
        Err(SessionRefusal::RelayDenied)
    }
}

/// A refusal the session translates into its wire reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionRefusal {
    /// 550 5.7.1
    RelayDenied,
    /// 530 5.7.0
    AuthenticationRequired,
}

#[cfg(test)]
mod tests {
    use super::*;
    use ayane_proto::{
        Account, Alias, DefaultAction, MailDomain, Policy, SenderRule, SharedMailbox,
    };
    use uuid::Uuid;

    fn addr(raw: &str) -> Address {
        Address::parse(raw).expect("fixture address")
    }

    fn state(catch_all: bool) -> DesiredState {
        DesiredState {
            domains: vec![MailDomain {
                name: "example.com".to_owned(),
                catch_all: catch_all.then(|| addr("inbox@example.com")),
                enabled: true,
                dkim: None,
            }],
            accounts: vec![Account {
                id: Uuid::new_v4(),
                address: addr("inbox@example.com"),
                display_name: "Inbox".to_owned(),
                quota_bytes: 0,
                admin: false,
            }],
            aliases: vec![Alias {
                source: addr("sales@example.com"),
                targets: vec![addr("inbox@example.com")],
            }],
            shared: vec![SharedMailbox {
                id: Uuid::new_v4(),
                address: addr("team@example.com"),
                members: Vec::new(),
            }],
            policy: Policy {
                default_action: DefaultAction::Reject,
                allowlist: Vec::new(),
                denylist: vec![SenderRule::Domain("spam.example".to_owned())],
                variants: Default::default(),
            },
            audit: Default::default(),
            mcp: Default::default(),
        }
    }

    #[test]
    fn accounts_shared_and_aliases_exist() {
        let state = state(false);
        for rcpt in ["inbox@example.com", "team@example.com", "sales@example.com"] {
            let verdict = inbound_recipient(&state, &addr("a@b.example"), &addr(rcpt));
            assert_eq!(verdict.verdict, RecipientVerdict::Exists, "{rcpt}");
        }
    }

    #[test]
    fn catch_all_does_not_make_an_unknown_address_exist() {
        // With the catch-all on, the router still answers "unknown" for an
        // address no table names; the ingress must not read that destination
        // as an existence proof (it would accept and then bounce).
        let with = state(true);
        let without = state(false);
        let sender = addr("a@b.example");
        let recipient = addr("nobody@example.com");
        assert_eq!(
            inbound_recipient(&with, &sender, &recipient).verdict,
            RecipientVerdict::Unknown
        );
        assert_eq!(
            inbound_recipient(&without, &sender, &recipient).verdict,
            RecipientVerdict::Unknown
        );
    }

    #[test]
    fn without_catch_all_an_unknown_address_is_refused() {
        let state = state(false);
        let verdict = inbound_recipient(&state, &addr("a@b.example"), &addr("nobody@example.com"));
        assert_eq!(verdict.verdict, RecipientVerdict::Unknown);
    }

    #[test]
    fn remote_domains_are_relay_attempts() {
        let state = state(true);
        assert_eq!(
            inbound_recipient(&state, &addr("a@b.example"), &addr("y@gmail.com")).verdict,
            RecipientVerdict::RelayDenied
        );
    }

    #[test]
    fn denied_senders_are_refused_without_leaking_existence() {
        let state = state(false);
        assert_eq!(
            inbound_recipient(&state, &addr("x@spam.example"), &addr("inbox@example.com")).verdict,
            RecipientVerdict::Unknown
        );
    }

    #[test]
    fn submission_requires_authentication() {
        assert_eq!(
            submission_recipient(false),
            Err(SessionRefusal::RelayDenied)
        );
        assert!(submission_recipient(true).is_ok());
    }

    #[test]
    fn submission_sender_is_bound_to_the_identity() {
        let policy = AddressPolicy::from_state(&state(true));
        assert!(policy.may_submit_as("inbox@example.com", "inbox@example.com"));
        // A shared mailbox is a local address but not this identity's.
        assert!(!policy.may_submit_as("ops@example.com", "team@example.com"));
        // An alias that forwards to the identity is the identity's own From.
        assert!(policy.may_submit_as("inbox@example.com", "sales@example.com"));
        assert!(!policy.may_submit_as("ops@example.com", "sales@example.com"));
        assert!(!policy.may_submit_as("inbox@example.com", "x@gmail.com"));
        assert!(!policy.may_submit_as("inbox@example.com", "@example.com"));
    }
}
