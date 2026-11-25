//! Pure routing and recipient policy.
//!
//! The service never guesses where a message goes: every delivery decision is a
//! function of one validated [`DesiredState`] snapshot plus the SMTP envelope.
//! Keeping this layer free of I/O means the whole matrix — aliases, shared
//! mailboxes, catch-all, allow/deny lists, subaddressing — is unit-testable
//! without a mail server.

use ayane_proto::{Address, DefaultAction, DesiredState};

pub mod client;
pub mod compose;
pub mod mime;
pub mod phishing;
pub mod smtp;

/// Where a message for `recipient` should go.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Route {
    /// Deliver into a regular mailbox.
    Mailbox(Address),
    /// Forward to the targets and keep no local copy.
    Forward(Vec<Address>),
    /// Deliver into a shared mailbox (its members open it over IMAP ACL).
    Shared(Address),
    /// Deliver into the domain's catch-all mailbox.
    CatchAll(Address),
    /// Hold the message in quarantine.
    Quarantine,
    /// Reject the message during the SMTP transaction.
    Reject,
}

/// Decide the route for one SMTP envelope.
///
/// Order of evaluation, which is also the documented policy:
///
/// 1. a sender on the deny list is rejected before anything else;
/// 2. an existing account, shared mailbox or alias wins;
/// 3. an unknown recipient in a domain with a catch-all goes to that mailbox —
///    unless the allow list is non-empty and the sender is not on it, in which
///    case the message is quarantined;
/// 4. otherwise the policy's default action applies.
#[must_use]
pub fn route(state: &DesiredState, sender: &Address, recipient: &Address) -> Route {
    if state
        .policy
        .denylist
        .iter()
        .any(|rule| rule.matches(sender))
    {
        return Route::Reject;
    }

    let hosted = state
        .domains
        .iter()
        .any(|domain| domain.enabled && domain.name == recipient.domain());
    if !hosted {
        return Route::Reject;
    }

    let candidates = candidate_recipients(recipient);
    for candidate in &candidates {
        if state
            .accounts
            .iter()
            .any(|account| account.address == *candidate)
        {
            return Route::Mailbox(candidate.clone());
        }
        if state
            .shared
            .iter()
            .any(|shared| shared.address == *candidate)
        {
            return Route::Shared(candidate.clone());
        }
        if let Some(alias) = state
            .aliases
            .iter()
            .find(|alias| alias.source == *candidate)
        {
            return Route::Forward(alias.targets.clone());
        }
    }

    let catch_all = state
        .domains
        .iter()
        .find(|domain| domain.name == recipient.domain())
        .and_then(|domain| domain.catch_all.clone());

    if let Some(target) = catch_all {
        if !state.policy.allowlist.is_empty()
            && !state
                .policy
                .allowlist
                .iter()
                .any(|rule| rule.matches(sender))
        {
            return Route::Quarantine;
        }
        return Route::CatchAll(target);
    }

    match state.policy.default_action {
        DefaultAction::Quarantine => Route::Quarantine,
        DefaultAction::Reject => Route::Reject,
    }
}

/// The recipient itself, then its `+tag`-stripped form (Postfix
/// `recipient_delimiter = +`).
fn candidate_recipients(recipient: &Address) -> Vec<Address> {
    let mut candidates = vec![recipient.clone()];
    if let Some(base) = recipient.without_subaddress() {
        candidates.push(base);
    }
    candidates
}

#[cfg(test)]
mod tests {
    use super::*;
    use ayane_proto::{Account, Alias, MailDomain, Policy, SenderRule, SharedMailbox};
    use uuid::Uuid;

    fn addr(raw: &str) -> Address {
        Address::parse(raw).expect("fixture address")
    }

    fn state_with_catch_all(allowlist: Vec<SenderRule>) -> DesiredState {
        DesiredState {
            domains: vec![MailDomain {
                name: "example.com".to_owned(),
                catch_all: Some(addr("inbox@example.com")),
                enabled: true,
            }],
            accounts: vec![
                Account {
                    id: Uuid::new_v4(),
                    address: addr("inbox@example.com"),
                    display_name: "Inbox".to_owned(),
                    quota_bytes: 0,
                    admin: false,
                },
                Account {
                    id: Uuid::new_v4(),
                    address: addr("ops@example.com"),
                    display_name: "Ops".to_owned(),
                    quota_bytes: 0,
                    admin: false,
                },
            ],
            aliases: vec![Alias {
                source: addr("sales@example.com"),
                targets: vec![addr("ops@example.com")],
            }],
            shared: vec![SharedMailbox {
                id: Uuid::new_v4(),
                address: addr("team@example.com"),
                members: vec![Uuid::new_v4()],
            }],
            policy: Policy {
                default_action: DefaultAction::Reject,
                allowlist,
                denylist: vec![SenderRule::Domain("spam.example".to_owned())],
                variants: Default::default(),
            },
            audit: Default::default(),
            mcp: Default::default(),
        }
    }

    #[test]
    fn explicit_accounts_win() {
        let state = state_with_catch_all(Vec::new());
        let route = route(&state, &addr("a@b.example"), &addr("ops@example.com"));
        assert_eq!(route, Route::Mailbox(addr("ops@example.com")));
    }

    #[test]
    fn subaddressing_resolves_to_the_base_mailbox() {
        let state = state_with_catch_all(Vec::new());
        let route = route(
            &state,
            &addr("a@b.example"),
            &addr("ops+alerts@example.com"),
        );
        assert_eq!(route, Route::Mailbox(addr("ops@example.com")));
    }

    #[test]
    fn shared_mailboxes_resolve_before_catch_all() {
        let state = state_with_catch_all(Vec::new());
        let route = route(&state, &addr("a@b.example"), &addr("team@example.com"));
        assert_eq!(route, Route::Shared(addr("team@example.com")));
    }

    #[test]
    fn aliases_forward_without_a_local_copy() {
        let state = state_with_catch_all(Vec::new());
        let route = route(&state, &addr("a@b.example"), &addr("sales@example.com"));
        assert_eq!(route, Route::Forward(vec![addr("ops@example.com")]));
    }

    #[test]
    fn unknown_recipients_reach_the_catch_all() {
        let state = state_with_catch_all(Vec::new());
        let route = route(&state, &addr("a@b.example"), &addr("whatever@example.com"));
        assert_eq!(route, Route::CatchAll(addr("inbox@example.com")));
    }

    #[test]
    fn denied_senders_are_rejected_before_the_catch_all() {
        let state = state_with_catch_all(Vec::new());
        let route = route(
            &state,
            &addr("bot@spam.example"),
            &addr("whatever@example.com"),
        );
        assert_eq!(route, Route::Reject);
    }

    #[test]
    fn a_non_empty_allow_list_quarantines_unknown_senders() {
        let allow = vec![SenderRule::Domain("partner.example".to_owned())];
        let state = state_with_catch_all(allow);
        let quarantined = route(
            &state,
            &addr("a@other.example"),
            &addr("whatever@example.com"),
        );
        assert_eq!(quarantined, Route::Quarantine);
        let allowed = route(
            &state,
            &addr("a@mail.partner.example"),
            &addr("whatever@example.com"),
        );
        assert_eq!(allowed, Route::CatchAll(addr("inbox@example.com")));
    }

    #[test]
    fn unknown_domains_are_rejected() {
        let state = state_with_catch_all(Vec::new());
        let route = route(&state, &addr("a@b.example"), &addr("ops@elsewhere.example"));
        assert_eq!(route, Route::Reject);
    }

    #[test]
    fn domains_match_only_as_whole_labels() {
        let state = state_with_catch_all(Vec::new());
        let route = route(
            &state,
            &addr("a@notspam.example"),
            &addr("whatever@example.com"),
        );
        assert_eq!(route, Route::CatchAll(addr("inbox@example.com")));
    }
}
