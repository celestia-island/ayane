//! Pure routing and recipient policy.
//!
//! The service never guesses where a message goes: every delivery decision is a
//! function of one validated [`DesiredState`] snapshot plus the SMTP envelope.
//! Keeping this layer free of I/O means the whole matrix — aliases, shared
//! mailboxes, catch-all, allow/deny lists, subaddressing — is unit-testable
//! without a mail server.

use ayane_proto::{Address, AddressVariants, DefaultAction, DesiredState};

pub mod compose;
pub mod mime;
pub mod phishing;

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

/// The precedence between objects that claim the same address.
///
/// [`DesiredState::validate`] does not refuse a state where one address is
/// claimed twice — a deployment that already holds one has to keep working —
/// so this order *is* the answer, and it is fixed rather than incidental:
///
/// ```text
/// account (Mailbox)  >  shared mailbox  >  alias  >  catch-all
/// ```
///
/// - An **account** is the address itself; nothing can outrank it.
/// - A **shared mailbox** is a real mailbox here (its members open it over
///   IMAP), so mail for it must land locally; an alias that would forward it
///   away loses, because forwarding a mailbox's own mail leaves every member
///   with an empty mailbox and a copy somewhere else.
/// - An **alias** is an explicit one-to-many rule and outranks the
///   **catch-all**, which only fires for addresses no object names.
///
/// Each step is checked for *both* the recipient and (when the policy allows
/// `+tag`) its base form before the next step runs, so a shared mailbox
/// spelled `team+alerts@` still beats an alias on `team@`. The order is
/// asserted by `a_shared_mailbox_outranks_an_alias_and_an_alias_outranks_the_catch_all`.
pub const ROUTE_PRECEDENCE: &[&str] = &["account", "shared", "alias", "catch-all"];

/// Decide the route for one SMTP envelope.
///
/// Order of evaluation, which is also the documented policy:
///
/// 1. a sender on the deny list is rejected before anything else;
/// 2. an existing account, shared mailbox or alias wins — in that order, see
///    [`ROUTE_PRECEDENCE`];
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

    // Step by step, not candidate by candidate: the whole candidate list is
    // asked each precedence level before the next level is consulted. That is
    // what makes the order in [`ROUTE_PRECEDENCE`] a property of the router
    // rather than of the order `candidate_recipients` happens to produce.
    let candidates = candidate_recipients(&state.policy.variants, recipient);
    for candidate in &candidates {
        if state
            .accounts
            .iter()
            .any(|account| account.address == *candidate)
        {
            return Route::Mailbox(candidate.clone());
        }
    }
    for candidate in &candidates {
        if state
            .shared
            .iter()
            .any(|shared| shared.address == *candidate)
        {
            return Route::Shared(candidate.clone());
        }
    }
    for candidate in &candidates {
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

/// The recipient itself, then — only when the policy's `inbound_plus` switch
/// is on — its `+tag`-stripped form (Postfix `recipient_delimiter = +`).
///
/// The switch is the single authority over tags on both sides of the service:
/// the rendered Postfix table strips a tag only with the switch on, so this
/// classifier must not pre-strip it either. Without the switch the exact
/// `a+tag@d` key is all there is: an account (nobody names one that way),
/// a shared mailbox or an alias — otherwise the recipient is unknown and
/// takes the catch-all / default action, exactly as the MTA delivers it.
fn candidate_recipients(variants: &AddressVariants, recipient: &Address) -> Vec<Address> {
    let mut candidates = vec![recipient.clone()];
    if variants.inbound_plus {
        if let Some(base) = recipient.without_subaddress() {
            candidates.push(base);
        }
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
                dkim: None,
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
    fn subaddressing_resolves_to_the_base_mailbox_only_with_the_switch_on() {
        // `inbound_plus` is the single authority over tags: the Postfix table
        // strips one only with the switch on, so the classifier must not
        // pre-strip it either.
        let mut state = state_with_catch_all(Vec::new());
        state.policy.variants.inbound_plus = true;
        let folded = route(
            &state,
            &addr("a@b.example"),
            &addr("ops+alerts@example.com"),
        );
        assert_eq!(folded, Route::Mailbox(addr("ops@example.com")));

        // Switch off: the tagged form is not the base mailbox — it is an
        // unknown recipient and reaches the catch-all, exactly as the MTA
        // delivers it.
        let off = state_with_catch_all(Vec::new());
        let unfolded = route(&off, &addr("a@b.example"), &addr("ops+alerts@example.com"));
        assert_eq!(unfolded, Route::CatchAll(addr("inbox@example.com")));
        // …and with no catch-all it is the default action, not `ops`'s box.
        let mut bare = state_with_catch_all(Vec::new());
        bare.domains[0].catch_all = None;
        assert_eq!(
            route(&bare, &addr("a@b.example"), &addr("ops+alerts@example.com")),
            Route::Reject
        );
    }

    #[test]
    fn dots_are_never_stripped_by_the_classifier() {
        // Dot variants are literal rows rendered into the MTA's table; the
        // classifier sees the recipient as written.
        let mut state = state_with_catch_all(Vec::new());
        state.policy.variants.inbound_dots = true;
        assert_eq!(
            route(&state, &addr("a@b.example"), &addr("o.ps@example.com")),
            Route::CatchAll(addr("inbox@example.com"))
        );
    }

    #[test]
    fn shared_mailboxes_resolve_before_catch_all() {
        let state = state_with_catch_all(Vec::new());
        let route = route(&state, &addr("a@b.example"), &addr("team@example.com"));
        assert_eq!(route, Route::Shared(addr("team@example.com")));
    }

    #[test]
    fn a_shared_mailbox_outranks_an_alias_and_an_alias_outranks_the_catch_all() {
        // The whole precedence in one table, because a state may hold all
        // three claims on one address (`validate` reports it as a warning
        // rather than refusing the state) and this is the answer that keeps
        // it working: shared > alias > catch-all.
        let _ = ROUTE_PRECEDENCE;
        let mut state = state_with_catch_all(Vec::new());
        // `team@` is a shared mailbox, an alias source and the catch-all.
        state.domains[0].catch_all = Some(addr("team@example.com"));
        state.aliases.push(ayane_proto::Alias {
            source: addr("team@example.com"),
            targets: vec![addr("elsewhere@other.example")],
        });
        assert_eq!(
            route(&state, &addr("a@b.example"), &addr("team@example.com")),
            Route::Shared(addr("team@example.com")),
            "a shared mailbox is delivered here, never forwarded away"
        );
        // An alias source that is not a shared mailbox beats the catch-all.
        state.aliases.push(ayane_proto::Alias {
            source: addr("list@example.com"),
            targets: vec![addr("elsewhere@other.example")],
        });
        assert_eq!(
            route(&state, &addr("a@b.example"), &addr("list@example.com")),
            Route::Forward(vec![addr("elsewhere@other.example")])
        );
        // …and the catch-all still catches what nothing names.
        assert_eq!(
            route(&state, &addr("a@b.example"), &addr("nobody@example.com")),
            Route::CatchAll(addr("team@example.com"))
        );
    }

    #[test]
    fn an_account_outranks_everything_else_claiming_its_address() {
        let mut state = state_with_catch_all(Vec::new());
        state.domains[0].catch_all = Some(addr("inbox@example.com"));
        state.aliases.push(ayane_proto::Alias {
            source: addr("inbox@example.com"),
            targets: vec![addr("elsewhere@other.example")],
        });
        assert_eq!(
            route(&state, &addr("a@b.example"), &addr("inbox@example.com")),
            Route::Mailbox(addr("inbox@example.com")),
            "the account is the address itself"
        );
    }

    #[test]
    fn a_plus_tagged_shared_mailbox_still_beats_an_alias_on_its_base() {
        // The precedence runs level by level over the *whole* candidate list,
        // so the folded `team@` a `team+alerts@` produces is still looked up
        // as a shared mailbox before any alias is consulted.
        let mut state = state_with_catch_all(Vec::new());
        state.policy.variants.inbound_plus = true;
        state.aliases.push(ayane_proto::Alias {
            source: addr("team@example.com"),
            targets: vec![addr("elsewhere@other.example")],
        });
        assert_eq!(
            route(
                &state,
                &addr("a@b.example"),
                &addr("team+alerts@example.com")
            ),
            Route::Shared(addr("team@example.com"))
        );
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
