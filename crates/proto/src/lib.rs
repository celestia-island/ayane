//! Wire types shared by the ayane service, the routing policy layer and the
//! configuration renderers.
//!
//! Everything in this crate is plain data plus its validation rules: no I/O,
//! no clocks, no environment access. The renderers in `ayane-engine` and the
//! policy in `ayane-mail` both consume [`DesiredState`], so a single validated
//! snapshot drives every generated configuration file.

use std::fmt;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Why a raw string is not a usable mail address.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AddressError {
    /// The string contains no `@`.
    #[error("address has no `@`")]
    MissingAt,
    /// The string contains more than one `@`.
    #[error("address contains more than one `@`")]
    MultipleAt,
    /// The local part or the domain is empty.
    #[error("address has an empty local part or domain")]
    EmptyPart,
    /// A character outside the ASCII mailbox/domain alphabet was found.
    #[error("address contains an unsupported character: {0:?}")]
    IllegalCharacter(char),
    /// A domain label is malformed (empty, leading/trailing dot or dash).
    #[error("address domain is malformed")]
    MalformedDomain,
    /// The address exceeds the SMTP length limits (64 / 254 octets).
    #[error("address is too long")]
    TooLong,
}

/// A bare e-mail address, normalised to lower case.
///
/// The type only accepts the plain `local@domain` form. Display names, quoted
/// local parts and non-ASCII (SMTPUTF8) addresses are rejected on purpose: the
/// generated Postfix maps must never contain a newline or a colon, and SMTPUTF8
/// is a separate decision that would have to be made for every map at once.
///
/// Construction goes through [`Address::parse`] (or serde), so any [`Address`]
/// value is safe to interpolate into a single-line map.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Address(String);

impl Address {
    /// Parse and normalise an address.
    ///
    /// # Errors
    ///
    /// Returns [`AddressError`] when the input is not a bare `local@domain`
    /// address within the SMTP length limits.
    pub fn parse(raw: &str) -> Result<Self, AddressError> {
        let raw = raw.trim();
        if raw.len() > 254 {
            return Err(AddressError::TooLong);
        }
        let (local, domain) = match raw.split_once('@') {
            Some(parts) => parts,
            None => return Err(AddressError::MissingAt),
        };
        if domain.contains('@') {
            return Err(AddressError::MultipleAt);
        }
        if local.is_empty() || domain.is_empty() {
            return Err(AddressError::EmptyPart);
        }
        if local.len() > 64 {
            return Err(AddressError::TooLong);
        }
        for ch in local.chars() {
            let allowed = ch.is_ascii_alphanumeric() || "!#$%&'*+-/=?^_`{|}~.".contains(ch);
            if !allowed {
                return Err(AddressError::IllegalCharacter(ch));
            }
        }
        validate_domain(domain)?;
        Ok(Self(format!(
            "{}@{}",
            local.to_ascii_lowercase(),
            domain.to_ascii_lowercase()
        )))
    }

    /// The normalised address.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The domain part, normalised to lower case.
    #[must_use]
    pub fn domain(&self) -> &str {
        self.0.split_once('@').map_or("", |(_, domain)| domain)
    }

    /// The local part, normalised to lower case.
    #[must_use]
    pub fn local(&self) -> &str {
        self.0.split_once('@').map_or(&self.0, |(local, _)| local)
    }

    /// The address with any `+tag` subaddress removed, if it has one.
    ///
    /// Postfix runs with `recipient_delimiter = +`, so `ops+alerts@example.com`
    /// is delivered to `ops@example.com` unless the base address does not exist.
    #[must_use]
    pub fn without_subaddress(&self) -> Option<Self> {
        let (local, domain) = self.0.split_once('@')?;
        let (base, _tag) = local.split_once('+')?;
        if base.is_empty() {
            return None;
        }
        Some(Self(format!("{base}@{domain}")))
    }

    /// The address with every `.` removed from its local part
    /// (`a.b.c@d` → `abc@d`), the domain untouched.
    ///
    /// This is the Gmail convention that a mailbox may be written with dots
    /// anywhere in its local part. Folding is idempotent, so a caller can
    /// compare [`fold_dots`](Self::fold_dots) against a stored primary
    /// address to decide whether the input is a dot variant of it. With no
    /// dot in the local part the address is unchanged.
    ///
    /// A local part made of dots alone folds to an empty one; that form is
    /// never a valid variant (the folded value is only ever compared against
    /// a stored primary address, which always has a real local part), so the
    /// callers treat it as "not this mailbox" rather than call it an address.
    #[must_use]
    pub fn fold_dots(&self) -> Self {
        let (local, domain) = self.split_domain();
        Self(format!(
            "{}@{domain}",
            local.chars().filter(|ch| *ch != '.').collect::<String>()
        ))
    }

    /// The address with its local part cut at the **first** `+`
    /// (`a+b+c@d` → `a@d`, `a+@d` → `a@d`), the domain untouched.
    ///
    /// Unlike [`without_subaddress`](Self::without_subaddress) this keeps a
    /// bare `a+` (an empty tag) folding to `a`, because the tag is the
    /// caller's to ignore: what matters is the base mailbox in front of it.
    /// An address with no `+` folds to itself.
    #[must_use]
    pub fn strip_plus(&self) -> Self {
        let (local, domain) = self.split_domain();
        let base = local.split_once('+').map_or(local, |(base, _tag)| base);
        Self(format!("{base}@{domain}"))
    }

    /// The two halves of the stored address, split at its single `@`.
    fn split_domain(&self) -> (&str, &str) {
        self.0
            .split_once('@')
            .map_or((self.0.as_str(), ""), |(local, domain)| (local, domain))
    }
}

/// Validate a standalone domain name (policy rules, hosted domains).
///
/// # Errors
///
/// Returns [`AddressError::MalformedDomain`] on empty/oversized/mislabelled
/// input and [`AddressError::IllegalCharacter`] on anything outside ASCII
/// alphanumerics, hyphens and dots — the exact character set the postfix
/// access-map renderer interpolates, so a rule can never inject a line.
pub fn check_domain(domain: &str) -> Result<(), AddressError> {
    validate_domain(domain)
}

fn validate_domain(domain: &str) -> Result<(), AddressError> {
    if domain.len() > 253 || domain.starts_with('.') || domain.ends_with('.') {
        return Err(AddressError::MalformedDomain);
    }
    for label in domain.split('.') {
        if label.is_empty() || label.starts_with('-') || label.ends_with('-') {
            return Err(AddressError::MalformedDomain);
        }
        for ch in label.chars() {
            if !(ch.is_ascii_alphanumeric() || ch == '-') {
                return Err(AddressError::IllegalCharacter(ch));
            }
        }
    }
    Ok(())
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<String> for Address {
    type Error = AddressError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(&value)
    }
}

impl From<Address> for String {
    fn from(value: Address) -> Self {
        value.0
    }
}

/// A sender matched by the recipient policy.
///
/// Rules are either a full address (`ops@partner.example`) or a whole domain
/// (`partner.example`, which also matches every subdomain).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SenderRule {
    /// Exact sender address.
    Address(Address),
    /// Whole domain and its subdomains.
    Domain(String),
}

impl SenderRule {
    /// Whether this rule matches `sender`.
    #[must_use]
    pub fn matches(&self, sender: &Address) -> bool {
        match self {
            Self::Address(address) => address == sender,
            Self::Domain(domain) => {
                let sender_domain = sender.domain();
                sender_domain == domain
                    || sender_domain
                        .strip_suffix(domain.as_str())
                        .is_some_and(|prefix| prefix.ends_with('.'))
            }
        }
    }
}

/// What to do with a message for an unknown recipient in a domain without a
/// catch-all.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DefaultAction {
    /// Hold the message in the quarantine mailbox and notify the operator.
    Quarantine,
    /// Reject the message during the SMTP transaction (the default: fail
    /// closed, never silently black-hole mail).
    #[default]
    Reject,
}

/// Message audit configuration: fixed keyword matches plus an optional AI
/// pass. The AI leg speaks ONLY the org's arona panel — no other provider
/// is wired, on purpose (the mail service stays inside the family's AI
/// perimeter).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditConfig {
    /// Master switch for the whole audit surface.
    #[serde(default)]
    pub enabled: bool,
    /// Literal keywords (matched case-insensitively against subject and
    /// body) that flag a message.
    #[serde(default)]
    pub keywords: Vec<String>,
    /// The AI pass through arona.
    #[serde(default)]
    pub ai: AuditAiConfig,
}

/// The arona-backed AI audit leg.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditAiConfig {
    /// Master switch for the AI leg (still gated by `audit.enabled`).
    #[serde(default)]
    pub enabled: bool,
    /// arona base URL, e.g. `https://arona.example.org`.
    #[serde(default)]
    pub endpoint: String,
    /// Model id requested from arona.
    #[serde(default)]
    pub model: String,
    /// Bearer token for arona. Lives only in the server's state store
    /// (0600 redb); never enters a git tree.
    #[serde(default)]
    pub api_token: String,
}

/// MCP tool-surface configuration: which JSON-RPC methods the `/api/mcp`
/// proxy exposes, and the bearer token callers must present.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpConfig {
    /// Methods exposed on `/api/mcp` (absent = none exposed).
    #[serde(default)]
    pub tools: Vec<String>,
    /// Bearer token for MCP callers; regenerated only through the admin
    /// surface (shown once). Empty disables the proxy entirely.
    #[serde(default)]
    pub token: String,
}

/// The Gmail-style address variants the administrator may allow, split into
/// four independent switches: receiving and sending, dots and plus tags.
///
/// Every switch defaults to off, so a policy stored before this type existed
/// renders exactly the configuration it rendered before.
///
/// The two inbound switches have no say in *which* mailbox a variant reaches —
/// the aliasing machinery in `ayane-engine` decides that — and the two
/// outbound switches gate which From addresses a mailbox session may send as
/// (see `ayane`'s send-identity resolver). They are kept together because an
/// administrator reasons about them as one table.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AddressVariants {
    /// Inbound: dots inside the local part fold to the dot-less mailbox
    /// (`a.b.c@d` is delivered to `abc@d`).
    #[serde(default)]
    pub inbound_dots: bool,
    /// Inbound: a `+tag` suffix is stripped to the base mailbox
    /// (`a+tag@d` is delivered to `a@d`).
    #[serde(default)]
    pub inbound_plus: bool,
    /// Outbound: a user may send From their own address with dots inserted.
    #[serde(default)]
    pub outbound_dots: bool,
    /// Outbound: a user may send From their own address with a `+tag`.
    #[serde(default)]
    pub outbound_plus: bool,
}

impl AddressVariants {
    /// Whether any inbound variant is enabled (the engine's gate for the
    /// Postfix variant map).
    #[must_use]
    pub fn any_inbound(&self) -> bool {
        self.inbound_dots || self.inbound_plus
    }

    /// Whether any outbound variant is enabled (the send-identity gate).
    #[must_use]
    pub fn any_outbound(&self) -> bool {
        self.outbound_dots || self.outbound_plus
    }
}

/// Recipient policy for unknown recipients.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Policy {
    /// What happens when a domain has no catch-all and the recipient does not
    /// exist.
    pub default_action: DefaultAction,
    /// When non-empty, catch-all delivery only accepts mail from these senders;
    /// everything else is quarantined.
    pub allowlist: Vec<SenderRule>,
    /// Senders that are rejected before any other rule runs.
    pub denylist: Vec<SenderRule>,
    /// Gmail-style address variants (dots and `+tag`, inbound and outbound).
    /// Defaults to every switch off, so states stored before the field
    /// existed keep their exact behaviour.
    #[serde(default)]
    pub variants: AddressVariants,
}

/// A hosted mail domain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MailDomain {
    /// Domain name, lower case (`example.com`).
    pub name: String,
    /// Optional catch-all destination for unknown local parts.
    pub catch_all: Option<Address>,
    /// Disabled domains keep their data but stop accepting mail.
    pub enabled: bool,
}

/// A regular mailbox.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Account {
    /// Stable identifier referenced by shared mailboxes.
    pub id: Uuid,
    /// Primary address.
    pub address: Address,
    /// Display name used in headers and the webmail.
    pub display_name: String,
    /// Mailbox quota in bytes; `0` means unlimited.
    pub quota_bytes: u64,
    /// Whether this account may administer the service (admin sessions).
    /// Defaults false for states stored before the field existed.
    #[serde(default)]
    pub admin: bool,
}

/// A forwarding rule that does not keep a local copy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Alias {
    /// Address that receives the mail.
    pub source: Address,
    /// Where the mail is forwarded to. External targets are allowed.
    pub targets: Vec<Address>,
}

/// A mailbox several people can open.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SharedMailbox {
    /// Stable identifier.
    pub id: Uuid,
    /// Shared address.
    pub address: Address,
    /// Accounts that may open it.
    pub members: Vec<Uuid>,
}

/// Why a [`DesiredState`] cannot be rendered.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StateError {
    /// Two objects claim the same address.
    #[error("address `{0}` is claimed more than once")]
    DuplicateAddress(String),
    /// A domain referenced by an object is not hosted.
    #[error("domain `{0}` is not hosted by this instance")]
    UnknownDomain(String),
    /// A catch-all points outside its own domain.
    #[error("catch-all `{0}` must belong to its own domain")]
    ForeignCatchAll(String),
    /// A shared mailbox has no members.
    #[error("shared mailbox `{0}` has no members")]
    EmptySharedMailbox(String),
    /// A shared mailbox is the alias source or the catch-all of a domain.
    ///
    /// This is **not** a validation failure: an address that is both is
    /// ambiguous (an alias keeps no local copy, a shared mailbox is delivered
    /// locally, a catch-all names a mailbox), but refusing the state would
    /// block a deployment that already holds one — the address is real, and
    /// the operator's data is not this layer's to refuse. It is reported by
    /// [`DesiredState::warnings`], and `ayane_mail::route` resolves it in a
    /// fixed, documented order (a shared mailbox wins over an alias, an alias
    /// over the catch-all) so the same state always delivers the same way.
    #[error("shared mailbox `{0}` is also an alias source or a catch-all")]
    SharedMailboxConflict(String),
    /// A hosted domain name is not a valid DNS name.
    #[error("hosted domain is malformed: {0}")]
    MalformedDomain(String),
}

/// The full desired configuration of one instance.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DesiredState {
    /// Hosted domains.
    pub domains: Vec<MailDomain>,
    /// Regular mailboxes.
    pub accounts: Vec<Account>,
    /// Forwarding rules.
    pub aliases: Vec<Alias>,
    /// Shared mailboxes.
    pub shared: Vec<SharedMailbox>,
    /// Recipient policy.
    pub policy: Policy,
    /// Message audit configuration (keyword + AI through arona).
    #[serde(default)]
    pub audit: AuditConfig,
    /// MCP tool-surface configuration.
    #[serde(default)]
    pub mcp: McpConfig,
}

impl DesiredState {
    /// Validate the snapshot before anything is rendered or written.
    ///
    /// # Errors
    ///
    /// Returns [`StateError`] on duplicate addresses, unknown domains or an
    /// unusable catch-all / shared mailbox.
    pub fn validate(&self) -> Result<(), StateError> {
        let mut seen = std::collections::HashSet::new();
        // Policy rule domains reach the postfix access-map renderer raw;
        // validate() is the REST path's only guard, so it enforces the
        // same DNS character law the ws policy editor does.
        for rule in self
            .policy
            .allowlist
            .iter()
            .chain(self.policy.denylist.iter())
        {
            if let SenderRule::Domain(domain) = rule {
                if let Err(error) = check_domain(domain) {
                    return Err(StateError::DuplicateAddress(format!(
                        "policy domain rule rejected: {error}"
                    )));
                }
            }
        }
        for domain in &self.domains {
            // A hosted domain name is interpolated into DNS records, Postfix
            // mailbox maps and the variant regexp table; validate() is the
            // only guard on the REST / ws write paths.
            if let Err(error) = check_domain(&domain.name) {
                return Err(StateError::MalformedDomain(format!(
                    "{}: {error}",
                    domain.name
                )));
            }
            if !seen.insert(format!("@{}", domain.name)) {
                return Err(StateError::DuplicateAddress(domain.name.clone()));
            }
        }
        // An address one object claims twice. `route` answers one `Route` per
        // recipient, so an address that is both a shared mailbox (local) and
        // an alias source (forwarded away), or a catch-all, has to be resolved
        // somewhere. It is resolved in `ayane_mail::route` (shared > alias >
        // catch-all, fixed and tested) and reported here — refusing the state
        // would block a deployment that already holds one, and the operator's
        // data is not this layer's to refuse.
        for shared in &self.shared {
            let also_forwarded = self
                .aliases
                .iter()
                .any(|alias| alias.source == shared.address);
            let also_catch_all = self.domains.iter().any(|domain| {
                domain
                    .catch_all
                    .as_ref()
                    .is_some_and(|catch_all| *catch_all == shared.address)
            });
            // Reported by `warnings`, never refused (see the variant).
            let _ = (also_forwarded, also_catch_all);
        }
        for address in self.addresses() {
            if !seen.insert(address.to_string()) {
                // A shared mailbox claimed twice is the one duplicate that is
                // a warning rather than a refusal: it is exactly the shape of
                // `SharedMailboxConflict`, and `route` has a fixed answer for
                // it (the shared mailbox wins). Everything else can be claimed
                // by only one object.
                if self.is_shared_only_duplicate(address) {
                    continue;
                }
                return Err(StateError::DuplicateAddress(address.to_string()));
            }
        }
        for domain in &self.domains {
            if let Some(catch_all) = &domain.catch_all {
                if catch_all.domain() != domain.name {
                    return Err(StateError::ForeignCatchAll(catch_all.to_string()));
                }
                if !seen.contains(&format!("@{}", catch_all.domain())) {
                    return Err(StateError::UnknownDomain(catch_all.domain().to_owned()));
                }
            }
        }
        for shared in &self.shared {
            if shared.members.is_empty() {
                return Err(StateError::EmptySharedMailbox(shared.address.to_string()));
            }
            if !seen.contains(&format!("@{}", shared.address.domain())) {
                return Err(StateError::UnknownDomain(
                    shared.address.domain().to_owned(),
                ));
            }
        }
        for account in &self.accounts {
            if !seen.contains(&format!("@{}", account.address.domain())) {
                return Err(StateError::UnknownDomain(
                    account.address.domain().to_owned(),
                ));
            }
        }
        for alias in &self.aliases {
            if !seen.contains(&format!("@{}", alias.source.domain())) {
                return Err(StateError::UnknownDomain(alias.source.domain().to_owned()));
            }
        }
        Ok(())
    }

    /// Whether `address` is claimed more than once solely because a shared
    /// mailbox is also an alias source or a catch-all — the ambiguity
    /// [`DesiredState::warnings`] reports instead of refusing.
    fn is_shared_only_duplicate(&self, address: &Address) -> bool {
        let shared = self.shared.iter().any(|entry| entry.address == *address);
        let conflicting = self.aliases.iter().any(|alias| alias.source == *address)
            || self.domains.iter().any(|domain| {
                domain
                    .catch_all
                    .as_ref()
                    .is_some_and(|catch_all| catch_all == address)
            });
        let account = self.accounts.iter().any(|entry| entry.address == *address);
        shared && conflicting && !account
    }

    /// Everything wrong with this state that does **not** stop it from
    /// working: conditions the operator should know about, which the renderers
    /// and the delivery path already resolve in a fixed way.
    ///
    /// It exists because [`DesiredState::validate`] has to stay the gate that
    /// refuses states that cannot be rendered or served, while a deployment
    /// that already holds an ambiguous object must keep working. A warning is
    /// therefore always something the rest of the stack has a documented
    /// answer for — currently one: a shared mailbox that is also an alias
    /// source or a catch-all (`ayane_mail::route` picks the shared mailbox).
    #[must_use]
    pub fn warnings(&self) -> Vec<StateError> {
        let mut out = Vec::new();
        for shared in &self.shared {
            let also_forwarded = self
                .aliases
                .iter()
                .any(|alias| alias.source == shared.address);
            let also_catch_all = self.domains.iter().any(|domain| {
                domain
                    .catch_all
                    .as_ref()
                    .is_some_and(|catch_all| *catch_all == shared.address)
            });
            if also_forwarded || also_catch_all {
                out.push(StateError::SharedMailboxConflict(
                    shared.address.to_string(),
                ));
            }
        }
        out
    }

    fn addresses(&self) -> impl Iterator<Item = &Address> {
        self.accounts
            .iter()
            .map(|account| &account.address)
            .chain(self.shared.iter().map(|shared| &shared.address))
            .chain(self.aliases.iter().map(|alias| &alias.source))
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalises_case() {
        let address = Address::parse("Ops.Team@Example.COM").expect("address");
        assert_eq!(address.as_str(), "ops.team@example.com");
        assert_eq!(address.local(), "ops.team");
        assert_eq!(address.domain(), "example.com");
    }

    #[test]
    fn rejects_unusable_forms() {
        for raw in [
            "",
            "no-at-sign",
            "two@at@example.com",
            "@example.com",
            "user@",
            "user name@example.com",
            "user@example..com",
            "user@-example.com",
            "user@example.com.",
            "user\r\n@example.com",
        ] {
            assert!(
                Address::parse(raw).is_err(),
                "`{raw}` must be rejected as an address"
            );
        }
    }

    #[test]
    fn strips_subaddresses() {
        let address = Address::parse("ops+alerts@example.com").expect("address");
        assert_eq!(
            address.without_subaddress().map(|base| base.to_string()),
            Some("ops@example.com".to_owned())
        );
        let plain = Address::parse("ops@example.com").expect("address");
        assert!(plain.without_subaddress().is_none());
    }

    #[test]
    fn domain_rules_match_whole_labels_only() {
        let rule = SenderRule::Domain("spam.example".to_owned());
        assert!(rule.matches(&Address::parse("bot@spam.example").expect("addr")));
        assert!(rule.matches(&Address::parse("bot@mail.spam.example").expect("addr")));
        assert!(!rule.matches(&Address::parse("bot@notspam.example").expect("addr")));
    }

    #[test]
    fn serde_rejects_the_same_inputs_as_parse() {
        let parsed: Address = serde_json::from_str("\"ops@example.com\"").expect("address");
        assert_eq!(parsed.as_str(), "ops@example.com");
        assert!(serde_json::from_str::<Address>("\"ops@example.com\\r\\nBcc: x@y\"").is_err());
    }

    fn address(raw: &str) -> Address {
        Address::parse(raw).expect("fixture address")
    }

    fn fixture() -> DesiredState {
        DesiredState {
            domains: vec![MailDomain {
                name: "example.com".to_owned(),
                catch_all: Some(address("inbox@example.com")),
                enabled: true,
            }],
            accounts: vec![Account {
                id: Uuid::nil(),
                address: address("inbox@example.com"),
                display_name: "Inbox".to_owned(),
                quota_bytes: 0,
                admin: false,
            }],
            aliases: vec![Alias {
                source: address("sales@example.com"),
                targets: vec![address("inbox@example.com")],
            }],
            shared: vec![SharedMailbox {
                id: Uuid::nil(),
                address: address("team@example.com"),
                members: vec![Uuid::nil()],
            }],
            policy: Policy::default(),

            audit: Default::default(),
            mcp: Default::default(),
        }
    }

    #[test]
    fn validates_a_healthy_state() {
        fixture().validate().expect("state must validate");
    }

    #[test]
    fn rejects_duplicate_addresses() {
        let mut state = fixture();
        state.accounts.push(Account {
            id: Uuid::nil(),
            address: address("inbox@example.com"),
            display_name: "Dup".to_owned(),
            quota_bytes: 0,
            admin: false,
        });
        assert!(matches!(
            state.validate(),
            Err(StateError::DuplicateAddress(_))
        ));
    }

    #[test]
    fn rejects_accounts_in_unhosted_domains() {
        let mut state = fixture();
        state.accounts[0].address = address("inbox@elsewhere.example");
        assert!(matches!(
            state.validate(),
            Err(StateError::UnknownDomain(_))
        ));
    }

    #[test]
    fn rejects_a_catch_all_from_another_domain() {
        let mut state = fixture();
        state.domains[0].catch_all = Some(address("inbox@other.example"));
        assert!(matches!(
            state.validate(),
            Err(StateError::ForeignCatchAll(_))
        ));
    }

    #[test]
    fn rejects_a_shared_mailbox_without_members() {
        let mut state = fixture();
        state.shared[0].members.clear();
        assert!(matches!(
            state.validate(),
            Err(StateError::EmptySharedMailbox(_))
        ));
    }

    #[test]
    fn a_shared_mailbox_that_is_also_an_alias_source_is_a_warning_not_a_refusal() {
        // The address is ambiguous (local delivery versus a forward), but the
        // stack has an answer for it: `route` picks the shared mailbox. A
        // deployment that already holds one must keep loading, so `validate`
        // accepts the state and `warnings` names it.
        let mut state = fixture();
        state.aliases[0].source = address("team@example.com");
        state.validate().expect("an ambiguous address is not fatal");
        let warnings = state.warnings();
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert!(
            matches!(&warnings[0], StateError::SharedMailboxConflict(a) if a == "team@example.com"),
            "{warnings:?}"
        );
    }

    #[test]
    fn a_shared_mailbox_that_is_also_a_catch_all_is_a_warning_not_a_refusal() {
        let mut state = fixture();
        state.domains[0].catch_all = Some(address("team@example.com"));
        state.accounts[0].address = address("other@example.com");
        state.aliases.clear();
        state.validate().expect("an ambiguous address is not fatal");
        assert!(matches!(
            state.warnings().as_slice(),
            [StateError::SharedMailboxConflict(_)]
        ));
    }

    #[test]
    fn a_healthy_state_has_no_warnings() {
        assert!(fixture().warnings().is_empty());
    }

    // ── Gmail-style address variants ──────────────────────────────────────

    #[test]
    fn fold_dots_removes_every_dot_from_the_local_part() {
        for (raw, folded) in [
            ("a.b.c@example.com", "abc@example.com"),
            ("a.b.c.d.e.f@example.com", "abcdef@example.com"),
            (".a@example.com", "a@example.com"),
            ("a.@example.com", "a@example.com"),
            ("abc@example.com", "abc@example.com"),
            ("a.b@example.com", "ab@example.com"),
            // The domain keeps its dots: only the local part folds.
            ("a.b@mail.example.com", "ab@mail.example.com"),
            // A plus tag survives folding; stripping is the other switch.
            ("a.b+tag@example.com", "ab+tag@example.com"),
        ] {
            assert_eq!(address(raw).fold_dots().as_str(), folded, "folding `{raw}`");
        }
    }

    #[test]
    fn fold_dots_is_idempotent_and_self_inverse_on_dotless_input() {
        let dotted = address("jane.doe@example.com");
        let once = dotted.fold_dots();
        assert_eq!(once.clone().fold_dots(), once);
        let plain = address("janedoe@example.com");
        assert_eq!(plain.fold_dots(), plain);
    }

    #[test]
    fn a_local_part_of_dots_only_folds_to_an_empty_local_part() {
        // Not an address any caller accepts as a variant, but the fold itself
        // must be total: callers compare against a real primary address, so an
        // empty local part simply never matches.
        assert_eq!(address("...@example.com").fold_dots().local(), "");
        assert_eq!(address(".@example.com").fold_dots().local(), "");
    }

    #[test]
    fn strip_plus_cuts_at_the_first_plus() {
        for (raw, stripped) in [
            ("a+b@example.com", "a@example.com"),
            ("a+b+c@example.com", "a@example.com"),
            ("a++@example.com", "a@example.com"),
            ("a+@example.com", "a@example.com"),
            ("a@example.com", "a@example.com"),
            // Folding dots is the other switch; stripping leaves them alone.
            ("a.b+tag@example.com", "a.b@example.com"),
            // The domain is never touched, even with a `+` in a label name.
            ("a+tag@plus.example.com", "a@plus.example.com"),
        ] {
            assert_eq!(
                address(raw).strip_plus().as_str(),
                stripped,
                "stripping `{raw}`"
            );
        }
    }

    #[test]
    fn strip_plus_is_idempotent() {
        let once = address("a+b+c@example.com").strip_plus();
        assert_eq!(once.clone().strip_plus(), once);
    }

    #[test]
    fn both_variants_compose_in_either_order() {
        // The order does not matter: dots are removed and the local part is
        // cut at the first `+`.
        let combined = address("a.b+x@example.com");
        assert_eq!(combined.strip_plus().fold_dots().as_str(), "ab@example.com");
        assert_eq!(combined.fold_dots().strip_plus().as_str(), "ab@example.com");
        assert_eq!(
            address("a.b.c+d@example.com").strip_plus().fold_dots(),
            address("abc@example.com")
        );
    }

    #[test]
    fn variants_default_to_off_and_round_trip_through_serde() {
        let policy = Policy::default();
        assert!(!policy.variants.any_inbound());
        assert!(!policy.variants.any_outbound());
        assert_eq!(policy.variants, AddressVariants::default());

        // A policy stored before the field existed reads back with every
        // switch off — no behaviour change for an old snapshot.
        let legacy: Policy =
            serde_json::from_str(r#"{"default_action":"reject","allowlist":[],"denylist":[]}"#)
                .expect("legacy policy");
        assert_eq!(legacy, Policy::default());

        // An absent switch inside a present object is off too.
        let partial: Policy = serde_json::from_str(
            r#"{"default_action":"reject","allowlist":[],"denylist":[],
                "variants":{"inbound_plus":true}}"#,
        )
        .expect("partial policy");
        assert!(partial.variants.inbound_plus);
        assert!(!partial.variants.inbound_dots);
        assert!(!partial.variants.outbound_dots);
        assert!(!partial.variants.outbound_plus);

        let all_on = Policy {
            variants: AddressVariants {
                inbound_dots: true,
                inbound_plus: true,
                outbound_dots: true,
                outbound_plus: true,
            },
            ..Policy::default()
        };
        let json = serde_json::to_string(&all_on).expect("serialize");
        assert!(json.contains("\"inbound_dots\":true"), "{json}");
        let round_trip: Policy = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(round_trip, all_on);
        assert!(round_trip.variants.any_inbound());
        assert!(round_trip.variants.any_outbound());
    }

    #[test]
    fn variants_add_no_validation_constraint() {
        // Every combination of the four booleans validates: they only change
        // how addresses are matched, never what a state may contain.
        for bits in 0u8..16 {
            let mut state = fixture();
            state.policy.variants = AddressVariants {
                inbound_dots: bits & 1 != 0,
                inbound_plus: bits & 2 != 0,
                outbound_dots: bits & 4 != 0,
                outbound_plus: bits & 8 != 0,
            };
            state
                .validate()
                .unwrap_or_else(|e| panic!("combination {bits:04b} rejected: {e}"));
        }
    }
}
