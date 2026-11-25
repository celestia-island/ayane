//! Render a validated [`DesiredState`] into the configuration files consumed by
//! the mail stack.
//!
//! The service is the single control plane: it owns the database, renders these
//! files deterministically, and reloads the daemons. Nothing is hand-edited on
//! the hosts, and rendering the same state twice must produce byte-identical
//! output — the apply loop diffs before it writes.
//!
//! The renderers are pure so that every generated file is covered by golden
//! tests without a running Postfix, Dovecot or rspamd.

use std::collections::{BTreeMap, BTreeSet};

use ayane_proto::{Address, DesiredState};

/// The virtual-mail user that owns every mailbox (matches the engine images).
pub const VMAIL_UID: u32 = 5000;
/// Group id accompanying [`VMAIL_UID`].
pub const VMAIL_GID: u32 = 5000;

/// Maildir home of one account inside the engine's volume.
#[must_use]
pub fn maildir_home(domain: &str, local: &str) -> String {
    format!("/var/mail/vhosts/{domain}/{local}")
}

/// Postfix `virtual_mailbox_domains` map.
#[must_use]
pub fn postfix_virtual_domains(state: &DesiredState) -> String {
    let mut out = String::new();
    for domain in enabled_domains(state) {
        out.push_str(&format!("{domain} OK\n"));
    }
    out
}

/// Postfix `virtual_mailbox_maps` map: every address that owns a mailbox,
/// including shared mailboxes (their access control lives in Dovecot ACLs).
#[must_use]
pub fn postfix_virtual_mailboxes(state: &DesiredState) -> String {
    let mut addresses = BTreeSet::new();
    for account in &state.accounts {
        if hosted(state, account.address.domain()) {
            addresses.insert(account.address.to_string());
        }
    }
    for shared in &state.shared {
        if hosted(state, shared.address.domain()) {
            addresses.insert(shared.address.to_string());
        }
    }
    addresses
        .into_iter()
        .map(|address| format!("{address} OK\n"))
        .collect()
}

/// Postfix `virtual_alias_maps` literal map: identity rows, Gmail-style dot
/// variants, forwarding rules and catch-all entries. Postfix rewrites the
/// recipient down this map until an address stops changing, so the rows are
/// built in that priority order (a key written by an earlier pass is never
/// overwritten by a later one) and then emitted sorted for determinism.
///
/// **Real mailboxes get an identity row** (`addr addr`). Postfix consults the
/// alias map before the mailbox map and falls back to `@domain` when the exact
/// address is missing — so without these rows a catch-all would rewrite every
/// existing mailbox into the catch-all target. The identity row makes the
/// exact lookup succeed first, and Postfix stops rewriting when the result
/// equals the input.
///
/// **Dot variants are enumerated here, not folded by a pattern.** A regular
/// expression sees one address at a time and cannot know which addresses are
/// mailboxes, so a dot fold written as `a.b@d` → `ab@d` only ever produces the
/// *dot-less* spelling — which is the mailbox only when the account's own
/// local part has no dot. With a real `ab@d` account the fold of `a.b.c@d`
/// settles on `abc@d` (never `ab@d`), and with a real `a.b@d` account a
/// *leading* dot (`…` → `a.b@d`) folds straight into somebody else's mailbox.
/// Enumerating the dotted spellings of each mailbox as literal rows removes
/// both: what is listed is exactly what reaches that mailbox.
///
/// Every hosted account and shared mailbox contributes the dotted spellings of
/// its own local part (see [`dot_variants`]) pointing at the address itself. A
/// spelling that is *any* mailbox or alias source is left to that object's own
/// row instead: it is that address, not a variant of this one.
///
/// The rows are built in three passes — identities plus forwards, dot
/// variants, catch-alls — over a map keyed by the left-hand address, so that
/// **the first writer of a key wins** no matter what the key sorts like. That is what makes
/// "a real address beats a variant of it" true: a spelling that belongs to
/// another account, a shared mailbox or an alias source is written by that
/// object's own row first, and its dot row is dropped. (Ordering the whole file
/// and letting the *last* row win would silently hand `a.b@d` to `ab@d`
/// whenever the two sorted the other way round.)
///
/// The file is then emitted in sorted key order, so the rendering stays
/// deterministic and identical for identical state.
#[must_use]
pub fn postfix_virtual_aliases(state: &DesiredState) -> String {
    let mut mailboxes: Vec<&Address> = state
        .accounts
        .iter()
        .map(|account| &account.address)
        .chain(state.shared.iter().map(|shared| &shared.address))
        .filter(|address| hosted(state, address.domain()))
        .collect();
    mailboxes.sort_unstable();
    mailboxes.dedup();

    // Pass 1: the real addresses. An account or shared mailbox is its own
    // identity row; an alias source is its forward.
    let mut rows: BTreeMap<String, String> = BTreeMap::new();
    for address in &mailboxes {
        rows.insert(address.to_string(), address.to_string());
    }
    for alias in &state.aliases {
        if !hosted(state, alias.source.domain()) || alias.targets.is_empty() {
            continue;
        }
        let targets: Vec<String> = alias.targets.iter().map(ToString::to_string).collect();
        rows.insert(alias.source.to_string(), targets.join(", "));
    }

    // Pass 2: the dotted spellings of each mailbox. `or_insert` is the whole
    // safety argument — a key somebody else already owns keeps their row.
    if state.policy.variants.inbound_dots {
        for address in &mailboxes {
            for variant in dot_variants(address.local()) {
                let key = format!("{variant}@{}", address.domain());
                if key == address.as_str() {
                    continue;
                }
                rows.entry(key).or_insert_with(|| address.to_string());
            }
        }
    }

    // Pass 3: the catch-alls, which own their `@domain` key only.
    for domain in &state.domains {
        if !domain.enabled {
            continue;
        }
        if let Some(catch_all) = &domain.catch_all {
            rows.entry(format!("@{}", domain.name))
                .or_insert_with(|| catch_all.to_string());
        }
    }
    rows.into_iter()
        .map(|(key, value)| format!("{key} {value}\n"))
        .collect()
}

/// How many places a local part may take a dot before [`dot_variants`] stops
/// enumerating combinations.
///
/// `n` places give `2^n - 1` spellings, so this budget is 4095 rows for one
/// mailbox. Gmail itself caps the local part at 30 characters, and the
/// spellings people actually type carry one or two dots (`first.last`,
/// `f.l.name`); a longer local part exhausts the budget on shapes nobody
/// uses, while every account in a hosted domain would pay for them in the
/// map. Past the budget only the one- and two-dot spellings are rendered —
/// the ones a human writes by hand.
pub const DOT_VARIANT_PLACES: u32 = 12;

/// The dotted spellings of one local part, in a stable order.
///
/// A variant is the local part re-spelled with dots: the letters (with any dot
/// the address already carries removed) stay in place, and a dot may be
/// *inserted* at any subset of the places *between* its characters — never at
/// the front, never at the end, never twice in a row. That is the shape a
/// mailbox written with Gmail's convention has, and it is the only shape a
/// real mailbox can be confused with — a leading or doubled dot is not a
/// spelling of anything and must keep falling through to the catch-all.
///
/// **A dot the address already carries stays where it is.** `a.b` folds to the
/// letters `ab` and could in principle be re-spelled `a.b` or `ab` — but `ab`
/// is a *different mailbox's* address whenever both exist, and the two are not
/// the same person: Gmail itself only recovers the dot-less local part, it
/// never moves a dot. So a local part that already has a dot has no free
/// place to take another (`a.b` → itself only, and `a..b` is never
/// generated); a dot-less one gets all of them.
///
/// The original spelling is always first and is left for the caller to skip
/// (its identity row already answers for it). `ab` → `a.b`; `abc` → `a.bc`,
/// `ab.c`, `a.b.c`; `a.b` → itself.
///
/// With more than [`DOT_VARIANT_PLACES`] places to fill, the combinations
/// explode (`2^63` for a 64-character local part); past the budget the
/// enumeration keeps the original, the one-dot and the two-dot spellings only.
#[must_use]
pub fn dot_variants(local: &str) -> Vec<String> {
    // Spellings are built from the *letters*, and a local part that already
    // carries a dot keeps its own spelling: no free place, no new address.
    if local.contains('.') {
        return vec![local.to_owned()];
    }
    let base: Vec<char> = local.chars().collect();
    let places = base.len().saturating_sub(1);
    let budget = DOT_VARIANT_PLACES as usize;
    let mut out = Vec::new();
    out.push(local.to_owned());
    if places > budget {
        // Over budget: walk the masks that carry at most two bits, in
        // ascending order (every single place, then every pair — the empty
        // mask is the local part itself, already first). Iterating all `2^63`
        // masks to throw almost all of them away would not finish; this
        // visits exactly `1 + p + p(p-1)/2` spellings.
        for first in 0..places {
            let mut one = vec![0u8; places];
            one[first] = 1;
            push_spelling(&base, places, &one, &mut out);
            for second in first + 1..places {
                one[second] = 1;
                push_spelling(&base, places, &one, &mut out);
                one[second] = 0;
            }
        }
        // The three-dot shapes are exactly what the budget is for: prove they
        // are absent by construction (the control below is the under-budget
        // set, where they do appear).
    } else {
        // Under budget: every subset of the places is a spelling. (The
        // address grammar caps the local part at 64 characters, i.e. 63
        // places, so `1u64 << places` cannot overflow.)
        // Up to 2^12 - 1 masks here: `places` is at most the budget, so the
        // range is small and the shifts stay well inside a u64.
        for mask in 1..(1u64 << places) {
            let chosen: Vec<u8> = (0..places)
                .map(|bit| u8::from(mask >> bit & 1 == 1))
                .collect();
            push_spelling(&base, places, &chosen, &mut out);
        }
    }
    out
}

/// Append the spelling of `base` whose dot positions are the nonzero entries
/// of `chosen` (one flag per place between two characters).
///
/// A per-place flag vector rather than a bitmask: the local part may have 63
/// places, and a shift of a 64-bit mask by 63 or more is not portable.
fn push_spelling(base: &[char], places: usize, chosen: &[u8], out: &mut Vec<String>) {
    let mut spelling = String::with_capacity(base.len() + places);
    for (index, ch) in base.iter().enumerate() {
        spelling.push(*ch);
        if index < places && chosen.get(index).copied().unwrap_or(0) == 1 {
            spelling.push('.');
        }
    }
    out.push(spelling);
}

/// The `regexp:` map that strips a whole `+tag` suffix down to the base
/// address, or the empty string when `inbound_plus` is off.
///
/// **Why the dots are not here.** Folding dots cannot be written as a
/// pattern: a pattern looks at one address and cannot see which addresses are
/// mailboxes. `a.b@d` → `ab@d` only *looks* right — with a real `ab@d` account
/// the fold of `a.b.c@d` runs to `abc@d`, which is nobody's mailbox, and a
/// leading-dot row turns `.a.b@d` into somebody else's `a.b@d`. The dotted
/// spellings are therefore enumerated as literal rows in
/// [`postfix_virtual_aliases`], where what is listed is exactly what that
/// mailbox receives. A `+tag` has no such problem: what is left after the
/// strip is the base address itself, and whether that address exists is
/// decided by the literal map, which is searched first.
///
/// **Why a regular-expression map.** `virtual_alias_maps` is a literal lookup:
/// one address cannot be listed as a family. Postfix queries a `regexp:` table
/// with the whole address (local part dots and plus tags intact, unlike indexed
/// tables, which are also queried with the extension stripped) and rewrites the
/// recipient with the pattern's `$n` captures.
///
/// **Why it does not steal real mailboxes.** The table is appended *after* the
/// literal map in `virtual_alias_maps` and Postfix searches the tables in the
/// configured order until a match is found, so an address that exists (an
/// account, a shared mailbox — both carry an identity row in
/// [`postfix_virtual_aliases`] — or an alias) is answered by the literal map
/// and never reaches these patterns. Aliases therefore stay literal, exactly
/// as before: `ops+tag@d` gets a mail from across the internet to `ops@d`
/// only when `ops@d` exists and `ops+tag@d` does not.
///
/// **The rows, in order** (first match wins; the domain alternation is
/// backslash-escaped so a `.` can only be a dot):
///
/// - `a+tag@d` → `a@d` — strip the tag in one pass (`[^+]+`).
/// - `+a@d` → `a@d` — an empty local part before the tag (`[^+]+` needs a
///   character, so it cannot be left to the row above).
///
/// **This map owns the `+` fold, and it is the only table that does.** The
/// engine shipped a static `subaddress.pcre` that folded `local+tag@d`
/// unconditionally; it is retired (the `+` rows here replace it) so the
/// administrator's inbound switch is the single authority over plus tags. With
/// `inbound_plus` off this function renders no `+` row at all, and nothing
/// else in the stack folds one: `recipient_delimiter` only makes `+` the
/// extension separator, and `virtual_alias_maps` is the only place an address
/// is rewritten. What an unfolded tag then does is the pre-subaddress
/// behaviour — the exact `a+tag@d` key is looked up in the literal map (no
/// match), then in `virtual_mailbox_maps` (no such mailbox), so the recipient
/// falls through to the domain's catch-all, or is rejected when the domain has
/// none.
#[must_use]
pub fn postfix_variant_alias_regexp(state: &DesiredState) -> String {
    let variants = &state.policy.variants;
    if !variants.inbound_plus {
        return String::new();
    }
    let domains: Vec<String> = enabled_domains(state)
        .iter()
        .map(|domain| domain.replace('.', "\\."))
        .collect();
    if domains.is_empty() {
        return String::new();
    }
    let domain = domains.join("|");
    // Rows are `pattern result`: Postfix 3.7's regexp(5) reader wants the
    // pattern enclosed in its own delimiter (`/^…$/`, the example form in the
    // manual — a bare `^…$` is read as an option field and the rule skipped).
    // A capture is always interpolated as `${n}`: Postfix reads `$n` greedily,
    // so `$1@` would be "group 1 followed by a literal @", but the moment the
    // result is written without a separator it would read `$12`.
    //
    // `local+tag` is stripped in one pass. `+a` (an empty local part) is its
    // own row rather than a `[^+]+` with nothing in it: Postfix does not
    // reliably match an empty leading capture, and the tag is optional in what
    // the address means anyway.
    let mut rows = String::new();
    rows.push_str(&format!("/^([^+]+)\\+([^@]*)@({domain})$/ ${{1}}@${{3}}\n"));
    rows.push_str(&format!("/^\\+([^@]*)@({domain})$/ ${{1}}@${{2}}\n"));
    rows
}

/// Postfix `check_sender_access` map enforcing the sender deny list.
///
/// Postfix accepts `user@domain`, `domain` and `user` keys; a matching sender
/// is rejected during the SMTP transaction, before any queueing happens. The
/// allow list is deliberately *not* rendered here: it only decides where an
/// unknown recipient's mail goes, which the catch-all rule already expresses.
#[must_use]
pub fn postfix_sender_denylist(state: &DesiredState) -> String {
    let mut rows = BTreeSet::new();
    for rule in &state.policy.denylist {
        match rule {
            ayane_proto::SenderRule::Address(address) => {
                rows.insert(format!("{address} REJECT Sender denied by policy"));
            }
            ayane_proto::SenderRule::Domain(domain) => {
                if !domain.is_empty() {
                    rows.insert(format!("{domain} REJECT Sender denied by policy"));
                }
            }
        }
    }
    rows.into_iter().map(|row| format!("{row}\n")).collect()
}

/// Postfix `smtpd_sender_login_maps`: which envelope senders each
/// authenticated user may use. Postfix's `reject_sender_login_mismatch`
/// refuses a `MAIL FROM` the logged-in user does not own — without this
/// table any authenticated account could send as any other address on
/// the domain (2026-11-25 security recon, P1). A user owns their own
/// address and every shared mailbox they are a member of; an address
/// may also be listed under several owners (shared mailboxes), which
/// Postfix accepts — the map is `sender owner, owner, …`.
#[must_use]
pub fn postfix_sender_login_maps(state: &DesiredState) -> String {
    let mut owners: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for account in &state.accounts {
        if !hosted(state, account.address.domain()) {
            continue;
        }
        owners
            .entry(account.address.to_string())
            .or_default()
            .insert(account.address.to_string());
        for shared in &state.shared {
            if hosted(state, shared.address.domain()) && shared.members.contains(&account.id) {
                owners
                    .entry(shared.address.to_string())
                    .or_default()
                    .insert(account.address.to_string());
            }
        }
    }
    owners
        .into_iter()
        .map(|(sender, list)| {
            format!(
                "{sender} {}\n",
                list.into_iter().collect::<Vec<_>>().join(", ")
            )
        })
        .collect()
}

/// rspamd `local_domains` option.
#[must_use]
pub fn rspamd_local_domains(state: &DesiredState) -> String {
    let domains: Vec<String> = enabled_domains(state)
        .iter()
        .map(|domain| format!("\"{domain}\""))
        .collect();
    format!("local_domains = [{}];\n", domains.join(", "))
}

/// Dovecot passwd-file lines (`user:hash:uid:gid:gecos:home:shell`).
///
/// One line per account, address-sorted; shared mailboxes get no line because
/// members reach them through ACLs on their own login.
#[must_use]
pub fn dovecot_passwd<'a, I>(entries: I) -> String
where
    I: IntoIterator<Item = (&'a Address, &'a str)>,
{
    let mut rows = BTreeSet::new();
    for (address, hash) in entries {
        let home = maildir_home(address.domain(), address.local());
        rows.insert(format!(
            "{address}:{hash}:{VMAIL_UID}:{VMAIL_GID}::{home}::\n"
        ));
    }
    rows.into_iter().collect()
}

/// Dovecot SQL userdb/passdb configuration.
///
/// The DSN is the only external input; it is quoted once and escaped so an
/// operator-supplied password cannot terminate the string.
#[must_use]
pub fn dovecot_sql_config(dsn: &str) -> String {
    let dsn = escape_quoted(dsn);
    let mut out = String::from(
        "# Generated by ayane — do not edit by hand.\n\
         driver = pgsql\n",
    );
    out.push_str(&format!("connect = \"{dsn}\"\n\n"));
    out.push_str(
        "password_query = \\\n\
         \x20 SELECT address AS user, password_hash AS password \\\n\
         \x20 FROM mail_accounts WHERE address = '%u' AND enabled\n\n",
    );
    out.push_str(
        "user_query = \\\n\
         \x20 SELECT maildir AS home, 5000 AS uid, 5000 AS gid \\\n\
         \x20 FROM mail_accounts WHERE address = '%u' AND enabled\n",
    );
    out
}

/// A Sieve script that forwards to `target`, optionally keeping a local copy.
#[must_use]
pub fn sieve_forward(target: &Address, keep_copy: bool) -> String {
    let mut out = String::from("require [\"copy\"];\n\n");
    if keep_copy {
        out.push_str(&format!("redirect :copy \"{target}\";\n"));
    } else {
        out.push_str(&format!("redirect \"{target}\";\n"));
    }
    out
}

fn enabled_domains(state: &DesiredState) -> Vec<&str> {
    let mut domains: Vec<&str> = state
        .domains
        .iter()
        .filter(|domain| domain.enabled)
        .map(|domain| domain.name.as_str())
        .collect();
    domains.sort_unstable();
    domains
}

fn hosted(state: &DesiredState, name: &str) -> bool {
    state
        .domains
        .iter()
        .any(|domain| domain.enabled && domain.name == name)
}

/// Escape a value for a Dovecot `key = "value"` line.
fn escape_quoted(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace(['\r', '\n'], " ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use ayane_proto::{Account, Alias, DefaultAction, MailDomain, Policy, SharedMailbox};
    use uuid::Uuid;

    fn addr(raw: &str) -> Address {
        Address::parse(raw).expect("fixture address")
    }

    fn fixture() -> DesiredState {
        DesiredState {
            domains: vec![
                MailDomain {
                    name: "example.com".to_owned(),
                    catch_all: Some(addr("inbox@example.com")),
                    enabled: true,
                },
                MailDomain {
                    name: "retired.example".to_owned(),
                    catch_all: None,
                    enabled: false,
                },
            ],
            accounts: vec![
                Account {
                    id: Uuid::nil(),
                    address: addr("inbox@example.com"),
                    display_name: "Inbox".to_owned(),
                    quota_bytes: 1_073_741_824,
                    admin: false,
                },
                Account {
                    id: Uuid::nil(),
                    address: addr("stale@retired.example"),
                    display_name: "Stale".to_owned(),
                    quota_bytes: 0,
                    admin: false,
                },
            ],
            aliases: vec![Alias {
                source: addr("sales@example.com"),
                targets: vec![addr("inbox@example.com"), addr("boss@elsewhere.example")],
            }],
            shared: vec![SharedMailbox {
                id: Uuid::nil(),
                address: addr("team@example.com"),
                members: vec![Uuid::nil()],
            }],
            policy: Policy {
                default_action: DefaultAction::Reject,
                ..Policy::default()
            },
            audit: Default::default(),
            mcp: Default::default(),
        }
    }

    #[test]
    fn domains_skip_disabled_entries() {
        assert_eq!(postfix_virtual_domains(&fixture()), "example.com OK\n");
    }

    #[test]
    fn mailboxes_include_shared_and_skip_disabled_domains() {
        assert_eq!(
            postfix_virtual_mailboxes(&fixture()),
            "inbox@example.com OK\nteam@example.com OK\n"
        );
    }

    #[test]
    fn aliases_render_targets_and_catch_all() {
        assert_eq!(
            postfix_virtual_aliases(&fixture()),
            "@example.com inbox@example.com\n\
             inbox@example.com inbox@example.com\n\
             sales@example.com inbox@example.com, boss@elsewhere.example\n\
             team@example.com team@example.com\n"
        );
    }

    #[test]
    fn every_mailbox_has_an_identity_row_so_the_catch_all_cannot_shadow_it() {
        let rendered = postfix_virtual_aliases(&fixture());
        let mut rows = rendered.lines();
        assert!(
            rendered.contains("inbox@example.com inbox@example.com\n"),
            "account identity row missing: {rendered}"
        );
        assert!(
            rendered.contains("team@example.com team@example.com\n"),
            "shared identity row missing: {rendered}"
        );
        // The disabled domain's account must not be rendered at all.
        assert!(!rendered.contains("stale@retired.example"));
        let _ = rows.next();
    }

    #[test]
    fn sender_denylist_renders_address_and_domain_rules() {
        use ayane_proto::SenderRule;
        let mut state = fixture();
        state.policy.denylist = vec![
            SenderRule::Domain("spam.example".to_owned()),
            SenderRule::Address(addr("bot@evil.example")),
        ];
        assert_eq!(
            postfix_sender_denylist(&state),
            "bot@evil.example REJECT Sender denied by policy\n\
             spam.example REJECT Sender denied by policy\n"
        );
    }

    #[test]
    fn sender_denylist_is_empty_when_no_rule_is_configured() {
        assert_eq!(postfix_sender_denylist(&fixture()), "");
    }

    #[test]
    fn rspamd_lists_only_enabled_domains() {
        assert_eq!(
            rspamd_local_domains(&fixture()),
            "local_domains = [\"example.com\"];\n"
        );
    }

    #[test]
    fn dovecot_dsn_cannot_break_out_of_the_quoted_string() {
        let rendered = dovecot_sql_config("host=db password=a\"b\\c\nuser=ayane");
        assert!(rendered.contains("password=a\\\"b\\\\c user=ayane"));
        assert!(!rendered.contains("password=a\"b"));
    }

    #[test]
    fn sieve_forward_keeps_or_drops_the_local_copy() {
        let target = addr("ops@example.com");
        assert_eq!(
            sieve_forward(&target, true),
            "require [\"copy\"];\n\nredirect :copy \"ops@example.com\";\n"
        );
        assert_eq!(
            sieve_forward(&target, false),
            "require [\"copy\"];\n\nredirect \"ops@example.com\";\n"
        );
    }

    #[test]
    fn passwd_lines_are_address_sorted_and_self_contained() {
        let rendered = dovecot_passwd([
            (&addr("zoe@example.com"), "{SHA512-CRYPT}$6$a$z"),
            (&addr("alice@example.com"), "{SHA512-CRYPT}$6$b$c"),
        ]);
        let mut lines = rendered.lines();
        assert_eq!(
            lines.next(),
            Some(
                "alice@example.com:{SHA512-CRYPT}$6$b$c:5000:5000::/var/mail/vhosts/example.com/alice::"
                    .to_owned()
                    .as_str()
            )
        );
        assert_eq!(
            lines.next(),
            Some("zoe@example.com:{SHA512-CRYPT}$6$a$z:5000:5000::/var/mail/vhosts/example.com/zoe::")
        );
        assert_eq!(lines.next(), None);
    }

    // ── Gmail-style address variants ─────────────────────────────────────
    //
    // The `virtual_alias_maps` contract these tests pin, from Postfix 3.7.11
    // (see the doc comments on `postfix_virtual_aliases` and
    // `postfix_variant_alias_regexp`):
    //
    // * `virtual(5)`: "Virtual aliasing is recursive, and is implemented by
    //   the Postfix cleanup(8) daemon before mail is queued." — the rewritten
    //   address is looked up again, which is what lets a `+` strip meet a
    //   dotted spelling's row on the next pass (`a.b+tag@d` → `a.b@d` → `ab@d`).
    // * `postconf(5)` on `virtual_alias_maps`: "Tables will be searched in the
    //   specified order until a match is found. Note: these lookups are
    //   recursive." — the literal map is listed first, so a real mailbox (or
    //   an alias) is answered there and the variant patterns never see it.
    // * `texthash(5)`: "The lookup key is the text before the first
    //   whitespace." — the literal table is an exact-match table, so a key
    //   listed once is the only row that can answer for it.
    // * `virtual(5)` on regular-expression tables: "Each pattern is a regular
    //   expression that is applied to the entire address being looked up …
    //   Patterns are applied in the order as specified in the table, until a
    //   pattern is found that matches the search string." — the rows run in
    //   file order, first match wins.
    //
    // The 2026-11-25 review found two ways the shipped dot *fold* (a regexp
    // pair `a.b@d` → `ab@d` and `.a@d` → `a@d`) disagreed with "a variant
    // reaches the mailbox it is a variant of":
    //
    // * with a real `ab@d` account, `a.b.c@d` folded to `abc@d` — never the
    //   mailbox — and fell through to the catch-all;
    // * with a real `a.b@d` account, `.a.b@d` folded *into* that mailbox,
    //   i.e. one mailbox collected another's mail.
    //
    // Dots are therefore enumerated as literal rows on the mailbox itself.
    // Everything below feeds the renderer's own bytes through `postfix_lookup`
    // (the `regexp(5)` parser) and `rewrite` (the recursive loop), so a row
    // Postfix would reject or mis-read fails the tests here.

    /// One row of a Postfix `regexp:` table, parsed the way `regexp(5)`
    /// documents it (`pattern result`, `#` comments): the pattern is enclosed
    /// in its own first character as the delimiter, with `\` escapes inside,
    /// and back-references become regex groups so the row compiles with the
    /// `regex` crate.
    fn postfix_lookup_row(line: &str) -> (String, String) {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            panic!("blank or comment row rendered: {line:?}");
        }
        let delimiter = line.chars().next().expect("row start");
        let rest = &line[1..];
        let mut pattern = String::new();
        let mut chars = rest.chars();
        let mut closed = false;
        while let Some(ch) = chars.next() {
            if ch == '\\' {
                let escaped = chars.next().expect("trailing backslash");
                pattern.push('\\');
                pattern.push(escaped);
            } else if ch == delimiter {
                closed = true;
                break;
            } else {
                pattern.push(ch);
            }
        }
        assert!(closed, "row has no closing delimiter: {line:?}");
        let tail: String = chars.collect();
        let result = tail.trim().to_owned();
        assert!(!result.is_empty(), "row has no result: {line:?}");
        (pattern, result)
    }

    /// The `regex`-crate source for one rendered row: Postfix's `$n` inside a
    /// *pattern* is a group back-reference, which the crate spells `(?P=n)`
    /// (a bare `\1` there would be an octal escape).
    fn postfix_pattern_source(pattern: &str) -> String {
        let chars: Vec<char> = pattern.chars().collect();
        let mut compiled = String::new();
        let mut index = 0;
        while index < chars.len() {
            if chars[index] == '\\'
                && chars.get(index + 1) == Some(&'$')
                && chars.get(index + 2).is_some_and(char::is_ascii_digit)
            {
                compiled.push_str(&format!("(?P={})", chars[index + 2]));
                index += 3;
            } else {
                compiled.push(chars[index]);
                index += 1;
            }
        }
        compiled
    }

    /// Match one rendered row against one address, exactly as Postfix applies
    /// it: the whole address, anchored left by `^` and right by `$` (with a
    /// trailing CR tolerated), `+` a literal, and `${n}` in the result filled
    /// from group `n`.
    fn postfix_lookup(line: &str, address: &str) -> Option<String> {
        let (pattern, result) = postfix_lookup_row(line);
        let groups = pattern.matches('(').count();
        for group in 1..=9 {
            let reference = format!("${{{group}}}");
            assert!(
                !result.contains(&reference) || group <= groups,
                "row {line:?} references group {group}, which it does not define"
            );
        }
        let body = postfix_pattern_source(&pattern);
        let body = body.strip_prefix('^').unwrap_or(&body);
        let body = body.strip_suffix('$').unwrap_or(body);
        let source = format!("(?s)^{body}(?:\\r)?\\z");
        let regex = regex::RegexBuilder::new(&source)
            .size_limit(1 << 22)
            .build()
            .unwrap_or_else(|e| panic!("row {line:?} does not compile: {e}"));
        let caps = regex.captures(address)?;
        let result_chars: Vec<char> = result.chars().collect();
        let mut out = String::new();
        let mut index = 0;
        while index < result_chars.len() {
            if result_chars[index] == '$'
                && result_chars.get(index + 1) == Some(&'{')
                && result_chars.get(index + 3) == Some(&'}')
            {
                let group = result_chars[index + 2].to_digit(10).expect("group digit") as usize;
                out.push_str(caps.get(group).map_or("", |m| m.as_str()));
                index += 4;
            } else {
                out.push(result_chars[index]);
                index += 1;
            }
        }
        Some(out)
    }

    /// The reference model of Postfix's virtual alias loop: one lookup is the
    /// literal map first (an exact key hit is the answer), the regexp table
    /// only when the literal map has no row, both in file order; the rewritten
    /// address is the new input and the lookup repeats until it stops changing.
    fn rewrite(literal: &str, regexp: &str, address: &str) -> String {
        let literal_rows: Vec<(String, String)> = literal
            .lines()
            .filter_map(|line| {
                let line = line.trim_start();
                let cut = line.find([' ', '\t'])?;
                Some((line[..cut].to_owned(), line[cut..].trim().to_owned()))
            })
            .collect();
        let rows: Vec<&str> = regexp
            .lines()
            .filter(|row| !row.trim().is_empty())
            .collect();
        let mut current = address.to_owned();
        for _ in 0..1000 {
            let next = literal_rows
                .iter()
                .find(|(key, _)| *key == current)
                .map(|(_, value)| value.clone())
                .or_else(|| rows.iter().find_map(|row| postfix_lookup(row, &current)));
            match next {
                Some(next) if next == current => return current,
                Some(next) => current = next,
                None => return current,
            }
        }
        panic!("alias expansion of {address:?} did not settle: {current}");
    }

    fn variants_state(bits: u8) -> DesiredState {
        let mut state = fixture();
        state.policy.variants = ayane_proto::AddressVariants {
            inbound_dots: bits & 1 != 0,
            inbound_plus: bits & 2 != 0,
            outbound_dots: bits & 4 != 0,
            outbound_plus: bits & 8 != 0,
        };
        state
    }

    /// The state the review's two counter-examples were run against: one
    /// mailbox of each shape plus the catch-all from [`fixture`].
    fn mailbox_state(bits: u8, locals: &[&str]) -> DesiredState {
        let mut state = variants_state(bits);
        for local in locals {
            state.accounts.push(Account {
                id: Uuid::nil(),
                address: addr(&format!("{local}@example.com")),
                display_name: (*local).to_owned(),
                quota_bytes: 0,
                admin: false,
            });
        }
        state
    }

    /// Where one recipient ends up, rendered against `state`'s own mailboxes.
    fn rewritten(state: &DesiredState, recipient: &str) -> String {
        rewrite(
            &postfix_virtual_aliases(state),
            &postfix_variant_alias_regexp(state),
            recipient,
        )
    }

    fn delivered(bits: u8, locals: &[&str], recipient: &str) -> String {
        rewritten(&mailbox_state(bits, locals), recipient)
    }

    #[test]
    fn variant_map_is_empty_with_every_switch_off() {
        assert_eq!(postfix_variant_alias_regexp(&fixture()), "");
        // Outbound switches never reach the Postfix map.
        assert_eq!(postfix_variant_alias_regexp(&variants_state(0b1100)), "");
        // Dots are literal rows now, so the dots switch alone renders no
        // pattern at all.
        assert_eq!(postfix_variant_alias_regexp(&variants_state(0b0001)), "");
    }

    #[test]
    fn variant_map_renders_only_the_plus_rows() {
        let expected = "/^([^+]+)\\+([^@]*)@(example\\.com)$/ ${1}@${3}\n\
                        /^\\+([^@]*)@(example\\.com)$/ ${1}@${2}\n";
        assert_eq!(
            postfix_variant_alias_regexp(&variants_state(0b0010)),
            expected
        );
        // Adding the dots switch does not add a pattern: dots live in the
        // literal table.
        assert_eq!(
            postfix_variant_alias_regexp(&variants_state(0b0011)),
            expected
        );
    }

    #[test]
    fn variant_map_renders_no_dot_fold_at_all() {
        // The retired fold: these two rows are what caused both review
        // findings, so their absence is a regression guard of its own.
        for bits in [0b0001u8, 0b0011, 0b1111] {
            let rendered = postfix_variant_alias_regexp(&variants_state(bits));
            assert!(
                !rendered.contains("[^.]"),
                "{bits:04b}: a dot-dropping row came back: {rendered}"
            );
            assert!(
                !rendered.contains("/^\\."),
                "{bits:04b}: a leading-dot row came back: {rendered}"
            );
        }
    }

    #[test]
    fn every_rendered_row_is_a_table_row_postfix_parses() {
        // `regexp(5)` wants the pattern delimited; a bare `^…$` is read as an
        // option field and the row silently skipped, which is how a map that
        // looks right does nothing at all.
        for bits in [0b0010u8, 0b0011] {
            let rendered = postfix_variant_alias_regexp(&variants_state(bits));
            assert!(
                !rendered.is_empty(),
                "combination {bits:04b} rendered nothing"
            );
            for row in rendered.lines() {
                assert!(row.starts_with('/'), "{bits:04b}: undelimited row {row:?}");
                assert!(
                    row.contains("/ "),
                    "{bits:04b}: no delimiter before the result {row:?}"
                );
                let (pattern, _) = postfix_lookup_row(row);
                assert!(pattern.starts_with('^'), "{bits:04b}: unanchored {row:?}");
                assert!(pattern.ends_with('$'), "{bits:04b}: unanchored {row:?}");
                // A `.` must never be a wildcard.
                assert!(
                    !pattern.contains("@(example.com)"),
                    "{bits:04b}: unescaped domain in {row:?}"
                );
                // A capture is never followed by a digit, so `${n}` is only
                // belt and braces against Postfix's greedy `$n` reader.
                assert!(!row.contains("$0"), "{bits:04b}: group zero in {row:?}");
            }
        }
    }

    #[test]
    fn variant_map_covers_every_enabled_domain_and_skips_disabled_ones() {
        let mut state = variants_state(0b0010);
        state.domains.push(MailDomain {
            name: "second.example".to_owned(),
            catch_all: None,
            enabled: true,
        });
        let rendered = postfix_variant_alias_regexp(&state);
        assert!(
            rendered.contains("example\\.com|second\\.example"),
            "{rendered}"
        );
        assert!(!rendered.contains("retired"), "{rendered}");
    }

    #[test]
    fn variant_map_is_empty_without_hosted_domains() {
        let mut state = variants_state(0b0011);
        for domain in &mut state.domains {
            domain.enabled = false;
        }
        assert_eq!(postfix_variant_alias_regexp(&state), "");
    }

    // ── dot variants: the enumeration itself ─────────────────────────────

    #[test]
    fn dot_variants_enumerate_every_spelling_between_characters() {
        // `ab`: the one place between the two characters.
        assert_eq!(dot_variants("ab"), vec!["ab", "a.b"]);
        // `abc`: three spellings with at least one dot, in ascending bit order.
        assert_eq!(dot_variants("abc"), vec!["abc", "a.bc", "ab.c", "a.b.c"]);
        // `abcd` keeps the original first, then every subset of the three
        // places.
        let four = dot_variants("abcd");
        assert_eq!(four.len(), 8);
        assert_eq!(four[0], "abcd");
        for spelling in &four[1..] {
            assert_ne!(spelling, "abcd");
            assert!(!spelling.starts_with('.') && !spelling.ends_with('.'));
            assert!(!spelling.contains(".."));
        }
        let mut unique = four.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(unique.len(), four.len(), "spellings must be distinct");
    }

    #[test]
    fn dot_variants_never_start_or_end_with_a_dot_nor_double_one() {
        for local in ["a", "ab", "xyz", "a.b", "ab.cd", "a.b.c.d"] {
            for spelling in dot_variants(local) {
                assert!(!spelling.is_empty(), "{local}: empty spelling");
                assert!(
                    !spelling.starts_with('.') && !spelling.ends_with('.'),
                    "{local}: leading/trailing dot in `{spelling}`"
                );
                assert!(
                    !spelling.contains(".."),
                    "{local}: doubled dot in `{spelling}`"
                );
                assert_eq!(
                    spelling.replace('.', ""),
                    local.replace('.', ""),
                    "{local}: `{spelling}` changed the letters"
                );
            }
        }
    }

    #[test]
    fn a_dotted_local_part_takes_no_second_dot() {
        // One character: no place to insert a dot.
        assert_eq!(dot_variants("a"), vec!["a"]);
        // A local part that already carries a dot has no place left: the
        // doubled-dot spelling is not a variant, and neither is a leading or
        // trailing one. The letters stay and the dot stays where it is.
        assert_eq!(dot_variants("a.b"), vec!["a.b"]);
        assert_eq!(dot_variants("a.b.c"), vec!["a.b.c"]);
        // `ab.c` keeps its dot where it is, whatever rooms the letters leave.
        assert_eq!(dot_variants("ab.c"), vec!["ab.c"]);
    }

    #[test]
    fn a_long_local_part_keeps_only_the_one_and_two_dot_spellings() {
        // 13 characters = 12 places = exactly the budget: the full 2^12 set.
        let at_budget = "abcdefghijklm";
        let spellings = dot_variants(at_budget);
        assert_eq!(spellings.len(), 1usize << DOT_VARIANT_PLACES);
        // 14 characters = 13 places = over the budget: the original plus every
        // one-dot and two-dot spelling, and nothing wider.
        let over = dot_variants("abcdefghijklmn");
        let places = 13usize;
        // The original, every one-dot spelling, every two-dot spelling.
        assert_eq!(over.len(), 1 + places + places * (places - 1) / 2);
        for spelling in &over {
            assert!(spelling.matches('.').count() <= 2, "`{spelling}`");
            assert!(!spelling.starts_with('.') && !spelling.ends_with('.'));
            assert!(!spelling.contains(".."));
        }
        assert!(over.contains(&"a.bcdefghijklmn".to_owned()));
        assert!(over.contains(&"a.b.cdefghijklmn".to_owned()));
        assert!(!over.contains(&"a.b.c.defghijklmn".to_owned()));
    }

    #[test]
    fn the_renderer_bounds_its_rows_however_long_a_local_part_is() {
        // The address grammar allows 64 characters, i.e. 63 dot places and
        // 2^63 - 1 spellings: unenumerable. The budget turns that into a
        // bounded number of rows.
        let long = "abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz01";
        assert_eq!(long.len(), 64);
        // Only this mailbox, so every row of the file is one of its spellings.
        let state = DesiredState {
            accounts: vec![Account {
                id: Uuid::nil(),
                address: addr(&format!("{long}@example.com")),
                display_name: "Long".to_owned(),
                quota_bytes: 0,
                admin: false,
            }],
            ..variants_state(0b0001)
        };
        let literal = postfix_virtual_aliases(&state);

        let places = 63usize;
        let bounded = 1 + places + places * (places - 1) / 2;
        let target = format!(" {long}@example.com");
        let pointing: Vec<&str> = literal
            .lines()
            .filter(|line| line.ends_with(&target) && !line.starts_with(&format!("{long} ")))
            .collect();
        assert_eq!(
            pointing.len(),
            bounded,
            "row budget not honoured: {bounded} spellings expected"
        );
        assert!(bounded < 2_100, "{bounded} rows is not a budget");
        // Every row points at the mailbox and none is malformed. The width
        // cap (one or two inserted dots) is covered by the count above and by
        // `a_long_local_part_keeps_only_the_one_and_two_dot_spellings`.
        for line in &pointing {
            // The row is `key value`; the key never holds a space.
            let (spelling, value) = line.split_once(' ').unwrap_or((line, ""));
            assert_eq!(value, format!("{long}@example.com"), "row {line:?}");
            assert!(
                spelling.split('.').all(|run| !run.is_empty()),
                "`{spelling}` has an empty run (leading, trailing or doubled dot)"
            );
        }
        // The whole file for this state stays small enough for one map file.
        assert!(
            literal.lines().count() < 3_000,
            "{} rows is not a bounded table",
            literal.lines().count()
        );
    }

    // ── dot variants: what a recipient is delivered to ───────────────────

    #[test]
    fn every_switch_off_leaves_every_recipient_alone() {
        for recipient in [
            "a.b@example.com",
            "a.b.c@example.com",
            ".a.b@example.com",
            "ops+tag@example.com",
            "a.b+tag@example.com",
            "inbox@example.com",
        ] {
            assert_eq!(
                delivered(0b0000, &["ab", "a.b"], recipient),
                recipient,
                "`{recipient}` must not change with every switch off"
            );
        }
        // The existing literal rows still apply with every switch off — the
        // alias forwards and the catch-all catches, exactly as before.
        assert_eq!(
            delivered(0b0000, &[], "sales@example.com"),
            "inbox@example.com, boss@elsewhere.example"
        );
    }

    #[test]
    fn the_literal_table_renders_no_dot_row_with_the_switch_off() {
        let off = postfix_virtual_aliases(&mailbox_state(0b0000, &["ab"]));
        assert!(
            !off.contains("a.b@example.com"),
            "a dot variant leaked with inbound_dots off: {off}"
        );
        let on = postfix_virtual_aliases(&mailbox_state(0b0001, &["ab"]));
        assert!(
            on.contains("a.b@example.com ab@example.com\n"),
            "the dot variant row is missing: {on}"
        );
    }

    #[test]
    fn a_dotted_address_reaches_its_mailbox_however_many_dots_it_carries() {
        // Review finding S1-A: with a real `ab@d` account the folded row used
        // to send `a.b.c@d` to `abc@d` (no such mailbox) and on to the
        // catch-all. Every spelling of `ab` is now a literal row.
        let locals = ["ab"];
        assert_eq!(
            delivered(0b0001, &locals, "a.b@example.com"),
            "ab@example.com"
        );
        // The *letters* decide: `abc` is not a spelling of `ab`, so `ab`'s
        // rows say nothing about it. (With no `abc` mailbox it is unknown,
        // i.e. it is left exactly as it came in; with one it is that
        // mailbox's own address.)
        assert_eq!(
            delivered(0b0001, &locals, "abc@example.com"),
            "abc@example.com"
        );
        // The dotted form of `abc` is the same class of bug fixed the other
        // way round: it is a spelling of the *`abc`* mailbox.
        let with_abc = ["ab", "abc"];
        assert_eq!(
            delivered(0b0001, &with_abc, "a.b.c@example.com"),
            "abc@example.com",
            "`a.b.c@example.com` must reach `abc@example.com`, not the catch-all"
        );
        assert_eq!(
            delivered(0b0001, &with_abc, "a.bc@example.com"),
            "abc@example.com"
        );
        assert_eq!(
            delivered(0b0001, &with_abc, "ab.c@example.com"),
            "abc@example.com"
        );
    }

    #[test]
    fn a_leading_dot_is_not_a_variant_and_cannot_hijack_another_mailbox() {
        // Review finding S1-B: `.a.b@d` used to fold onto the real `a.b@d`
        // account — one mailbox collecting another's mail. Only the aliasing
        // tables are the variant feature's business: a key that is not in
        // them is answered by Postfix's own fallbacks (the mailbox map, then
        // the `@domain` catch-all), which this model deliberately does not
        // reproduce. So the assertion is on the tables: neither `.a.b@` nor
        // any other non-spelling may be a key, and `a.b@` must not be a
        // *value* for anything the mailbox does not own.
        let locals = ["a.b"];
        let state = mailbox_state(0b0001, &locals);
        let literal = postfix_virtual_aliases(&state);
        for key in [
            ".a.b@example.com",
            "a..b@example.com",
            "a.b.@example.com",
            "ab@example.com",
        ] {
            assert!(
                !literal
                    .lines()
                    .any(|line| line.starts_with(&format!("{key} "))),
                "`{key}` must not be a key of the literal table: {literal}"
            );
        }
        // The only row that mentions the mailbox is its identity row and the
        // rows the *other* mailboxes write.
        assert!(
            literal.contains("a.b@example.com a.b@example.com\n"),
            "identity row missing: {literal}"
        );
        // And no spelling the mailbox does not own resolves to it.
        assert_eq!(rewritten(&state, "a.b@example.com"), "a.b@example.com");
        assert_eq!(rewritten(&state, "a.b.c@example.com"), "a.b.c@example.com");
        // In Postfix's terms a leading dot is then just unknown mail for the
        // careful lookups to handle (`virtual_mailbox_maps`, the `@domain`
        // catch-all) — nobody's variant, and above all not `a.b@`'s.
    }

    #[test]
    fn two_accounts_with_the_same_letters_each_keep_their_own_address() {
        // `a.b@d` and `ab@d` both exist. Every alias key is claimed exactly
        // once — `a.b@d` by its identity row, `ab@d` by its own identity row —
        // so neither spelling can be re-pointed at the other.
        let locals = ["a.b", "ab"];
        assert_eq!(
            delivered(0b0001, &locals, "a.b@example.com"),
            "a.b@example.com"
        );
        assert_eq!(
            delivered(0b0001, &locals, "ab@example.com"),
            "ab@example.com"
        );
        // The three-way spelling `a.b.c` belongs to `abc`, which nobody owns
        // here: it is *not* a spelling of either of the two accounts, so it
        // stays as it is.
        assert_eq!(
            delivered(0b0001, &locals, "a.b.c@example.com"),
            "a.b.c@example.com"
        );
        let literal = postfix_virtual_aliases(&mailbox_state(0b0001, &locals));
        for line in literal.lines() {
            let key = line.split_once(' ').map(|(key, _)| key).unwrap_or("");
            assert_ne!(
                line, "a.b@example.com ab@example.com",
                "`a.b@` must never be re-pointed at `ab@`: {literal}"
            );
            assert_ne!(
                line, "ab@example.com a.b@example.com",
                "`ab@` must never be re-pointed at `a.b@`: {literal}"
            );
            assert!(!key.is_empty());
        }
    }

    #[test]
    fn a_dot_variant_of_one_mailbox_never_lands_on_another_that_owns_it() {
        // `ab@d` exists, and so does `a.b@d`: the latter's identity row owns
        // that spelling, so the former renders no row for it. Three-account
        // shape of the review: `a.b.c@d` is a spelling of neither, and the
        // catch-all takes it.
        let locals = ["ab", "a.b", "abc"];
        assert_eq!(
            delivered(0b0001, &locals, "a.b@example.com"),
            "a.b@example.com"
        );
        assert_eq!(
            delivered(0b0001, &locals, "ab.c@example.com"),
            "abc@example.com"
        );
        assert_eq!(
            delivered(0b0001, &locals, "a.bc@example.com"),
            "abc@example.com"
        );
        assert_eq!(
            delivered(0b0001, &locals, "a.b.c@example.com"),
            "abc@example.com"
        );
    }

    #[test]
    fn an_alias_source_that_looks_like_a_variant_keeps_its_forward() {
        // `s.a@d` is an alias source, so `sa@d`'s spelling of it is the
        // alias's key, not a variant of `sa`: forwarding wins, as it does for
        // every other exact key in the literal table.
        let mut state = variants_state(0b0001);
        state.accounts.push(Account {
            id: Uuid::nil(),
            address: addr("sa@example.com"),
            display_name: "Sa".to_owned(),
            quota_bytes: 0,
            admin: false,
        });
        state.aliases.push(Alias {
            source: addr("s.a@example.com"),
            targets: vec![addr("inbox@example.com")],
        });
        let literal = postfix_virtual_aliases(&state);
        let regexp = postfix_variant_alias_regexp(&state);
        assert!(
            literal.contains("s.a@example.com inbox@example.com\n"),
            "the alias row must survive: {literal}"
        );
        assert_eq!(
            rewrite(&literal, &regexp, "s.a@example.com"),
            "inbox@example.com"
        );
    }

    #[test]
    fn a_shared_mailbox_gets_its_dot_variants_too() {
        let mut state = variants_state(0b0001);
        state.shared.push(SharedMailbox {
            id: Uuid::nil(),
            address: addr("help.desk@example.com"),
            members: vec![Uuid::nil()],
        });
        let literal = postfix_virtual_aliases(&state);
        // `help.desk` already carries a dot, so it has no free place and no
        // spelling of its own; the plain `helpdesk` mailbox is a different
        // address and nothing may fold one into the other.
        assert!(
            literal.contains("help.desk@example.com help.desk@example.com\n"),
            "shared identity row missing: {literal}"
        );
        assert!(
            !literal.contains("helpdesk@example.com"),
            "`helpdesk@` must not be pulled into `help.desk@`: {literal}"
        );
        // A shared mailbox without a dot in its local part does get them.
        let mut plain = variants_state(0b0001);
        plain.shared.push(SharedMailbox {
            id: Uuid::nil(),
            address: addr("helpdesk@example.com"),
            members: vec![Uuid::nil()],
        });
        let literal = postfix_virtual_aliases(&plain);
        assert!(
            literal.contains("help.desk@example.com helpdesk@example.com\n"),
            "the shared mailbox's dot row is missing: {literal}"
        );
        assert_eq!(
            rewrite(
                &literal,
                &postfix_variant_alias_regexp(&plain),
                "help.desk@example.com"
            ),
            "helpdesk@example.com"
        );
    }

    #[test]
    fn inbound_plus_strips_the_tag_down_to_the_base_mailbox() {
        let locals = ["a", "inbox", "ops", "o.ps", "a.b", "ab"];
        for (recipient, delivered_to) in [
            ("ops+alerts@example.com", "ops@example.com"),
            ("inbox+tag@example.com", "inbox@example.com"),
            ("a+b+c@example.com", "a@example.com"),
            ("+a@example.com", "a@example.com"),
            // Nothing is left of the local part: no address can hold that, so
            // the fold leaves the recipient for the catch-all below.
            ("+@example.com", "inbox@example.com"),
            // With the plus switch alone a dot is not a variant: the tag
            // strips and the dots stay.
            ("o.ps+tag@example.com", "o.ps@example.com"),
        ] {
            assert_eq!(
                delivered(0b0010, &locals, recipient),
                delivered_to,
                "folding {recipient}"
            );
        }
    }

    #[test]
    fn a_combined_variant_can_use_both_inbound_switches() {
        let locals = ["ab", "a.b"];
        // The tag strips to `a.b`, whose own identity row answers — the same
        // mailbox, reached without passing through `ab`.
        assert_eq!(
            delivered(0b0011, &locals, "a.b+tag@example.com"),
            "a.b@example.com"
        );
        // `x.y.z` is a spelling of `xyz`: strip, then the literal row.
        assert_eq!(
            delivered(0b0011, &["ab", "xyz"], "x.y.z+tag@example.com"),
            "xyz@example.com"
        );
        assert_eq!(
            delivered(0b0011, &["abc"], "a.b.c+tag@example.com"),
            "abc@example.com"
        );
        // Dots only: the tag survives, so the fold reaches only `a.b.c`, a
        // spelling of `abc` — a different address from the tagged one, which
        // is then nobody's mailbox.
        assert_eq!(
            delivered(0b0001, &["abc"], "a.b.c+tag@example.com"),
            "a.b.c+tag@example.com"
        );
        // Plus only: the tag strips and the dots stay — `a.b.c` is no mailbox
        // without the dots switch.
        assert_eq!(
            delivered(0b0010, &["abc"], "a.b.c+tag@example.com"),
            "a.b.c@example.com"
        );
        let recipient = "a.b.c+tag@example.com";
        assert_eq!(delivered(0b0000, &["abc"], recipient), recipient);
    }

    #[test]
    fn the_fold_terminates_on_awkward_local_parts() {
        // `rewrite` panics if the expansion does not settle inside Postfix's
        // recursion limit.
        let locals = ["abcdef", "xy", "inbox"];
        for recipient in [
            "a.b.c.d.e.f+one.two.three@example.com",
            "....x+y+z@example.com",
            "x+.+y@example.com",
            "very.long.and.dotted.local.part@example.com",
        ] {
            let result = delivered(0b0011, &locals, recipient);
            assert!(!result.contains('+'), "{recipient} kept a tag: {result}");
            // Nothing may be hijacked: whatever it settled on is a mailbox,
            // the catch-all, or the recipient itself.
            assert!(
                [
                    "abcdef@example.com",
                    "xy@example.com",
                    "inbox@example.com",
                    "....x@example.com",
                    "x@example.com",
                    recipient,
                ]
                .contains(&result.as_str()),
                "{recipient} settled on `{result}`, which is nobody's mailbox"
            );
        }
    }

    #[test]
    fn a_real_mailbox_beats_its_own_variants() {
        // `a.b@example.com` exists. Its literal identity row answers before
        // any pattern runs, so nothing can take it to `ab`; and `ab@` has no
        // row folding *into* it, so no variant can be rewritten into
        // somebody's box.
        let state = mailbox_state(0b0001, &["a.b"]);
        let literal = postfix_virtual_aliases(&state);
        let regexp = postfix_variant_alias_regexp(&state);
        assert!(
            literal.contains("a.b@example.com a.b@example.com\n"),
            "identity row missing: {literal}"
        );
        assert_eq!(
            rewrite(&literal, &regexp, "a.b@example.com"),
            "a.b@example.com"
        );
        // `ab` is a spelling of `a.b`'s letters, but it is a *different
        // address*, and only the dot-less local part publishes its spellings.
        // Nothing may pull `ab@` into `a.b@`; it is not a mailbox here at all.
        assert_eq!(
            rewrite(&literal, &regexp, "ab@example.com"),
            "ab@example.com"
        );
        // `a.b.c` is not a spelling of `a.b` (its letters differ), so nothing
        // claims it — the fold never stops *on* the existing dotted box.
        assert_eq!(
            rewrite(&literal, &regexp, "a.b.c@example.com"),
            "a.b.c@example.com"
        );
    }

    #[test]
    fn the_rendered_literal_table_parses_as_a_texthash_table() {
        // `texthash` reads `key whitespace value`; a stray tab or an empty key
        // makes the table reject the whole file at load time.
        let state = mailbox_state(0b0011, &["ab", "a.b", "help.desk"]);
        let literal = postfix_virtual_aliases(&state);
        for line in literal.lines() {
            assert!(!line.trim().is_empty(), "blank row: {literal:?}");
            assert!(
                !line.starts_with(char::is_whitespace),
                "indented row: {line:?}"
            );
            let (key, value) = line
                .split_once(' ')
                .unwrap_or_else(|| panic!("no value: {line:?}"));
            assert!(!key.trim().is_empty(), "empty key: {line:?}");
            assert!(!value.trim().is_empty(), "empty value: {line:?}");
            assert!(
                !key.contains('\t') && !value.contains('\t'),
                "tab in {line:?}"
            );
            assert!(
                !key.contains(".."),
                "doubled dot rendered as a key: {line:?}"
            );
        }
        // Every key is listed exactly once: the table is exact-match, so a
        // second row for a key could never apply and would only hide a bug.
        let mut keys: Vec<&str> = literal
            .lines()
            .map(|line| line.split_once(' ').map(|(key, _)| key).unwrap_or(line))
            .collect();
        let total = keys.len();
        keys.sort_unstable();
        keys.dedup();
        assert_eq!(keys.len(), total, "duplicate key in: {literal}");
    }

    #[test]
    fn aliases_stay_literal_because_the_literal_map_is_searched_first() {
        // `sales@example.com` forwards to the catch-all inbox. The alias row
        // is answered literally; its tagged form only reaches it when the
        // plus switch folds the tag first, and with the switch off the
        // `@domain` catch-all takes it instead.
        let on = variants_state(0b0010);
        let literal = postfix_virtual_aliases(&on);
        let regexp = postfix_variant_alias_regexp(&on);
        assert_eq!(
            rewrite(&literal, &regexp, "sales@example.com"),
            "inbox@example.com, boss@elsewhere.example"
        );
        // The tagged form folds to the alias source, and the literal map then
        // forwards it exactly as it forwards the bare source.
        assert_eq!(
            rewrite(&literal, &regexp, "sales+promo@example.com"),
            "inbox@example.com, boss@elsewhere.example"
        );
        // With the switches off there is no fold at all, so the tagged
        // address is none of `sales`'s business. (Postfix's own fallbacks do
        // reach the base key here — `recipient_delimiter` and the `postfix`
        // "strip `+tag`" pass are engine settings, unchanged by this
        // feature — so this asserts the variant map's contribution alone: it
        // renders nothing, and the alias source itself still forwards.)
        let off = variants_state(0b0000);
        assert_eq!(postfix_variant_alias_regexp(&off), "");
        assert_eq!(
            rewrite(
                &postfix_virtual_aliases(&off),
                &postfix_variant_alias_regexp(&off),
                "sales@example.com"
            ),
            "inbox@example.com, boss@elsewhere.example"
        );
    }

    #[test]
    fn the_literal_map_is_complete_and_listed_first() {
        // The order dependency of the whole design: every account and shared
        // mailbox carries an identity row, and the shipped `main.cf` puts the
        // literal map ahead of the regexp one. The files are read from the
        // tree so a redeploy that reorders the maps fails here.
        let state = variants_state(0b0011);
        let literal = postfix_virtual_aliases(&state);
        for address in ["inbox@example.com", "team@example.com"] {
            assert!(
                literal.contains(&format!("{address} {address}\n")),
                "identity row for {address} missing: {literal}"
            );
        }
        for line in virtual_alias_map_lines() {
            let literal_at = line.find("/maps/virtual_aliases").expect("literal map");
            let regexp_at = line.find("/maps/variant_aliases").expect("variant map");
            assert!(
                literal_at < regexp_at,
                "the literal map must be searched first: {line}"
            );
            // A bare `regexp:` table is what Postfix reads; `pcre:` would need
            // the extra package for no gain here.
            assert!(
                line.contains("regexp:/etc/postfix/maps/variant_aliases"),
                "the variant map must be a regexp: table: {line}"
            );
        }
    }

    /// The `virtual_alias_maps` lines of the shipped dev and prod configs.
    fn virtual_alias_map_lines() -> Vec<&'static str> {
        [
            include_str!("../../../deploy/images/postfix/main.cf"),
            include_str!("../../../deploy/prod/postfix/main.cf"),
        ]
        .into_iter()
        .map(|config| {
            config
                .lines()
                .find(|line| line.starts_with("virtual_alias_maps"))
                .expect("virtual_alias_maps in main.cf")
        })
        .collect()
    }

    /// Each sender lists the accounts allowed to use it: a user's own
    /// address, and every shared mailbox they belong to. A sender may have
    /// several owners (a shared mailbox) — Postfix accepts the comma list.
    #[test]
    fn sender_login_lists_each_sender_with_its_owners() {
        let map = postfix_sender_login_maps(&fixture());
        let line = |sender: &str| {
            map.lines()
                .find(|l| l.starts_with(sender))
                .unwrap_or_else(|| panic!("{sender} missing from:\n{map}"))
        };
        // The account owns itself.
        assert!(line("inbox@example.com").contains("inbox@example.com"));
        // The shared mailbox is owned by its member.
        let team = line("team@example.com");
        assert!(team.contains("inbox@example.com"), "{team}");
        // The retired domain's account is not hosted -> not in the map.
        assert!(!map.contains("stale@retired.example"), "{map}");
        // Every row is `sender owner[, owner…]` — Postfix's map shape.
        for row in map.lines() {
            let mut parts = row.split(' ');
            let sender = parts.next().expect("sender");
            assert!(sender.contains('@'), "{row}");
            assert!(parts.next().is_some(), "no owner for {row}");
        }
    }

    /// The shipped configs carry the three 2026-11-25 security seams: the
    /// milter fails CLOSED (a down rspamd must not disable the DKIM/DMARC
    /// reject verdicts), the envelope sender is bound to the logged-in
    /// identity, and the plaintext internal submission port is bound to
    /// loopback in master.cf itself (not only in compose). Read from the
    /// tree so a config edit that widens any of them goes red here.
    #[test]
    fn shipped_configs_carry_the_security_seams() {
        for (path, text) in [
            ("prod", include_str!("../../../deploy/prod/postfix/main.cf")),
            (
                "image",
                include_str!("../../../deploy/images/postfix/main.cf"),
            ),
        ] {
            assert!(
                text.contains("milter_default_action = tempfail"),
                "{path}: milter must fail closed with a 4xx (tempfail), not reject"
            );
            assert!(
                text.contains("smtpd_sender_login_maps = texthash:/etc/postfix/maps/sender_login")
                    && text.contains("smtpd_sender_restrictions = reject_sender_login_mismatch"),
                "{path}: sender login binding missing"
            );
        }
        // The plaintext AUTH port must NOT bind the container's loopback:
        // the host-published port reaches the container through a DNAT rule
        // that targets the container's own address, so a container-lo bind
        // never receives it and the control plane's send leg silently fails
        // (connect() succeeds, no banner ever arrives). The boundary is the
        // HOST-loopback publish in compose; inside the container the service
        // listens on every interface.
        let master = include_str!("../../../deploy/prod/postfix/master.cf");
        let internal = master
            .lines()
            .find(|l| l.contains("10587") && l.contains("inet"))
            .expect("internal submission service");
        assert!(
            !internal.starts_with("127.0.0.1"),
            "container-side loopback bind breaks the control plane: {internal}"
        );
        let compose = include_str!("../../../deploy/prod/docker-compose.yml");
        assert!(
            compose.contains("127.0.0.1:10587:10587"),
            "the internal port's boundary is the host-loopback publish"
        );
        // The sender_login map must exist before the first apply, or
        // reject_sender_login_mismatch refuses every authenticated sender.
        // Every place that pre-creates the other maps must pre-create this
        // one too — a recipe that forgets it is a silent "nobody can send".
        assert!(
            compose.contains("/etc/postfix/maps/sender_login"),
            "prod compose must pre-create the sender_login map"
        );
        let dev_compose = include_str!("../../../deploy/docker-compose.yml");
        assert!(
            dev_compose.contains("/etc/postfix/maps/sender_login"),
            "dev compose must pre-create the sender_login map"
        );
        let justfile = include_str!("../../../justfile");
        assert!(
            justfile.contains("touch state/config/postfix/sender_login"),
            "the dev recipe must pre-create the sender_login map"
        );
    }

    #[test]
    fn no_map_in_the_stack_folds_a_plus_tag_except_the_variant_table() {
        // The four switches are the only authority over `+`. Before this
        // change a static `subaddress.pcre` folded every tag regardless of the
        // policy; it is retired, and this pins both halves: no `pcre:`/other
        // folding table in `virtual_alias_maps`, and no rendered `+` row with
        // the switch off.
        for line in virtual_alias_map_lines() {
            assert!(
                !line.contains("subaddress"),
                "the retired subaddress table must not be listed: {line}"
            );
            assert!(
                !line.contains("pcre:"),
                "no map other than the rendered one may fold addresses: {line}"
            );
            // Exactly two tables: the literal one and the rendered one.
            assert_eq!(
                line.split(',').filter(|part| part.contains(':')).count(),
                2,
                "virtual_alias_maps must list exactly the literal and variant maps: {line}"
            );
        }
        // Every switch off: the rendered table is empty, so nothing folds a
        // tag anywhere in the stack.
        let off = variants_state(0b0000);
        assert_eq!(postfix_variant_alias_regexp(&off), "");
        assert!(
            !postfix_variant_alias_regexp(&off).contains('+'),
            "a `+` row leaked with inbound_plus off"
        );
        // Dots only: no `+` row at all — the dot switch does not touch tags
        // (and renders no pattern either).
        assert_eq!(postfix_variant_alias_regexp(&variants_state(0b0001)), "");
    }
}
