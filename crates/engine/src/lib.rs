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

use std::collections::BTreeSet;

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

/// Postfix `virtual_alias_maps` map: forwarding rules plus catch-all entries.
///
/// Real mailboxes get an **identity row** (`addr addr`). Postfix consults the
/// alias map before the mailbox map and falls back to `@domain` when the exact
/// address is missing — so without these rows a catch-all would rewrite every
/// existing mailbox into the catch-all target. The identity row makes the
/// exact lookup succeed first, and Postfix stops rewriting when the result
/// equals the input.
#[must_use]
pub fn postfix_virtual_aliases(state: &DesiredState) -> String {
    let mut rows = BTreeSet::new();
    for account in &state.accounts {
        if hosted(state, account.address.domain()) {
            rows.insert(format!("{} {}", account.address, account.address));
        }
    }
    for shared in &state.shared {
        if hosted(state, shared.address.domain()) {
            rows.insert(format!("{} {}", shared.address, shared.address));
        }
    }
    for alias in &state.aliases {
        if !hosted(state, alias.source.domain()) || alias.targets.is_empty() {
            continue;
        }
        let targets: Vec<String> = alias.targets.iter().map(ToString::to_string).collect();
        rows.insert(format!("{} {}", alias.source, targets.join(", ")));
    }
    for domain in &state.domains {
        if !domain.enabled {
            continue;
        }
        if let Some(catch_all) = &domain.catch_all {
            rows.insert(format!("@{} {catch_all}", domain.name));
        }
    }
    rows.into_iter().map(|row| format!("{row}\n")).collect()
}

/// The `regexp:` map that folds Gmail-style address variants onto the base
/// mailbox, or the empty string when the policy enables no inbound variant.
///
/// **Why a regular-expression map.** `virtual_alias_maps` is a literal lookup:
/// the dot and `+tag` variants of one address cannot be enumerated. Postfix
/// queries a `regexp:` table with the whole address (local part dots and plus
/// tags intact, unlike indexed tables, which are also queried with the
/// extension stripped) and rewrites the recipient with the pattern's `$n`
/// captures. Folding one dot per pass is enough because **virtual aliasing is
/// recursive**: `cleanup(8)` looks the rewritten address up again until it no
/// longer changes, so `a.b.c@d` folds to `.c`, then to `c`.
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
/// **The rows, in order** (first match wins; every row ends the address in
/// the domain alternation, which is backslash-escaped so a `.` can only be a
/// dot):
///
/// - `a+tag@d` → `a@d` — the local part before the `+` is dot-free, so this
///   row finishes the fold in one pass (`[^+]+`).
/// - `+a@d` → `a@d` — an empty local part before the tag (`[^+]+` needs a
///   character, so it cannot be left to the row above).
/// - `a.b@d` → `ab@d` — drop one dot; the right-hand class stops at the next
///   dot, so this row runs once per pass and the recursion does the rest.
///   It skips over a `+`, which keeps a tag out of the folded local part.
/// - `.a.b@d` → `a.b@d` — a leading dot has nothing in front of it, so this
///   row peels it instead (and repeats per pass).
///
/// **No arm fires on a dot-less, plus-less local part**, so a mailbox whose
/// primary address was matched by the literal map keeps its identity row and
/// stops there; the identities are also never a *source* of the fold, only a
/// possible destination.
#[must_use]
pub fn postfix_variant_alias_regexp(state: &DesiredState) -> String {
    let variants = &state.policy.variants;
    if !variants.any_inbound() {
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
    let mut rows = String::new();
    if variants.inbound_plus {
        // `local+tag` where the local part is dot-free: strip the tag in one
        // pass. `+a` (an empty local part) is its own row rather than a
        // `[^+]+` with nothing in it: Postfix does not reliably match an
        // empty leading capture, and the tag is optional in what the address
        // means anyway.
        rows.push_str(&format!("/^([^+]+)\\+([^@]*)@({domain})$/ ${{1}}@${{3}}\n"));
        rows.push_str(&format!("/^\\+([^@]*)@({domain})$/ ${{1}}@${{2}}\n"));
    }
    if variants.inbound_dots {
        // `a.b@d` → `ab@d`: drop one dot. One pass only here (the right-hand
        // class stops at the next dot), so the next pass repeats it and the
        // recursion finishes the fold; skipping over the `+` keeps a tag out
        // of the folded local part.
        rows.push_str(&format!(
            "/^([^.]+)\\.([^@]*)@({domain})$/ ${{1}}${{2}}@${{3}}\n"
        ));
        // `.a.b@d` → `a.b@d`: the row above needs a character in front of the
        // dot it drops, so a leading dot is peeled by this one instead.
        rows.push_str(&format!("/^\\.([^@]*)@({domain})$/ ${{1}}@${{2}}\n"));
    }
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
    // The `virtual_alias_maps` contract these tests pin, quoted from Postfix
    // 3.7.11 (see the doc comment on `postfix_variant_alias_regexp`):
    //
    // * `virtual(5)`: "Virtual aliasing is recursive, and is implemented by
    //   the Postfix cleanup(8) daemon before mail is queued." — the rewritten
    //   address is looked up again, which is what folds `a.b.c` one dot per
    //   pass.
    // * `postconf(5)` on `virtual_alias_maps`: "Tables will be searched in the
    //   specified order until a match is found. Note: these lookups are
    //   recursive." — the literal map is listed first, so a real mailbox (or
    //   an alias) is answered there and the variant patterns never see it.
    // * `virtual(5)` on regular-expression tables: "Each pattern is a regular
    //   expression that is applied to the entire address being looked up …
    //   Patterns are applied in the order as specified in the table, until a
    //   pattern is found that matches the search string." — the rows below run
    //   in file order, first match wins.
    //
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

    #[test]
    fn variant_map_is_empty_with_every_switch_off() {
        assert_eq!(postfix_variant_alias_regexp(&fixture()), "");
        // Outbound switches never reach the Postfix map.
        assert_eq!(postfix_variant_alias_regexp(&variants_state(0b1100)), "");
    }

    #[test]
    fn variant_map_renders_the_dot_rows() {
        assert_eq!(
            postfix_variant_alias_regexp(&variants_state(0b0001)),
            "/^([^.]+)\\.([^@]*)@(example\\.com)$/ ${1}${2}@${3}\n\
             /^\\.([^@]*)@(example\\.com)$/ ${1}@${2}\n"
        );
    }

    #[test]
    fn variant_map_renders_the_plus_rows() {
        assert_eq!(
            postfix_variant_alias_regexp(&variants_state(0b0010)),
            "/^([^+]+)\\+([^@]*)@(example\\.com)$/ ${1}@${3}\n\
             /^\\+([^@]*)@(example\\.com)$/ ${1}@${2}\n"
        );
    }

    #[test]
    fn variant_map_renders_both_families_with_the_tag_first() {
        assert_eq!(
            postfix_variant_alias_regexp(&variants_state(0b0011)),
            "/^([^+]+)\\+([^@]*)@(example\\.com)$/ ${1}@${3}\n\
             /^\\+([^@]*)@(example\\.com)$/ ${1}@${2}\n\
             /^([^.]+)\\.([^@]*)@(example\\.com)$/ ${1}${2}@${3}\n\
             /^\\.([^@]*)@(example\\.com)$/ ${1}@${2}\n"
        );
    }

    #[test]
    fn every_rendered_row_is_a_table_row_postfix_parses() {
        // `regexp(5)` wants the pattern delimited; a bare `^…$` is read as an
        // option field and the row silently skipped, which is how a map that
        // looks right does nothing at all.
        for bits in [0b0001u8, 0b0010, 0b0011] {
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
        let mut state = variants_state(0b0001);
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

    /// The four switches × the recipient shapes that matter.
    fn folded(bits: u8, recipient: &str) -> String {
        let state = variants_state(bits);
        rewrite(
            &postfix_virtual_aliases(&state),
            &postfix_variant_alias_regexp(&state),
            recipient,
        )
    }

    #[test]
    fn every_switch_off_leaves_every_recipient_alone() {
        for recipient in [
            "a.b@example.com",
            "a.b.c@example.com",
            "ops+tag@example.com",
            "a.b+tag@example.com",
            "inbox@example.com",
        ] {
            assert_eq!(
                folded(0b0000, recipient),
                recipient,
                "`{recipient}` must not change with every switch off"
            );
        }
        // The existing literal rows still apply with every switch off — the
        // alias forwards and the catch-all catches, exactly as before.
        assert_eq!(
            folded(0b0000, "sales@example.com"),
            "inbox@example.com, boss@elsewhere.example"
        );
    }

    #[test]
    fn inbound_dots_folds_any_number_of_dots_onto_the_base_mailbox() {
        for (recipient, delivered) in [
            ("a.b@example.com", "ab@example.com"),
            ("a.b.c@example.com", "abc@example.com"),
            ("x.y.z.w@example.com", "xyzw@example.com"),
            (".a.b@example.com", "ab@example.com"),
            ("alice.smith@example.com", "alicesmith@example.com"),
            ("inbox@example.com", "inbox@example.com"),
            // Not a hosted domain: nothing to fold.
            ("a.b@elsewhere.example", "a.b@elsewhere.example"),
        ] {
            assert_eq!(folded(0b0001, recipient), delivered, "folding {recipient}");
        }
    }

    #[test]
    fn inbound_plus_strips_the_tag_down_to_the_base_mailbox() {
        for (recipient, delivered) in [
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
            assert_eq!(folded(0b0010, recipient), delivered, "folding {recipient}");
        }
    }

    #[test]
    fn a_combined_variant_needs_both_inbound_switches() {
        let recipient = "a.b+tag@example.com";
        assert_eq!(folded(0b0011, recipient), "ab@example.com");
        // Dots only: the tag survives, so this is not the base mailbox.
        assert_eq!(folded(0b0001, recipient), "ab+tag@example.com");
        // Plus only: the tag strips, the dots stay.
        assert_eq!(folded(0b0010, recipient), "a.b@example.com");
        assert_eq!(folded(0b0000, recipient), recipient);
    }

    #[test]
    fn the_fold_terminates_on_awkward_local_parts() {
        // `rewrite` panics if the expansion does not settle inside Postfix's
        // recursion limit.
        for recipient in [
            "a.b.c.d.e.f+one.two.three@example.com",
            "....x+y+z@example.com",
            "x+.+y@example.com",
            "very.long.and.dotted.local.part@example.com",
        ] {
            let result = folded(0b0011, recipient);
            assert!(!result.contains('+'), "{recipient} kept a tag: {result}");
            assert!(
                !result.split('@').next().unwrap_or("").contains('.'),
                "{recipient} kept a dot: {result}"
            );
        }
    }

    #[test]
    fn a_real_mailbox_beats_its_own_variants() {
        // `a.b@example.com` exists. Its literal identity row answers before
        // any pattern runs, so the dot fold cannot take it to `ab`; and
        // `ab@example.com` is untouched (there is no row folding *into* a
        // mailbox), so no variant can be rewritten into somebody's box.
        let mut state = variants_state(0b0001);
        state.accounts.push(Account {
            id: Uuid::nil(),
            address: addr("a.b@example.com"),
            display_name: "Dotted".to_owned(),
            quota_bytes: 0,
            admin: false,
        });
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
        assert_eq!(
            rewrite(&literal, &regexp, "ab@example.com"),
            "ab@example.com"
        );
        // A variant of the dotted mailbox folds all the way down through the
        // recursion and then meets the catch-all: no `abc` mailbox exists, and
        // the fold never stops *on* the existing dotted box.
        assert_eq!(
            rewrite(&literal, &regexp, "a.b.c@example.com"),
            "abc@example.com"
        );
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
        // forwards it exactly as it forwards the bare source. (The recursion
        // has already finished by then — `sales` is a mailbox-shaped local
        // part with no dot and no tag, so the regexp table never sees it.)
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
        // mailbox carries an identity row, and `main.cf` puts the literal map
        // ahead of the regexp one.
        let state = variants_state(0b0011);
        let literal = postfix_virtual_aliases(&state);
        for address in ["inbox@example.com", "team@example.com"] {
            assert!(
                literal.contains(&format!("{address} {address}\n")),
                "identity row for {address} missing: {literal}"
            );
        }
        let maps =
            "texthash:/etc/postfix/maps/virtual_aliases, regexp:/etc/postfix/maps/variant_aliases";
        let literal_at = maps.find("virtual_aliases").expect("literal map");
        let regexp_at = maps.find("variant_aliases").expect("regexp map");
        assert!(
            literal_at < regexp_at,
            "the literal map must be searched first: {maps}"
        );
    }
}
