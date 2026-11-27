set shell := ["bash", "-c"]

_default:
    @just --list

# Type-check all targets.
check:
    cargo check --workspace --all-targets

# Lint with clippy (deny warnings).
lint:
    cargo clippy --workspace --all-targets -- -D warnings

# Run all tests.
test:
    cargo test --workspace

# Format check.
fmt:
    cargo fmt --all -- --check

# Format write.
fmt-write:
    cargo fmt --all

# Dependency licences: permissive only, no AGPL/GPL/LGPL in the tree.
licenses:
    cargo deny check licenses bans sources

# One-shot gate.
gate: fmt lint test licenses

# ── engine rig (dev, single host) ──────────────────────────────────────────

# Run the control plane on 127.0.0.1:3023 (expects AYANE_ADMIN_TOKEN).
#
# With `AYANE_MAIL_ENABLED=1` the same process also binds the SMTP listeners and
# runs the delivery consumer and the outbound transport: one binary, one state
# directory, one set of traffic counters. Without it nothing binds a port.
serve:
    cargo run -p ayane

# Run the control plane with the mail engine in-process, for a bare-metal rig
# (spool and mail root are siblings under state/, as the defaults say).
serve-mail:
    #!/bin/bash
    set -euo pipefail
    mkdir -p state/spool state/mail state/store
    export AYANE_MAIL_ENABLED=1
    export AYANE_MAIL_HOSTNAME="${AYANE_MAIL_HOSTNAME:-mx.example.test}"
    export AYANE_MAIL_LISTENERS="${AYANE_MAIL_LISTENERS:-inbound@127.0.0.1:3025}"
    exec cargo run -p ayane

# The split-process shape of the same mail service (kept for an installation
# that wants the listener under its own unit): `just serve` plus this.
serve-smtpd:
    #!/bin/bash
    set -euo pipefail
    mkdir -p state/spool state/mail
    exec cargo run -p ayane-smtpd --bin ayane-smtpd -- --role inbound \
        --listen "${AYANE_SMTPD_LISTEN:-127.0.0.1:3025}" \
        --spool state/spool --state state/desired-state.json \
        --hostname "${AYANE_MAIL_HOSTNAME:-mx.example.test}"

# Bring the legacy Postfix/Dovecot rig up (only for the read path an existing
# deployment still serves over IMAP; a fresh instance does not need it).
engine-up:
    #!/bin/bash
    mkdir -p state/config/postfix state/config/dovecot state/config/rspamd state/mail state/rspamd state/store
    [[ -f state/config/dovecot/passwd ]] || touch state/config/dovecot/passwd
    [[ -f state/config/postfix/virtual_domains ]] || touch state/config/postfix/virtual_domains
    [[ -f state/config/postfix/virtual_mailboxes ]] || touch state/config/postfix/virtual_mailboxes
    [[ -f state/config/postfix/virtual_aliases ]] || touch state/config/postfix/virtual_aliases
    # The Gmail-style variant table: Postfix refuses to start with a map file
    # that does not exist, and an empty table simply never matches.
    [[ -f state/config/postfix/variant_aliases ]] || touch state/config/postfix/variant_aliases
    [[ -f state/config/postfix/sender_denylist ]] || touch state/config/postfix/sender_denylist
    [[ -f state/config/postfix/sender_login ]] || touch state/config/postfix/sender_login
    [[ -f state/config/rspamd/options.inc ]] || echo 'local_domains = [];' > state/config/rspamd/options.inc
    docker compose -f deploy/docker-compose.yml up -d --build

# Stop the engine (keeps state/).
engine-down:
    docker compose -f deploy/docker-compose.yml down

# End-to-end smoke against the running rig (engine-up + serve first).
smoke:
    cargo test -p ayane --test smoke -- --ignored --nocapture