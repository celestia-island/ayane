<div align="center">
  <img src="https://raw.githubusercontent.com/celestia-island/celestia-island.github.io/main/res/logos/ayane.webp" alt="ayane" width="180" />
</div>

<h1 align="center">Ayane</h1>

<div align="center">
  <strong>The mail service Celestia runs — its own SMTP engine, a maildir read path and a control plane</strong>
</div>

<br />

<div align="center">

**English** ·
[简体中文](docs/zh-Hans/README.md) ·
[繁體中文](docs/zh-Hant/README.md) ·
[日本語](docs/ja/README.md) ·
[한국어](docs/ko/README.md) ·
[Deutsch](docs/de/README.md) ·
[Français](docs/fr/README.md) ·
[Español](docs/es/README.md) ·
[Русский](docs/ru/README.md)

</div>

> **Status: live.** The control plane, rendered webmail and the Celestia ID
> sign-in run on the production rig (`mail.acgsyzx.me`). The mail engine is
> this repository's own: `crates/smtpd` speaks SMTP inbound and submission,
> verifies SPF/DKIM/ARC/DMARC, delivers into maildirs with its own retry
> horizon, and sends off-host mail over MX with DKIM signing. The webmail reads
> those same maildirs directly — there is no IMAP server in the stack any
> more, and no Dovecot to configure.

## Why this exists

Self-hosted mail is a solved problem at the *engine* layer and an unsolved one at
the *organisation* layer: shared mailboxes, catch-all with allow/deny policy,
quarantine, safe rendering, a DNS wizard an operator can actually follow, and an
agent-facing surface. Ayane builds that layer, and speaks SMTP and the maildir
format itself rather than configuring somebody else's daemon.

Named after **Ayane Okusora** (奥空 アヤネ) of Blue Archive: secretary and
communications officer of the Abydos Countermeasures Committee, a principled
rule-keeper who maintains the committee's ledger. Secretary → mailbox
administration, communications officer → routing, rule-keeper → policy and
audit, ledger → the audit trail.

The emblem — a hand-drawn colored-pencil mark in the lacrymira house style,
served from the org site — encodes the same reading: her reticle-shaped halo
(the precise ledger-keeper), the headset with boom mic (the communications
officer), the envelope (the mail), and one red accent for her red-framed
glasses.

## Architecture

```mermaid
flowchart LR
  subgraph Internet
    Peer[Remote MTA]
  end
  subgraph Ayane[ayane — one process when AYANE_MAIL_ENABLED=1]
    LSN[smtpd listeners<br/>inbound · submission]
    VER[verify<br/>SPF · DKIM · ARC · DMARC]
    Q[(spool<br/>crash-safe queue)]
    DEL[delivery<br/>retry · bounce · forward]
    OUT[outbound<br/>MX · STARTTLS · DKIM sign]
    MD[(maildirs<br/>new · cur · tmp)]
    API[control plane<br/>domains · mailboxes · policy · audit]
    WEB[webmail RPC<br/>mail.list · mail.read · mail.send]
  end
  Peer --> LSN
  LSN --> VER
  VER --> Q
  Q --> DEL
  DEL --> MD
  DEL --> OUT
  OUT --> Peer
  WEB -->|reads and renames| MD
  WEB -->|stages a send| Q
  API -->|writes the routing snapshot| DEL
```

## Engine and licences

The mail engine is this repository's own code, under this repository's licence
(SySL 1.0). What it keeps out of the crate is anything copyleft:

| Component | Role | Licence | Boundary |
|---|---|---|---|
| `ayane-smtpd` | SMTP in/out, verification, queue, delivery, maildir | SySL 1.0 | this crate |
| `ayane-engine` | deterministic renderers for the retired Postfix/Dovecot configs | SySL 1.0 | this crate |
| maildir | the mailbox format on disk (`new`/`cur`/`tmp` per folder) | — | a file layout |

Deliberately **not** used: Stalwart (AGPL-3.0), mailcow (GPL-3.0, bundles SOGo
AGPL-3.0), Roundcube / SnappyMail (we ship our own webmail), `acme.sh`
(GPL-3.0 — ACME is done in Rust with `instant-acme`, Apache-2.0). The
`cargo deny` allow-list in `deny.toml` enforces the dependency side of this rule.

## Repository layout

```text
ayane/
  crates/
    proto/    wire types + validation (no I/O)
    mail/     routing, recipient policy, MIME construction (lettre, client only)
    engine/   deterministic renderers (the retired Postfix / Dovecot configs)
    smtpd/    the mail engine: SMTP, verification, queue, delivery, maildir reader
    core/     HTTP surface (`ayane` binary)
  deploy/     compose topology, parameter table, Stage-0 verification checklist
  docs/      user-facing documentation
```

## Quickstart (development)

```bash
cargo run -p ayane
curl -s http://127.0.0.1:3023/api/health
```

The bind address is a candidate for local development only; the deployment
ledger assigns the real port when the service is deployed, and `AYANE_LISTEN`
overrides it.

## Deployment parameters

The full table lives in [`deploy/README.md`](deploy/README.md). In short, an
instance is described by: the mail domain(s), the public hostname, the
certificate source (mounted / uploaded / ACME), the PostgreSQL DSN, the outbound
relay, and the bootstrap administrator. Emit them as environment variables;
never commit real values.

## Roadmap

- **Stage 0** — workspace skeleton, config renderers, health surface, deployment
  parameter table and the engine verification checklist.
- **Stage 1** — the mail engine (inbound SMTP, verification, queue, delivery,
  outbound) plus the control plane: domains, accounts, aliases, shared
  mailboxes, catch-all policy, audit, reload loop.
- **Stage 2** — webmail API and UI on hikari: safe rendering, server-side image
  proxy, attachment hashing, sandboxed preview.
- **Stage 3** — protection depth: phishing heuristics, quarantine workflow, DNS
  wizard with live checks.
- **Stage 4** — MCP tools (read-mostly, human-in-the-loop sending) and agent
  deployment prompts.

## Licence

SySL 1.0 — see [LICENSE](LICENSE).