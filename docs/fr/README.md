---
title: "Ayane"
description: "Le service de messagerie que Celestia exploite — son propre moteur SMTP, un chemin de lecture maildir et un plan de contrôle."
---

<div align="center">
  <img src="https://raw.githubusercontent.com/celestia-island/celestia-island.github.io/main/res/logos/ayane.webp" alt="ayane" width="180" />
</div>

<h1 align="center">Ayane</h1>

<div align="center">
  <strong>Le service de messagerie que Celestia exploite — son propre moteur SMTP, un chemin de lecture maildir et un plan de contrôle</strong>
</div>

<br />

> **État : en production.** Le plan de contrôle, le webmail rendu côté serveur et la
> connexion via Celestia ID tournent sur l'environnement de production (`mail.acgsyzx.me`).
> Le moteur de messagerie est le code propre de ce dépôt : `crates/smtpd` parle SMTP en
> entrée et en soumission, vérifie SPF/DKIM/ARC/DMARC, remet dans des maildirs et envoie le
> courrier des autres domaines par MX avec signature DKIM. Le webmail lit ces mêmes maildirs
> directement : il n'y a plus de serveur IMAP dans la pile, ni de Dovecot à configurer.

## Pourquoi ce projet existe

La messagerie auto-hébergée est un problème résolu au niveau du *moteur* et non résolu au
niveau de l'*organisation* : boîtes partagées, catch-all avec politique d'autorisation et
de refus, quarantaine, rendu sûr, un assistant DNS qu'un opérateur peut réellement suivre,
et une surface exploitable par des agents. Ayane construit cette couche et parle SMTP et le format
maildir lui-même, au lieu de configurer le démon de quelqu'un d'autre.

## Le nom

Le nom vient d'**Ayane Okusora (奥空 アヤネ)**, personnage de Blue Archive — en français,
on écrit simplement « Ayane Okusora », dérivé du japonais signifiant « ciel vide » :
secrétaire et officière de communication du comité de contre-mesures d'Abydos, gardienne
des règles attachée à ses principes, qui tient le registre du comité. Secrétaire →
administration des boîtes aux lettres, officière de communication → routage, gardienne des
règles → politique et audit, registre → piste d'audit.

L'emblème — une marque au crayon de couleur dessinée à la main, dans le style maison de
lacrymira, servie depuis le site de l'organisation — encode la même lecture : son auréole en
forme de réticule (la tenue de registre précise), le casque à micro perche (l'officière de
communication), l'enveloppe (le courrier) et un unique accent rouge pour ses lunettes à
monture rouge.

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

## Moteurs et licences

Le moteur de messagerie est le code propre de ce dépôt (SySL 1.0). Tout ce qui est copyleft
reste hors du crate :

| Composant | Rôle | Licence | Frontière |
|---|---|---|---|
| `ayane-smtpd` | SMTP entrant/sortant, vérification, file d'attente, remise, maildir | SySL 1.0 | ce crate |
| `ayane-engine` | rendus déterministes des configurations Postfix/Dovecot retirées | SySL 1.0 | ce crate |
| maildir | le format de boîte sur disque (`new`/`cur`/`tmp` par dossier) | — | une disposition de fichiers |

Volontairement **non** utilisés : Stalwart (AGPL-3.0), mailcow (GPL-3.0, embarque SOGo
AGPL-3.0), Roundcube / SnappyMail (le webmail est le nôtre) et `acme.sh`
(GPL-3.0 — l'ACME se fait en Rust avec `instant-acme`, Apache-2.0). La liste autorisée de
`cargo deny` dans `deny.toml` impose le versant dépendances de cette règle.

## Organisation du dépôt

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

## Démarrage rapide (développement)

```bash
cargo run -p ayane
curl -s http://127.0.0.1:3023/api/health
```

Cette adresse d'écoute n'est qu'une candidate pour le développement local ; c'est le
registre de déploiement qui attribue le vrai port au moment du déploiement, et
`AYANE_LISTEN` la remplace.

## Paramètres de déploiement

Le tableau complet se trouve dans [`deploy/README.md`](../../deploy/README.md). En bref, une
instance est décrite par : le ou les domaines de messagerie, le nom d'hôte public, la source
du certificat (monté / téléversé / ACME), le DSN PostgreSQL, le relais sortant et
l'administrateur initial. Fournissez-les en variables d'environnement ; ne validez jamais
de valeurs réelles.

## Feuille de route

- **Stage 0** — squelette de l'espace de travail, moteurs de rendu de configuration,
  surface de santé, tableau des paramètres de déploiement et check-list de vérification
  des moteurs.
- **Stage 1** — le moteur de messagerie (SMTP entrant, vérification, file d'attente,
  remise, sortant) et le plan de contrôle : domaines, comptes, alias, boîtes partagées,
  politique catch-all, audit, boucle de rechargement.
- **Stage 2** — API et interface webmail sur hikari : rendu sûr, proxy d'images côté
  serveur, hachage des pièces jointes, aperçu en bac à sable.
- **Stage 3** — protection plus profonde : heuristiques anti-hameçonnage, circuit de
  quarantaine, assistant DNS avec vérifications en direct.
- **Stage 4** — outils MCP (surtout en lecture, envoi avec un humain dans la boucle) et
  prompts de déploiement pour les agents.

## Licence

SySL 1.0 — voir [LICENSE](../../LICENSE).
