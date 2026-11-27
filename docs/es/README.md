---
title: "Ayane"
description: "El servicio de correo que opera Celestia — su propio motor SMTP, una ruta de lectura maildir y un plano de control."
---

<div align="center">
  <img src="https://raw.githubusercontent.com/celestia-island/celestia-island.github.io/main/res/logos/ayane.webp" alt="ayane" width="180" />
</div>

<h1 align="center">Ayane</h1>

<div align="center">
  <strong>El servicio de correo que opera Celestia — su propio motor SMTP, una ruta de lectura maildir y un plano de control</strong>
</div>

<br />

> **Estado: en producción.** El plano de control, el webmail renderizado y el inicio de
> sesión con Celestia ID funcionan en el entorno de producción (`mail.acgsyzx.me`). El motor
> de correo es código propio de este repositorio: `crates/smtpd` habla SMTP de entrada y de
> envío, verifica SPF/DKIM/ARC/DMARC, entrega en maildirs y envía el correo de otros dominios
> por MX con firma DKIM. El webmail lee esos mismos maildirs directamente: ya no hay servidor
> IMAP en la pila ni Dovecot que configurar.

## Por qué existe

El correo autoalojado es un problema resuelto en la capa del *motor* y sin resolver en la
capa de la *organización*: buzones compartidos, catch-all con política de permitidos y
denegados, cuarentena, renderizado seguro, un asistente de DNS que un operador pueda seguir
de verdad y una superficie para agentes. Ayane construye esa capa y habla SMTP y el formato
maildir por sí mismo, en vez de configurar el demonio de otro.

## El nombre

El nombre viene de **Ayane Okusora (奥空 アヤネ)**, de Blue Archive — en español se
transcribe tal cual, «Ayane Okusora», del japonés «cielo vacío»: secretaria y oficial de
comunicaciones del Comité de Contramedidas de Abidos, guardiana de las normas que lleva el
registro del comité. Secretaria → administración de buzones, oficial de comunicaciones →
encaminamiento, guardiana de las normas → política y auditoría, registro → rastro de
auditoría.

El emblema —una marca dibujada a mano con lápices de colores, en el estilo de la casa
lacrymira, servida desde el sitio de la organización— codifica la misma lectura: su aureola
con forma de retícula (la llevanza precisa del registro), los auriculares con micrófono de
caña (la oficial de comunicaciones), el sobre (el correo) y un único acento rojo por sus
gafas de montura roja.

## Arquitectura

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

## Motores y licencias

El motor de correo es código propio de este repositorio (SySL 1.0). Todo lo copyleft queda
fuera del crate:

| Componente | Función | Licencia | Frontera |
|---|---|---|---|
| `ayane-smtpd` | SMTP de entrada/salida, verificación, cola, entrega, maildir | SySL 1.0 | este crate |
| `ayane-engine` | renderizadores deterministas de las configuraciones retiradas de Postfix/Dovecot | SySL 1.0 | este crate |
| maildir | el formato de buzón en disco (`new`/`cur`/`tmp` por carpeta) | — | una disposición de archivos |

Deliberadamente **no** se usan: Stalwart (AGPL-3.0), mailcow (GPL-3.0, incluye SOGo
AGPL-3.0), Roundcube / SnappyMail (el webmail es nuestro) ni `acme.sh`
(GPL-3.0 — ACME se hace en Rust con `instant-acme`, Apache-2.0). La lista permitida de
`cargo deny` en `deny.toml` impone el lado de dependencias de esta regla.

## Estructura del repositorio

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

## Inicio rápido (desarrollo)

```bash
cargo run -p ayane
curl -s http://127.0.0.1:3023/api/health
```

Esta dirección de escucha solo es una candidata para desarrollo local; el registro de
despliegue asigna el puerto real cuando se despliega el servicio, y `AYANE_LISTEN` la
sustituye.

## Parámetros de despliegue

La tabla completa está en [`deploy/README.md`](../../deploy/README.md). En resumen, una
instancia se describe con: el dominio o los dominios de correo, el nombre de host público,
el origen del certificado (montado / subido / ACME), el DSN de PostgreSQL, el relay de
salida y el administrador inicial. Pásalos como variables de entorno; nunca confirmes
valores reales.

## Hoja de ruta

- **Stage 0** — esqueleto del espacio de trabajo, renderizadores de configuración,
  superficie de salud, tabla de parámetros de despliegue y la lista de verificación de los
  motores.
- **Stage 1** — el motor de correo (SMTP entrante, verificación, cola, entrega, saliente)
  y el plano de control: dominios, cuentas, alias, buzones compartidos, política catch-all,
  auditoría y el bucle de recarga.
- **Stage 2** — API e interfaz de webmail sobre hikari: renderizado seguro, proxy de
  imágenes en el servidor, hash de los adjuntos, vista previa en caja de arena.
- **Stage 3** — más profundidad en la protección: heurísticas de phishing, flujo de
  cuarentena, asistente de DNS con comprobaciones en vivo.
- **Stage 4** — herramientas MCP (sobre todo de lectura, envío con una persona en el
  bucle) y prompts de despliegue para agentes.

## Licencia

SySL 1.0 — consulta [LICENSE](../../LICENSE).
