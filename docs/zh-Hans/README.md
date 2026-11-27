---
title: "Ayane"
description: "Celestia 自建的邮件服务——自写 SMTP 引擎、maildir 读路径与管理面。"
---

<div align="center">
  <img src="https://raw.githubusercontent.com/celestia-island/celestia-island.github.io/main/res/logos/ayane.webp" alt="ayane" width="180" />
</div>

<h1 align="center">Ayane</h1>

<div align="center">
  <strong>Celestia 自建的邮件服务——自写 SMTP 引擎、maildir 读路径与管理面</strong>
</div>

<br />

> **状态：已上线。** 控制面、渲染 Webmail 与 Celestia ID 登录已跑在生产
> rig（`mail.acgsyzx.me`）。邮件引擎是本仓自己的代码：`crates/smtpd` 收发 SMTP、
> 验证 SPF/DKIM/ARC/DMARC、投递进 maildir，域外信件经 MX 带 DKIM 签名送出。
> Webmail 直接读同一棵 maildir——栈里已经没有 IMAP 服务器，也没有 Dovecot 要配。

## 为什么要做这件事

自建邮件在**引擎**层是已经解决的问题，在**组织**层却还没有：共享信箱、
带允许/拒绝策略的 catch-all、隔离区、安全渲染、一份运维人员真能照着走的 DNS 向导，
以及一层给 agent 用的接口。Ayane 做的就是这一层，SMTP 与 maildir 格式则自己讲，
而不是去配别人的守护进程。

## 名字

名字取自《蔚蓝档案》的**奥空 アヤネ**：阿拜多斯对策委员会的秘书兼通信员，
守规矩、记着委员会的账本。秘书 → 信箱管理；通信员 → 路由；守规矩 → 策略与审计；
账本 → 审计留痕。

徽记是 lacrymira 家族风格的手绘彩铅标志，由组织站点提供，画的正是同一组对应：
准星状光环（一丝不苟的记账人）、带悬臂麦的耳麦（通信员）、信封（邮件），
以及一抹叠在她红框眼镜上的红色强调。

## 架构

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

## 引擎与许可

邮件引擎是本仓自己的代码（SySL 1.0）。一切 copyleft 留在 crate 之外：

| 组件 | 职责 | 许可 | 边界 |
|---|---|---|---|
| `ayane-smtpd` | SMTP 收发、验证、队列、投递、maildir 读写 | SySL 1.0 | 本 crate |
| `ayane-engine` | 已退役的 Postfix / Dovecot 配置的确定性渲染器 | SySL 1.0 | 本 crate |
| maildir | 磁盘上的信箱格式（每个文件夹 `new`/`cur`/`tmp`） | — | 一种文件布局 |

明确**不**引入：Stalwart（AGPL-3.0）、mailcow（GPL-3.0，含 SOGo AGPL-3.0）、
Roundcube / SnappyMail（Webmail 是自己的）、`acme.sh`（GPL-3.0——ACME 用 Rust 的
`instant-acme`，Apache-2.0）。`deny.toml` 的 `cargo deny` 允许清单强制执行这条的依赖侧。

## 仓库结构

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

## 快速开始（开发）

```bash
cargo run -p ayane
curl -s http://127.0.0.1:3023/api/health
```

这个监听地址只是本地开发的候选值；真实端口在服务部署时由部署账本分配，
`AYANE_LISTEN` 可覆盖。

## 部署参数

完整表格在 [`deploy/README.md`](../../deploy/README.md)。简言之，一个实例由这些描述：
邮件域名、对外主机名、证书来源（挂载 / 上传 / ACME）、PostgreSQL DSN、出站中继，
以及引导管理员。全部以环境变量提供；真实值绝不进版本库。

## 路线图

- **Stage 0** — 工作区骨架、配置渲染器、健康检查面、部署参数表与引擎验证清单。
- **Stage 1** — 邮件引擎（入站 SMTP、验证、队列、投递、出站）与控制面：
  域名、账号、别名、共享信箱、catch-all 策略、审计、重载循环。
- **Stage 2** — 建在 hikari 上的 Webmail API 与界面：安全渲染、服务端图片代理、
  附件哈希、沙箱预览。
- **Stage 3** — 防护纵深：钓鱼启发式判断、隔离区流程、带活体检查的 DNS 向导。
- **Stage 4** — MCP 工具（以读为主、发信需人在环内）与 agent 部署提示词。

## 许可

SySL 1.0——见 [LICENSE](../../LICENSE)。
