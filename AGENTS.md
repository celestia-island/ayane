# AGENTS.md — ayane 不变量

> 规则本体来自工作区 `/mnt/codespace/AGENTS.md`；本文件只写本仓特有、且**改动时应先读**的约束。

## 提交署名

- 作者/提交者一律 = 伊欧 `<langyo.china@gmail.com>`（repo 级 git config 已设）。
- 智能体经手的提交追加尾注 `Co-authored-by: demiurge <demiurge@celestia.world>`——额外署名，不顶替作者；
  squash 的 `squash_commit_message` 同样带该尾注。

## 分支

- **本机开发期**（2026-11-22 用户裁决）：`master` = 基线，`dev` = 迭代分支。
- 推远端后收敛为 `master` 单主干（worktree + feature 分支 + PR + squash merge），`dev` 届期删除；
  不设长期 `dev`。

## 许可证边界（硬约束）

- 本仓许可 = SySL 1.0（`LICENSE`）。
- **运行期引擎是自写代码**：SMTP 收/发、SPF·DKIM·ARC·DMARC 验证、队列、投递与 maildir 读写都在
  `crates/smtpd`（SySL 1.0）。`ayane-engine` 只保留对已退役 Postfix/Dovecot 配置的确定性渲染器；
  任何第三方守护进程都只经网络、文件或 SQL 交互——不链接、不 vendored、不打补丁进本仓。
- **禁 AGPL / GPL / LGPL 的 Rust 依赖**：`deny.toml` 的 allow-list 是判据，`just licenses` 必须绿。
- 明确不引入：Stalwart（AGPL-3.0）、mailcow（GPL-3.0，且含 SOGo AGPL-3.0）、Roundcube / SnappyMail、
  acme.sh（GPL-3.0；ACME 用 Rust `instant-acme`，Apache-2.0）。

## 门禁

`just gate` = `cargo fmt --check` → `cargo clippy --workspace --all-targets -- -D warnings` →
`cargo test --workspace` → `cargo deny check licenses bans sources`。

CI 不在 PR 上跑（工作区口径）：`ci.yml` 仅 `workflow_dispatch`；`depspec-lint` / `family-versions` /
`verify-versions` 只在 `master` 推送时跑。

## 代码边界

- `ayane-proto`：纯数据 + 校验，无 I/O、无时钟。
- `ayane-mail`：纯路由 / 收件人策略 / MIME 构造（`lettre` 只做**客户端**）。
- `ayane-engine`：纯渲染，输出已退役 Postfix / Dovecot / rspamd 配置文本（现行邮件面不读它）。
- `ayane-store`：redb 持久化（经 lacrymira KV 面）+ 密码哈希；快照式存取，无部分态。
- `ayane`（core）：HTTP 面 + apply 循环 + 进程生命周期。Webmail 的 `mail.*` 读路径经
  `ayane_smtpd::MaildirReader` 直接读 maildir，**不**起任何 IMAP 连接；消息 id = maildir 文件名
  （`:2,<flags>` 后缀，改名即改旗标），RPC 字段名 `uid` 不变、值域变了。
- `ayane-smtpd`：本仓自写的邮件面（收信 / 队列 / 投递 / 出站 / 计数器）。`ayane serve` 在
  `AYANE_MAIL_ENABLED=1` 时于**同一进程**内跑它（`crates/core/src/engine.rs`），reload = 热替换
  `Arc<ServerConfig>`；`ayane-smtpd --serve/--deliver` 是分进程形态。`admin.net.traffic` 读
  `ayane_smtpd::metrics` 的结构化计数，不再解析任何日志文本。
- 渲染必须确定性：同一状态两次输出逐字节相同，**先 diff 再写盘再 reload**。
- `crates/core/tests/engine_e2e.rs` 是同进程邮件面的端到端（真 socket 收信 → maildir → 计数 → apply/reload），
  不需要任何外部服务；`crates/core/tests/smoke.rs` 是 `#[ignore]` 的活体冒烟（要一个跑着的实例）：
  `just serve`（`AYANE_MAIL_ENABLED=1`）后 `AYANE_ADMIN_TOKEN=… cargo test -p ayane --test smoke -- --ignored --nocapture`。
- 端口（node-1 本机回环，登记在 `_ledger/ports-and-domains.md`）：3023 ayane API。IMAP（3043）与
  Postfix submission（30587）随旧 rig 一并退役，现行邮件面 = `AYANE_MAIL_LISTENERS`。
- 版本声明两段式（`^1` / `^0.8`）；禁三段式、`^*`、`^0.*`、裸 `*`、`latest`。

## 凭据与部署参数

- 部署参数（域名、DSN、中继凭据、证书路径）全部走环境变量 / `.env`（0600），示例一律占位符。
- 真实凭据只落 `/mnt/codespace/_secure/`（工作区红线 1），不进本仓、不进 PR、不进日志。