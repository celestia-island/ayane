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
- **运行期引擎一律独立进程**：Postfix / Dovecot(+Pigeonhole) / rspamd / ClamAV / Valkey 只经网络、文件或
  SQL 交互——不链接、不 vendored、不打补丁进本仓。
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
- `ayane-engine`：纯渲染，输出 Postfix / Dovecot / rspamd 配置文本。
- `ayane`（core）：HTTP 面 + 进程生命周期；不直接解析邮件。
- 渲染必须确定性：同一状态两次输出逐字节相同，**先 diff 再写盘再 reload**。
- 版本声明两段式（`^1` / `^0.8`）；禁三段式、`^*`、`^0.*`、裸 `*`、`latest`。

## 凭据与部署参数

- 部署参数（域名、DSN、中继凭据、证书路径）全部走环境变量 / `.env`（0600），示例一律占位符。
- 真实凭据只落 `/mnt/codespace/_secure/`（工作区红线 1），不进本仓、不进 PR、不进日志。