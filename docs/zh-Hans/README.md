# Ayane

<div align="center">
  <strong>Celestia 自建邮件服务——管理面、网页客户端与防护层，跑在成熟的 Postfix/Dovecot 栈上</strong>
</div>

> **状态：已上线。** 控制面、渲染 Webmail、防护层与 Celestia ID 登录已跑在生产 rig
> （`mail.acgsyzx.me`）；邮件引擎（Postfix / Dovecot / rspamd / ClamAV）已部署，DKIM、
> SPF、DMARC 齐。入站 25 实测通、rspamd 在门口拒垃圾；对大厂出站有限流（PTR 已生效，
> Postfix 自动重试）。

## 名字

**Ayane（奥空 アヤネ）**，《蔚蓝档案》阿拜多斯对策委员会的**秘书兼通信员**：
守规矩、记账、把消息送到该到的地方。秘书 → 信箱与账号管理；通信员 → 路由与转发；
守规矩 → 策略与审计；账本 → 审计留痕。

## 它做什么、不做什么

- **做**：域/账号/别名/共享信箱/catch-all 策略、隔离区、审计；网页客户端与安全渲染
  （远程内容默认不加载、服务端图片代理、附件只哈希 + 沙箱预览、钓鱼链接告警）；部署与
  DNS 向导；面向 agent 的 MCP 工具面。
- **不做**：SMTP/IMAP/存储协议栈。这些交给 Postfix、Dovecot、rspamd、ClamAV——**独立进程**，
  不进本仓、不链接、不 vendor。

## 许可边界

本仓 = SySL 1.0。引擎组件各自独立进程（Postfix IPL/EPL、Dovecot LGPL-2.1、rspamd Apache-2.0、
ClamAV GPL-2.0、Valkey BSD-3-Clause）；`deny.toml` 的 allow-list 禁掉 AGPL/GPL/LGPL 的 Rust 依赖。
明确不用：Stalwart（AGPL-3.0）、mailcow（GPL-3.0 + SOGo AGPL-3.0）、Roundcube/SnappyMail、acme.sh。

## 开发

```bash
cargo run -p ayane
curl -s http://127.0.0.1:3023/api/health
just gate   # fmt / clippy -D warnings / test / cargo deny
```

部署参数与验证清单见 [`deploy/README.md`](../../deploy/README.md)。