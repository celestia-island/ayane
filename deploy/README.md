# 部署参数与 Stage 0 验证清单

本目录是**部署面文档**：一个实例需要哪些参数、按什么顺序安装、装完怎么证明它是通的。
设计理由不写在这里（进 PR 描述）；这里只写**可执行的操作与判据**。

> 当前状态：Stage 0 骨架。下面的参数表与检查清单是**目标形态**，compose 落地后逐条打勾。

## 1. 参数表

所有参数经环境变量 / `.env`（0600）注入，真实值不进仓库。示例一律占位符。

| 参数 | 示例 | 说明 |
|---|---|---|
| `AYANE_DOMAIN` | `example.com` | 主邮件域；多域用逗号分隔 |
| `AYANE_HOSTNAME` | `mail.example.com` | 公网主机名，证书与 MX 指向它 |
| `AYANE_LISTEN` | `127.0.0.1:3023` | 控制面 HTTP 监听（仅回环，前门由反向代理终结） |
| `AYANE_DATABASE_URL` | `postgres://ayane:<password>@db:5432/ayane` | 控制面唯一权威库 |
| `AYANE_DB_PASSWORD` | `<password>` | 首次初始化用；之后只从 `.env` 读 |
| `AYANE_CERT_MODE` | `volume` / `upload` / `acme` | `volume`：挂载既有证书；`upload`：手工上传；`acme`：内置申请 |
| `AYANE_CERT_PATH` | `/etc/ayane/tls/fullchain.pem` | `volume` / `upload` 模式的证书路径 |
| `AYANE_CERT_KEY_PATH` | `/etc/ayane/tls/privkey.pem` | 私钥路径（600） |
| `AYANE_ACME_EMAIL` | `ops@example.com` | `acme` 模式的账户邮箱 |
| `AYANE_RELAY_HOST` | `smtp.relay.example:587` | 出站中继；留空则直投（需 PTR + 25 出站） |
| `AYANE_RELAY_USER` / `AYANE_RELAY_PASSWORD` | `<user>` / `<password>` | 中继凭据 |
| `AYANE_BOOTSTRAP_ADMIN` | `admin@example.com` | 空实例首登账号（注册默认关闭，首登即管理员） |
| `AYANE_QUARANTINE_ADDRESS` | `quarantine@example.com` | 隔离区收件地址 |
| `AYANE_LOG` | `ayane=info` | `tracing` 过滤串 |

前门反向代理须把浏览器的原始 `Host` 头原样透传给 ayane（Caddy 的 `reverse_proxy` 默认如此；nginx 须显式
`proxy_set_header Host $host;`）——否则 `/api/ws` 的同源校验（比对 `Origin` 与 `Host`）会以 403
拒绝浏览器的每一次 WebSocket 升级；不带 `Origin` 头的非浏览器客户端不受影响。

## 2. 安装顺序

1. 解析域名：`AYANE_HOSTNAME` 的 A/AAAA 与邮件域的 MX 指向本实例入口。
2. 起 PostgreSQL，建库建角色；DSN 写进 `.env`。
3. 起引擎容器：Postfix → Dovecot → rspamd → ClamAV → Valkey（顺序见 compose）。
4. 起控制面；`/api/health` 返回 `status=ok`。
5. 控制面渲染 Postfix / Dovecot / rspamd 配置 → 校验 → reload（先 diff 再写盘）。
6. 建域、建首个账号、配隔离区与策略。
7. 证书：`volume` / `upload` / `acme` 三选一，`openssl s_client` 验链。
8. 出站：中继凭据实测一封；无中继则确认 PTR 与 25 出站。

## 3. DNS 记录（向导会逐条检查）

| 记录 | 名称 | 期望 |
|---|---|---|
| MX | `@` | `10 mail.example.com.` |
| A/AAAA | `mail` | 实例入口 |
| SPF | `@` | `v=spf1 mx -all`（有中继时按中继要求追加 `include:`） |
| DKIM | `<selector>._domainkey` | rspamd 生成的公钥（1024/2048 位） |
| DMARC | `_dmarc` | `v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com` |
| PTR | 入口 IP | 反解到 `mail.example.com`（直投时必需） |
| MTA-STS | `_mta-sts` + `mta-sts` | 可后置；有证书后加 |
| TLS-RPT | `_smtp._tls` | 可后置 |

## 4. Stage 0 验证清单（逐条留证）

| # | 验证项 | 判据 |
|---|---|---|
| 1 | 入站 25 | 外部主机 `nc -vz <entry> 25` 通，且 `EHLO` 返回 250 |
| 2 | 出站 25 / 中继 | 实发一封到外部邮箱，SPF/DKIM/DMARC 三绿 |
| 3 | 收信到信箱 | 外部 → `@example.com` 落进 Dovecot，IMAP 可读 |
| 4 | catch-all + 白/黑名单 | 未知收件人进指定信箱；黑名单拒；白名单外进隔离 |
| 5 | 共享邮箱 ACL | 两个账号可同时打开同一信箱，第三个账号被拒 |
| 6 | 自动转发 / Sieve | 转发规则生效；保留副本开关按预期 |
| 7 | 病毒扫描 | EICAR 测试件被 ClamAV 拦下并进隔离 |
| 8 | 证书 | `volume` / `upload` / `acme` 三模式各验一次链与到期时间 |

第 1 项是**立项出口闸**：入口若拿不到公网 25，必须改走「中继收 + 中继发」或「CF Email
Routing 收 + 中继发」，并回写本表。