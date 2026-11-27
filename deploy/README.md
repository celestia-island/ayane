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

### 1.1 邮件面（同进程，默认关闭）

`ayane serve` 一旦打开邮件段就在**本进程**里同时跑控制面与邮件面（SMTP 监听、投递消费、出站），
不再需要 Postfix/Dovecot 容器。默认关闭：不设 `AYANE_MAIL_ENABLED` 时进程行为与打开前逐字节一致
（不绑端口、不开 spool、不起任何任务）。

| 参数 | 默认 | 说明 |
|---|---|---|
| `AYANE_MAIL_ENABLED` | `0` | `1` 打开邮件面；打开后 `AYANE_MAIL_LISTENERS` 与 `AYANE_MAIL_HOSTNAME` 为必填 |
| `AYANE_MAIL_HOSTNAME` | `localhost` | 问候语 / `Received:` / DMARC `authserv-id` 的名；`localhost` 会被拒绝启动 |
| `AYANE_MAIL_LISTENERS` | 空 | 逗号分隔的 `role@addr[,cert=PATH][key=PATH]`；role = `inbound` / `submission` / `submissions-tls`（后两个需证书） |
| `AYANE_MAIL_SPOOL_ROOT` | `$AYANE_STATE_DIR/spool` | 待投递队列根；**不可**与 `mail_root` 相同或互为子目录 |
| `AYANE_MAIL_ROOT` | `$AYANE_STATE_DIR/mail` | 落盘 maildir 根（spool 的兄弟目录，块⑤ 保留名教训） |
| `AYANE_MAIL_STATE` | `$AYANE_STATE_DIR/desired-state.json` | 投递消费与 DKIM 签名读取的路由快照；**由 `admin.apply` 写入**。设成别的路径会在启动期被拒（degraded，cause `state_path`）：消费端读的文件必须就是 apply 写的那个 |
| `AYANE_MAIL_MAX_MESSAGE_SIZE` | `26214400` | `SIZE` 上限（字节） |
| `AYANE_MAIL_MAX_HEADER_BYTES` | `1048576` | 头段上限（超限 `552 5.3.4`） |
| `AYANE_MAIL_PER_IP_LIMIT` | `8` | 单 IP 并发连接数 |
| `AYANE_MAIL_RETRY_MAX_AGE_SECONDS` | `432000` | 重试地平线（RFC 5321 §4.5.4.1 = 5 天） |
| `AYANE_MAIL_RETRY_MAX_ATTEMPTS` | `0` | 尝试上限，`0` = 用策略默认 |
| `AYANE_MAIL_QUOTA_BYTES` | `0` | 单信箱配额，`0` = 不限 |
| `AYANE_MAIL_DELIVERY_INTERVAL_SECONDS` | `30` | 空闲时投递轮询上限 |
| `AYANE_MAIL_OUTBOUND` | `0` | `1` = 域外收件人经 MX 直投（需 25 出站与 PTR） |
| `AYANE_MAIL_SMTP_PORT` | `25` | 出站连接端口 |
| `AYANE_MAIL_DKIM_KEY_ENV` | 空 | 每个域的签名私钥所在环境变量模板，如 `AYANE_DKIM_KEY_{domain}`（域名的点写成 `_`） |
| `AYANE_MAIL_REQUIRE_START` | `0` | `1` = 邮件面起不来就让进程退出（否则 degraded + 控制面继续服务） |

启动顺序因此是：起控制面（邮件段同时绑定）→ 建域/建账号 → `admin.apply`（写 `desired-state.json`
与各渲染表）→ 收信。**投递消费按 `AYANE_MAIL_STATE` 路由**：首次 apply 之前它读不到快照，会把这一轮
记为跳过（日志 `the state snapshot cannot be used`），队列里的信件不会丢，apply 之后自动投递。

分进程形态仍然可用：`ayane-smtpd --serve` / `--deliver` 读同一份 `desired-state.json` 与同一个 spool。
**该形态没有计数器**：`admin.net.traffic` 显示为空（「没有对端」与「没有计数表」是同一张空表），
所以同进程未开启邮件段时它同样是空的——这是计数的所在，不是故障。

分进程形态的 submission 监听器要真校验凭据，需带 `--password-hashes <apply 渲染的 dovecot passwd>`：
`ayane-smtpd` 已**没有**「放行所有登录」的开关（`--submission-authenticates` 已删除），不带 hash 文件时
它照常收信、但拒绝一切登录。

### 1.2 邮件面起不来时

`ayane serve` **不会**因为邮件面配错而整体退出：进程继续提供 API / RPC，`/api/health` 回 `200` 但
`status` 为 `degraded`，并带 `mail.degraded.{cause,retryable,reason}`。cause 取值：
`listeners`（无监听器 / submission 无证书）、`hostname`、`spool`、`roots`、`state`、`state_path`、
`tls`、`outbound`、`bind`（端口被占，唯一 `retryable: true` 的一类）。
部署脚本若要求「邮件面必须起来」，设 `AYANE_MAIL_REQUIRE_START=1`，那时启动失败才让进程退出。

前门反向代理须把浏览器的原始 `Host` 头原样透传给 ayane（Caddy 的 `reverse_proxy` 默认如此；nginx 须显式
`proxy_set_header Host $host;`）——否则 `/api/ws` 的同源校验（比对 `Origin` 与 `Host`）会以 403
拒绝浏览器的每一次 WebSocket 升级；不带 `Origin` 头的非浏览器客户端不受影响。

## 2. 安装顺序

1. 解析域名：`AYANE_HOSTNAME` 的 A/AAAA 与邮件域的 MX 指向本实例入口。
2. 起 PostgreSQL，建库建角色；DSN 写进 `.env`。
3. （可选）起老引擎容器：`ayane serve` 自带的邮件面已在步骤 4 内，这一步只对「读侧仍由 Dovecot 提供
   IMAP」的既有实例有意义；新实例不需要它。
4. 起控制面（`ayane serve`，邮件段打开时同一进程即绑定 SMTP 监听）；`/api/health` 返回 `status=ok`。
5. 控制面渲染配置文件并写路由快照（先 diff 再写盘）→ 热替换监听器配置；投递消费随即读到快照。
   **不再有 `docker compose exec … reload`**：邮件面在本进程内，reload = 换 `Arc<ServerConfig>`。
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