# oidctenant —— 多租户 OIDC 登录与账号关联 API

无前端的后端服务，演示并落地以下安全目标：

1. **业务身份只基于已核实的提供方组合** `(tenant_id, issuer, subject)`，
   `email` 仅作展示，绝不参与账号匹配 —— 两家企业的员工邮箱相同也不会串号。
2. 完整校验 OIDC 授权码流程的**签名、受众（aud/azp）、issuer、有效期、nonce、state、PKCE**。
3. **账号关联要求两个身份各自重新认证**（OIDC `prompt=login` + `auth_time` 新鲜度窗口）。
4. **登录/关联回调重复到达不会创建多个成员**（state 一次性消费 + 咨询锁 + 唯一约束）。
5. **只允许已配置的回调地址**（精确白名单匹配）。
6. **身份令牌绝不写进日志**（只记录错误分类，不记录 code/token）。

## 目录结构

```
cmd/server/             HTTP 服务入口（含过期 state 定时清理）
cmd/seed/               幂等写入租户与 IdP 配置
internal/config/        环境配置
internal/db/            pgx 连接池 + 嵌入式 SQL 迁移
internal/models/        持久化数据结构
internal/store/         所有 PostgreSQL 访问（事务、咨询锁、原子关联）
internal/oidcx/         go-oidc + oauth2 封装（发现/校验/交换/PKCE/nonce）
internal/auth/          state/nonce/PKCE/会话令牌随机值与哈希、回调白名单
internal/api/           HTTP handler：登录、回调、me、登出、账号关联
deploy/keycloak/import  acme / globex 两个测试 realm（含同邮箱用户）
deploy/seed.json        租户/IdP 的 seed 规格
integration/            针对真实 Keycloak + 真实 PostgreSQL 的端到端集成测试
```

## 数据模型要点

| 表 | 关键约束 / 含义 |
| --- | --- |
| `tenants` | 租户 |
| `identity_providers` | 租户**授权**的 `(issuer, client_id, secret, redirect_uris[])`，按 `(tenant_id, issuer)` 唯一 |
| `members` | 租户内的成员（业务账号） |
| `identities` | 已核实身份；**`UNIQUE(tenant_id, issuer, subject)` 是身份锚点**；`email` 无唯一约束 |
| `auth_requests` | 进行中的授权请求：`state` 主键 + `nonce` + `pkce_verifier`，一次性消费（`consumed_at`） |
| `sessions` | 不透明会话令牌（数据库存 SHA-256 哈希），含设备展示标签 `device_label`、`last_seen_at`/`last_ip` 最近活动、`revoked_at`/`revoked_reason` 活跃/已撤销状态 |
| `link_sessions` | 账号关联会话：A/B 两条 leg 的 issuer/subject/auth_time，一次性 token |

> 关联外部身份时，身份行的 `tenant_id` 是**发起关联的租户**。
> 因此 A 公司成员关联 B 公司 IdP 的身份，锚点是 `(A租户, B的issuer, subject)`，
> 与 B 公司自己的同名身份互不影响。

## API

所有业务错误返回稳定的 JSON：

```json
{ "error": "<error_type>", "message": "<human readable>" }
```

| error_type | HTTP | 触发场景 |
| --- | --- | --- |
| `authentication_failed` | 401 | 签名/受众/issuer/过期/nonce/PKCE/授权码交换失败、会话无效 |
| `tenant_unauthorized` | 403 | 租户未启用该 issuer、provider 被禁用、跨租户使用会话 |
| `binding_conflict` | 409 | 目标身份已绑给别的成员、自关联、关联会话重放 |
| `invalid_request` | 400 | state 缺失/已用/伪造、回调地址不在白名单、参数非法 |
| `reauthentication_required` | 401 | 关联时某一身份未在 `auth_time_max_age` 窗口内重新认证 |
| `not_found` | 404 | 撤销的设备会话不属于当前成员/租户（与“不存在”不可区分，防枚举） |
| `temporarily_unavailable` | 503 | 撤销与受保护请求竞争行锁超时，可安全重试 |

端点：

| 方法/路径 | 说明 |
| --- | --- |
| `GET  /healthz` | 健康检查 |
| `GET  /t/{slug}/login?issuer=...&return_to=/...` | 发起登录，302 到 IdP |
| `GET  /oauth/callback` | 登录回调（固定路径） |
| `GET  /t/{slug}/api/me` | 当前成员与其已绑定身份（需会话 Cookie `sid`） |
| `POST /t/{slug}/api/logout` | **只**吊销当前这台设备的会话（单设备退出语义保持不变） |
| `GET  /t/{slug}/api/sessions` | 列出当前成员在当前租户的设备会话（标签/创建/最近活动/活跃·已撤销/是否当前） |
| `POST /t/{slug}/api/sessions/{id}/revoke` | 撤销指定的某台设备（其他设备或当前设备）；重复撤销幂等 |
| `POST /t/{slug}/api/sessions/revoke-all` | 全部设备退出；body `{"include_current": false}` 表示只下线其他设备 |
| `POST /t/{slug}/api/links` | 发起账号关联，返回 `link_token` 与 `link_url`；body `{"issuer":"..."}` |
| `GET  /oauth/link/callback` | 关联第二身份的回调（强制重认证） |
| `GET  /t/{slug}/api/links/{token}` | 查询关联会话状态（一次性） |

## 设备会话管理（丢失设备只下线那一台）

在不透明 `sid` 之上为每条会话保存**不含令牌内容**的展示信息：

- `device_label`：登录时从 `User-Agent` 派生（剥离 CR/LF 等控制字符、截断 200 字符）；
- `created_at` / `last_seen_at` / `last_ip`：创建与最近活动；
- 状态：`active`（`revoked_at IS NULL` 且未过期）或 `revoked`。

**只暴露随机会话 UUID（v4），与 `sid` 不可互相推导；任何响应、列表、日志都不返回
原始 `sid`、`token_hash`、授权码或身份令牌。**

并发与撤销竞争的正确性来自数据库行锁（PostgreSQL `SELECT ... FOR UPDATE`）：

- 受保护请求在中间件里开启事务、`FOR UPDATE` 锁住本会话行，**锁持有整个请求期间**，
  并在同事务校验未撤销/未过期、刷新 `last_seen_at`；
- 撤销（单台/全部）对目标行 `FOR UPDATE` 后才写 `revoked_at`。
  因此撤销与该会话上的受保护操作被**线性化**：撤销先拿锁则请求拿锁即见 `revoked_at`
  → 401，绝不放行写入；请求先拿锁则撤销阻塞到请求结束，不存在“撤销后仍写入成功”；
- 全部退出按会话 `id` 排序加锁，避免并发批量撤销之间的 AB-BA 死锁；
  `lock_timeout` + 死锁检测在上层统一映射为 503（可安全重试）；
- 当前会话撤销自身（`logout`、撤销当前设备、含当前的全部退出）复用请求自己的租约事务，
  “响应完成”与“会话已撤销”是同一个提交点，并清理 `sid` Cookie；
- 其他成员 / 其他租户 / 未知的会话 id 返回完全一致的 `404 not_found`，无法枚举；
  跨租户携带他租户 `sid` 仍为 403（既有隔离语义不变）。

## 安全实现细节

- **state / nonce / PKCE**：均为 ≥256/128-bit 加密随机值，服务端持久化；
  PKCE 使用 S256；回调时 state 行被 `SELECT ... FOR UPDATE` 原子取出并标记消费，
  未知 state 与已消费 state 返回完全一致的错误（不泄露有效性）。
- **ID token 校验**（`internal/oidcx`，基于 coreos/go-oidc v3）：
  - 签名经 IdP JWKS 验证；go-oidc 的远程 KeySet 在遇到未知 `kid` 时自动重取 JWKS，
    **密钥轮换对应用透明**；
  - `iss` 必须等于发现文档 issuer；`aud` 必须包含本 client_id；`azp`（若有）必须等于本 client；
  - 过期/nbf/iat 由 go-oidc 校验；`nonce` 与 state 行中的值逐字节比较。
- **重复回调不重复建成员**：`LoginOrRegisterMember` 在事务内先取
  `pg_advisory_xact_lock(hashtextextended(issuer|subject))`，再查/插成员与身份；
  叠加 `UNIQUE(tenant_id, issuer, subject)`，并发首次登录也只产生一个成员。
- **账号关联双重认证**：发起记录 A 的认证时刻；对 B 的授权请求强制
  `prompt=login&max_age=0`，回调核对 IdP 的 `auth_time`；
  `CompleteLink` 在单事务里复核两条 leg 的新鲜度、A 锚点未被改动、B 非自身、
  B 是否已属于他人（冲突则整体回滚，不写入）。
- **回调白名单**：`redirect_uri` 与 `identity_providers.redirect_uris` 做**精确**匹配，
  不做前缀/通配，杜绝 open redirect。
- **日志脱敏**：访问日志把 query 中的 `code/id_token/access_token/refresh_token/state/token`
  统一替换为 `[REDACTED]`；认证失败只记录分类（signature/audience/nonce/...），
  全代码路径不打印原始令牌。

## 本地运行

需要 Go 1.23+、Docker（用于 Postgres 与 Keycloak）。

```bash
# 1) 起 Postgres + Keycloak（自动导入两个 realm）
docker compose -f deploy/docker-compose.yml up -d

# 2) 等 Keycloak 就绪后，写入租户/IdP 配置
export DATABASE_URL=postgres://oidc:oidc@localhost:5432/oidctenant?sslmode=disable
go run ./cmd/seed -file deploy/seed.json

# 3) 启动应用（回调固定为 BASE_URL + /oauth/callback）
BASE_URL=http://localhost:8080 ADDR=:8080 \
DATABASE_URL=postgres://oidc:oidc@localhost:5432/oidctenant?sslmode=disable \
  go run ./cmd/server
```

测试账号（两个 realm 各有一个 `alice@example.com`，刻意同邮箱）：

| realm | 用户名 | 密码 | 邮箱 |
| --- | --- | --- | --- |
| acme | `alice` | `alice-pass` | alice@example.com |
| acme | `carol` | `carol-pass` | carol@example.com |
| globex | `alice.globex` | `aliceg-pass` | alice@example.com |
| globex | `bob` | `bobg-pass` | bob@example.com |

浏览器手动走一遍（无前端，直接访问启动 URL）：

```
http://localhost:8080/t/acme/login?issuer=http://localhost:8180/realms/acme
```

## 测试

### 加密校验单元测试（不需要外部依赖）

```bash
go test ./internal/oidcx/...
```

覆盖：合法令牌基线、错误 nonce、错误受众、过期、伪造 issuer、不受信密钥签名。

### 端到端集成测试（真实 Keycloak + 真实 PostgreSQL）

测试用 `fergusstrange/embedded-postgres` 在进程内拉起真实 PostgreSQL，
但需要一个已导入 realm 的本地 Keycloak（见上）。可用 `KC_BASE_URL` 覆盖地址。

```bash
# Keycloak 已运行且导入了 acme/globex realm（并为测试端口注册回调）后：
KC_BASE_URL=http://localhost:8180 go test ./integration/... -v
```

> 集成测试默认把应用起在 **18080** 端口，因此需要在两个 realm 的 `*-rp` 客户端
> 额外注册 `http://localhost:18080/oauth/callback` 与
> `http://localhost:18080/oauth/link/callback`（生产部署只注册真实端口即可）。

集成用例与题目要求一一对应：

| 用例 | 验证内容 |
| --- | --- |
| `TestCrossTenantSameEmailIsolation` | **跨租户同邮箱**：两个 alice@example.com 落到不同 member；跨租户会话 403 |
| `TestLoginCallbackReplayDoesNotDuplicateMember` | 登录回调重放：第二次 400，成员/身份仍各 1 条 |
| `TestConcurrentFirstLoginsDoNotDuplicateMember` | 并发首次登录（咨询锁+唯一约束）只建一个成员 |
| `TestAuthorizationCodeReplay` | **授权码重复使用**：state 已消费即拒绝 |
| `TestStaleCodeWithFreshStateIsAuthnFailure` | 新 state + 旧 code：Keycloak invalid_grant → 401 `authentication_failed` |
| `TestUnknownAndReplayedState` | 伪造/已用 state 行为一致 |
| `TestSigningKeyRotation` | **密钥轮换**：新增更高优先级 RSA key 后不重启应用即可验证新 kid，旧 kid 仍在 JWKS |
| `TestAccountLinkingHappyPath` | 两个身份各自重认证后关联，一个成员持有两条已核实身份 |
| `TestLinkConflictWhenTargetAlreadyBound` | **绑定冲突**：目标身份已属他人 → 409 `binding_conflict`，不被抢占 |
| `TestLinkSameEmailAcrossTenants` | 跨租户**同邮箱**两身份也能正确关联（按 issuer+subject 而非邮箱） |
| `TestLinkRequiresReauthentication` | 认证超过新鲜度窗口 → 401 `reauthentication_required` |
| `TestLinkCannotBeReplayed` | 关联 state/token 一次性，重放 400，不产生第三条身份 |
| `TestUnauthorizedIssuerForTenant` | 未授权 issuer → 403 `tenant_unauthorized` |
| `TestRedirectURIMustBeWhitelisted` | 未登记回调地址 → 400 `invalid_request` |
| `TestLinkRejectsDisabledProvider` | 关联前禁用 provider 授权 → 403 `tenant_unauthorized` |
| `TestWrongPasswordIsAuthnFailure` | IdP 凭证错误不产生会话/成员 |
| `TestDeviceSessions_*`（embedded PG，无 Keycloak） | 设备会话：双设备区分/仅撤销其一、被撤销设备 401 而另一台可用、重复撤销幂等、撤销与受保护操作并发线性互斥（真实行锁，30 轮 fail-closed）、全部退出/下线其他设备、跨租户同邮箱与另一成员不可枚举或撤销、单设备 logout 语义不变、写入型接口同样 fail-closed、响应与日志不含原始 sid |
| `TestDeviceSessions_EndToEnd*`（需 Keycloak） | 真实 OIDC 登录两台/三台设备后列出、撤销其他设备、全部退出的端到端流程 |

## 生产化前还应补充（本项目刻意省略）

- provider `client_secret` / 会话存储的 KMS 加密与静态加密；
- CSRF 防护（state 已绑定浏览器会话，仍建议对发起端点加 CSRF token）；
- refresh token 轮转、会话固定防护、`sid`/`jti` 反向注销（back-channel logout）；
- issuer 级别允许的签名算法/时钟偏移（leeway）做成可配置；
- 审计日志（记录谁在何时把哪个 `(issuer,subject)` 关联给了哪个 member）。
