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
| `sessions` | 不透明会话令牌（数据库存 SHA-256 哈希）+ **设备展示标签 / 创建 / 最近活动 / 撤销状态** |
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
| `not_found` | 404 | 撤销不存在/不属于自己（含跨租户、跨成员）的设备会话，无法枚举 |

端点：

| 方法/路径 | 说明 |
| --- | --- |
| `GET  /healthz` | 健康检查 |
| `GET  /t/{slug}/login?issuer=...&return_to=/...` | 发起登录，302 到 IdP |
| `GET  /oauth/callback` | 登录回调（固定路径） |
| `GET  /t/{slug}/api/me` | 当前成员与其已绑定身份（需会话 Cookie `sid`） |
| `POST /t/{slug}/api/logout` | **单设备退出**：只吊销当前浏览器会话并清理 `sid`，其他设备不受影响 |
| `GET  /t/{slug}/api/sessions` | 列出当前成员在本租户的**设备会话**（标签、创建/最近活动时间、活跃/已撤销状态） |
| `DELETE /t/{slug}/api/sessions/{id}` | **撤销指定设备**；撤当前设备等价 logout；重复撤销幂等返回 `already_revoked` |
| `POST /t/{slug}/api/sessions/revoke-all` | **全部设备退出**：撤销其他全部设备 + 当前设备，清理 `sid` |
| `POST /t/{slug}/api/links` | 发起账号关联，返回 `link_token` 与 `link_url`；body `{"issuer":"..."}` |
| `GET  /oauth/link/callback` | 关联第二身份的回调（强制重认证） |
| `GET  /t/{slug}/api/links/{token}` | 查询关联会话状态（一次性） |

## 设备会话管理（丢失设备只撤那一台）

会话仍是不透明 `sid`（库内仅存 SHA-256）。在此之上每个会话额外保存：

- `display_label`：**只由 `User-Agent` 脱敏摘要得到**（折叠空白/控制字符、限长），
  绝不包含 sid、授权码、ID/access token；空 UA 记为 `Unknown device`；
- `created_at` / `last_activity_at`：创建与最近活动时间（鉴权命中时刷新）；
- 活跃/已撤销：由 `revoked_at IS NULL AND expires_at > now()` 派生；
  `revoked_at` 是永久、幂等的状态位。

对外列表/响应只暴露会话行的内部 UUID（不是 sid 本身）、标签与时间，
任何响应、日志、列表都不回显原始 sid、授权码或身份令牌。

**并发与撤销竞争的正确性**（中间件强保证）：

1. 每个受保护请求在一个**请求级事务**里执行；中间件用条件
   `UPDATE sessions SET last_activity_at=now() WHERE token_hash=$1
   AND revoked_at IS NULL AND expires_at>now() RETURNING ...`
   同时完成“取行 + 对该行加排他行锁 + 拒绝已撤销/已过期 + 刷新活动时间”。
2. 行锁持有到整个 handler 结束（事务提交）。撤销另一设备的语句在**独立事务**里
   对同一行 `FOR UPDATE`，因此与该设备正在进行的受保护操作严格串行：
   要么撤销先提交（随后该 sid 的鉴权立刻失败），要么受保护请求先提交
   （其任何写入/活动时间都不晚于 `revoked_at`）。**不存在“撤销之后还成功写入”**。
3. 响应写入前有“提交闸门”（`commitWriter`）：只有请求事务提交成功，
   handler 选定的 2xx 才会发给客户端，杜绝“客户端收到成功、事务却回滚”。
4. 撤销他人/全部设备在独立事务内**按 id 有序加锁**（`ORDER BY id FOR UPDATE`），
   消除并发互撤的死锁；遇 Postgres 死锁牺牲者做有限退避重试（撤销幂等，重试安全）。
5. 当前会话被撤销（在别的设备上被踢）后，下次访问受保护接口返回
   401 `authentication_failed` 并**下发删除 `sid` 的 Cookie**，浏览器侧结果一致。
6. 撤销的归属条件 `(tenant_id, member_id)` 直接写进 SQL：跨租户（即使邮箱相同）
   或同租户其他成员的会话 id 一律影响 0 行 → 404 `not_found`，无法枚举或撤销。

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
| `TestDeviceSessionsTwoDevicesAreDistinctAndSelectiveRevoke` | **两设备可区分、只撤一台**；被撤设备 me/关联接口 401 并清 Cookie，另一台仍可用 |
| `TestRevokeSessionIsIdempotent` | **重复撤销**稳定返回 revoked → already_revoked |
| `TestRevokeRacesWithInFlightProtectedOperation` | **撤销与受保护操作竞争**：在途请求提交后撤销才完成，其后无成功写入 |
| `TestRevokeCrossTenantAndCrossMemberIsDenied` | **跨租户同邮箱/另一成员**会话不能枚举或撤销（统一 404） |
| `TestLogoutKeepsSingleDeviceSemantics` | 原有**单设备 logout** 语义不变（不撤其他设备） |
| `TestRevokeAllDevicesLogsOutEverySession` | **全部设备退出**：三台全撤、当前 Cookie 清理 |
| `TestSessionLabelNeverContainsTokenMaterial` | 设备标签脱敏、控制字符注入失效、列表不泄漏 sid |

## 生产化前还应补充（本项目刻意省略）

- provider `client_secret` / 会话存储的 KMS 加密与静态加密；
- CSRF 防护（state 已绑定浏览器会话，仍建议对发起端点加 CSRF token）；
- refresh token 轮转、会话固定防护、`sid`/`jti` 反向注销（back-channel logout）；
- issuer 级别允许的签名算法/时钟偏移（leeway）做成可配置；
- 审计日志（记录谁在何时把哪个 `(issuer,subject)` 关联给了哪个 member）。
