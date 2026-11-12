# API 契约（CI 专用摘录）

> 本文件只保留 archtest 解析的错误码与路由清单；完整文档在本地 `docs/`，不随仓库发布。
> 修改错误码或路由时同步更新本文件，否则两个 API 契约测试会失败。

### 8.2 OAuth 端点错误码（已实现；RFC 6749 扁平格式）

下表所有代码都发在同一形状里：`{ "error": "<code>", "error_description": "..." }`。
这些端点的响应**不带** `application/problem+json`。

| 代码 | HTTP | 触发条件 |
|---|---|---|
| `invalid_request` | 400 | 缺少或非法参数；缺失 `grant_type` 也在此列 |
| `unsupported_grant_type` | 400 | 授权类型不受支持（RFC 6749 §5.2 的精确化，非破坏性） |
| `invalid_client` | 401 | 客户端认证失败；响应带 `WWW-Authenticate: Basic realm="token"` |
| `invalid_grant` | 400 | 授权码/刷新令牌/设备码无效、过期或已用 |
| `invalid_scope` | 400 | 请求了未注册的 scope |
| `invalid_token` | 401 | Bearer 令牌无效（`/userinfo`、网关入口） |
| `unauthorized_client` | 400 | 客户端未被批准使用该授权类型 |
| `access_denied` | 400 | 用户在同意页拒绝 |
| `authorization_pending` | 400 | 设备码尚未被批准 |
| `slow_down` | 400 | 设备码轮询过快，响应体带 `interval` |
| `expired_token` | 400 | 设备码已过期 |
| `login_required` | 401 | 需要先建立会话 |
| `consent_not_found` / `consent_expired` / `consent_used` | 404 / 400 / 400 | 同意票据的三种失效形态 |

客户端认证规则（ADR-0030，`crates/re0auth-app` 的 `authenticate_client`）：

- 公开客户端（`secret_hash` 为 NULL）**不得**携带 secret，携带即 `invalid_client`。放行会让任何人给公开客户端随便挂一个 secret，从而掩盖配置错误。
- 机密客户端必须携带正确 secret；缺省与错误一律 `invalid_client`，不区分是"没带"还是"带错了"。
- 同时支持 `client_secret_basic`（`Authorization: Basic`，按 RFC 6749 §2.3.1 做百分号解码）与 `client_secret_post`（表单字段）。两者同时出现且 `client_id` 不一致时报 `invalid_request`。
- **认证先于凭据消费**：错误的 secret 不会烧掉授权码或轮换刷新令牌。

### 8.3 网关、会话与管理错误码（已实现；RFC 9457 problem+json）

网关与会话端点发 §8.1 的 problem 形状，`code` 成员取下表的值。
（`/api/oauth/pending` 与 `/api/oauth/consent` 属于会话面，因此也是 problem 形状，
尽管它们的代码是 `consent_*`。）

网关错误码由 `GatewayError::code()` 产生（`crates/re0auth-app/src/gateway.rs`）：

| 代码 | HTTP | 触发条件 |
|---|---|---|
| `invalid_request` | 400 | 资源名/参数非法 |
| `invalid_token` | 401 | 访问令牌无效 |
| `insufficient_scope` | 403 | 令牌或上游 scope 不足 |
| `binding_required` | 403 | 用户没有该上游的绑定 |
| `upstream_needs_reauth` | 403 / 401 | 绑定或上游凭据需要重新授权 |
| `access_denied` | 403 | 绑定存在但尚未激活（`pending`） |
| `binding_revoked` | 403 | 绑定已被撤销；重新授权无用，需要重新连接 |
| `unknown_connector` | 404 | 未注册的连接器 |
| `endpoint_not_found` | 404 | 连接器上没有该资源 |
| `raw_not_allowed` | 403 | 客户端无 `raw_access`，或令牌缺 `<connector>.raw.read` scope（INV-RAW-01 双闸门） |
| `not_found` | 404 | 上游返回 404 |
| `invalid_parameter` | 400 | 上游拒绝了我们发送的参数（上游 400/422）。业务类，不计熔断 |
| `upstream_busy` | 503 | 熔断打开，响应应带 `Retry-After` |
| `upstream_rate_limited` | 429 | 上游限流 |
| `upstream_response_too_large` | 502 | 上游响应超过 4 MiB 被截断 |
| `upstream_unavailable` | 502 | 上游不可达、超时或 5xx |
| `upstream_contract_changed` | 502 | 上游 JSON 不满足资源配置声明的视图（路径缺失或类型不符） |
| `account_banned` | 403 | 账号已被封禁（登录与网关两条入口都拒绝） |
| `internal_error` | 500 | 服务端内部错误 |
| `invalid_csrf` | 403 | 状态变更缺少或错误的 CSRF 令牌 |
| `rate_limited` | 429 | 本服务限流（设备码尝试、匿名入口按 IP、数据面按 client_id），响应带 `Retry-After` |
| `forbidden` | 403 | 已认证但不是管理员（管理 API）；与 401 `login_required` 严格区分 |
| `conflict` | 409 | 管理写操作违反业务规则：自降级、降级最后一个管理员、乐观锁 `expected_updated_at` 不匹配 |
| `server_error` | 500 | 会话/管理 API 的内部错误 |
| `last_identity` | 409 | 解绑最后一个登录方式；账号会因此永久无法登录，改用注销账号 |
| `bindings_not_revocable` | 409 | 注销账号时上游拒绝确认撤销，先重试再注销 |
| `identity_already_bound` | 409 | 挂载的登录方式已属于另一个账号；不合并，也不透露是哪个账号 |
| `login_requires_attach` | 409 | 已登录状态下用陌生凭证登录；改从账户页挂载 |
| `login_requires_logout` | 409 | 已登录状态下换用另一个账号的凭证登录；先登出 |

401 与 403 分开：401 表示 token 无效/过期（密码学上无法验证），403 表示 token 有效但权限不足。**混用会导致"重授权 → 仍然 403 → 再重授权"的死循环。**

`upstream_needs_reauth`、`binding_revoked` 与 `access_denied` 的区别：前者表示**需要用户重新授权**才能恢复；`binding_revoked` 表示绑定已被撤销，重新授权不解决问题，必须重新连接（`binding_required` 则是从未连过）；`access_denied` 只覆盖尚未激活的 `pending` 绑定。三者的修复动作不同，混用会把用户送进「重授权 → 仍然 403」的死循环。

### 8.4 规划中、尚未实现的错误码

以下代码**不在当前契约内**，出现任何一个是 bug：

| 代码 | 状态 | 说明 |
|---|---|---|
| `unsupported_token_type` | 已结案，不实现 | RFC 7009 §2.2.1 要求「无法用提示定位时必须扩展到所有令牌类型检索」。本服务同时支持 access 与 refresh 的吊销，「服务不支持该令牌类型」的场景为零；若对未知提示返回 400，反而违反该 MUST，并把常见的 `urn:ietf:params:oauth:token-type:refresh_token` 写法从成功变成回归。`/oauth/revoke` 只解析 `token_type_hint`，从不据它拒绝。 |

`binding_revoked` 与 `unsupported_grant_type` 已实现，见 §8.2 / §8.3。
补实现时必须同时更新本节与 §8.2/§8.3，不允许只改代码。

## 9. Header、分页、版本

- `X-Request-Id`：**已实现**。客户端可传，服务端必回。传入值经校验（≤128 字节、仅 `[A-Za-z0-9._:-]`）；非法或缺失时服务端生成 UUIDv7 替代，**不会因此拒绝请求**。该值同时写入 `audit_logs.request_id`，可据此把客户端报告关联到安全事实。
- `Retry-After`：**已实现**。限流产生的 429 与熔断/上游限流产生的 503/429 都带该头（`gateway_error()` 写入真实秒数，非正值下限 1 秒）。
- `RateLimit-Limit`、`RateLimit-Policy`：**已实现**（仅 429 响应）。`RateLimit-Limit` 是实际生效的 burst，`RateLimit-Policy` 形如 `30;w=60`。
- `RateLimit-Remaining`、`RateLimit-Reset`：**不实现，且是有意为之**。GCRA 把额度存在一个不透明的原子里，要给出剩余量只能另起一个计数器并行维护；两个写入者必然漂移，客户端会得到"还有额度"的错误信息。缺失比说谎好。限流命中的 responses 用 `Retry-After` 表达该等多久。
- 分页：`limit`（默认 20，最大 100）+ `cursor`；响应带 `next_cursor`。**未实现**。

## 附录 A：当前已实现的全部路由

可执行事实，由 `crates/re0auth-http/src/lib.rs` 的 `router()` 定义。新增或删除路由必须同步本清单。
该清单由 `the_routes_in_api_surface_match_the_router` 与 `router()` 逐一比对，不一致即测试失败。

```text
GET    /healthz
GET    /readyz
GET    /metrics
GET    /.well-known/openid-configuration
GET    /jwks.json
GET    /api/auth/providers
GET    /auth/login
GET    /auth/callback
GET    /oauth/authorize
POST   /oauth/authorize
POST   /oauth/device_authorization
POST   /oauth/token
POST   /oauth/introspect
POST   /oauth/revoke
GET    /userinfo
POST   /userinfo
GET    /api/oauth/pending
POST   /api/oauth/consent
GET    /api/me
DELETE /api/me
GET    /api/me/authorizations
GET    /api/me/bindings
DELETE /api/me/bindings
GET    /api/me/bindings/upstreams
POST   /api/me/bindings/begin
GET    /api/me/bindings/callback
DELETE /api/me/bindings/{id}
GET    /api/me/identities
POST   /api/me/identities/begin
DELETE /api/me/identities/{id}
DELETE /api/me/authorizations/{client_id}
POST   /api/logout
POST   /api/logout-all
GET    /device/start
GET    /device/qr.svg
POST   /device/approve
POST   /device/deny
GET    /openapi.json
GET    /api/v1/upstreams
GET    /api/v1/upstreams/{connector}/{resource}/schema
GET    /api/v1/upstreams/{connector}/{resource}
GET    /api/v1/raw/{connector}/{resource}
GET    /api/v1/assets/{connector}/{resource}
GET    /api/admin/stats
GET    /api/admin/clients
POST   /api/admin/clients
GET    /api/admin/clients/{id}
PATCH  /api/admin/clients/{id}
POST   /api/admin/clients/{id}/rotate-secret
GET    /api/admin/users
PATCH  /api/admin/users/{id}
GET    /api/admin/connectors
GET    /api/admin/connectors/{id}
GET    /api/admin/bindings
DELETE /api/admin/bindings/{id}
POST   /api/admin/killswitch
GET    /api/admin/audit
```
- 版本：路径 `/api/v1`；破坏性变更升 v2，旧版至少保留 6 个月。
- `Cache-Control: no-store` 用于 token/device 响应。
- 客户端地址默认取对端地址；只有 `trusted_proxies` 配置后才解析 `X-Forwarded-For`，只取最右侧一跳（HR-03）。
