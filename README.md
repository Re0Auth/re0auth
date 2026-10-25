# Re0Auth

音游数据的身份与委托授权层：对下游是标准 OAuth 2.0 / OIDC 授权中心与网关，对上游是联邦客户端。**卖点是下游不必再维护游戏登录态**——玩家只授权一次，之后每个下游一次点击接入，可单独撤销。Rust 编写，单二进制加 SQLite，可自托管。

上游凭据由 Connector 承担（可持有根凭证，只进独立加密存储或内存中转）；内核不存根凭证是工程卫生规则，不是安全承诺（ADR-0041）。

当前状态：可运行的最小后端切片与最小 SvelteKit 静态 SPA。后端包含 SQLite 存储、授权码/同意/刷新/设备流、外部 OIDC 登录、Session/CSRF、一次性设备批准票据与 12 条 `/api/admin/*` 管理接口；前端包含 `/login`、`/consent`、`/device` 与 `/account` 账号授权管理（**管理后台 UI 未做**，见 `docs/BACKLOG.md` B11）。Playwright 浏览器 E2E 覆盖登录、同意、设备批准与绑定上游四条真实路径。

## 构建

`rust-embed` 在编译时读取 `web/build`，所以干净环境先构建 SPA：

```sh
sh tools/build-all.sh
```

脚本等价于先构建 SPA，再编译 release 二进制。最终二进制自带 SPA，不需要 Node 运行时。

## 许可

**AGPL-3.0-or-later**，全文见 [LICENSE](LICENSE)。贡献与换牌约定见 [CONTRIBUTING.md](CONTRIBUTING.md)。
