# Re0Auth web

SvelteKit 静态 SPA，承载登录入口、授权同意、设备码入口和账号授权管理。

## 路由

| 路由 | 作用 |
|---|---|
| `/login` | 跳转后端 `/auth/login`，由外部 IdP 完成登录 |
| `/consent` | 读取 `request` 参数，展示 client/scopes，批准或拒绝 |
| `/device` | 输入设备码，提交到后端 `/device/start` |
| `/account` | 展示当前用户与已授权 client；支持撤销授权、绑定与退出所有会话 |
| `/about` | 静态公示页：运营方、Connector 的性质、以及明确的「不做承诺」清单（ADR-0041） |

设备批准确认表单仍由 Rust 服务端渲染：一次性 approval ticket 只放在隐藏字段和 POST body，不进 URL、不写 cookie。`/device` SPA 只负责入口。

## 开发

要求 Node 24 与 npm 11，后端默认运行在 `127.0.0.1:8080`。

```sh
npm ci --include=dev
npm run dev
```

`vite.config.ts` 已把 `/auth`、`/api`、`/oauth`、`/device/start`、`/device/approve`、`/device/deny`、`/userinfo`、`/.well-known`、`/jwks.json` 代理到后端；`/device`、`/login`、`/consent` 留在 SPA。

## 检查与构建

```sh
npm run check
npm run build
npm run test:e2e
```

`test:e2e` 需要先构建 release 二进制并安装 Chromium：`npx playwright install chromium`。输出在 `build/`，由 `adapter-static` 生成 `index.html` 作为 SPA fallback。`re0auth-http` 通过 `rust-embed` 在编译时嵌入 `web/build`，所以本地跑 `cargo build`/`cargo test` 前必须先完成一次 `npm run build`；也可以在仓库根运行 `sh tools/build-all.sh`。CI 与 Dockerfile 已按这个顺序编排。

## 前端约束

- 不引入 `sveltekit-superforms`；表单用 zod + 原生 `fetch`。
- 近黑主按钮，蓝色只做焦点/链接/选中态。
- 认证卡片 420–480px，中文正常字距，shadow-as-border。
