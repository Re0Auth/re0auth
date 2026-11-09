# 下游机器人样例（Python，零依赖）

这个目录只有一个目标：让一个**没读过本仓源码**的第三方机器人作者，按一份文档就走完
「设备流授权 → 调网关取数 → 撤销」的闭环。它同时是 `DESIGN.md` §12 验收要求的实物。

只用标准库（`urllib` / `json` / `time` / `argparse`），没有 requirements.txt。

## 前置

1. 一个跑起来的实例。本地可以直接用发布版二进制：

   ```sh
   cargo run --release -p re0auth-server -- --config config.toml
   ```

2. 一个客户端。设备流用于机器人，不需要重定向地址：

   ```sh
   re0auth-server --config config.toml admin create-client \
       --name "示例机器人" --scope openid --scope profile
   ```

   输出里的 `client_id` 下面要用；如果建的是机密客户端，还会给一次性 `secret`。
   新客户端默认是 `pending`，需要管理员在后台或 CLI 里改为 `approved`。

3. 一个连接器与一次绑定。样例只读取**用户已绑定**的上游，服务不会替你绑定：

   ```toml
   [[connectors]]
   id = "phihub"
   base_url = "https://example.invalid"

   [connectors.oauth]
   # ...
   ```

   用户登录账户页，点「连接」完成绑定。之后样例里的 `--connector phihub` 才有意义。

## 运行

```sh
python3 examples/python/re0auth_bot.py \
    --issuer http://127.0.0.1:8080 \
    --client-id <client_id> \
    --connector phihub \
    --resource save_info \
    --scope "openid profile"
```

按提示打开打印出的地址、输入设备码并批准；脚本随后取数、打印信封、撤销令牌。

## 每一步的协议依据

| 步骤 | 端点 | 依据 | 容易踩的坑 |
|---|---|---|---|
| 申请设备码 | `POST /oauth/device_authorization` | RFC 8628 §3.1 | 这个端点用**扁平**错误体（RFC 6749 §5.2），不是 problem+json |
| 轮询换令牌 | `POST /oauth/token` | RFC 8628 §3.4 | `authorization_pending` 要按 `interval` 继续；`slow_down` 必须把间隔 **+5 秒**，立刻重试只会更慢 |
| 调网关 | `GET /api/v1/upstreams/{connector}/{resource}` | 本仓 `API-SURFACE.md` §7 | 成功体是六字段信封；错误体是 problem+json，**分支依据是 `code`**，不是 HTTP 状态或 `title` |
| 撤销 | `POST /oauth/revoke` | RFC 7009 | 未知令牌也回 `200`；不要把它当存在性探针 |

## 为什么撤销走 `/oauth/revoke`

- `/oauth/revoke` 是**应用自己**的动作：撤销自己持有的令牌，机器人能独立完成。
- `DELETE /api/me/authorizations/{client_id}` 是**用户**的动作：需要浏览器会话 + CSRF，
  用户在账户页点「撤销」。样例不假装能替用户做主。

## 形状以 `openapi.json` 为准

仓库根的 [`openapi.json`](../../openapi.json) 由代码生成、并由闸门保证与路由一致。
本文只解释顺序与坑，字段清单不要在文档里抄第二份。

## 边界

- 令牌只放在内存里，不落盘、不打日志；
- 不接触上游根凭证，样例拿到的只是本服务签发的访问令牌；
- 不把令牌塞进前端：设备流的意义就是让机器自己持有它。
