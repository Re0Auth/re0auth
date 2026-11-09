# Token 路径基准

`cargo bench -p re0auth-server --bench token_paths` 测量四条真实服务路径的单次成本：授权码兑换、刷新轮换、设备码轮询、网关令牌校验，外加一次裸的 RS256 签名作为归因基线。

## 运行

```sh
# 全部基准
cargo bench -p re0auth-server --bench token_paths

# 只看某一条（Criterion 按子串过滤）
cargo bench -p re0auth-server --bench token_paths -- exchange_code
```

基线对比必须同机、同命令、同 profile。`bench` profile 默认继承 `release`（`lto = "thin"`、`codegen-units = 1`），因此数字接近发布构建。

## 环境与口径

| 项 | 值 |
|---|---|
| 平台 | Windows 10.0.26200 / x86_64-pc-windows-msvc |
| CPU | Intel Core Ultra 7 255HX（32 GB） |
| 编译器 | rustc 1.99.1 |
| 存储 | `sqlite::memory:`（1 连接），排除磁盘延迟 |
| 时钟 | 兑换/刷新用固定时钟；设备轮询每次 +5 s，避免落入 slow-down 分支 |
| 采样 | 30 样本，预热 1 s，测量 3 s |

预置数据在基准开始前写入，迭代不重新建库；需要全新授权码/刷新令牌的基准用 `iter_custom` 把种子写入排除在计时之外。

## 基线（并行签名之前）

| 基准 | 中位数 | 置信区间 |
|---|---:|---|
| `exchange_code` | 2.053 ms | 2.001 – 2.108 ms |
| `refresh` | 1.913 ms | 1.890 – 1.940 ms |
| `device_poll_pending` | 131.6 µs | 128.8 – 135.1 µs |
| `verify_gateway_token` | 17.67 µs | 17.56 – 17.86 µs |
| `sign_access`（单次 RS256） | 764.6 µs | — |

## 热点（按实测影响排序）

1. **RS256 签名**：单次 764.6 µs；`exchange_code` 与 `refresh` 各签两次（access + `openid` 的 id_token），合计约 1.53 ms，占端点中位数的 73–80%。
2. **设备码轮询的重复读取**：`exchange_device_code` 先 `find_by_device_hash` 取行，随后 `poll` 事务内再 `SELECT` 同一行；两次读相同主键。
3. **token 流程的重复客户端查询**：`authenticate_client` 已校验 `Approved`，三条流程随后又调用 `require_approved_client` 重查同一行。
4. **网关门禁４次查询**：`is_revoked`、`is_family_revoked`、`users().get`、`consents().find`，合计 17.7 µs；相对上游 RTT 可忽略。

## 第 1 轮优化：并行签发

`OAuthService::issue` 改为 `async`，把两次相互独立的签名分别交给 `spawn_blocking`，再同时等待。

| 基准 | 优化前 | 优化后 | 变化 |
|---|---:|---:|---:|
| `exchange_code` | 2.053 ms | 1.057 ms | −48.5% |
| `refresh` | 1.913 ms | 1.193 ms | −37.6% |

同批次未改动基准的漂移为 ±5–7%（`verify_gateway_token` +6.8%、`sign_access` +3.8%、`device_poll_pending` −6.5%），因此上表的变化远高于噪声；基线与新值的置信区间不重叠。

代价：单个 token 请求在约 0.8 ms 内占用两个 blocking 线程；总 CPU 不变，但异步 worker 不再被 RSA 运算阻塞，并发下的排队时间也随之下降。

## 尚未处理

- 合并设备轮询的 `find` + `poll`（预计该基准再降 10–15%）。
- 删除三条 token 流程中重复的 `require_approved_client`（对 token 基准 <1%，但每次少一次查询）。
- 网关路径中 `verify_gateway_token` 与 `GatewayService::fetch` 对同一 `users` 行的重复读取。
