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

## 测量方法：交替 A/B

同一二进制连续运行会出现单调上升的漂移（实测三次 122 → 139 → 145 µs，约 18%，热降频所致），顺序 A/B 会把漂移误判成改动效果。

因此每一项改动都按下面步骤测量：

1. 改动前用 `cargo bench --no-run` 构建基准二进制，复制为 `target/bench_old.exe`；
2. 落地改动后再次构建，复制为 `target/bench_new.exe`；
3. 交替运行两者各 3 次（OLD/NEW/OLD/NEW/OLD/NEW），比较中位数与置信区间。

## 第 1 轮优化：并行签发

`OAuthService::issue` 改为 `async`，把两次相互独立的签名分别交给 `spawn_blocking`，再同时等待。

| 基准 | 优化前 | 优化后 | 变化 |
|---|---:|---:|---:|
| `exchange_code` | 2.053 ms | 1.057 ms | −48.5% |
| `refresh` | 1.913 ms | 1.193 ms | −37.6% |

同批次未改动基准的漂移为 ±5–7%（`verify_gateway_token` +6.8%、`sign_access` +3.8%、`device_poll_pending` −6.5%），因此上表的变化远高于噪声；基线与新值的置信区间不重叠。

代价：单个 token 请求在约 0.8 ms 内占用两个 blocking 线程；总 CPU 不变，但异步 worker 不再被 RSA 运算阻塞，并发下的排队时间也随之下降。

## 第 2 轮优化：设备轮询合并为单次读取

`exchange_device_code` 原先先 `find_by_device_hash` 取行校验归属，再调用 `poll`，而 `poll` 事务内又读同一行。现在 `DeviceCodeRepo::poll` 直接接收 `client_id`，在读取后、任何状态写入前判断归属并返回 `DevicePoll::ClientMismatch`：重复读取消失，且错误文案与「不匹配不写状态」的语义保持不变。

| 配对 | OLD | NEW |
|---|---:|---:|
| 1 | 131.45 µs | 96.19 µs |
| 2 | 128.81 µs | 93.11 µs |
| 3 | 135.74 µs | 91.84 µs |

中位数由 **131.45 µs** 降至 **93.7 µs（−28.7%）**，两侧置信区间不重叠。

## 第 3 轮优化：撤销检查合并为单次查询

`verify_gateway_token` 原先分别调用 `is_revoked` 与 `is_family_revoked`，两条 SQL 判一个决定。新增 `AccessTokenRepo::is_denied`，SQLite 实现用一条 `SELECT EXISTS(...) OR EXISTS(...)` 完成，并在同一快照上判定。

| 配对 | OLD | NEW |
|---|---:|---:|
| 1 | 22.68 µs | 22.91 µs |
| 2 | 26.36 µs | 26.49 µs |
| 3 | 24.97 µs | 25.92 µs |

结论：**无可检出差异**。该基准自身在 20–29 µs 间波动，单次查询约 1 µs，小于噪声。改动保留（少一次往返、判定使用同一快照），但不宣称性能收益。

## 第 4 轮优化：设备轮询普通路径单条原子更新

上一轮之后，普通轮询仍要 `BEGIN IMMEDIATE` + SELECT + UPDATE + COMMIT 四步。现在 `poll` 先用一条带完整条件的 `UPDATE ... WHERE` 处理「pending、未过期、间隔已到、归属正确」这一最常见分支：命中即 `Pending`，未命中才进入原事务按慢轮询/已批准/已拒绝/已过期/已消费/归属不符分类。

| 配对 | OLD | NEW |
|---|---:|---:|
| 1 | 87.10 µs | 72.75 µs |
| 2 | 92.05 µs | 73.48 µs |
| 3 | 85.63 µs | 71.09 µs |

中位数由 **87.10 µs** 降至 **72.75 µs（−16.5%）**，两侧置信区间不重叠。

## 第 5 轮优化：删除重复的客户端放行检查

`authenticate_client` 已经返回「存在且状态为 `Approved`」的客户端；三条 token 流程随后又调用一次 `require_approved_client`，把同一行再读一遍。该检查已删除，方法本身一并移除。唯一的语义差别是并发管理操作恰好在两次检查之间把客户端挂起——旧代码也只是在第二次检查时点判断，本身并不构成原子保证。

| 配对 | OLD | NEW |
|---|---:|---:|
| 1 | 1.1143 ms | 1.0639 ms |
| 2 | 1.3125 ms | 1.3336 ms |
| 3 | 1.0986 ms | 1.0836 ms |

中位数 1.1143 ms → 1.0836 ms（−2.8%），差异小于该基准的波动，**不宣称收益**。

## 未采纳：网关路径重复读取 `users`

`verify_gateway_token` 与 `GatewayService::fetch` 各读一次 `users` 行（同一请求内约 6 µs）。合并需要把用户状态穿透两层接口，或把「封禁」错误从网关层的 403 改到令牌层的 401，二者都会增加耦合或改变可观察行为；该路径的耗时由上游 RTT（数十毫秒）主导，收益不可测。按「不做无证据的顺手优化」放弃。
