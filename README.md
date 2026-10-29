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

## 安装

镜像已发布到两个仓库，内容完全相同（同一 digest，支持 `linux/amd64` 与 `linux/arm64`）：

```sh
# 国内
docker pull docker.cnb.cool/r-0semi/re0auth:latest

# 国际
docker pull ghcr.io/re0auth/re0auth:latest
```

镜像以 UID/GID `65532` 非 root 运行，只往 `/app/data` 写入。

### 1. 准备数据目录与密钥

主密钥与签名密钥必须先生成，服务不会替你创建主密钥：

```sh
umask 077
mkdir -p data/keys

# 32 字节主密钥（64 位 hex），丢失后已加密的上游凭据无法恢复
openssl rand -hex 32 > data/keys/master.key

# RS256 签名密钥（PKCS#8 PEM）；没有时启动会自动生成
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
  -out data/keys/signing-key.pem

chmod 600 data/keys/master.key data/keys/signing-key.pem
# 容器以 65532 运行，所以目录归属必须交给它
sudo chown -R 65532:65532 data
```

### 2. 启动

```sh
docker run -d --name re0auth \
  -p 127.0.0.1:8080:8080 \
  -v "$PWD/data:/app/data" \
  docker.cnb.cool/r-0semi/re0auth:latest
```

镜像自带一份 [`config.docker.toml`](config.docker.toml)，挂载为 `/app/config.toml`。默认 `issuer` 是 `http://127.0.0.1:8080`，**对外服务前必须改成你的公网地址**，否则下发 token 里的 `iss` 会是错的值。改法二选一：

```sh
# 方式一：环境变量覆盖（优先级高于配置文件）
docker run ... -e RE0AUTH_SERVER__ISSUER=https://auth.example.com ...

# 方式二：挂载自己的配置文件
docker run ... -v "$PWD/config.toml:/app/config.toml:ro" ...
```

环境变量前缀是 `RE0AUTH_`，层级用双下划线，例如 `RE0AUTH_SERVER__BIND`、`RE0AUTH_DATABASE__URL`。

注意：环境变量是**在配置文件之上覆盖**，不能完全代替配置文件。镜像内的 `/app/config.toml` 提供完整基础，所以只传一两个变量没问题；但如果连配置文件都不挂又只传部分字段，会报 `missing field`。

### 3. 验证

```sh
curl -fsS http://127.0.0.1:8080/healthz   # 进程存活
curl -fsS http://127.0.0.1:8080/readyz    # 数据库可用且迁移完成
```

`/healthz` 只证明进程没死，`/readyz` 才能证明可以接流量。镜像已内置 `HEALTHCHECK`，两者都用作判据。

### 4. 创建首个管理员

新建用户默认角色是 `user`，必须显式给 `admin`：

```sh
docker exec re0auth /app/re0auth-server --config /app/config.toml \
  admin create-user --display-name admin --role admin

docker exec re0auth /app/re0auth-server --config /app/config.toml \
  admin create-session --user-id <上一步输出的 user_id>
```

`create-session` 打印的 cookie 只出现一次，立刻用它登录 `/account`，不要落到日志里。

### 5. 反向代理

镜像只监听容器内的 8080，TLS 终止交给反向代理。默认**不信任**任何 `X-Forwarded-For`，需要显式声明：

```toml
[server]
trusted_proxies = ["172.16.0.0/12"]
```

把 `0.0.0.0/0` 写进去会被 `--check-config` 拒绝。

### 配置校验

改完配置先跑一次静态校验，它不读密钥，只查结构：

```sh
docker run --rm -v "$PWD/config.toml:/app/config.toml:ro" \
  docker.cnb.cool/r-0semi/re0auth:latest --config /app/config.toml --check-config
```

密钥格式错误要到真正启动时才会暴露，所以这一步不能代替重启验证。

完整运维细节（备份、密钥轮换、升级、保留期）见 [`docs/design/OPERATIONS.md`](docs/design/OPERATIONS.md)。

## 许可

**AGPL-3.0-or-later**，全文见 [LICENSE](LICENSE)。贡献与换牌约定见 [CONTRIBUTING.md](CONTRIBUTING.md)。
