#!/usr/bin/env sh
# 恢复演练：在临时目录还原备份并验证可用。
set -eu

cd "$(dirname "$0")/.."

BACKUP_DIR=${BACKUP_DIR:-backups}
PORT=${PORT:-18081}
STAMP=${1:-}

if ! command -v sqlite3 >/dev/null 2>&1; then
    echo "缺少 sqlite3 命令" >&2
    exit 1
fi

if [ -z "$STAMP" ]; then
    latest=$(ls -1t "$BACKUP_DIR"/re0auth-*.db 2>/dev/null | head -1 || true)
    if [ -z "$latest" ]; then
        echo "在 $BACKUP_DIR 下没有找到备份" >&2
        exit 1
    fi
    STAMP=$(basename "$latest" .db | sed 's/^re0auth-//')
fi

db_src="$BACKUP_DIR/re0auth-$STAMP.db"
key_src="$BACKUP_DIR/master-$STAMP.key"
sign_src="$BACKUP_DIR/signing-$STAMP.pem"
sum_src="$BACKUP_DIR/re0auth-$STAMP.sha256"

for f in "$db_src" "$key_src" "$sign_src" "$sum_src"; do
    if [ ! -f "$f" ]; then
        echo "缺少备份文件: $f" >&2
        exit 1
    fi
done

echo "[1/4] 校验备份文件哈希"
sha256sum -c "$sum_src"

echo "[2/4] 在临时目录还原"
work=$(mktemp -d 2>/dev/null || { mkdir -p "target/drill.$$"; echo "target/drill.$$"; })
cleanup() {
    if [ -n "${pid:-}" ]; then
        kill "$pid" >/dev/null 2>&1 || true
        wait "$pid" 2>/dev/null || true
    fi
    rm -rf "$work"
}
trap cleanup EXIT INT TERM

mkdir -p "$work/keys"
cp "$db_src" "$work/re0auth.db"
cp "$key_src" "$work/keys/master.key"
cp "$sign_src" "$work/keys/signing-key.pem"
chmod 600 "$work/keys/master.key" "$work/keys/signing-key.pem"

integrity=$(sqlite3 "$work/re0auth.db" "PRAGMA integrity_check;")
if [ "$integrity" != "ok" ]; then
    echo "还原后的数据库完整性失败: $integrity" >&2
    exit 1
fi
echo "  完整性 ok"

echo "[3/4] 配置校验"
RE0AUTH_DATABASE__URL="sqlite://$work/re0auth.db" \
RE0AUTH_CRYPTO__MASTER_KEY_FILE="$work/keys/master.key" \
RE0AUTH_CRYPTO__SIGNING_KEY_FILE="$work/keys/signing-key.pem" \
RE0AUTH_SERVER__BIND="127.0.0.1:$PORT" \
    cargo run -q -p re0auth-server -- --config config.example.toml --check-config

echo "[4/4] 启动并等待 readyz"
RE0AUTH_DATABASE__URL="sqlite://$work/re0auth.db" \
RE0AUTH_CRYPTO__MASTER_KEY_FILE="$work/keys/master.key" \
RE0AUTH_CRYPTO__SIGNING_KEY_FILE="$work/keys/signing-key.pem" \
RE0AUTH_SERVER__BIND="127.0.0.1:$PORT" \
    cargo run -q -p re0auth-server -- --config config.example.toml \
    >"$work/server.log" 2>&1 &
pid=$!

ready=0
for _ in $(seq 1 60); do
    if [ "$(curl -sS -m 2 "http://127.0.0.1:$PORT/readyz" 2>/dev/null || true)" = "ready" ]; then
        ready=1
        break
    fi
    sleep 1
done

if [ "$ready" != "1" ]; then
    echo "readyz 未在 60 秒内就绪；日志：" >&2
    sed -n '1,20p' "$work/server.log" >&2 || true
    exit 1
fi

echo "  readyz 返回 ready"
echo
echo "恢复演练通过: $STAMP"
