#!/usr/bin/env sh
# 备份数据库与密钥。需要 sqlite3 命令。
set -eu

cd "$(dirname "$0")/.."

DATA_DIR=${DATA_DIR:-data}
KEY_DIR=${KEY_DIR:-$DATA_DIR/keys}
BACKUP_DIR=${BACKUP_DIR:-backups}
DB=${DB:-$DATA_DIR/re0auth.db}

if ! command -v sqlite3 >/dev/null 2>&1; then
    echo "缺少 sqlite3 命令；用 .backup 才能拿到一致快照" >&2
    echo "Debian/Ubuntu: apt-get install -y sqlite3" >&2
    exit 1
fi

if [ ! -f "$DB" ]; then
    echo "数据库不存在: $DB" >&2
    exit 1
fi

for f in "$KEY_DIR/master.key" "$KEY_DIR/signing-key.pem"; do
    if [ ! -f "$f" ]; then
        echo "缺少密钥文件: $f" >&2
        echo "三样必须一起备份，缺一件备份就不可恢复" >&2
        exit 1
    fi
done

umask 077
mkdir -p "$BACKUP_DIR"

stamp=$(date +%Y%m%d%H%M%S)
db_out="$BACKUP_DIR/re0auth-$stamp.db"
key_out="$BACKUP_DIR/master-$stamp.key"
sign_out="$BACKUP_DIR/signing-$stamp.pem"
sum_out="$BACKUP_DIR/re0auth-$stamp.sha256"

# 先装清理，失败时删半成品
cleanup() {
    rm -f "$db_out" "$key_out" "$sign_out" "$sum_out"
}
trap cleanup EXIT INT TERM

# .backup 走 SQLite 在线备份 API，服务运行中也能拿到一致快照
sqlite3 "$DB" ".backup '$db_out'"

# 备份出来必须能读且完整，否则后面拷密钥是白搭
integrity=$(sqlite3 "$db_out" "PRAGMA integrity_check;")
if [ "$integrity" != "ok" ]; then
    echo "备份文件完整性校验失败: $integrity" >&2
    exit 1
fi

cp "$KEY_DIR/master.key" "$key_out"
cp "$KEY_DIR/signing-key.pem" "$sign_out"

chmod 600 "$db_out" "$key_out" "$sign_out"

# 校验和覆盖三件，恢复时先验证再动线上文件
{
    sha256sum "$db_out" "$key_out" "$sign_out"
} > "$sum_out"

trap - EXIT INT TERM

echo "备份完成:"
echo "  数据库  $db_out"
echo "  主密钥  $key_out"
echo "  签名密钥 $sign_out"
echo "  校验和  $sum_out"
echo
echo "校验: sha256sum -c $sum_out"
echo "恢复演练: sh tools/restore-drill.sh $stamp"
