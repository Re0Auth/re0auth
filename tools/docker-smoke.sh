#!/usr/bin/env sh
set -eu

cd "$(dirname "$0")/.."

IMAGE=${IMAGE:-re0auth:ci}
NAME=${NAME:-re0auth-ci-smoke}
VOLUME=${VOLUME:-re0auth-ci-smoke-data}
PORT=${PORT:-18080}

cleanup() {
    docker rm -f "$NAME" >/dev/null 2>&1 || true
    docker volume rm "$VOLUME" >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker build -t "$IMAGE" .

# The server refuses to start without a master key. Create one in a volume as
# root, then hand the volume to the runtime user so the 0600 file is readable.
docker volume rm "$VOLUME" >/dev/null 2>&1 || true
docker volume create "$VOLUME" >/dev/null
docker run --rm --user 0 -v "$VOLUME:/app/data" --entrypoint sh "$IMAGE" -c '
    set -eu
    umask 077
    mkdir -p /app/data/keys
    head -c 32 /dev/urandom | od -An -tx1 | tr -d " \n" > /app/data/keys/master.key
    test "$(wc -c < /app/data/keys/master.key)" -eq 64
    chmod 600 /app/data/keys/master.key
    chown -R 65532:65532 /app/data
'

docker run -d --name "$NAME" -p "127.0.0.1:${PORT}:8080" -v "$VOLUME:/app/data" "$IMAGE" >/dev/null

user=$(docker inspect --format '{{.Config.User}}' "$NAME")
if [ "$user" != "65532:65532" ]; then
    echo "container is not running as 65532:65532 (got: $user)" >&2
    exit 1
fi

ready=0
for _ in $(seq 1 60); do
    if curl -fsS "http://127.0.0.1:${PORT}/healthz" >/dev/null 2>&1; then
        ready=1
        break
    fi
    sleep 1
done

if [ "$ready" != "1" ]; then
    echo "healthz did not become ready within 60s" >&2
    docker logs "$NAME" >&2 || true
    exit 1
fi

test "$(curl -fsS "http://127.0.0.1:${PORT}/healthz")" = "ok"
test "$(curl -fsS "http://127.0.0.1:${PORT}/readyz")" = "ready"

# The binary must carry the SPA; no Node runtime exists in the final image.
curl -fsS "http://127.0.0.1:${PORT}/login" | grep -q "_app/immutable"
curl -fsS "http://127.0.0.1:${PORT}/consent" | grep -q "_app/immutable"
curl -fsS "http://127.0.0.1:${PORT}/device" | grep -q "_app/immutable"
curl -fsS "http://127.0.0.1:${PORT}/account" | grep -q "_app/immutable"

# Reserved API paths must 404, not fall back to the SPA shell.
status=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:${PORT}/api/does-not-exist")
test "$status" = "404"

echo "docker smoke ok: non-root 65532:65532, health/readiness, SPA fallback (/login,/consent,/device,/account), reserved API 404"
