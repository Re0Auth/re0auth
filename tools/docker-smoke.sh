#!/usr/bin/env sh
set -eu

cd "$(dirname "$0")/.."

IMAGE=${IMAGE:-re0auth:ci}
NAME=${NAME:-re0auth-ci-smoke}
PORT=${PORT:-18080}

cleanup() {
    docker rm -f "$NAME" >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker build -t "$IMAGE" .

docker run -d --name "$NAME" -p "127.0.0.1:${PORT}:8080" "$IMAGE" >/dev/null

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
