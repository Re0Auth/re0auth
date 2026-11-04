#!/usr/bin/env sh
set -eu

cd "$(dirname "$0")/.."

(cd web && pnpm install --frozen-lockfile && pnpm run build)
cargo build --release --locked -p re0auth-server
