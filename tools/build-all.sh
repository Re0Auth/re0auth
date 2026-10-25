#!/usr/bin/env sh
set -eu

cd "$(dirname "$0")/.."

(cd web && npm ci --include=dev && npm run build)
cargo build --release --locked -p re0auth-server
