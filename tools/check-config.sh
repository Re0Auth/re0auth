#!/usr/bin/env sh
set -eu

cd "$(dirname "$0")/.."
exec cargo run -p re0auth-server -- --config "${1:-config.example.toml}" --check-config
