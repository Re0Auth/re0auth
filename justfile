# Windows: put Git Bash on PATH (for example C:\Program Files\Git\bin\bash.exe).
set shell := ["bash", "-euo", "pipefail", "-c"]

# The local gate. CI runs the same commands.
check: fmt clippy test arch config

fmt:
    cargo fmt --all -- --check

fmt-fix:
    cargo fmt --all

clippy:
    cargo clippy --workspace --all-targets -- -D warnings

test:
    cargo test --workspace --all-targets

arch:
    cargo test -p re0auth-archtest -- --nocapture

config:
    bash tools/check-config.sh config.example.toml

semver:
    bash tools/check-semver.sh

docker:
    bash tools/docker-smoke.sh

deny:
    @command -v cargo-deny >/dev/null || { echo "install cargo-deny: cargo install cargo-deny --locked"; exit 1; }
    cargo deny check

audit:
    @command -v cargo-audit >/dev/null || { echo "install cargo-audit: cargo install cargo-audit --locked"; exit 1; }
    cargo audit

build:
    cargo build --workspace

run:
    cargo run -p re0auth-server -- --config config.toml

web:
    cd web && pnpm install --frozen-lockfile && pnpm run check && pnpm run build

e2e:
    cd web && pnpm exec playwright test

clean:
    cargo clean
