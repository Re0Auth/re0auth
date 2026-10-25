#!/usr/bin/env sh
set -eu

cd "$(dirname "$0")/.."

# A brand-new repository has no baseline yet. The gate becomes active as soon as
# a parent commit exists; CI checks out full history so this is not a silent skip.
if [ "${GITHUB_EVENT_NAME:-}" = "pull_request" ] \
    && git rev-parse --verify origin/main >/dev/null 2>&1; then
    baseline=origin/main
elif git rev-parse --verify HEAD~1 >/dev/null 2>&1; then
    baseline=HEAD~1
elif git rev-parse --verify origin/main >/dev/null 2>&1; then
    baseline=origin/main
else
    echo "no baseline commit available; semver gate starts with the next commit"
    exit 0
fi

if ! command -v cargo-semver-checks >/dev/null 2>&1; then
    echo "cargo-semver-checks is required; install it before running this gate" >&2
    exit 1
fi

cargo semver-checks check-release --package re0auth-api --baseline-rev "$baseline"
