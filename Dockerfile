# syntax=docker/dockerfile:1

FROM node:24-bookworm-slim AS web

WORKDIR /web
COPY web/package.json web/package-lock.json ./
RUN npm ci --include=dev
COPY web/ ./
RUN npm run build

FROM rust:1.99.1-bookworm AS builder

# aws-lc-sys (jsonwebtoken/aws_lc_rs) builds through CMake; SQLite is bundled.
RUN apt-get update \
    && apt-get install -y --no-install-recommends cmake perl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY --from=web /web/build ./web/build
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN cargo build --release --locked -p re0auth-server

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates wget \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /app/data/keys \
    && chown -R 65532:65532 /app

WORKDIR /app
COPY --from=builder --chown=65532:65532 /src/target/release/re0auth-server /app/re0auth-server
COPY --chown=65532:65532 config.docker.toml /app/config.toml

# Numeric UID/GID works even without a passwd entry. The process never runs as root.
USER 65532:65532

EXPOSE 8080
STOPSIGNAL SIGTERM
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget -qO- http://127.0.0.1:8080/healthz >/dev/null || exit 1

ENTRYPOINT ["/app/re0auth-server"]
CMD ["--config", "/app/config.toml"]
