# syntax=docker/dockerfile:1

FROM node:24-bookworm-slim@sha256:01d566e8d94d8c619591d78652babfccd3c6992a3dffa9ed5ab39e11cf6c70e9 AS web

WORKDIR /web
RUN corepack enable && corepack prepare pnpm@11.8.0 --activate
COPY web/package.json web/pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile --prod=false
COPY web/ ./
# i18n catalogs live at the repository root; the SPA imports them via ../../../locales.
COPY locales /locales
RUN pnpm run build

FROM rust:1.99.1-bookworm@sha256:e6f2cff35d0f309acf8433b4f05878ed77092602c5065cc81801177da0bb3a9c AS builder

# aws-lc-sys (jsonwebtoken/aws_lc_rs) builds through CMake; SQLite is bundled.
RUN apt-get update \
    && apt-get install -y --no-install-recommends cmake perl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY --from=web /web/build ./web/build
COPY Cargo.toml Cargo.lock ./
COPY vendor ./vendor
COPY locales ./locales
COPY crates ./crates
RUN cargo build --release --locked -p re0auth-server

FROM debian:bookworm-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc

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
