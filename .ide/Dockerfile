# 沿用默认镜像，避免双容器模式
FROM cnbcool/default-dev-env:latest

# aws-lc、sqlite 编译依赖
RUN apt-get update \
  && apt-get install -y --no-install-recommends \
     build-essential cmake clang libclang-dev perl pkg-config libssl-dev \
     curl ca-certificates \
  && rm -rf /var/lib/apt/lists/*

# 锁定工具链，避免重复下载
ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
  | sh -s -- -y --no-modify-path --profile minimal \
      --default-toolchain 1.98.0 -c rustfmt -c clippy \
  && rustc --version

# 缺 Node 24 时补齐
RUN node --version 2>/dev/null | grep -q '^v24' \
  || (curl -fsSL https://deb.nodesource.com/setup_24.x | bash - \
      && apt-get install -y --no-install-recommends nodejs \
      && rm -rf /var/lib/apt/lists/*)
