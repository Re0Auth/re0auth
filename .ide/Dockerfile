# 沿用默认镜像，避免双容器模式
FROM cnbcool/default-dev-env:latest

# aws-lc、sqlite 编译依赖
RUN apt-get update \
  && apt-get install -y --no-install-recommends \
     build-essential cmake clang libclang-dev perl pkg-config libssl-dev \
     curl ca-certificates \
  && rm -rf /var/lib/apt/lists/*

# 装默认位置并链进 PATH，免环境变量
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
  | sh -s -- -y --profile minimal \
      --default-toolchain 1.98.0 -c rustfmt -c clippy \
  && ln -sf /root/.cargo/bin/* /usr/local/bin/

# 缺 Node 24 时补齐
RUN node --version 2>/dev/null | grep -q '^v24' \
  || (curl -fsSL https://deb.nodesource.com/setup_24.x | bash - \
      && apt-get install -y --no-install-recommends nodejs \
      && rm -rf /var/lib/apt/lists/*)
