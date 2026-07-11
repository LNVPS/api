# syntax=docker/dockerfile:1
#
# Container image for the standalone lnvps_fw demo API (the `serve_api`
# example): the token-authed control API + embedded dashboard, driven by a
# simulated live-traffic feed. It runs the full control plane but needs no
# root and no eBPF datapath at runtime, so it deploys anywhere as a plain
# container for demonstration.
#
# Build context is the lnvps_fw/ workspace root:
#   docker build -f lnvps_fw/Dockerfile -t lnvps-fw-demo lnvps_fw
#   docker run --rm -p 8899:8899 -e API_TOKEN=devtoken lnvps-fw-demo
#   open https://localhost:8899/   (self-signed TLS; paste the token)

# --- Stage 1: build the single-file dashboard bundle (JS + CSS inlined) ---
FROM oven/bun:1 AS dashboard
WORKDIR /dash
COPY lnvps_fw_service/dashboard/package.json lnvps_fw_service/dashboard/bun.lock ./
RUN bun install --frozen-lockfile
COPY lnvps_fw_service/dashboard/ ./
RUN bun run build

# --- Stage 2: compile the demo binary (build.rs still builds the eBPF crate) ---
FROM rustlang/rust:nightly-trixie AS builder
# bpf-linker needs LLVM; libelf is used by the aya-build eBPF pipeline; the
# build-std eBPF target needs rust-src. aya-build shells out to the `nightly`
# toolchain alias (the base image only ships a date-stamped nightly), so
# install it explicitly with rust-src.
RUN apt-get update \
    && apt-get install -y --no-install-recommends llvm clang libelf-dev \
    && rm -rf /var/lib/apt/lists/* \
    && rustup toolchain install nightly --component rust-src \
    && cargo install bpf-linker --locked
WORKDIR /src
COPY . .
# The daemon embeds dashboard/dist/index.html via include_str!, so drop in the
# freshly-built bundle before cargo compiles the service.
COPY --from=dashboard /dash/dist/index.html lnvps_fw_service/dashboard/dist/index.html
RUN cargo build --release -p lnvps_fw_service --example serve_api

# --- Stage 3: minimal runtime ---
FROM debian:trixie-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /src/target/release/examples/serve_api /usr/local/bin/lnvps-fw-demo
# Bind on all interfaces inside the container; token defaults to `devtoken`
# (override with -e API_TOKEN=...). TLS is a self-signed cert generated on boot.
ENV BIND_ADDR=0.0.0.0:8899
EXPOSE 8899
ENTRYPOINT ["/usr/local/bin/lnvps-fw-demo"]
