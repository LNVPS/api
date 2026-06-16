# Build stage
FROM rust:1.94-slim-bookworm AS builder

RUN apt-get update && apt-get install -y pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy workspace manifests
COPY Cargo.toml Cargo.lock ./
COPY lnvps_agent/Cargo.toml lnvps_agent/
COPY lnvps_api_common/Cargo.toml lnvps_api_common/

# Build dependencies (cached layer)
RUN mkdir -p lnvps_agent/src && \
    echo 'fn main() {}' > lnvps_agent/src/main.rs && \
    mkdir -p lnvps_api_common/src && \
    echo 'fn main() {}' > lnvps_api_common/src/lib.rs && \
    cargo build --release -p lnvps_agent && \
    rm -rf lnvps_agent/src lnvps_api_common/src

# Copy source and rebuild
COPY lnvps_agent/src lnvps_agent/src
COPY lnvps_api_common/src lnvps_api_common/src
RUN cargo build --release -p lnvps_agent

# Runtime stage
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/lnvps_agent /usr/local/bin/lnvps_agent

# Default settings path (mount your settings.yaml at /etc/lnvps-agent/settings.yaml)
ENV LNVPS_AGENT_CONFIG=/etc/lnvps-agent/settings.yaml

ENTRYPOINT ["/usr/local/bin/lnvps_agent"]
