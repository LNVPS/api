# Build stage
FROM rust:1.94-slim-bookworm AS builder

RUN apt-get update && \
    apt-get install -y pkg-config libssl-dev && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app/src
COPY . .
RUN cargo install --locked --root /app/build --path lnvps_agent lnvps_agent

# Runtime stage
FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y ca-certificates libssl3 && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/build/bin/lnvps_agent /usr/local/bin/lnvps_agent

# Default settings path (mount your settings.yaml at /etc/lnvps-agent/settings.yaml)
ENV LNVPS_AGENT_CONFIG=/etc/lnvps-agent/settings.yaml

ENTRYPOINT ["/usr/local/bin/lnvps_agent"]
