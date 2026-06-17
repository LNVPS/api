ARG IMAGE=rust:trixie

FROM $IMAGE AS build
WORKDIR /app/src

# Install build dependencies
RUN apt update && apt -y install pkg-config libssl-dev && \
    rm -rf /var/lib/apt/lists/*

# Copy source
COPY . .

# Build (fail early by running lnvps_agent tests)
RUN cargo test --locked --package lnvps_agent -- --test-threads=1 \
  && cargo install --locked --root /app/build --path lnvps_agent lnvps_agent

FROM debian:trixie-slim AS runner
WORKDIR /app
RUN apt update && \
    apt install -y ca-certificates libssl3 && \
    rm -rf /var/lib/apt/lists/*
COPY --from=build /app/build .
ENTRYPOINT ["./bin/lnvps_agent"]
