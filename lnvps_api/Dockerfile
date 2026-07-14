ARG IMAGE=rust:trixie
ARG HOST_INFO_IMAGE=registry.v0l.io/lnvps-host-info:latest

# --- cargo-chef base: install toolchain deps + cargo-chef once (cached) ---
FROM $IMAGE AS chef
RUN apt update && apt -y install protobuf-compiler libvirt-dev libva-dev \
    && rm -rf /var/lib/apt/lists/*
RUN cargo install cargo-chef --locked
WORKDIR /app/src

# --- planner: produce a dependency recipe from the manifests only ---
FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

# --- build: cook dependencies (cached layer), then compile the app ---
FROM chef AS build
COPY --from=planner /app/src/recipe.json recipe.json
# Cook deps for both the dev profile (tests) and release profile (final build).
# This layer is only invalidated when Cargo.toml / Cargo.lock change.
RUN cargo chef cook --recipe-path recipe.json --tests --package lnvps_api \
    && cargo chef cook --release --recipe-path recipe.json --package lnvps_api
COPY . .
RUN cargo test --locked --package lnvps_api -- --test-threads=1 \
    && cargo build --release --locked --package lnvps_api --bin lnvps_api --bin fix_lnurlp_topups \
    && mkdir -p /app/build/bin \
    && cp target/release/lnvps_api target/release/fix_lnurlp_topups /app/build/bin/

# Download host-info binaries from pre-built multi-arch images using crane
FROM gcr.io/go-containerregistry/crane:latest AS crane-bin
FROM debian:trixie-slim AS crane
RUN apt update && apt install -y ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=crane-bin /ko-app/crane /usr/local/bin/crane

ARG HOST_INFO_IMAGE
ARG REGISTRY_USER
ARG REGISTRY_PASS
RUN crane auth login registry.v0l.io -u "${REGISTRY_USER}" -p "${REGISTRY_PASS}" \
    && crane export --platform linux/amd64 ${HOST_INFO_IMAGE} - | tar -xf - -C /tmp app/lnvps-host-info \
    && mv /tmp/app/lnvps-host-info /lnvps-host-info-amd64
RUN crane auth login registry.v0l.io -u "${REGISTRY_USER}" -p "${REGISTRY_PASS}" \
    && crane export --platform linux/arm64 ${HOST_INFO_IMAGE} - | tar -xf - -C /tmp app/lnvps-host-info \
    && mv /tmp/app/lnvps-host-info /lnvps-host-info-arm64

FROM debian:trixie-slim AS runner
WORKDIR /app
RUN apt update && \
    apt install -y ca-certificates libssl3 && \
    rm -rf /var/lib/apt/lists/*
COPY --from=build /app/build .
COPY --from=crane /lnvps-host-info-amd64 ./bin/lnvps-host-info
COPY --from=crane /lnvps-host-info-arm64 ./bin/lnvps-host-info-arm64
ENTRYPOINT ["./bin/lnvps_api"]
