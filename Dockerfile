ARG IMAGE=rust:trixie
ARG HOST_INFO_IMAGE=registry.v0l.io/lnvps-host-info:latest

# --- chef base: toolchain deps + cargo-chef, shared by every service ---
FROM $IMAGE AS chef
RUN apt update && apt -y install protobuf-compiler libvirt-dev libva-dev pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*
# Prebuilt cargo-chef binary via cargo-binstall: avoids a multi-minute
# from-source compile of cargo-chef on every cold cache.
RUN curl -L --proto '=https' --tlsv1.2 -sSf https://raw.githubusercontent.com/cargo-bins/cargo-binstall/main/install-from-binstall-release.sh | bash \
    && cargo binstall -y --locked cargo-chef
WORKDIR /app/src

# --- planner: produce a dependency recipe from the manifests only ---
FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

# --- build: cook workspace deps once (cached layer), compile ALL bins once ---
FROM chef AS build
COPY --from=planner /app/src/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json
COPY . .
RUN cargo build --release --locked --bins \
      -p lnvps_api -p lnvps_api_admin -p lnvps_operator -p lnvps_nostr -p lnvps_agent \
    && mkdir -p /out \
    && cp target/release/lnvps_api target/release/fix_lnurlp_topups \
          target/release/lnvps_api_admin target/release/lnvps_operator \
          target/release/lnvps_nostr target/release/lnvps_agent /out/

# --- crane: fetch pre-built host-info binaries for the api image ---
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

# --- shared runtime base ---
FROM debian:trixie-slim AS runtime
WORKDIR /app
RUN apt update && \
    apt install -y ca-certificates libssl3 && \
    rm -rf /var/lib/apt/lists/*

# --- per-service images (buildx bake targets, one per published image) ---
FROM runtime AS lnvps-api
COPY --from=build /out/lnvps_api /out/fix_lnurlp_topups ./bin/
COPY --from=crane /lnvps-host-info-amd64 ./bin/lnvps-host-info
COPY --from=crane /lnvps-host-info-arm64 ./bin/lnvps-host-info-arm64
ENTRYPOINT ["./bin/lnvps_api"]

FROM runtime AS lnvps-api-admin
COPY --from=build /out/lnvps_api_admin ./bin/
ENTRYPOINT ["./bin/lnvps_api_admin"]

FROM runtime AS lnvps-operator
COPY --from=build /out/lnvps_operator ./bin/
# The operator holds a Kubernetes token, the database DSN and the field
# encryption key, and writes nothing to its own filesystem.
USER 65534:65534
ENTRYPOINT ["./bin/lnvps_operator"]

FROM runtime AS lnvps-nostr
COPY --from=build /out/lnvps_nostr ./bin/
ENTRYPOINT ["./bin/lnvps_nostr"]

FROM runtime AS lnvps-agent
COPY --from=build /out/lnvps_agent ./bin/
ENTRYPOINT ["./bin/lnvps_agent"]
