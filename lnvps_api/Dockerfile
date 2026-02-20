ARG IMAGE=rust:trixie
ARG HOST_INFO_IMAGE=registry.v0l.io/lnvps-host-info:latest

FROM $IMAGE AS build
WORKDIR /app/src
COPY . .
RUN apt update && apt -y install protobuf-compiler libvirt-dev libva-dev
RUN cargo test --locked --package lnvps_api -- --test-threads=1 \
  && cargo install --locked --root /app/build --path lnvps_api lnvps_api

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