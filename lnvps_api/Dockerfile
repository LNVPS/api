ARG IMAGE=rust:trixie
ARG HOST_INFO_IMAGE=lnvps-host-info

FROM $IMAGE AS build
WORKDIR /app/src
COPY . .
RUN apt update && apt -y install protobuf-compiler libvirt-dev libva-dev
RUN cargo test --locked --package lnvps_api -- --test-threads=1 \
  && cargo install --locked --root /app/build --path lnvps_api lnvps_api

# Copy host-info binaries from pre-built multi-arch images
FROM ${HOST_INFO_IMAGE}:latest-amd64 AS host-info-amd64
FROM ${HOST_INFO_IMAGE}:latest-arm64 AS host-info-arm64

FROM debian:trixie-slim AS runner
WORKDIR /app
RUN apt update && \
    apt install -y ca-certificates libssl3 && \
    rm -rf /var/lib/apt/lists/*
COPY --from=build /app/build .
COPY --from=host-info-amd64 /app/lnvps-host-info ./bin/lnvps-host-info
COPY --from=host-info-arm64 /app/lnvps-host-info ./bin/lnvps-host-info-arm64
ENTRYPOINT ["./bin/lnvps_api"]