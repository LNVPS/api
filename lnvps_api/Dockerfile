ARG IMAGE=rust:trixie

FROM $IMAGE AS build
WORKDIR /app/src
COPY . .
RUN apt update && apt -y install protobuf-compiler libvirt-dev
RUN cargo test --locked --package lnvps_api --package lnvps_nostr -- --test-threads=1 \
  && cargo install --locked --root /app/build --path lnvps_api lnvps_api \
  && cargo install --locked --root /app/build --path lnvps_nostr lnvps_nostr

FROM debian:trixie-slim AS runner
WORKDIR /app
RUN apt update && \
    apt install -y ca-certificates libssl3 && \
    rm -rf /var/lib/apt/lists/*
COPY --from=build /app/build .
ENTRYPOINT ["./bin/lnvps_api"]