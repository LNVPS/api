ARG IMAGE=rust:bookworm

FROM $IMAGE AS build
WORKDIR /app/src
COPY . .
RUN apt update && apt -y install protobuf-compiler libvirt-dev
RUN cargo test --package lnvps_api --package lnvps_nostr \
  && cargo install --root /app/build --path lnvps_api lnvps_api \
  && cargo install --root /app/build --path lnvps_nostr lnvps_nostr

FROM $IMAGE AS runner
WORKDIR /app
COPY --from=build /app/build .
ENTRYPOINT ["./bin/lnvps_api"]