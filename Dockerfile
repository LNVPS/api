ARG IMAGE=rust:bookworm

FROM $IMAGE AS build
WORKDIR /app/src
COPY . .
RUN apt update && apt -y install protobuf-compiler libvirt-dev
RUN cargo test && cargo install --path lnvps_api --root /app/build

FROM $IMAGE AS runner
WORKDIR /app
COPY --from=build /app/build .
ENTRYPOINT ["./bin/api"]