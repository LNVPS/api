ARG IMAGE=rust:bookworm

FROM $IMAGE AS build
WORKDIR /app/src
COPY . .
RUN apt update && apt -y install protobuf-compiler
RUN cargo test && cargo install --path . --root /app/build

FROM $IMAGE AS runner
WORKDIR /app
COPY --from=build /app/build .
ENTRYPOINT ["./bin/api"]