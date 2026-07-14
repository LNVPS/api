ARG IMAGE=rust:trixie

FROM $IMAGE AS chef
RUN cargo install cargo-chef --locked
WORKDIR /app/src

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS build
COPY --from=planner /app/src/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json --package lnvps_nostr
COPY . .
RUN cargo build --release --locked --package lnvps_nostr --bin lnvps_nostr \
    && mkdir -p /app/build/bin \
    && cp target/release/lnvps_nostr /app/build/bin/

FROM debian:trixie-slim AS runner
WORKDIR /app
RUN apt update && \
    apt install -y ca-certificates libssl3 && \
    rm -rf /var/lib/apt/lists/*
COPY --from=build /app/build .
ENTRYPOINT ["./bin/lnvps_nostr"]
