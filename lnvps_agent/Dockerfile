ARG IMAGE=rust:trixie

FROM $IMAGE AS chef
RUN apt update && apt -y install pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*
RUN cargo install cargo-chef --locked
WORKDIR /app/src

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS build
COPY --from=planner /app/src/recipe.json recipe.json
RUN cargo chef cook --recipe-path recipe.json --tests --package lnvps_agent \
    && cargo chef cook --release --recipe-path recipe.json --package lnvps_agent
COPY . .
RUN cargo test --locked --package lnvps_agent -- --test-threads=1 \
    && cargo build --release --locked --package lnvps_agent --bin lnvps_agent \
    && mkdir -p /app/build/bin \
    && cp target/release/lnvps_agent /app/build/bin/

FROM debian:trixie-slim AS runner
WORKDIR /app
RUN apt update && \
    apt install -y ca-certificates libssl3 && \
    rm -rf /var/lib/apt/lists/*
COPY --from=build /app/build .
ENTRYPOINT ["./bin/lnvps_agent"]
