ARG IMAGE=rust:trixie

FROM $IMAGE AS chef
RUN apt update && apt -y install libva-dev libclang-dev \
    && rm -rf /var/lib/apt/lists/*
RUN cargo install cargo-chef --locked
WORKDIR /app/src

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS build
COPY --from=planner /app/src/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json
COPY . .
RUN cargo build --release --locked --bin lnvps-host-info \
    && cp target/release/lnvps-host-info /lnvps-host-info

FROM debian:trixie-slim AS runner
WORKDIR /app
COPY --from=build /lnvps-host-info .
ENTRYPOINT ["./lnvps-host-info"]
