ARG IMAGE=rust:trixie

FROM $IMAGE AS chef
RUN apt update && apt -y install libva-dev libclang-dev \
    && rm -rf /var/lib/apt/lists/*
# Prebuilt cargo-chef binary via cargo-binstall: avoids a multi-minute
# from-source compile of cargo-chef on every cold cache.
RUN curl -L --proto '=https' --tlsv1.2 -sSf https://raw.githubusercontent.com/cargo-bins/cargo-binstall/main/install-from-binstall-release.sh | bash \
    && cargo binstall -y --locked cargo-chef
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
