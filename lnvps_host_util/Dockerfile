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
# The binary links libva at build time for VA-API detection, so the runtime
# image needs the shared library too. Without it the image builds fine and then
# fails on every run with "libva.so.2: cannot open shared object file".
RUN apt update && apt -y install --no-install-recommends libva2 libva-drm2 \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=build /lnvps-host-info .
ENTRYPOINT ["./lnvps-host-info"]
