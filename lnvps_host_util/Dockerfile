ARG IMAGE=rust:trixie

FROM $IMAGE AS build
WORKDIR /app/src

# Install dependencies first (cached layer)
RUN apt update && apt -y install libva-dev libclang-dev

# Copy only workspace Cargo.toml and the host_util crate
COPY Cargo.toml ./
COPY lnvps_host_util ./lnvps_host_util

# Build
RUN cargo install --locked --root /app/build --path lnvps_host_util lnvps_host_util

FROM debian:trixie-slim AS runner
WORKDIR /app
COPY --from=build /app/build/bin/lnvps-host-info .
ENTRYPOINT ["./lnvps-host-info"]
