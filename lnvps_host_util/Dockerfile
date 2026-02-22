ARG IMAGE=rust:trixie

FROM $IMAGE AS build
WORKDIR /app/src

# Install dependencies first (cached layer)
RUN apt update && apt -y install libva-dev libclang-dev

# Copy source
COPY . .

# Build
RUN cargo install --locked --root /app/build --path lnvps_host_util lnvps_host_util

FROM debian:trixie-slim AS runner
WORKDIR /app
COPY --from=build /app/build/bin/lnvps-host-info .
ENTRYPOINT ["./lnvps-host-info"]
