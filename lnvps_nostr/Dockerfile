ARG IMAGE=rust:trixie

FROM $IMAGE AS build
WORKDIR /app/src

# Copy only workspace Cargo.toml and required crates
COPY Cargo.toml ./
COPY try-procedure ./try-procedure
COPY lnvps_db ./lnvps_db
COPY lnvps_nostr ./lnvps_nostr

RUN cargo install --locked --root /app/build --path lnvps_nostr lnvps_nostr

FROM debian:trixie-slim AS runner
WORKDIR /app
RUN apt update && \
    apt install -y ca-certificates libssl3 && \
    rm -rf /var/lib/apt/lists/*
COPY --from=build /app/build .
ENTRYPOINT ["./bin/lnvps_nostr"]
