ARG IMAGE=rust:bookworm

FROM $IMAGE AS build
WORKDIR /app/src

# Copy only workspace Cargo.toml and required crates
COPY Cargo.toml ./
COPY try-procedure ./try-procedure
COPY lnvps_db ./lnvps_db
COPY lnvps_api_common ./lnvps_api_common
COPY lnvps_api_admin ./lnvps_api_admin

RUN cargo install --locked --root /app/build --path lnvps_api_admin lnvps_api_admin

FROM $IMAGE AS runner
WORKDIR /app
COPY --from=build /app/build/ .
ENTRYPOINT ["./bin/lnvps_api_admin"]