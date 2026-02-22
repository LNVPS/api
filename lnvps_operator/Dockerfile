ARG IMAGE=rust:bookworm

FROM $IMAGE AS build
WORKDIR /app/src

# Copy only workspace Cargo.toml and required crates
COPY Cargo.toml ./
COPY try-procedure ./try-procedure
COPY lnvps_db ./lnvps_db
COPY lnvps_operator ./lnvps_operator

RUN cargo install --locked --root /app/build --path lnvps_operator lnvps_operator

FROM $IMAGE AS runner
WORKDIR /app
COPY --from=build /app/build/ .
ENTRYPOINT ["./bin/lnvps_operator"]