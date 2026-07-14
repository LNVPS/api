ARG IMAGE=rust:bookworm

FROM $IMAGE AS chef
RUN cargo install cargo-chef --locked
WORKDIR /app/src

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS build
COPY --from=planner /app/src/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json --package lnvps_api_admin
COPY . .
RUN cargo build --release --locked --package lnvps_api_admin --bin lnvps_api_admin \
    && mkdir -p /app/build/bin \
    && cp target/release/lnvps_api_admin /app/build/bin/

FROM $IMAGE AS runner
WORKDIR /app
COPY --from=build /app/build/ .
ENTRYPOINT ["./bin/lnvps_api_admin"]
