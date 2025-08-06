ARG IMAGE=rust:bookworm

FROM $IMAGE AS build
WORKDIR /app/src
COPY . .
RUN cargo install lnvps_api_admin --root /app/build --path lnvps_api_admin

FROM $IMAGE AS runner
WORKDIR /app
COPY --from=build /app/build/ .
ENTRYPOINT ["./bin/lnvps_api_admin"]