ARG IMAGE=rust:bookworm

FROM $IMAGE AS build
WORKDIR /app/src
COPY . .
RUN cargo install --root /app/build --path lnvps_operator lnvps_operator

FROM $IMAGE AS runner
WORKDIR /app
COPY --from=build /app/build/ .
ENTRYPOINT ["./bin/lnvps_operator"]