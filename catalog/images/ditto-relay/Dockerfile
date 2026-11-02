FROM rust:1-trixie AS build
RUN apt-get update && apt-get install -y --no-install-recommends clang cmake pkg-config && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
RUN cargo build --release --locked

FROM debian:trixie-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates jq && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /data && chown 1000:1000 /data
COPY --from=build /src/target/release/ditto-relay /usr/local/bin/ditto-relay
USER 1000:1000
ENV HOME=/data
VOLUME /data
EXPOSE 13131
ENTRYPOINT ["ditto-relay"]
CMD ["--config", "/etc/ditto-relay/ditto-relay.toml"]
