#!/usr/bin/env bash
set -euo pipefail

# Wait for LND to be fully ready and copy credentials to a known path.
# Usage: ./wait-for-lnd.sh [timeout_seconds]

TIMEOUT=${1:-120}
LND_CONTAINER=$(docker compose -f docker-compose.e2e.yaml ps -q lnd)

echo "Waiting for LND to be ready (timeout: ${TIMEOUT}s)..."

for i in $(seq 1 "$TIMEOUT"); do
    if docker exec "$LND_CONTAINER" lncli --network=regtest getinfo >/dev/null 2>&1; then
        echo "LND is ready after ${i}s"

        # Copy TLS cert and macaroon to host
        mkdir -p /tmp/e2e-lnd/data/chain/bitcoin/regtest
        docker cp "$LND_CONTAINER":/root/.lnd/tls.cert /tmp/e2e-lnd/tls.cert
        docker cp "$LND_CONTAINER":/root/.lnd/data/chain/bitcoin/regtest/admin.macaroon \
            /tmp/e2e-lnd/data/chain/bitcoin/regtest/admin.macaroon

        echo "LND credentials copied to /tmp/e2e-lnd/"

        # Generate a wallet address and mine initial blocks so LND has funds
        ADDR=$(docker exec "$LND_CONTAINER" lncli --network=regtest newaddress p2wkh | jq -r .address)
        BITCOIND_CONTAINER=$(docker compose -f docker-compose.e2e.yaml ps -q bitcoind)
        docker exec "$BITCOIND_CONTAINER" bitcoin-cli -regtest \
            -rpcuser=polaruser -rpcpassword=polarpass \
            generatetoaddress 101 "$ADDR" >/dev/null

        echo "Mined 101 blocks to LND address ${ADDR}"
        exit 0
    fi
    sleep 1
done

echo "ERROR: LND did not become ready within ${TIMEOUT}s"
docker compose -f docker-compose.e2e.yaml logs lnd | tail -30
exit 1
