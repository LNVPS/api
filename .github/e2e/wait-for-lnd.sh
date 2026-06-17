#!/usr/bin/env bash
set -euo pipefail

# Wait for both LND nodes to be fully ready, fund them, open a channel from
# lnd-payer → lnd, and copy the lnd-payer credentials to a known host path.
#
# Usage: ./wait-for-lnd.sh [timeout_seconds]

TIMEOUT=${1:-120}
LND_CONTAINER=$(docker compose -f docker-compose.e2e.yaml ps -q lnd)
PAYER_CONTAINER=$(docker compose -f docker-compose.e2e.yaml ps -q lnd-payer)
BITCOIND_CONTAINER=$(docker compose -f docker-compose.e2e.yaml ps -q bitcoind)

BTC_CLI() {
    docker exec "$BITCOIND_CONTAINER" bitcoin-cli -regtest \
        -rpcuser=polaruser -rpcpassword=polarpass "$@"
}
LND_CLI() {
    docker exec "$LND_CONTAINER" lncli --network=regtest "$@"
}
PAYER_CLI() {
    docker exec "$PAYER_CONTAINER" lncli --network=regtest "$@"
}

wait_for_node() {
    local name="$1"
    local cli_fn="$2"
    echo "Waiting for ${name} to be ready (timeout: ${TIMEOUT}s)..."
    for i in $(seq 1 "$TIMEOUT"); do
        if $cli_fn getinfo >/dev/null 2>&1; then
            echo "${name} is ready after ${i}s"
            return 0
        fi
        sleep 1
    done
    echo "ERROR: ${name} did not become ready within ${TIMEOUT}s"
    return 1
}

# Wait for both nodes
wait_for_node "lnd"       LND_CLI
wait_for_node "lnd-payer" PAYER_CLI

# Copy lnd credentials to host (used by the API server)
mkdir -p /tmp/e2e-lnd/data/chain/bitcoin/regtest
docker cp "$LND_CONTAINER":/root/.lnd/tls.cert \
    /tmp/e2e-lnd/tls.cert
docker cp "$LND_CONTAINER":/root/.lnd/data/chain/bitcoin/regtest/admin.macaroon \
    /tmp/e2e-lnd/data/chain/bitcoin/regtest/admin.macaroon
echo "lnd credentials copied to /tmp/e2e-lnd/"

# Copy lnd-payer credentials to host (used by E2E tests to pay invoices)
mkdir -p /tmp/e2e-lnd-payer/data/chain/bitcoin/regtest
docker cp "$PAYER_CONTAINER":/root/.lnd/tls.cert \
    /tmp/e2e-lnd-payer/tls.cert
docker cp "$PAYER_CONTAINER":/root/.lnd/data/chain/bitcoin/regtest/admin.macaroon \
    /tmp/e2e-lnd-payer/data/chain/bitcoin/regtest/admin.macaroon
echo "lnd-payer credentials copied to /tmp/e2e-lnd-payer/"

# Fund both nodes' on-chain wallets (101 blocks each to activate segwit)
LND_ADDR=$(LND_CLI newaddress p2wkh | jq -r .address)
PAYER_ADDR=$(PAYER_CLI newaddress p2wkh | jq -r .address)
BTC_CLI generatetoaddress 101 "$LND_ADDR"   >/dev/null
BTC_CLI generatetoaddress 101 "$PAYER_ADDR" >/dev/null
echo "Funded lnd ($LND_ADDR) and lnd-payer ($PAYER_ADDR) with 101 blocks each"

# Connect lnd-payer to lnd as a peer.
# lnd listens on port 9735 inside the compose network (service hostname "lnd").
# Retry for up to 30 s because the wallet can still be initialising after
# getinfo returns successfully.
LND_PUBKEY=$(LND_CLI getinfo | jq -r .identity_pubkey)
echo "Connecting lnd-payer to lnd (pubkey: ${LND_PUBKEY})..."
for i in $(seq 1 30); do
    if PAYER_CLI connect "${LND_PUBKEY}@lnd:9735" 2>/dev/null; then
        echo "lnd-payer connected to lnd after ${i}s"
        break
    fi
    if [[ "$i" -eq 30 ]]; then
        echo "ERROR: could not connect lnd-payer to lnd within 30s"
        exit 1
    fi
    sleep 1
done

# Open a 10M sat channel from lnd-payer → lnd
PAYER_CLI openchannel --node_key "$LND_PUBKEY" --local_amt 10000000
echo "Channel open request submitted (10M sats)"

# Mine 6 blocks so the channel is confirmed and active
BTC_CLI generatetoaddress 6 "$LND_ADDR" >/dev/null
echo "Mined 6 confirmation blocks"

# Wait until the channel is active on the payer side
echo "Waiting for channel to become active..."
for i in $(seq 1 60); do
    ACTIVE=$(PAYER_CLI listchannels | jq '[.channels[] | select(.active == true)] | length')
    if [[ "$ACTIVE" -ge 1 ]]; then
        echo "Channel is active after ${i}s"
        break
    fi
    if [[ "$i" -eq 60 ]]; then
        echo "ERROR: channel did not become active within 60s"
        PAYER_CLI listchannels >&2
        exit 1
    fi
    sleep 1
done
