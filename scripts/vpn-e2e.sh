#!/usr/bin/env bash
# vpn-e2e.sh — LNVPS and lvd together, on real namespaces, carrying packets.
#
# lnvps_e2e/tests/vpn_lvd.rs needs two things no other harness needs at once: a
# running stack (API, admin API, database, LND) and root, for the network
# namespaces the route server and the customer live in. run-e2e.sh runs its
# tests as the invoking user, and tunnel-e2e.sh runs as root with no stack, so
# this brings up one and runs the harness under the other.
#
# Usage:
#   ./scripts/vpn-e2e.sh [--no-build] [--keep]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$(cd "$SCRIPT_DIR/.." && pwd)"

BUILD_ARGS=()
KEEP=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --no-build) BUILD_ARGS+=(--no-build); shift ;;
        --keep)     KEEP=1; shift ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

cleanup() {
    if [[ "$KEEP" -eq 0 ]]; then
        echo ""
        echo "=== Stopping the stack ==="
        # run-e2e.sh's own cleanup runs on exit; this tears down what
        # --no-cleanup left behind.
        docker compose -f "${COMPOSE_FILE:-docker-compose.e2e.yaml}" down -v --remove-orphans || true
        for f in /tmp/lnvps-e2e-api.pid /tmp/lnvps-e2e-admin.pid; do
            [[ -f "$f" ]] && kill "$(cat "$f")" 2>/dev/null || true
        done
    fi
}
trap cleanup EXIT

# The daemon under test has to exist before the harness can run it.
echo "=== Building lvd and the harness ==="
cargo build -p lnvps_vpn
cargo test -p lnvps_e2e --test vpn_lvd --no-run

echo "=== Bringing up the stack ==="
# Fixed here rather than left to each process: the harness derives its
# database name from this, so a run id that does not survive `sudo` means the
# harness invents a fresh, unmigrated database and every query fails with
# "table doesn't exist".
export LNVPS_E2E_RUN_ID="${LNVPS_E2E_RUN_ID:-$(date +%s%3N)}"

./scripts/run-e2e.sh --setup-only --no-cleanup "${BUILD_ARGS[@]}"

# The harness reads the same variables the rest of the suite does, and needs
# them to survive sudo.
BIN="$(ls -t target/debug/deps/vpn_lvd-* | grep -v '\.d$' | head -1)"
echo "=== Running the harness as root ($BIN) ==="
sudo -E \
    LNVPS_API_URL="${LNVPS_API_URL:-http://localhost:8000}" \
    LNVPS_ADMIN_API_URL="${LNVPS_ADMIN_API_URL:-http://localhost:8001}" \
    LNVPS_DB_URL="${LNVPS_DB_URL:-}" \
    LNVPS_DB_BASE_URL="${LNVPS_DB_BASE_URL:-}" \
    LNVPS_E2E_RUN_ID="$LNVPS_E2E_RUN_ID" \
    NOSTR_SECRET_KEY="${NOSTR_SECRET_KEY:-}" \
    ADMIN_NOSTR_SECRET_KEY="${ADMIN_NOSTR_SECRET_KEY:-}" \
    "$BIN" --ignored --test-threads=1 --nocapture
