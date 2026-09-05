#!/usr/bin/env bash
# run-e2e.sh — Build, start infrastructure, and run the LNVPS E2E test suite.
#
# Usage:
#   ./scripts/run-e2e.sh [OPTIONS]
#
# Options:
#   --no-build       Skip cargo build step
#   --setup-only     Bring the stack up and stop, printing how to reach it
#   --no-cleanup     Leave API servers and DB running after the run
#   --filter FILTER  Pass a test-name filter to cargo test (e.g. lifecycle)
#   --ignored        Run only #[ignore]d tests (the model-dependent agent suite)
#   --run-id ID      Override the run ID (default: timestamp)
#
# Environment variables (all optional):
#   LNVPS_E2E_RUN_ID    Override the run ID
#   LNVPS_DB_BASE_URL   DB server URL without DB name (default: mysql://root:root@localhost:3377)
#   COMPOSE_FILE        docker-compose file to use (default: docker-compose.e2e.yaml)
#   LNVPS_API_URL       User API base URL (default: http://localhost:8000)
#   LNVPS_ADMIN_API_URL Admin API base URL (default: http://localhost:8001)
#
# Examples:
#   # Full run (start docker, build, run tests, stop docker)
#   ./scripts/run-e2e.sh
#
#   # Run only the lifecycle test without rebuilding
#   ./scripts/run-e2e.sh --no-build --filter lifecycle

set -euo pipefail

# ---------------------------------------------------------------------------
# Parse arguments
# ---------------------------------------------------------------------------
SKIP_BUILD=0
SKIP_CLEANUP=0
SETUP_ONLY=0
FILTER=""
RUN_IGNORED=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --no-build)    SKIP_BUILD=1;   shift ;;
        --setup-only)  SETUP_ONLY=1;   shift ;;
        --no-cleanup)  SKIP_CLEANUP=1; shift ;;
        --filter)      FILTER="$2";    shift 2 ;;
        --ignored)     RUN_IGNORED=1;  shift ;;
        --run-id)
            export LNVPS_E2E_RUN_ID="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1" >&2
            exit 1
            ;;
    esac
done

# ---------------------------------------------------------------------------
# Resolve paths
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

COMPOSE_FILE="${COMPOSE_FILE:-docker-compose.e2e.yaml}"
DB_BASE="${LNVPS_DB_BASE_URL:-mysql://root:root@localhost:3377}"
export LNVPS_DB_BASE_URL="$DB_BASE"

# Extract host/port from DB_BASE for CLI access (strips the mysql:// scheme)
# mysql://root:root@localhost:3377  →  host=localhost  port=3377  user=root  pass=root
DB_HOST=$(echo "$DB_BASE" | sed -E 's|mysql://[^@]+@([^:/]+).*|\1|')
DB_PORT=$(echo "$DB_BASE" | sed -E 's|.*:([0-9]+)$|\1|')
DB_USER=$(echo "$DB_BASE" | sed -E 's|mysql://([^:]+):.*|\1|')
DB_PASS=$(echo "$DB_BASE" | sed -E 's|mysql://[^:]+:([^@]+)@.*|\1|')

# ---------------------------------------------------------------------------
# mysql_exec SQL — run a SQL statement against the e2e MariaDB.
#
# Prefers running inside the DB container via `docker compose exec` because that
# is deterministic in CI: it does not depend on a host mysql/mariadb client being
# installed, nor on the published port being reachable from the runner host
# (which was the cause of repeated "MariaDB did not become ready" CI failures).
# Falls back to a host client only if compose exec is unavailable.
# ---------------------------------------------------------------------------
mysql_exec() {
    local sql="$1"
    # Preferred: execute inside the db service container.
    #
    # stderr is captured rather than discarded: a swallowed SQL error turns
    # into a bare "failed to seed" with no cause, which is what made the
    # payment_method_config seeding failure so hard to diagnose. The password
    # warning mariadb always prints is filtered out instead.
    local err
    if err=$(docker compose -f "$COMPOSE_FILE" exec -T db \
        mariadb -u "$DB_USER" "-p${DB_PASS}" -e "$sql" 2>&1); then
        return 0
    fi
    if [[ -n "$err" ]]; then
        grep -v "Using a password on the command line" <<<"$err" >&2 || true
    fi
    # Fallbacks: host clients (used for local dev where the client is installed).
    if command -v mariadb >/dev/null 2>&1; then
        mariadb -h "$DB_HOST" -P "$DB_PORT" -u "$DB_USER" "-p${DB_PASS}" \
            -e "$sql" 2>/dev/null
    elif command -v mysql >/dev/null 2>&1; then
        mysql -h "$DB_HOST" -P "$DB_PORT" -u "$DB_USER" "-p${DB_PASS}" \
            -e "$sql" 2>/dev/null
    else
        # Last resort: docker exec by published-port lookup.
        local container
        container=$(docker ps --filter "publish=${DB_PORT}" --format "{{.Names}}" | head -1)
        if [[ -z "$container" ]]; then
            return 1
        fi
        docker exec "$container" mariadb -u "$DB_USER" "-p${DB_PASS}" -e "$sql" 2>/dev/null
    fi
}

# ---------------------------------------------------------------------------
# Trap: stop API servers on exit (always)
# ---------------------------------------------------------------------------
API_PID_FILE="/tmp/lnvps-e2e-api.pid"
ADMIN_PID_FILE="/tmp/lnvps-e2e-admin-api.pid"

# ---------------------------------------------------------------------------
# Stop an API left running by a previous --no-cleanup invocation.
#
# Each run provisions a *fresh* database, but a surviving API is still bound to
# the old one. Because the new process then fails to bind the port while the old
# one keeps answering the health check, the run would proceed against a stale
# server and fail later with a baffling "Table ... doesn't exist".
# ---------------------------------------------------------------------------
reap_stale_api() {
    local pid_file="$1" name="$2"
    [[ -f "$pid_file" ]] || return 0
    local pid
    pid=$(cat "$pid_file")
    if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
        echo "Stopping stale ${name} from a previous run (pid ${pid})"
        kill "$pid" 2>/dev/null || true
        for _ in $(seq 1 20); do
            kill -0 "$pid" 2>/dev/null || break
            sleep 0.5
        done
        kill -9 "$pid" 2>/dev/null || true
    fi
    rm -f "$pid_file"
}

# Fail fast when a port is held by something we do not manage, instead of
# silently testing against whatever is listening.
require_free_port() {
    local url="$1" name="$2"
    if curl -sf "$url" >/dev/null 2>&1; then
        echo "ERROR: ${name} is already serving on ${url} and is not ours." >&2
        echo "       Stop it (or set ${3}) before running the suite." >&2
        exit 1
    fi
}

cleanup() {
    local exit_code=$?
    echo ""
    echo "=== Cleanup ==="
    if [[ -f "$API_PID_FILE" ]]; then
        api_pid=$(cat "$API_PID_FILE")
        kill "$api_pid" 2>/dev/null || true
        wait "$api_pid" 2>/dev/null || true
        rm -f "$API_PID_FILE"
        echo "Stopped user API"
    fi
    if [[ -f "$ADMIN_PID_FILE" ]]; then
        admin_pid=$(cat "$ADMIN_PID_FILE")
        kill "$admin_pid" 2>/dev/null || true
        wait "$admin_pid" 2>/dev/null || true
        rm -f "$ADMIN_PID_FILE"
        echo "Stopped admin API"
    fi
    if [[ "$SKIP_CLEANUP" -eq 0 ]]; then
        docker compose -f "$COMPOSE_FILE" down -v
        echo "Stopped docker infrastructure"
    fi
    exit "$exit_code"
}

if [[ "$SKIP_CLEANUP" -eq 0 ]]; then
    trap cleanup EXIT
fi

# ---------------------------------------------------------------------------
# 1. Start docker infrastructure
# ---------------------------------------------------------------------------
echo "=== Starting infrastructure ($COMPOSE_FILE) ==="
# --wait blocks until services with a healthcheck (db, bitcoind) report healthy,
# so the DB is reachable before we probe it. Falls back to plain up -d on older
# docker that doesn't support --wait.
if ! docker compose -f "$COMPOSE_FILE" up -d --wait 2>/dev/null; then
    docker compose -f "$COMPOSE_FILE" up -d
fi

# ---------------------------------------------------------------------------
# 2. Wait for LND (if present in compose file) and copy credentials
# ---------------------------------------------------------------------------
if grep -q "^  lnd:" "$COMPOSE_FILE" 2>/dev/null; then
    echo "=== Waiting for LND ==="
    .github/e2e/wait-for-lnd.sh 120
fi

# ---------------------------------------------------------------------------
# 3. Generate run ID and create per-run test database
# ---------------------------------------------------------------------------
if [[ -z "${LNVPS_E2E_RUN_ID:-}" ]]; then
    export LNVPS_E2E_RUN_ID="$(date +%s%3N)"
fi
DB_NAME="lnvps_e2e_${LNVPS_E2E_RUN_ID}"
echo "=== Run ID: ${LNVPS_E2E_RUN_ID} | Database: ${DB_NAME} ==="

# Wait for MariaDB to accept connections (first-time volume init can take a while in CI)
DB_READY_TIMEOUT=300
echo "Waiting for MariaDB (timeout: ${DB_READY_TIMEOUT}s)..."
for i in $(seq 1 "$DB_READY_TIMEOUT"); do
    if mysql_exec "SELECT 1" >/dev/null 2>&1; then
        echo "MariaDB ready after ${i}s"
        break
    fi
    if [[ "$i" -eq "$DB_READY_TIMEOUT" ]]; then
        echo "ERROR: MariaDB did not become ready within ${DB_READY_TIMEOUT}s" >&2
        echo "--- docker compose ps ---" >&2
        docker compose -f "$COMPOSE_FILE" ps >&2 || true
        echo "--- db container logs (tail) ---" >&2
        docker compose -f "$COMPOSE_FILE" logs --tail=40 db >&2 || true
        echo "--- last mysql_exec attempt (stderr) ---" >&2
        docker compose -f "$COMPOSE_FILE" exec -T db \
            mariadb -u "$DB_USER" "-p${DB_PASS}" -e "SELECT 1" >&2 || true
        exit 1
    fi
    sleep 1
done

mysql_exec "CREATE DATABASE IF NOT EXISTS \`${DB_NAME}\`;"
echo "Created test database: ${DB_NAME}"

# ---------------------------------------------------------------------------
# 4. Write per-run DB URL into API configs (work on temp copies)
# ---------------------------------------------------------------------------
DB_URL="${DB_BASE}/${DB_NAME}"
TMP_API_CONFIG="/tmp/lnvps-e2e-api-config.yaml"
TMP_ADMIN_CONFIG="/tmp/lnvps-e2e-admin-config.yaml"

sed "s|db: \"mysql://.*\"|db: \"${DB_URL}\"|g" \
    .github/e2e/api-config.yaml > "$TMP_API_CONFIG"

sed "s|db: \"mysql://.*\"|db: \"${DB_URL}\"|g" \
    .github/e2e/admin-config.yaml > "$TMP_ADMIN_CONFIG"

# Keep the servers' listen addresses in step with the URLs the tests use.
# Overriding only the client URL used to leave the server binding the default
# port, which failed with a bare "Address already in use" 90 seconds later.
set_listen() {
    local config="$1" url="$2"
    [[ -n "$url" ]] || return 0
    local hostport="${url#*://}"
    hostport="${hostport%%/*}"
    local port="${hostport##*:}"
    [[ "$port" != "$hostport" ]] || return 0
    sed -i "/^listen:/d" "$config"
    echo "listen: \"0.0.0.0:${port}\"" >> "$config"
    echo "Pinned $(basename "$config") to port ${port}"
}
set_listen "$TMP_API_CONFIG" "${LNVPS_API_URL:-}"
set_listen "$TMP_ADMIN_CONFIG" "${LNVPS_ADMIN_API_URL:-}"

echo "API configs written with DB: ${DB_URL}"

# ---------------------------------------------------------------------------
# 5. Build API servers
# ---------------------------------------------------------------------------
if [[ "$SKIP_BUILD" -eq 0 ]]; then
    echo "=== Building API servers ==="
    # `agent` enables the live-chat support websocket exercised by
    # lnvps_e2e::agent_chat; it is not a default feature.
    cargo build -p lnvps_api --features agent
    cargo build -p lnvps_api_admin
fi

# ---------------------------------------------------------------------------
# 6. Start admin API
#
# The admin API runs the database schema migrations on startup (and, unlike the
# user API, does not build any payment providers). We start it first so the
# schema exists before we seed the payment_method_config rows the user API
# needs.
# ---------------------------------------------------------------------------
echo "=== Starting admin API ==="
reap_stale_api "$ADMIN_PID_FILE" "admin API"
require_free_port "${LNVPS_ADMIN_API_URL:-http://localhost:8001}/" "Admin API" "LNVPS_ADMIN_API_URL"
LNVPS_NO_DEV_SETUP=1 cargo run -p lnvps_api_admin --bin lnvps_api_admin -- --config "$TMP_ADMIN_CONFIG" \
    > /tmp/lnvps-e2e-admin-api.log 2>&1 &
echo $! > "$ADMIN_PID_FILE"

for i in $(seq 1 90); do
    if curl -sf "${LNVPS_ADMIN_API_URL:-http://localhost:8001}/" >/dev/null 2>&1; then
        echo "Admin API ready after ${i}s"
        break
    fi
    if ! kill -0 "$(cat "$ADMIN_PID_FILE")" 2>/dev/null; then
        echo "ERROR: Admin API exited during startup" >&2
        tail -20 /tmp/lnvps-e2e-admin-api.log >&2
        exit 1
    fi
    if [[ "$i" -eq 90 ]]; then
        echo "ERROR: Admin API failed to start within 90s" >&2
        echo "--- Admin API log ---" >&2
        tail -30 /tmp/lnvps-e2e-admin-api.log >&2
        exit 1
    fi
    sleep 1
done

# ---------------------------------------------------------------------------
# 7. Seed payment providers into the database
#
# Payment providers are now sourced exclusively from the `payment_method_config`
# table (there is no YAML fallback). The user API refuses to start without an
# enabled Lightning + on-chain config for the default company, so seed both to
# point at the docker-compose LND node. Idempotent (skips if already present).
# ---------------------------------------------------------------------------
echo "=== Seeding payment_method_config (LND Lightning + OnChain) ==="
LND_URL="https://localhost:10009"
LND_CERT="/tmp/e2e-lnd/tls.cert"
LND_MACAROON="/tmp/e2e-lnd/data/chain/bitcoin/regtest/admin.macaroon"
SEED_SQL="USE \`${DB_NAME}\`;
SET @cid = (SELECT MIN(id) FROM company);
INSERT INTO payment_method_config (company_id, payment_method, name, enabled, provider_type, config)
SELECT @cid, 0, 'E2E LND', 1, 'lnd', '{\"type\":\"lnd\",\"url\":\"${LND_URL}\",\"cert_path\":\"${LND_CERT}\",\"macaroon_path\":\"${LND_MACAROON}\"}'
WHERE NOT EXISTS (SELECT 1 FROM payment_method_config WHERE company_id = @cid AND payment_method = 0);
INSERT INTO payment_method_config (company_id, payment_method, name, enabled, provider_type, config)
SELECT @cid, 4, 'E2E LND OnChain', 1, 'onchain', '{\"type\":\"onchain\",\"url\":\"${LND_URL}\",\"cert_path\":\"${LND_CERT}\",\"macaroon_path\":\"${LND_MACAROON}\",\"address_type\":\"witness_pubkey_hash\",\"min_confirmations\":1}'
WHERE NOT EXISTS (SELECT 1 FROM payment_method_config WHERE company_id = @cid AND payment_method = 4);"
if ! mysql_exec "$SEED_SQL"; then
    echo "ERROR: failed to seed payment_method_config" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# 8. Start user API
# ---------------------------------------------------------------------------
echo "=== Starting user API ==="
reap_stale_api "$API_PID_FILE" "user API"
require_free_port "${LNVPS_API_URL:-http://localhost:8000}/" "User API" "LNVPS_API_URL"
LNVPS_NO_DEV_SETUP=1 cargo run -p lnvps_api --features agent -- --config "$TMP_API_CONFIG" \
    > /tmp/lnvps-e2e-api.log 2>&1 &
echo $! > "$API_PID_FILE"

for i in $(seq 1 90); do
    if curl -sf "${LNVPS_API_URL:-http://localhost:8000}/" >/dev/null 2>&1; then
        echo "User API ready after ${i}s"
        break
    fi
    if ! kill -0 "$(cat "$API_PID_FILE")" 2>/dev/null; then
        echo "ERROR: User API exited during startup" >&2
        tail -20 /tmp/lnvps-e2e-api.log >&2
        exit 1
    fi
    if [[ "$i" -eq 90 ]]; then
        echo "ERROR: User API failed to start within 90s" >&2
        echo "--- User API log ---" >&2
        tail -30 /tmp/lnvps-e2e-api.log >&2
        exit 1
    fi
    sleep 1
done

# ---------------------------------------------------------------------------
# 9. Run E2E tests
# ---------------------------------------------------------------------------
if [[ "$SETUP_ONLY" -eq 1 ]]; then
    # For harnesses that need the stack *and* root, which cargo cannot give
    # them at once: this leaves everything running for another process to drive.
    echo "=== Stack ready ==="
    echo "LNVPS_API_URL=${LNVPS_API_URL:-http://localhost:8000}"
    echo "LNVPS_ADMIN_API_URL=${LNVPS_ADMIN_API_URL:-http://localhost:8001}"
    echo "LNVPS_DB_URL=${DB_URL}"
    exit 0
fi

echo "=== Running E2E tests ==="
# --nocapture so a test that skips itself (no data, or a third-party endpoint
# down) says so in the CI log instead of passing silently.
TEST_CMD="cargo test -p lnvps_e2e --"
if [[ "$RUN_IGNORED" -eq 1 ]]; then
    TEST_CMD="$TEST_CMD --ignored"
fi
TEST_CMD="$TEST_CMD --test-threads=1 --nocapture"
if [[ -n "$FILTER" ]]; then
    TEST_CMD="$TEST_CMD $FILTER"
fi
eval "$TEST_CMD"

# ---------------------------------------------------------------------------
# 10. SshClient integration tests against the compose sshd
#
# These live in lnvps_api_common (they use the library directly, not HTTP) and
# skip themselves unless these two variables are set. The `linux-ssh` feature
# is what compiles SshClient in.
# ---------------------------------------------------------------------------
SSH_KEY="$REPO_ROOT/volumes/e2e-sshd/id_ed25519"
if [[ ! -f "$SSH_KEY" ]]; then
    # The tests skip themselves without these variables, so a missing key would
    # otherwise pass the run without ever touching SSH.
    echo "ERROR: $SSH_KEY missing — the sshd service did not start" >&2
    docker compose -f "$COMPOSE_FILE" logs --tail=40 sshd >&2 || true
    exit 1
fi

echo "=== Running SshClient integration tests ==="
LNVPS_TEST_SSH_ADDR="${LNVPS_TEST_SSH_ADDR:-localhost:2222}" \
LNVPS_TEST_SSH_KEY="$SSH_KEY" \
    cargo test -p lnvps_api_common --features linux-ssh --test ssh_client

# ---------------------------------------------------------------------------
# 11. ObjectStore integration tests against the compose rustfs
#
# The unit tests pin our SigV4 output against AWS's published vector, which
# proves the arithmetic but not that a server accepts it: a canonical request
# that differs by one byte of path encoding fails as an opaque 403 at the
# bucket. rustfs is the same S3 implementation the app catalog ships, so backup
# uploads are exercised against a real one here.
# ---------------------------------------------------------------------------
echo "=== Running ObjectStore integration tests ==="
# An unauthenticated request to the root is a 403, which is a healthy S3 and
# not a failure — what matters is that something answered at all.
if [[ "$(curl -s -o /dev/null -w '%{http_code}' \
    "${LNVPS_TEST_S3_ENDPOINT:-http://localhost:9400}")" == "000" ]]; then
    # The tests skip themselves without these variables, so an unreachable
    # rustfs would otherwise pass the run without a single upload happening.
    echo "ERROR: rustfs is not answering on ${LNVPS_TEST_S3_ENDPOINT:-http://localhost:9400}" >&2
    docker compose -f "$COMPOSE_FILE" logs --tail=40 rustfs >&2 || true
    exit 1
fi
export LNVPS_TEST_S3_ENDPOINT="${LNVPS_TEST_S3_ENDPOINT:-http://localhost:9400}"
export LNVPS_TEST_S3_ACCESS_KEY="${LNVPS_TEST_S3_ACCESS_KEY:-e2eaccesskey}"
export LNVPS_TEST_S3_SECRET_KEY="${LNVPS_TEST_S3_SECRET_KEY:-e2esecretkey}"
cargo test -p lnvps_api_common --test object_store -- --test-threads=1

# The backup uploader's own command line, run in the image the operator names,
# against the same rustfs. The builder unit tests assert what the script says;
# only this catches a busybox `tar` flag or a `curl` invocation that a real S3
# server refuses -- a backup that silently never existed until somebody tries
# to restore it.
echo "=== Running backup uploader integration test ==="
cargo test -p lnvps_operator the_uploader_script_really_uploads -- --test-threads=1
