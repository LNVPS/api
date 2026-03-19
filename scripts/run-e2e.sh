#!/usr/bin/env bash
# run-e2e.sh — Build, start infrastructure, and run the LNVPS E2E test suite.
#
# Usage:
#   ./scripts/run-e2e.sh [OPTIONS]
#
# Options:
#   --no-build       Skip cargo build step
#   --no-cleanup     Leave API servers and DB running after the run
#   --filter FILTER  Pass a test-name filter to cargo test (e.g. lifecycle)
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
FILTER=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --no-build)    SKIP_BUILD=1;   shift ;;
        --no-cleanup)  SKIP_CLEANUP=1; shift ;;
        --filter)      FILTER="$2";    shift 2 ;;
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
# mysql_exec SQL — run a SQL statement via local client or docker exec fallback
# ---------------------------------------------------------------------------
mysql_exec() {
    local sql="$1"
    if command -v mysql >/dev/null 2>&1; then
        mysql -h "$DB_HOST" -P "$DB_PORT" -u "$DB_USER" "-p${DB_PASS}" \
            -e "$sql" 2>/dev/null
    elif command -v mariadb >/dev/null 2>&1; then
        mariadb -h "$DB_HOST" -P "$DB_PORT" -u "$DB_USER" "-p${DB_PASS}" \
            -e "$sql" 2>/dev/null
    else
        # Fall back to docker exec into a running MariaDB/MySQL container
        local container
        container=$(docker ps --filter "publish=${DB_PORT}" --format "{{.Names}}" | head -1)
        if [[ -z "$container" ]]; then
            echo "ERROR: no mysql/mariadb client found and no container listening on port ${DB_PORT}" >&2
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
docker compose -f "$COMPOSE_FILE" up -d

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

# Wait for MariaDB to accept connections (first-time volume init can take >30s in CI)
DB_READY_TIMEOUT=600
echo "Waiting for MariaDB at ${DB_HOST}:${DB_PORT} (timeout: ${DB_READY_TIMEOUT}s)..."
for i in $(seq 1 "$DB_READY_TIMEOUT"); do
    if mysql_exec "SELECT 1" >/dev/null 2>&1; then
        echo "MariaDB ready after ${i}s"
        break
    fi
    if [[ "$i" -eq "$DB_READY_TIMEOUT" ]]; then
        echo "ERROR: MariaDB did not become ready within ${DB_READY_TIMEOUT}s" >&2
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

echo "API configs written with DB: ${DB_URL}"

# ---------------------------------------------------------------------------
# 5. Build API servers
# ---------------------------------------------------------------------------
if [[ "$SKIP_BUILD" -eq 0 ]]; then
    echo "=== Building API servers ==="
    cargo build -p lnvps_api -p lnvps_api_admin
fi

# ---------------------------------------------------------------------------
# 6. Start user API
# ---------------------------------------------------------------------------
echo "=== Starting user API ==="
LNVPS_NO_DEV_SETUP=1 cargo run -p lnvps_api -- --config "$TMP_API_CONFIG" \
    > /tmp/lnvps-e2e-api.log 2>&1 &
echo $! > "$API_PID_FILE"

for i in $(seq 1 90); do
    if curl -sf "${LNVPS_API_URL:-http://localhost:8000}/" >/dev/null 2>&1; then
        echo "User API ready after ${i}s"
        break
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
# 7. Start admin API
# ---------------------------------------------------------------------------
echo "=== Starting admin API ==="
LNVPS_NO_DEV_SETUP=1 cargo run -p lnvps_api_admin --bin lnvps_api_admin -- --config "$TMP_ADMIN_CONFIG" \
    > /tmp/lnvps-e2e-admin-api.log 2>&1 &
echo $! > "$ADMIN_PID_FILE"

for i in $(seq 1 90); do
    if curl -sf "${LNVPS_ADMIN_API_URL:-http://localhost:8001}/" >/dev/null 2>&1; then
        echo "Admin API ready after ${i}s"
        break
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
# 8. Run E2E tests
# ---------------------------------------------------------------------------
echo "=== Running E2E tests ==="
TEST_CMD="cargo test -p lnvps_e2e -- --test-threads=1"
if [[ -n "$FILTER" ]]; then
    TEST_CMD="$TEST_CMD $FILTER"
fi
eval "$TEST_CMD"
