#!/usr/bin/env bash
# Start one catalog compose document locally and prove it comes up.
#
# Validation checks the document; this checks the images. A container that
# cannot start under the hardening the operator applies is invisible in the
# document and only shows up when something runs it.
#
#   scripts/app-catalog-test.sh catalog/strfry.yaml [--bin path/to/compose-to-docker]
#
# Exits non-zero if a service exits, restarts, or an ingress port never answers.
set -euo pipefail

APP_FILE=""
BIN=""
while [ $# -gt 0 ]; do
    case "$1" in
        --bin) BIN="$2"; shift 2 ;;
        -h|--help) sed -n '2,12p' "$0"; exit 0 ;;
        *) APP_FILE="$1"; shift ;;
    esac
done
[ -n "$APP_FILE" ] || { echo "usage: $0 <catalog/app.yaml> [--bin <compose-to-docker>]" >&2; exit 2; }
[ -f "$APP_FILE" ] || { echo "no such file: $APP_FILE" >&2; exit 2; }

APP="$(basename "$APP_FILE" .yaml)"
OUT_DIR="${OUT_DIR:-.local/catalog/$APP}"
# How long the whole stack gets to reach running, and how long an ingress port
# gets to answer once it is.
START_TIMEOUT="${START_TIMEOUT:-300}"
PROBE_TIMEOUT="${PROBE_TIMEOUT:-120}"
# Long enough to catch an app that starts, reads its config and then exits —
# the shape of every outage this script exists to catch.
SETTLE="${SETTLE:-20}"

# Config values for fields the customer must supply at order time. A required
# field with no value here fails the render loudly rather than being skipped.
app_config() {
    case "$1" in
        # A real bech32 npub (pubkey 0x…01): HAVEN decodes it at startup, so a
        # merely pattern-shaped string would crashloop the container.
        haven) echo "--config owner_npub=npub1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqshp52w2" ;;
        buzz)  echo "--config owner_pubkey=0000000000000000000000000000000000000000000000000000000000000001" ;;
        appweaver) echo "--config master_pubkey=79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798" ;;
        *)     echo "" ;;
    esac
}

if [ -z "$BIN" ]; then
    cargo build -q -p lnvps_compose --bin compose-to-docker
    BIN="target/debug/compose-to-docker"
fi

COMPOSE_FILE="$OUT_DIR/docker-compose.yaml"
rm -rf "$OUT_DIR"

cleanup() {
    docker compose -f "$COMPOSE_FILE" down --volumes --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "==> rendering $APP_FILE"
# shellcheck disable=SC2046  # app_config emits separate arguments on purpose
RENDER="$("$BIN" "$APP_FILE" --out-dir "$OUT_DIR" --hostname localhost $(app_config "$APP"))"
echo "$RENDER"

# Ingress ports are published on loopback at the container number, which on a
# developer machine can already be taken by something unrelated. Shifting the
# host side keeps the container side — the number the app was configured with —
# untouched.
if [ -n "${HOST_PORT_OFFSET:-}" ]; then
    while read -r port; do
        sed -i "s/127\.0\.0\.1:$port:/127.0.0.1:$((port + HOST_PORT_OFFSET)):/" "$COMPOSE_FILE"
    done < <(grep -oE '127\.0\.0\.1:[0-9]+:' "$COMPOSE_FILE" | cut -d: -f2 | sort -un)
fi

# A port already taken on this machine stops the stack before it starts. Say so
# here rather than leaving it to read as an app failure.
for port in $(grep -oE '127\.0\.0\.1:[0-9]+:' "$COMPOSE_FILE" | cut -d: -f2 | sort -un); do
    if (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then
        echo "FAIL $APP: port $port is already in use on this host"
        exit 1
    fi
done

echo "==> creating volumes"
docker compose -f "$COMPOSE_FILE" up --no-start

# Docker has no fsGroup, so a fresh named volume is root-owned and a non-root
# service cannot write to it. The renderer prints the chown that stands in for
# it; run exactly those, so the local difference stays in one place.
echo "$RENDER" | grep -E '^\s+docker run --rm -u 0 ' | while read -r cmd; do
    echo "==> $cmd"
    eval "$cmd"
done

echo "==> starting $APP"
if ! docker compose -f "$COMPOSE_FILE" up -d --wait --wait-timeout "$START_TIMEOUT"; then
    echo "FAIL $APP: did not reach running within ${START_TIMEOUT}s"
    docker compose -f "$COMPOSE_FILE" ps -a
    docker compose -f "$COMPOSE_FILE" logs --no-color --tail 200
    exit 1
fi

echo "==> settling ${SETTLE}s"
sleep "$SETTLE"

# `--wait` returns once containers are up; an app that exits a moment later is
# the failure we are looking for, so the state is re-read after settling. An
# exited init step is expected — it renders as a one-shot service the app waits
# on — so only a non-zero exit or a restart counts against it.
failed=0
states="$(docker compose -f "$COMPOSE_FILE" ps -a --format '{{.Name}} {{.State}} {{.ExitCode}}')"
while read -r name state status; do
    [ -n "$name" ] || continue
    # Without a stdin of its own, docker would eat the rest of the loop's input.
    restarts="$(docker inspect -f '{{.RestartCount}}' "$name" </dev/null 2>/dev/null || echo 0)"
    case "$state" in
        running) [ "$restarts" -eq 0 ] || { echo "FAIL $name restarted $restarts time(s)"; failed=1; } ;;
        exited)  [ "$status" = "0" ] || { echo "FAIL $name exited with status $status"; failed=1; } ;;
        *)       echo "FAIL $name is $state"; failed=1 ;;
    esac
done <<EOF
$states
EOF

# An ingress port is what a customer reaches, so a stack that is "running" but
# never binds is not up. The renderer publishes those on loopback at the
# container number, so the rendered file is where the list comes from — reading
# it back off `docker compose ps` would leave the probe silently skipped if that
# output format ever changes.
ports="$(grep -oE '127\.0\.0\.1:[0-9]+:' "$COMPOSE_FILE" | cut -d: -f2 | sort -un)"
# An expose value written in a form this does not recognise would drop the
# guard silently, so anything but the two known values fails the run instead.
doc_body="$(sed 's/^[[:space:]]*#.*$//; s/[[:space:]]#.*$//' "$APP_FILE")"
unknown="$(printf '%s\n' "$doc_body" | grep -oE 'expose:[[:space:]]*[^,}[:space:]]+' \
    | grep -vE 'expose:[[:space:]]*"?(none|ingress)"?$' || true)"
if [ -n "$unknown" ]; then
    echo "FAIL $APP: unrecognised expose value: $unknown"
    failed=1
fi
if printf '%s\n' "$doc_body" | grep -qE 'expose:[[:space:]]*"?ingress"?' && [ -z "$ports" ]; then
    echo "FAIL $APP: declares an ingress port but nothing was published"
    failed=1
fi
if [ "$failed" -eq 0 ]; then
    for port in $ports; do
        # Accepting a connection is the only signal that generalises: an
        # ingress port can be a websocket relay, and asking one for a page can
        # legitimately return nothing. The HTTP status, when there is one, is
        # printed as information rather than asserted on.
        echo "==> probing 127.0.0.1:$port"
        deadline=$((SECONDS + PROBE_TIMEOUT))
        until (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; do
            if [ "$SECONDS" -ge "$deadline" ]; then
                echo "FAIL $APP: nothing listening on port $port within ${PROBE_TIMEOUT}s"
                failed=1
                break
            fi
            sleep 2
        done
        if [ "$failed" -eq 0 ]; then
            code="$(curl -s -o /dev/null -m 5 -w '%{http_code}' "http://127.0.0.1:$port/" 2>/dev/null || true)"
            echo "    open (HTTP ${code:-000})"
        fi
    done
fi

if [ "$failed" -ne 0 ]; then
    docker compose -f "$COMPOSE_FILE" ps -a
    docker compose -f "$COMPOSE_FILE" logs --no-color --tail 200
    exit 1
fi

echo "PASS $APP"
