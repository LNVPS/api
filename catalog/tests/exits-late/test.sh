#!/usr/bin/env bash
set -uo pipefail
cd "$(dirname "$0")/../../.."
BIN="${1:-}"

ctx="$(mktemp -d)"
trap 'rm -rf "$ctx"' EXIT
cat > "$ctx/Dockerfile" <<'D'
FROM busybox:stable
USER 1000
ENTRYPOINT ["sh", "-c", "httpd -p 8080 -h /; sleep 30; exit 1"]
D
docker build -q -t lnvps-test-exits-late:local "$ctx" >/dev/null || exit 2

args=(catalog/tests/exits-late/exits-late.yaml)
[ -n "$BIN" ] && args+=(--bin "$BIN")
out="$(HOST_PORT_OFFSET="${HOST_PORT_OFFSET:-20000}" SETTLE=1 PROBE_TIMEOUT=20 scripts/app-catalog-test.sh "${args[@]}" 2>&1)"
status=$?
echo "$out" | tail -n 25
if [ "$status" -eq 0 ] || echo "$out" | grep -q '^PASS'; then
    echo "FAIL: script passed an app that exits after the probe"
    exit 1
fi
echo "$out" | grep -q 'exited with status 1' || { echo "FAIL: not failed for the exit"; exit 1; }
echo "OK: script failed the late-exiting app"
