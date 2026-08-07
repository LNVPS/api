#!/usr/bin/env bash
# tunnel-e2e.sh — Run the marketplace tunnel harness: both ends, real kernel.
#
# The harness (lnvps_e2e/tests/tunnel_netns.rs) builds a route server and a node
# out of network namespaces, configures each end with the real production code
# paths, and pings across the tunnel — including to a guest sitting behind the
# node, which is the path a customer's traffic takes.
#
# It needs root (namespaces, veth, WireGuard), so the tests are #[ignore]d and
# only run from here.
#
# Usage:
#   ./scripts/tunnel-e2e.sh [--filter NAME]

set -euo pipefail

# Every harness that needs a real kernel. Listed once: a test added here and
# nowhere else is one nobody ever runs.
TESTS=(tunnel_netns node_libvirt node_probe)
TEST_ARGS=()
for t in "${TESTS[@]}"; do TEST_ARGS+=(--test "$t"); done

FILTER=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --filter) FILTER="$2"; shift 2 ;;
        --) shift; break ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$(cd "$SCRIPT_DIR/.." && pwd)"

# Built as the invoking user so the build cache and toolchain resolve against
# the normal $HOME; only the run needs to be privileged.
echo "=== Building the tunnel harness ==="
for t in "${TESTS[@]}"; do
    cargo test -p lnvps_e2e --test "$t" --no-run
done

CMD=(cargo test -p lnvps_e2e "${TEST_ARGS[@]}" -- --ignored --test-threads=1)
[[ -n "$FILTER" ]] && CMD+=("$FILTER")
[[ $# -gt 0 ]] && CMD+=("$@")

echo "=== Running the tunnel harness as root ==="
if [[ "$(id -u)" -eq 0 ]]; then
    "${CMD[@]}"
else
    sudo -E "${CMD[@]}"
fi
