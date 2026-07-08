#!/usr/bin/env bash
# fw-e2e.sh — Build the eBPF datapath and run the firewall netns test harness.
#
# The firewall harness tests (lnvps_fw_service, tests/smoke.rs) build a virtual
# network out of Linux network namespaces + veth pairs, load the compiled XDP
# program into a "filter" namespace, and drive real traffic through it. They
# require CAP_NET_ADMIN / CAP_BPF, so they are marked #[ignore] and only run
# here (as root).
#
# Usage:
#   ./scripts/fw-e2e.sh [--test NAME] [-- <extra cargo test args>]
#
# Options:
#   --test NAME   Run a single integration test binary (default: smoke)
#   --filter F    Only run tests whose name matches F
#
# Examples:
#   sudo ./scripts/fw-e2e.sh
#   ./scripts/fw-e2e.sh --filter syn_rate_limit
#
# The eBPF object is built for the bpfel-unknown-none target via aya-build in
# lnvps_fw_service/build.rs; this only needs a nightly toolchain + bpf-linker
# (see docs/agents/fw-testing.md).

set -euo pipefail

TEST_BIN="smoke"
FILTER=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --test)   TEST_BIN="$2"; shift 2 ;;
        --filter) FILTER="$2";   shift 2 ;;
        --)       shift; break ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
FW_DIR="$REPO_ROOT/lnvps_fw"
cd "$FW_DIR"

# ---------------------------------------------------------------------------
# 1. Build the test binary (and, via build.rs, the eBPF object) as the invoking
#    user so the build cache and toolchain resolve against the normal $HOME.
# ---------------------------------------------------------------------------
echo "=== Building firewall harness test binary ($TEST_BIN) ==="
cargo test -p lnvps_fw_service --test "$TEST_BIN" --no-run

# ---------------------------------------------------------------------------
# 2. Run the ignored harness tests as root. `-E` preserves the environment
#    (PATH, CARGO_*, HOME) so cargo finds the already-built artifacts and the
#    nightly toolchain when it re-checks freshness.
# ---------------------------------------------------------------------------
CMD=(cargo test -p lnvps_fw_service --test "$TEST_BIN" -- --ignored --test-threads=1)
if [[ -n "$FILTER" ]]; then
    CMD+=("$FILTER")
fi
# Any remaining args after `--` are forwarded to the test harness.
if [[ $# -gt 0 ]]; then
    CMD+=("$@")
fi

echo "=== Running harness tests as root ==="
if [[ "$(id -u)" -eq 0 ]]; then
    "${CMD[@]}"
else
    sudo -E "${CMD[@]}"
fi
