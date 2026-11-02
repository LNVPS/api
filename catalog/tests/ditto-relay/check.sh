#!/usr/bin/env bash
set -euo pipefail
dir="$(cd "$(dirname "$0")" && pwd)"
addr="$1"
url="ws://$addr/"

send() {
    python3 "$dir/ws.py" "$url" "$1"
}

nip11="$(curl -sf -m 10 -H 'Accept: application/nostr+json' "http://$addr/")"
echo "$nip11" | jq -e '.supported_nips | index(45)' >/dev/null || { echo "NIP-11 does not list NIP-45"; exit 1; }

bad="$(send "[\"EVENT\",$(cat "$dir/reject.json")]")"
echo "reject: $bad"
echo "$bad" | jq -e '.[0] == "OK" and .[2] == false and (.[3] | startswith("blocked:"))' >/dev/null \
    || { echo "event the policy rejects was not refused"; exit 1; }

good="$(send "[\"EVENT\",$(cat "$dir/accept.json")]")"
echo "accept: $good"
echo "$good" | jq -e '.[0] == "OK" and .[2] == true' >/dev/null \
    || { echo "event the policy accepts was refused"; exit 1; }

count="$(send '["COUNT","c",{"kinds":[1]}]')"
echo "count: $count"
echo "$count" | jq -e '.[0] == "COUNT" and .[2].count == 1' >/dev/null \
    || { echo "COUNT should see only the accepted event"; exit 1; }
echo "write policy check passed"
