#!/usr/bin/env bash
set -euo pipefail
dir="$(cd "$(dirname "$0")" && pwd)"
addr="$1"
"$dir/policy-test.sh" >/dev/null || { echo "policy-test.sh failed"; exit 1; }
url="ws://$addr/"

send() {
    python3 "$dir/ws.py" "$url" "$1"
}

nip11="$(curl -sf -m 10 -H 'Accept: application/nostr+json' "http://$addr/")"
echo "$nip11" | jq -e '.supported_nips | index(45)' >/dev/null || { echo "NIP-11 does not list NIP-45"; exit 1; }

expect_refused() {
    local file="$1" prefix="$2" reply
    reply="$(send "[\"EVENT\",$(cat "$dir/$file")]")"
    echo "$file: $reply"
    echo "$reply" | jq -e --arg p "$prefix" '.[0] == "OK" and .[2] == false and (.[3] | startswith($p))' >/dev/null \
        || { echo "$file was not refused with '$prefix'"; exit 1; }
}

expect_refused reject-kind.json "blocked: kind 7"
expect_refused reject-pubkey.json "blocked: this pubkey is blocked"
expect_refused reject-size.json "blocked: event is larger"
expect_refused reject-pow.json "pow:"

good="$(send "[\"EVENT\",$(cat "$dir/accept.json")]")"
echo "accept: $good"
echo "$good" | jq -e '.[0] == "OK" and .[2] == true' >/dev/null \
    || { echo "event the policy accepts was refused"; exit 1; }

count="$(send '["COUNT","c",{"kinds":[1]}]')"
echo "count: $count"
echo "$count" | jq -e '.[0] == "COUNT" and .[2].count == 1' >/dev/null \
    || { echo "COUNT should see only the accepted event"; exit 1; }
echo "built-in write policy check passed"
