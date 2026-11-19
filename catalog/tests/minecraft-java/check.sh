#!/usr/bin/env bash
set -euo pipefail
dir="$(cd "$(dirname "$0")" && pwd)"
addr="$1"

deadline=$((SECONDS + ${STATUS_TIMEOUT:-300}))
until reply="$(python3 "$dir/ping.py" "$addr" 2>/dev/null)"; do
    if [ "$SECONDS" -ge "$deadline" ]; then
        echo "no Minecraft status reply from $addr"
        exit 1
    fi
    sleep 3
done
echo "status: $reply"
echo "$reply" | jq -e '.version.name == "1.21.4" and .players.max == 20 and (.description | tostring | contains("A Minecraft server"))' >/dev/null \
    || { echo "status does not match the configured version, slots and MOTD"; exit 1; }
echo "minecraft status ping passed"
