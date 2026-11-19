#!/usr/bin/env bash
set -euo pipefail
dir="$(cd "$(dirname "$0")" && pwd)"
filter="$dir/../../images/ditto-relay/policy.jq"

event() {
    jq -nc --arg id "$1" --argjson kind "$2" --arg pubkey "$3" --arg ip "$4" --argjson at "$5" --argjson authed "${6:-null}" \
        '{type: "new", event: {id: $id, kind: $kind, pubkey: $pubkey, content: "x"}, receivedAt: $at, sourceType: "IP4", sourceInfo: $ip, authed: $authed}'
}

run() {
    local policy="$1"
    jq -c --unbuffered -n --argjson policy "[$policy]" -f "$filter" 2>/dev/null \
        | jq -r '[.id, .action] | join(":")'
}

expect() {
    local name="$1" want="$2" got="$3"
    [ "$got" = "$want" ] || { echo "FAIL $name: want '$want' got '$got'"; exit 1; }
    echo "ok   $name"
}

a=$(printf 'aa%.0s' {1..32})
b=$(printf 'bb%.0s' {1..32})
base='"kinds":"","allow":"","deny":"","min_pow":"0","max_size":"0","per_minute":"0","require_auth":"false"'
over() { echo "{$base}" | jq -c --argjson o "$1" '. + $o'; }

expect defaults-accept "00:accept" "$(event 00 1 "$a" 1.1.1.1 1000 | run "$(over '{}')")"
expect kinds "01:accept
02:reject" "$( { event 01 1 "$a" 1.1.1.1 1000; event 02 7 "$a" 1.1.1.1 1000; } | run "$(over '{"kinds":"1,30023"}')")"
expect allow "03:accept
04:reject" "$( { event 03 1 "$a" 1.1.1.1 1000; event 04 1 "$b" 1.1.1.1 1000; } | run "$(over "{\"allow\":\"$a\"}")")"
expect deny "05:reject
06:accept" "$( { event 05 1 "$a" 1.1.1.1 1000; event 06 1 "$b" 1.1.1.1 1000; } | run "$(over "{\"deny\":\"$a\"}")")"
expect pow "0fff:reject
00ff:accept" "$( { event 0fff 1 "$a" 1.1.1.1 1000; event 00ff 1 "$a" 1.1.1.1 1000; } | run "$(over '{"min_pow":"8"}')")"
expect size "07:reject" "$(event 07 1 "$a" 1.1.1.1 1000 | run "$(over '{"max_size":"20"}')")"
expect auth "08:reject
09:accept" "$( { event 08 1 "$a" 1.1.1.1 1000; event 09 1 "$a" 1.1.1.1 1000 "\"$a\""; } | run "$(over '{"require_auth":"true"}')")"
expect rate-limit "10:accept
11:accept
12:reject
13:accept
14:accept" "$( { event 10 1 "$a" 1.1.1.1 1000; event 11 1 "$a" 1.1.1.1 1010; event 12 1 "$a" 1.1.1.1 1020; event 13 1 "$a" 2.2.2.2 1020; event 14 1 "$a" 1.1.1.1 1100; } | run "$(over '{"per_minute":"2"}')")"

hostile='x"; touch /tmp/ditto-pwned; $(touch /tmp/ditto-pwned) `touch /tmp/ditto-pwned` \n'
rm -f /tmp/ditto-pwned
event 15 1 "$a" 1.1.1.1 1000 | run "$(over "$(jq -nc --arg h "$hostile" '{kinds:$h, allow:$h, deny:$h, min_pow:$h, max_size:$h, per_minute:$h, require_auth:$h}')")" >/dev/null || true
[ ! -e /tmp/ditto-pwned ] || { echo "FAIL policy executed customer text"; exit 1; }
echo "ok   policy never executes its configuration"
echo "policy-test passed"
