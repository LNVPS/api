#!/usr/bin/env bash
# Report catalog images whose tag no longer resolves to the pinned digest.
#
# Every catalog image is pinned as `repo:tag@sha256:...`. The tag is there for
# a human to read; the digest is what actually runs. Because the tag is mutable,
# the publisher can move it at any time, and a pinned deployment will simply
# keep running the old bytes without saying so.
#
# That silence is the point of pinning, but it also means an upstream release
# (or a compromised re-push of the same tag) is invisible. This resolves each
# tag now and diffs it against the pin, so the difference arrives as a report
# to review rather than as an automatic rollout.
#
#   scripts/catalog-digest-drift.sh [catalog/*.yaml]
#
# Exits 1 if any tag has moved, 0 if every pin is current. Drift is not a fault:
# it usually means there is a new upstream version to review, test and re-pin.
set -euo pipefail

FILES=("$@")
[ "${#FILES[@]}" -gt 0 ] || FILES=(catalog/*.yaml)

command -v docker >/dev/null || { echo "docker is required" >&2; exit 2; }

drifted=0
checked=0

# `image: repo:tag@sha256:...` in any catalog document, service or init step.
while read -r file image; do
    ref="${image%@*}"
    pinned="${image##*@}"
    checked=$((checked + 1))

    if ! current="$(docker buildx imagetools inspect "$ref" \
        --format '{{.Manifest.Digest}}' 2>/dev/null)"; then
        echo "?? $file: $ref: could not resolve: registry error or tag removed"
        drifted=1
        continue
    fi

    if [ "$current" = "$pinned" ]; then
        echo "ok $file: $ref"
    else
        echo "!! $file: $ref"
        echo "     pinned:  $pinned"
        echo "     current: $current"
        drifted=1
    fi
done < <(grep -hoE '^[[:space:]]*image:[[:space:]]*\S+@sha256:[0-9a-f]{64}' "${FILES[@]}" \
    --with-filename \
    | sed -E 's/:[[:space:]]*image:[[:space:]]*/ /')

[ "$checked" -gt 0 ] || { echo "no pinned images found in: ${FILES[*]}" >&2; exit 2; }

if [ "$drifted" -ne 0 ]; then
    echo
    echo "One or more tags have moved. Review the new image, run"
    echo "scripts/app-catalog-test.sh against it, then update the pin."
    exit 1
fi

echo
echo "$checked image(s) pinned to the digest their tag currently resolves to."
