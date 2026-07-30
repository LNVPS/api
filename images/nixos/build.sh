#!/usr/bin/env bash
#
# Build a LNVPS NixOS cloud-init qcow2, compress it and emit a SHA256SUMS file
# ready to publish. Requires Nix with flakes enabled.
#
# Usage:
#   ./build.sh [version] [arch]
#     version   image version label used in filenames (default: derived channel, e.g. 24.11)
#     arch      x86_64 | arm64                        (default: x86_64)
#
# Outputs (in ./out):
#   nixos-<version>-cloudinit-<arch>.qcow2.xz
#   SHA256SUMS
set -euo pipefail
cd "$(dirname "$0")"

VERSION="${1:-24.11}"
ARCH="${2:-x86_64}"

case "$ARCH" in
  x86_64) NIX_SYSTEM="x86_64-linux" ;;
  arm64 | aarch64) NIX_SYSTEM="aarch64-linux"; ARCH="arm64" ;;
  *) echo "unknown arch: $ARCH (expected x86_64 or arm64)" >&2; exit 1 ;;
esac

OUT_DIR="out"
BASENAME="nixos-${VERSION}-cloudinit-${ARCH}"
mkdir -p "$OUT_DIR"

echo ">> Building qcow2 for ${NIX_SYSTEM} (this can take a while)…"
# result/ is a symlink to a store path containing nixos.qcow2
nix build ".#packages.${NIX_SYSTEM}.qcow" --out-link result

QCOW_SRC="$(find -L result -maxdepth 1 -name '*.qcow2' | head -1)"
if [[ -z "$QCOW_SRC" ]]; then
  echo "!! No qcow2 found under result/" >&2
  exit 1
fi

echo ">> Compressing with xz (LNVPS decompresses .xz images host-side)…"
# Copy out of the read-only store, then compress.
cp -f "$QCOW_SRC" "$OUT_DIR/${BASENAME}.qcow2"
rm -f "$OUT_DIR/${BASENAME}.qcow2.xz"
xz -T0 -9 "$OUT_DIR/${BASENAME}.qcow2"

echo ">> Writing SHA256SUMS…"
( cd "$OUT_DIR" && sha256sum "${BASENAME}.qcow2.xz" > SHA256SUMS )

echo
echo "Done. Publish these:"
ls -lh "$OUT_DIR/${BASENAME}.qcow2.xz" "$OUT_DIR/SHA256SUMS"
echo
echo "Then register the image (see images/nixos/README.md)."
