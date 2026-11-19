#!/usr/bin/env bash
#
# Build a LNVPS NixOS cloud-init qcow2, compress it and emit a SHA256SUMS file
# ready to publish. Requires Nix with flakes enabled.
#
# Usage:
#   ./build.sh [version] [arch] [variant]
#     version   image version label used in filenames (default: derived channel, e.g. 24.11)
#     arch      x86_64 | arm64                        (default: x86_64)
#     variant   cloudinit | encrypted | all           (default: all)
#
# Outputs (in ./out):
#   nixos-<version>-cloudinit-<arch>.qcow2.xz
#   nixos-<version>-encrypted-<arch>.qcow2.xz
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

VARIANT="${3:-all}"
case "$VARIANT" in
  all) VARIANTS="cloudinit encrypted" ;;
  cloudinit | encrypted) VARIANTS="$VARIANT" ;;
  *) echo "unknown variant: $VARIANT (expected cloudinit, encrypted or all)" >&2; exit 1 ;;
esac

OUT_DIR="out"
mkdir -p "$OUT_DIR"

build_variant() {
  local variant="$1" attr basename qcow_src
  case "$variant" in
    cloudinit) attr="qcow-efi" ;;
    encrypted) attr="qcow-efi-encrypted" ;;
  esac
  basename="nixos-${VERSION}-${variant}-${ARCH}"

  echo ">> Building ${variant} qcow2 (UEFI) for ${NIX_SYSTEM} (this can take a while)…"
  nix build ".#packages.${NIX_SYSTEM}.${attr}" --out-link "result-${variant}"

  qcow_src="$(find -L "result-${variant}" -maxdepth 1 -name '*.qcow2' | head -1)"
  if [[ -z "$qcow_src" ]]; then
    echo "!! No qcow2 found under result-${variant}/" >&2
    exit 1
  fi

  echo ">> Compressing with xz (LNVPS decompresses .xz images host-side)…"
  cp -f "$qcow_src" "$OUT_DIR/${basename}.qcow2"
  chmod u+w "$OUT_DIR/${basename}.qcow2"
  rm -f "$OUT_DIR/${basename}.qcow2.xz"
  xz -T0 -9 "$OUT_DIR/${basename}.qcow2"
}

for variant in $VARIANTS; do
  build_variant "$variant"
done

echo ">> Writing SHA256SUMS…"
( cd "$OUT_DIR" && sha256sum nixos-*.qcow2.xz > SHA256SUMS )

echo
echo "Done. Publish these:"
ls -lh "$OUT_DIR"/nixos-*.qcow2.xz "$OUT_DIR/SHA256SUMS"
echo
echo "Then register the images (see images/nixos/README.md)."
