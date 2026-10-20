#!/usr/bin/env bash
# Fetch the official simsong/bulk_extractor v2.2.0 Linux build (GPL-3.0-or-later)
# and the corresponding source archive. SHA-256 is pinned in
# packaging/linux/runtime-manifest.json against the release's own SHA256SUMS.
#
# Unlike Windows (a standalone bulk_extractor64.exe), upstream only publishes
# Linux builds as a Snap package. A .snap is a squashfs image, so this script
# unpacks it with unsquashfs (requires squashfs-tools) and lifts out the
# bulk_extractor binary plus the shared libraries it links against, then
# rewrites its RPATH with patchelf so it runs standalone — no snapd, no
# confinement, no system-wide install. MemHunter still only ever invokes it
# as a separate subprocess (see providers/bulk_extractor.py), never linked
# into the Apache-2.0 engine, so the GPL-3.0 isolation from the Windows build
# is preserved. Does not run at application startup.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
MANIFEST="$ROOT/packaging/linux/runtime-manifest.json"
CACHE_DIR="$ROOT/packaging/cache"
DEST="$ROOT/app/desktop/resources/tools/bulk_extractor"
EXTRACT_DIR="$CACHE_DIR/bulk-extractor-extract-linux"

for tool in unsquashfs patchelf; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "required tool not found: $tool (apt-get install squashfs-tools patchelf)" >&2
    exit 1
  fi
done

jget() { python3 -c "import json,sys; print(json.load(open('$MANIFEST'))$1)"; }

SNAP_URL="$(jget "['bulk_extractor']['snap_url']")"
SNAP_SHA="$(jget "['bulk_extractor']['snap_sha256']")"
SNAP_FILE="$CACHE_DIR/$(jget "['bulk_extractor']['snap_filename']")"
SRC_URL="$(jget "['bulk_extractor']['source_url']")"
SRC_SHA="$(jget "['bulk_extractor']['source_sha256']")"
SRC_FILE="$CACHE_DIR/$(jget "['bulk_extractor']['source_filename']")"

mkdir -p "$CACHE_DIR" "$DEST"
rm -rf "$EXTRACT_DIR"

if [[ ! -f "$SNAP_FILE" || "${FORCE:-0}" == "1" ]]; then
  echo "Downloading $SNAP_URL"
  curl -sL -o "$SNAP_FILE" "$SNAP_URL"
fi
HASH="$(shasum -a 256 "$SNAP_FILE" | cut -d' ' -f1)"
if [[ "$HASH" != "$SNAP_SHA" ]]; then
  rm -f "$SNAP_FILE"
  echo "SHA-256 mismatch for $(basename "$SNAP_FILE"). Expected $SNAP_SHA got $HASH" >&2
  exit 1
fi

if [[ ! -f "$SRC_FILE" || "${FORCE:-0}" == "1" ]]; then
  echo "Downloading $SRC_URL"
  curl -sL -o "$SRC_FILE" "$SRC_URL"
fi
HASH="$(shasum -a 256 "$SRC_FILE" | cut -d' ' -f1)"
if [[ "$HASH" != "$SRC_SHA" ]]; then
  rm -f "$SRC_FILE"
  echo "SHA-256 mismatch for $(basename "$SRC_FILE"). Expected $SRC_SHA got $HASH" >&2
  exit 1
fi

unsquashfs -d "$EXTRACT_DIR" -q "$SNAP_FILE"

BIN="$EXTRACT_DIR/usr/bin/bulk_extractor"
if [[ ! -f "$BIN" ]]; then
  echo "bulk_extractor binary not found inside the snap at usr/bin/bulk_extractor" >&2
  exit 1
fi

rm -rf "$DEST"
mkdir -p "$DEST/lib"
install -m 0755 "$BIN" "$DEST/bulk_extractor"

# Bundle every shared library the snap ships alongside the binary (OpenSSL
# engines, abseil, libexpat, libz, ...) into one flat lib/ dir, then point
# the binary at it with a relative RPATH so it runs outside the snap sandbox.
if [[ -d "$EXTRACT_DIR/usr/lib/x86_64-linux-gnu" ]]; then
  cp -a "$EXTRACT_DIR/usr/lib/x86_64-linux-gnu/." "$DEST/lib/"
fi
if [[ -d "$EXTRACT_DIR/lib/x86_64-linux-gnu" ]]; then
  cp -a "$EXTRACT_DIR/lib/x86_64-linux-gnu/." "$DEST/lib/"
fi
patchelf --set-rpath '$ORIGIN/lib' "$DEST/bulk_extractor"

# Every copied library still carries whatever RPATH/RUNPATH it had inside the
# snap's confinement (or none at all), which doesn't resolve once these files
# sit in resources/tools/bulk_extractor/lib/ outside that sandbox — a library
# that depends on a sibling (e.g. libabsl_random_internal_randen.so depending
# on libabsl_random_internal_randen_hwaes.so) can fail to resolve even though
# the sibling is right there, because nothing points at "the same directory
# as me". Point every .so at itself (`$ORIGIN`) so sibling lookups work both
# at runtime and when a bundler (linuxdeploy) statically walks dependencies.
find "$DEST/lib" -name '*.so*' -type f -print0 | while IFS= read -r -d '' lib; do
  patchelf --set-rpath '$ORIGIN' "$lib" 2>/dev/null || true
done

cp -f "$SRC_FILE" "$DEST/"

cat > "$DEST/README.txt" <<EOF
bulk_extractor v$(jget "['bulk_extractor']['version']") (Linux x64)
License: $(jget "['bulk_extractor']['license']")
Source: $(jget "['bulk_extractor']['project']")
Built from: $(jget "['bulk_extractor']['linux_asset']") (official snap, unpacked with unsquashfs)
Snap SHA-256: $SNAP_SHA
Source archive SHA-256: $SRC_SHA

This binary and its bundled shared libraries (lib/) were extracted from
upstream's official Linux Snap package — the only Linux build upstream
publishes for this release — and are not modified beyond an RPATH rewrite
(patchelf --set-rpath '\$ORIGIN/lib') so they run without snapd.

MemHunter invokes ./bulk_extractor as a separate process, never linked into
the Apache-2.0 engine, to keep this GPL-3.0-or-later component isolated.
MemHunter does not download bulk_extractor at runtime.
EOF

echo "bulk_extractor v$(jget "['bulk_extractor']['version']") ready at $DEST"
