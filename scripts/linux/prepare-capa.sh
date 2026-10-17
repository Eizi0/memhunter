#!/usr/bin/env bash
# Fetch the official Mandiant CAPA Linux x64 zip (Apache-2.0).
# SHA-256 is pinned in packaging/linux/runtime-manifest.json, verified here
# against the freshly downloaded file. Does not run at application startup.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
MANIFEST="$ROOT/packaging/linux/runtime-manifest.json"
CACHE_DIR="$ROOT/packaging/cache"
DEST="$ROOT/app/desktop/resources/tools/capa"
EXTRACT_DIR="$CACHE_DIR/capa-extract-linux"

jget() { python3 -c "import json,sys; print(json.load(open('$MANIFEST'))$1)"; }

ZIP_URL="$(jget "['capa']['zip_url']")"
ZIP_SHA="$(jget "['capa']['zip_sha256']")"
ZIP_FILE="$CACHE_DIR/$(jget "['capa']['zip_filename']")"
LICENSE_URL="$(jget "['capa']['license_url']")"

mkdir -p "$CACHE_DIR" "$DEST"
rm -rf "$EXTRACT_DIR"
mkdir -p "$EXTRACT_DIR"

if [[ ! -f "$ZIP_FILE" || "${FORCE:-0}" == "1" ]]; then
  echo "Downloading $ZIP_URL"
  curl -sL -o "$ZIP_FILE" "$ZIP_URL"
fi
HASH="$(shasum -a 256 "$ZIP_FILE" | cut -d' ' -f1)"
if [[ "$HASH" != "$ZIP_SHA" ]]; then
  rm -f "$ZIP_FILE"
  echo "SHA-256 mismatch for $(basename "$ZIP_FILE"). Expected $ZIP_SHA got $HASH" >&2
  exit 1
fi

unzip -q -o "$ZIP_FILE" -d "$EXTRACT_DIR"

BIN="$(find "$EXTRACT_DIR" -maxdepth 2 -type f -name 'capa' | head -1)"
if [[ -z "$BIN" ]]; then
  echo "capa binary not found inside $(basename "$ZIP_FILE")" >&2
  exit 1
fi
install -m 0755 "$BIN" "$DEST/capa"

LICENSE_COPIED=0
while IFS= read -r -d '' f; do
  cp -f "$f" "$DEST/"
  LICENSE_COPIED=1
done < <(find "$EXTRACT_DIR" -maxdepth 2 -type f \( -iname 'LICENSE*' -o -iname 'NOTICE*' \) -print0)
if [[ "$LICENSE_COPIED" == "0" && -n "$LICENSE_URL" ]]; then
  curl -sL -o "$DEST/LICENSE.txt" "$LICENSE_URL"
fi

cat > "$DEST/README.txt" <<EOF
Mandiant CAPA v$(jget "['capa']['version']") (Linux x64)
License: $(jget "['capa']['license']")
Source: $(jget "['capa']['project']")
Asset: $(basename "$ZIP_FILE")
SHA-256: $ZIP_SHA
MemHunter invokes ./capa as a separate process against extracted PE
artifacts only. MemHunter does not download CAPA at runtime.
EOF

echo "CAPA v$(jget "['capa']['version']") ready at $DEST"
