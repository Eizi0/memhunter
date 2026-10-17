#!/usr/bin/env bash
# Prepare the relocatable Linux x86_64 Python engine runtime.
# Downloads only the official python-build-standalone CPython build and
# verifies SHA-256. Installs pinned lockfile deps including yara-python 4.5.4.
# CAPA, FLOSS, and bulk_extractor are prepared separately (prepare-capa.sh,
# prepare-floss.sh, prepare-bulk-extractor.sh).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
MANIFEST="$ROOT/packaging/linux/runtime-manifest.json"
CACHE_DIR="$ROOT/packaging/cache"
DEST="$ROOT/app/desktop/resources/runtime"
ENGINE_DIR="$ROOT/engine"
LOCKFILE="$ENGINE_DIR/requirements.lock.txt"

jget() { python3 -c "import json,sys; print(json.load(open('$MANIFEST'))$1)"; }

PY_URL="$(jget "['python']['url']")"
PY_SHA="$(jget "['python']['sha256']")"
PY_FILE="$CACHE_DIR/$(jget "['python']['filename']")"

mkdir -p "$CACHE_DIR"

if [[ ! -f "$PY_FILE" || "${FORCE:-0}" == "1" ]]; then
  echo "Downloading python-build-standalone CPython runtime..."
  curl -sL -o "$PY_FILE" "$PY_URL"
fi
HASH="$(shasum -a 256 "$PY_FILE" | cut -d' ' -f1)"
if [[ "$HASH" != "$PY_SHA" ]]; then
  rm -f "$PY_FILE"
  echo "SHA-256 mismatch for $(basename "$PY_FILE"). Expected $PY_SHA got $HASH" >&2
  exit 1
fi

if [[ -d "$DEST" ]]; then
  echo "Removing previous runtime at $DEST for a deterministic rebuild"
  rm -rf "$DEST"
fi
mkdir -p "$DEST"
# python-build-standalone's install_only tarball extracts to a top-level
# python/ dir containing bin/, lib/, include/, etc. Keep that layout intact
# (CPython resolves its stdlib relative to the real bin/ path) and symlink
# runtime/python -> python/bin/python3.12 so engine.rs's python_candidates()
# (which looks for `runtime/python` on non-Windows) finds it.
tar -xzf "$PY_FILE" -C "$DEST" --strip-components=0
PYBIN="$(find "$DEST/python/bin" -maxdepth 1 -name 'python3.*' ! -name '*-config' | sort | tail -1)"
if [[ -z "$PYBIN" ]]; then
  echo "python3.x binary not found under $DEST/python/bin" >&2
  exit 1
fi
ln -sf "python/bin/$(basename "$PYBIN")" "$DEST/python"

# Resolve the actual site-packages dir from the interpreter itself rather
# than guessing the exact lib/pythonX.Y path.
SITE="$("$DEST/python" -c 'import sysconfig; print(sysconfig.get_paths()["purelib"])')"

"$DEST/python" -m ensurepip --upgrade >/dev/null
"$DEST/python" -m pip install \
  --no-cache-dir \
  --no-compile \
  --no-warn-script-location \
  -r "$LOCKFILE"

ENGINE_BUILD="$ENGINE_DIR/build"
if [[ -d "$ENGINE_BUILD" ]]; then
  echo "Removing leftover engine build directory $ENGINE_BUILD"
  rm -rf "$ENGINE_BUILD"
fi
ENGINE_PKG="$SITE/memhunter_engine"
rm -rf "$ENGINE_PKG"
find "$SITE" -maxdepth 1 -name 'memhunter_engine-*.dist-info' -exec rm -rf {} +

"$DEST/python" -m pip install \
  --upgrade \
  --no-cache-dir \
  --no-compile \
  --no-deps \
  --no-warn-script-location \
  "$ENGINE_DIR"

# Developer source still contains PE-sieve / mal_unpack for tests. They must
# not ship in the end-user runtime (no EXE is bundled; UI must not offer them).
for rel in \
  "providers/pe_sieve.py" \
  "providers/mal_unpack.py" \
  "analysis/pe_sieve_workflows.py" \
  "analysis/mal_unpack_workflows.py"; do
  leftover="$ENGINE_PKG/$rel"
  if [[ -f "$leftover" ]]; then
    echo "Stripping removed provider from runtime: $leftover"
    rm -f "$leftover"
  fi
done

cat > "$DEST/runtime-info.json" <<EOF
{
  "app_version": "$(jget "['engine']['version']")",
  "python_version": "$(jget "['python']['version']")",
  "volatility3": "$(jget "['engine']['volatility3']")",
  "pefile": "$(jget "['engine']['pefile']")",
  "yara_python": "$(jget "['engine']['yara_python']")",
  "prepared_utc": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
EOF

"$DEST/python" -c "
import importlib, sys
mods = ['memhunter_engine', 'volatility3', 'pefile', 'yara']
for m in mods:
    importlib.import_module(m)
import yara
if getattr(yara, '__version__', '') != '4.5.4':
    raise SystemExit('yara-python must be 4.5.4, got ' + str(getattr(yara, '__version__', None)))
for gone in ('memhunter_engine.providers.pe_sieve', 'memhunter_engine.providers.mal_unpack'):
    try:
        importlib.import_module(gone)
        raise SystemExit(gone + ' must not be packaged')
    except ImportError:
        pass
for needed in (
    'memhunter_engine.providers.pe_extraction',
    'memhunter_engine.providers.capa',
    'memhunter_engine.providers.floss',
    'memhunter_engine.volatility.pe_dump',
    'memhunter_engine.volatility.kernel_symbols',
    'memhunter_engine.volatility.symbol_pack',
):
    importlib.import_module(needed)
from memhunter_engine.version import APP_VERSION
from importlib.metadata import version
vol = version('volatility3')
if vol != '2.28.0':
    raise SystemExit('volatility3 must be 2.28.0, got ' + vol)
yp = version('yara-python')
if yp != '4.5.4':
    raise SystemExit('yara-python must be 4.5.4, got ' + yp)
print('runtime_ok', APP_VERSION, vol, sys.version.split()[0], yp)
"

RULES_SRC="$ENGINE_PKG/rules/yara/bundled"
if [[ ! -d "$RULES_SRC" ]]; then
  RULES_SRC="$ENGINE_DIR/memhunter_engine/rules/yara/bundled"
fi
RULES_DEST="$ROOT/app/desktop/resources/rules/yara/bundled"
if [[ ! -d "$RULES_SRC" ]]; then
  echo "packaged Signature Detection rules missing: $RULES_SRC" >&2
  exit 1
fi
rm -rf "$RULES_DEST"
mkdir -p "$(dirname "$RULES_DEST")"
cp -R "$RULES_SRC" "$RULES_DEST"
echo "bundled_yara_rules $RULES_DEST"

echo "Engine runtime ready at $DEST"
