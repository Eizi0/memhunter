# Third-party notices

MemHunter's own source (`app/`, `engine/memhunter_engine/`, `tests/` except vendored fixtures,
and project documentation) is licensed under Apache-2.0 — see `LICENSE` and `NOTICE`.

This engine wraps several external forensic tools as separate processes or libraries. The Windows
facts below (versions, hashes, license fields) were originally verified by the Dumplyzer project
this codebase is derived from, against package metadata and upstream release assets at the time;
they are carried forward here rather than re-verified line by line, since the Windows-side
components are unchanged. The Linux entries added for MemHunter's native Linux support are
verified independently below.

## Windows: redistributed with the engine runtime

| Component | Version | License |
|-----------|---------|---------|
| CPython embeddable (Windows x64) | 3.12.10 | Python Software Foundation License (PSF) |
| volatility3 | 2.28.0 | **Volatility Software License 1.0** (Volatility Foundation) — *not* Apache-2.0, not relicensed. Full text: https://www.volatilityfoundation.org/license/vsl-v1.0 |
| pefile | 2024.8.26 | MIT |
| yara-python | 4.5.4 | Apache-2.0 (Python bindings); libyara itself is BSD-3-Clause |

The Volatility 3 license text is shipped alongside the runtime it's bundled with and is never
removed or altered.

## Windows: downloaded once at first analysis (not shipped)

| Component | Notes |
|-----------|--------|
| Volatility Foundation Windows ISF pack (`windows.zip`) | Official archive from `downloads.volatilityfoundation.org`. Not bundled in any installer; fetched on explicit in-app consent ("Download & Continue") for one kernel build, or supplied locally by the analyst. |

## Windows: redistributed as separate programs (subprocess only, never linked)

| Component | Version | License |
|-----------|---------|---------|
| bulk_extractor | 2.2.0 | **GPL-3.0-or-later** for post-NPS project-authored code. Invoked as a separate `.exe` process, never imported/linked — this boundary is what keeps the Apache-2.0 codebase clean of GPL "linking" obligations. License text and corresponding source shipped under `app/desktop/resources/tools/bulk_extractor/`. |
| CAPA | 9.4.0 | Apache-2.0. Invoked as a separate `.exe` process against extracted PE artifacts only. |
| FLOSS | 3.1.1 | Apache-2.0. Invoked as a separate `.exe` process against extracted PE artifacts only. |

## Linux: redistributed with the engine runtime

| Component | Version | License |
|-----------|---------|---------|
| CPython (python-build-standalone, x86_64-unknown-linux-gnu, install_only) | 3.12.15 (release `20261013`) | Python Software Foundation License (PSF). Build project: https://github.com/astral-sh/python-build-standalone (Apache-2.0 build scripts; the interpreter itself is still PSF-licensed CPython) — the same relocatable-build project `uv`/`rye` use. No official Linux-portable 3.12.10 build exists (unlike the Windows embeddable zip); 3.12.15 is the closest 3.12.x build available. SHA-256 of `cpython-3.12.15+20261013-x86_64-unknown-linux-gnu-install_only.tar.gz`: `5d546fc004fc2435fa142eb8f42ed8de5eb4725963dc22f7e6671014a80eb560`, verified against the release's own `SHA256SUMS` and by independent re-download. |
| volatility3 | 2.28.0 | Volatility Software License 1.0 — same terms and same obligations as the Windows build; see above. |
| pefile | 2024.8.26 | MIT |
| yara-python | 4.5.4 | Apache-2.0 (Python bindings); libyara itself is BSD-3-Clause |

## Linux: redistributed as separate programs (subprocess only, never linked)

| Component | Version | License |
|-----------|---------|---------|
| bulk_extractor | 2.2.0 | **GPL-3.0-or-later**, same isolation as Windows (separate process, never imported). Upstream publishes Linux builds only as a Snap package (`bulk-extractor_2.2.0_amd64.snap`, SHA-256 `dbc0749a7a84e2710c104a09fd921b93c1db9e2147bb11da978dea7af0e16c67`, verified against the release's own `SHA256SUMS`); `scripts/linux/prepare-bulk-extractor.sh` unpacks that squashfs image with `unsquashfs`, lifts out the `bulk_extractor` binary and its bundled shared libraries (OpenSSL engines, abseil, libexpat, libz — all from the same official snap, unmodified), and rewrites its RPATH with `patchelf` so it runs without snapd/confinement. Corresponding source (`bulk_extractor-2.2.0.tar.gz`, SHA-256 `b9e15d40d711aa43590e1bf1a25d30943e3bad8371281d7c80d3803a6f34c268`) is shipped alongside it under `app/desktop/resources/tools/bulk_extractor/`, same as Windows. |
| CAPA | 9.4.0 | Apache-2.0. Official Linux x64 build (`capa-v9.4.0-linux.zip`, SHA-256 `07800a1d20a21eb18fc98716e2ae81b668e0c9a04defd588c8aa17ea3d3281e4`). Invoked as a separate process against extracted PE artifacts only. |
| FLOSS | 3.1.1 | Apache-2.0. Official Linux x64 build (`floss-v3.1.1-linux.zip`, SHA-256 `40c05a869f34f7e2417b17ca290cc54bd3671ee1f0a2d9bd5103284c01a54666`). Invoked as a separate process against extracted PE artifacts only. |

All Linux hashes above were independently verified: each asset was downloaded directly from its
GitHub release and re-hashed locally with `shasum -a 256`, then cross-checked against the
publisher's own `SHA256SUMS` file where one exists (python-build-standalone, bulk_extractor) —
not copied from a third party. See `packaging/linux/runtime-manifest.json` for the pinned URLs
and hashes the `scripts/linux/prepare-*.sh` scripts verify against at build time.

## Bundled data

| Component | Notes |
|-----------|--------|
| Mozilla Public Suffix List (`public_suffix_list.dat`) | Shipped under `engine/memhunter_engine/data/` for domain IOC validation. License: Mozilla Public License 2.0. Source: https://publicsuffix.org/list/public_suffix_list.dat — not relicensed. |

## Not redistributed

PE-sieve and mal_unpack are not integrated and are not shipped or invoked.

## Other build-time / UI dependencies

Frontend (`app/frontend/package-lock.json`) and desktop (`app/desktop/Cargo.lock`,
`package-lock.json`) packages record their own license fields in their lockfiles (commonly MIT
and Apache-2.0 for Tauri/React/Vite). Those lockfiles are the source of truth; this file does not
restate every transitive dependency's license.
