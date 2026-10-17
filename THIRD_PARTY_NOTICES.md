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

## Linux: redistributed as separate programs (added for MemHunter)

*Filled in during the Linux-support work with independently verified versions, release-asset
SHA-256 hashes, and license text, matching the same diligence as the Windows table above —
see the project's CHANGELOG for when this section was completed.*

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
