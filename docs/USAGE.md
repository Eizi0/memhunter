# Using MemHunter

Two ways to run an investigation: the desktop app, or the `memhunter` CLI. Both drive the
exact same analysis engine — nothing the GUI can do is GUI-only.

## Desktop app

1. **Import Memory Dump** (top bar) — pick a `.raw`/`.mem`/`.vmem`/`.dmp` image, or drag one onto
   the window. MemHunter hashes it (SHA-256, shown on Overview) and never copies it out of its
   original location.
2. Pick an **analysis mode** when prompted:
   - **Complete Analysis** (recommended) — processes, command lines, modules, network, handles,
     findings, IOCs, network artifacts, timeline, for whichever OS the dump turns out to be
     (Windows or Linux, detected automatically).
   - **Quick Triage** — OS + process list only, for a fast first look.
   - **Custom Analysis** — pick capabilities individually.
3. If the dump is Windows and needs kernel symbols, MemHunter offers to download the matching
   PDB from Microsoft's symbol server for that build only (a few MB) — this needs internet
   access once per Windows build; nothing else in the app does.
4. **Signatures** (YARA) and **CAPA** are separate, on-demand scans — not part of Complete
   Analysis, since they take longer and aren't always needed:
   - **Signatures** → Memory Image tab → select rule categories → **Scan Memory Image**.
   - **Carved Data** → Extracted Files → **Run PE Reconstruction** first (CAPA/FLOSS need an
     extracted PE, not the raw dump) → then run CAPA/FLOSS from the artifact's row.
5. **ATT&CK** — once Signatures or CAPA has produced at least one tagged finding, this view
   aggregates them by MITRE technique ID. Pick any finding → **Generate draft rule** → Sigma or
   YARA — a starting point to refine, not a finished detection.
6. **Export** — HTML, JSON, CSV or XLSX report scoped to whatever analysis already ran.

Findings, IOCs, and signature matches are investigation leads, not a verdict — MemHunter never
scores or blocks anything.

## CLI

The CLI (`engine/memhunter_engine/cli/`) calls the same handlers the desktop app does, so results
are identical. Install it (see [README.md](../README.md#install)), then:

```bash
# Import a memory image (idempotent — re-importing the same file returns the same evidence_id,
# and discards any previous analysis for it so a re-run starts clean)
memhunter import /path/to/dump.raw
# Imported: evidence_id=<uuid>
#   detected_os=None sha256=<sha256>

memhunter list
# <uuid>  dump.raw   os=unknown    status=imported

# Run the full guided profile. If the dump is Windows and needs kernel symbols, this downloads
# them automatically and retries once; pass --no-fetch-symbols on an air-gapped workstation.
memhunter analyze <evidence_id> --profile full

memhunter list
# <uuid>  dump.raw   os=Windows NT ...   status=analyzed

# Signature Detection (YARA) over the raw memory image
memhunter yara-scan <evidence_id>
# YARA scan complete: 9 match(es).

# MITRE ATT&CK coverage, aggregated from whatever CAPA/YARA has already produced
memhunter attck <evidence_id>
# 2 technique(s) observed:
#   T1003.001  <- memhunter_credtheft_comsvcs_minidump_memory, ...
#   T1218.011  <- memhunter_credtheft_comsvcs_minidump_memory, ...

# Draft a Sigma or YARA rule from one specific finding (a yara_match id, capa_capability id,
# or process id — ids come from --json output of the commands above)
memhunter gen-rule yara_match <match_id> --format sigma

# Full HTML investigation report
memhunter report <evidence_id> --format html
# Report written: /path/to/exports/.../report.html
```

Run `memhunter <command> --help` for every flag; `--json` on `analyze`/`yara-scan`/`capa`
prints the full structured result instead of a one-line summary, for scripting.

### A realistic pipeline

```bash
#!/usr/bin/env bash
set -euo pipefail
DUMP="$1"
EVID=$(memhunter import "$DUMP" | grep -oE 'evidence_id=\S+' | cut -d= -f2)
memhunter analyze "$EVID" --profile full
memhunter yara-scan "$EVID"
memhunter attck "$EVID"
memhunter report "$EVID" --format html
```

Drop that in a triage runbook or a CI job — the whole investigation runs headless, no desktop
session required.

## Which evidence OS is supported

Both Windows and Linux memory images get a guided profile (process list, command lines,
modules/libraries, network, handles — picked from the dump itself, not the host OS). PE
reconstruction, CAPA, and FLOSS stay Windows-artifact-only by design (PE is a Windows executable
format). Anything outside the guided profile is reachable through **Plugins** (raw Volatility 3
plugin access) on either OS.

## Where things are stored

Nothing from the memory image itself is ever copied into the install directory. Analysis output,
the SQLite database, and exports live under the platform data directory
(`%LOCALAPPDATA%\MemHunter` on Windows, `~/.local/share/memhunter` on Linux, or
`$MEMHUNTER_DATA_DIR` if set) — see **Settings** in the app, or `memhunter_engine.paths` in code.
