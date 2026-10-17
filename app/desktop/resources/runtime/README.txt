MemHunter bundled Python engine runtime

This directory is populated at installer build time by:

  scripts/windows/prepare-engine-runtime.ps1   (Windows: embeddable CPython + memhunter_engine)
  scripts/linux/prepare-engine-runtime.sh      (Linux: python-build-standalone + memhunter_engine)

It is intentionally empty in a source checkout and in a `cargo tauri dev` /
`npm run tauri dev` session — the desktop app falls back to the development
virtualenv at engine/.venv instead (see app/desktop/src/engine.rs,
python_candidates()). It exists here, tracked in git, only so tauri-build's
bundle.resources validation (tauri.conf.json) has a real path to point at
before a release runtime has been prepared.

Do not store evidence, databases, or extracted artifacts here.
