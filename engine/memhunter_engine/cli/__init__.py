"""MemHunter command-line interface.

Headless entry point for the analysis engine, independent of the Tauri
desktop shell. Reuses the exact same bootstrap (`memhunter_engine.server
.handle_app_init`) and RPC handler registry the desktop app's stdio
protocol dispatches into, so the CLI and the GUI always run identical
analysis code — there is no second implementation to keep in sync.
"""

from memhunter_engine.cli.main import main

__all__ = ["main"]
