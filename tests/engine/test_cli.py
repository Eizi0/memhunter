"""CLI result-parsing regression tests.

A real end-to-end run against a real memory dump caught three bugs here:
cmd_import, cmd_yara_scan and cmd_capa were reading job result fields at the
wrong nesting level (e.g. ``result["id"]`` instead of
``result["evidence"]["id"]``), because the job handlers return a nested DTO
(``{"evidence": {...}}`` / ``{"scan": {...}, "matches": [...]}``) rather than
a flat dict. These tests pin down the real handler shapes with fakes so a
future refactor of those DTOs breaks here instead of silently in the field.
"""

from __future__ import annotations

import argparse
from importlib import import_module
from typing import Any
from uuid import uuid4

import pytest

from memhunter_engine.errors import AppError

# `memhunter_engine/cli/__init__.py` does `from .main import main`, which
# rebinds the `main` attribute on the `memhunter_engine.cli` package from the
# submodule to the function — so `memhunter_engine.cli.main` is the function,
# not the submodule. Fetch the real submodule from sys.modules instead.
cli_main = import_module("memhunter_engine.cli.main")


@pytest.fixture(autouse=True)
def _patch_handlers(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli_main.server, "HANDLERS", {}, raising=False)


def _install(monkeypatch: pytest.MonkeyPatch, method: str, *, result=None, error=None) -> None:
    job_id = str(uuid4())

    def _submit(_params: dict[str, Any]) -> dict[str, Any]:
        return {"id": job_id}

    def _get(_params: dict[str, Any]) -> dict[str, Any]:
        if error is not None:
            return {"status": "failed", "error": error.to_dict(), "message": None}
        return {"status": "completed", "result": result, "message": None}

    handlers = dict(cli_main.server.HANDLERS)
    handlers[method] = _submit
    handlers["jobs.get"] = _get
    monkeypatch.setattr(cli_main.server, "HANDLERS", handlers, raising=False)


def test_cmd_import_reads_nested_evidence(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    _install(
        monkeypatch,
        "evidence.import",
        result={"evidence": {"id": "ev-1", "detected_os": "Windows", "sha256": "abc123"}},
    )
    rc = cli_main.cmd_import(argparse.Namespace(path="/tmp/x.raw"))
    out = capsys.readouterr().out
    assert rc == 0
    assert "evidence_id=ev-1" in out
    assert "detected_os=Windows" in out
    assert "sha256=abc123" in out


def test_cmd_yara_scan_reads_nested_match_count(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    _install(
        monkeypatch,
        "yara.scan_memory",
        result={"scan": {"match_count": 9}, "matches": [{}] * 9},
    )
    rc = cli_main.cmd_yara_scan(
        argparse.Namespace(evidence_id="ev-1", target="memory", artifact_id=None, rules=None, json=False)
    )
    out = capsys.readouterr().out
    assert rc == 0
    assert "9 match(es)" in out


def test_cmd_capa_reads_nested_capability_count(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    _install(
        monkeypatch,
        "capa.scan_artifact",
        result={"scan": {"capability_count": 4}, "capabilities": [{}] * 4},
    )
    rc = cli_main.cmd_capa(argparse.Namespace(evidence_id="ev-1", artifact_id="art-1", json=False))
    out = capsys.readouterr().out
    assert rc == 0
    assert "4 capabilit(y/ies)" in out


def test_cmd_report_reads_primary_path(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    _install(
        monkeypatch,
        "export.generate",
        result={"primary_path": "/tmp/out/report.html", "output_dir": "/tmp/out"},
    )
    rc = cli_main.cmd_report(
        argparse.Namespace(evidence_id="ev-1", format="html", scope="complete", out=None)
    )
    out = capsys.readouterr().out
    assert rc == 0
    assert "Report written: /tmp/out/report.html" in out


def test_cmd_analyze_auto_fetches_kernel_symbols_then_retries(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """analysis.run fails once with kernel_symbols_required; the CLI should
    call symbols.fetch with the guid/age from the error payload, then retry
    analysis.run automatically — not surface the raw error to the user."""
    kernel_err = AppError(
        code="kernel_symbols_required",
        message="This Windows dump needs kernel symbol tables before analysis can continue.",
        data={"pdb_name": "ntkrnlmp.pdb", "guid": "ABCDEF", "age": 1},
    )

    call_log: list[str] = []
    job_id = str(uuid4())
    analyze_attempts = {"n": 0}

    def _submit_analysis(_params: dict[str, Any]) -> dict[str, Any]:
        call_log.append("analysis.run")
        return {"id": job_id}

    def _submit_symbols(_params: dict[str, Any]) -> dict[str, Any]:
        call_log.append("symbols.fetch")
        return {"id": job_id}

    def _get(_params: dict[str, Any]) -> dict[str, Any]:
        last = call_log[-1]
        if last == "analysis.run":
            analyze_attempts["n"] += 1
            if analyze_attempts["n"] == 1:
                return {"status": "failed", "error": kernel_err.to_dict(), "message": None}
            return {"status": "completed", "result": {"ok": True}, "message": None}
        return {"status": "completed", "result": {"ok": True}, "message": None}

    handlers = dict(cli_main.server.HANDLERS)
    handlers["analysis.run"] = _submit_analysis
    handlers["symbols.fetch"] = _submit_symbols
    handlers["jobs.get"] = _get
    monkeypatch.setattr(cli_main.server, "HANDLERS", handlers, raising=False)

    rc = cli_main.cmd_analyze(
        argparse.Namespace(
            evidence_id="ev-1",
            profile="full",
            capabilities=None,
            json=False,
            no_fetch_symbols=False,
        )
    )
    assert rc == 0
    assert call_log == ["analysis.run", "symbols.fetch", "analysis.run"]
    assert analyze_attempts["n"] == 2


def test_cmd_analyze_no_fetch_symbols_propagates_error(monkeypatch: pytest.MonkeyPatch) -> None:
    kernel_err = AppError(
        code="kernel_symbols_required",
        message="This Windows dump needs kernel symbol tables before analysis can continue.",
        data={"pdb_name": "ntkrnlmp.pdb", "guid": "ABCDEF", "age": 1},
    )
    _install(monkeypatch, "analysis.run", error=kernel_err)
    with pytest.raises(AppError, match="kernel symbol tables"):
        cli_main.cmd_analyze(
            argparse.Namespace(
                evidence_id="ev-1",
                profile="full",
                capabilities=None,
                json=False,
                no_fetch_symbols=True,
            )
        )
