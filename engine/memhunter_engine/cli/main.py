"""`memhunter` command-line entry point.

Design: every subcommand is a thin wrapper around the same RPC handler
registry (`memhunter_engine.server.HANDLERS`) the desktop app's stdio
JSON-RPC protocol dispatches into. Job-backed operations (import, analyze,
scans, exports) are submitted the same way the GUI submits them, then
polled here until they reach a terminal state, with progress printed to
stderr so stdout stays clean for piping (e.g. `memhunter report ... --format
json --out -` to stdout).
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from typing import Any

from memhunter_engine import server
from memhunter_engine.errors import AppError

_POLL_INTERVAL_SECONDS = 0.35
_TERMINAL_STATUSES = {"completed", "failed", "cancelled"}


def _call(method: str, params: dict[str, Any] | None = None) -> Any:
    handler = server.HANDLERS.get(method)
    if handler is None:
        raise AppError(code="unknown_method", message=f"Unknown RPC method: {method}")
    return handler(params or {})


def _run_job(method: str, params: dict[str, Any], *, label: str) -> dict[str, Any]:
    submitted = _call(method, params)
    job_id = submitted["id"]
    last_message = None
    while True:
        job = _call("jobs.get", {"job_id": job_id})
        status = job.get("status")
        message = job.get("message")
        if message and message != last_message:
            print(f"  [{status}] {message}", file=sys.stderr)
            last_message = message
        if status in _TERMINAL_STATUSES:
            if status == "completed":
                return job
            error = job.get("error") or {}
            raise AppError(
                code=error.get("code", "job_failed"),
                message=error.get("message", f"{label} failed."),
                details=error.get("details"),
                suggestion=error.get("suggestion"),
                data=error.get("data") or {},
            )
        time.sleep(_POLL_INTERVAL_SECONDS)


def _bootstrap(data_dir: str | None) -> None:
    params = {"data_dir": data_dir} if data_dir else {}
    _call("app.init", params)


def _print_json(data: Any) -> None:
    print(json.dumps(data, indent=2, ensure_ascii=False, default=str))


def cmd_import(args: argparse.Namespace) -> int:
    job = _run_job("evidence.import", {"path": args.path}, label="Import")
    evidence = (job.get("result") or {}).get("evidence") or {}
    print(f"Imported: evidence_id={evidence.get('id')}")
    print(f"  detected_os={evidence.get('detected_os')} sha256={evidence.get('sha256')}")
    return 0


def cmd_list(_args: argparse.Namespace) -> int:
    items = _call("evidence.list", {}).get("items", [])
    if not items:
        print("No evidence imported yet. Run `memhunter import <dump>` first.")
        return 0
    for ev in items:
        print(
            f"{ev['id']}  {ev.get('filename', '?'):<32}  "
            f"os={ev.get('detected_os') or 'unknown':<10} "
            f"status={ev.get('import_status')}"
        )
    return 0


def cmd_analyze(args: argparse.Namespace) -> int:
    capabilities = args.capabilities.split(",") if args.capabilities else []
    params = {
        "evidence_id": args.evidence_id,
        "profile": args.profile,
        "capabilities": [c.strip() for c in capabilities if c.strip()],
    }
    try:
        job = _run_job("analysis.run", params, label="Analysis")
    except AppError as exc:
        if exc.code != "kernel_symbols_required" or args.no_fetch_symbols:
            raise
        guid = exc.data.get("guid")
        age = exc.data.get("age")
        pdb_name = exc.data.get("pdb_name")
        if not guid or not age:
            raise
        print(
            f"  Windows kernel symbols required ({pdb_name}); "
            "fetching from Microsoft's symbol server…",
            file=sys.stderr,
        )
        _run_job(
            "symbols.fetch",
            {"evidence_id": args.evidence_id, "pdb_name": pdb_name, "guid": guid, "age": age},
            label="Symbol fetch",
        )
        print("  Symbols ready, retrying analysis…", file=sys.stderr)
        job = _run_job("analysis.run", params, label="Analysis")
    print(f"Analysis complete (profile={args.profile}).")
    if args.json:
        _print_json(job.get("result"))
    return 0


def cmd_profiles(_args: argparse.Namespace) -> int:
    _print_json(_call("analysis.profiles", {}))
    return 0


def cmd_yara_scan(args: argparse.Namespace) -> int:
    method = {
        "memory": "yara.scan_memory",
        "artifact": "yara.scan_artifact",
        "extracted": "yara.scan_extracted",
    }[args.target]
    params: dict[str, Any] = {"evidence_id": args.evidence_id}
    if args.target == "artifact":
        if not args.artifact_id:
            print("--artifact-id is required for --target artifact", file=sys.stderr)
            return 2
        params["artifact_id"] = args.artifact_id
    if args.rules:
        params["rule_names"] = args.rules.split(",")
    job = _run_job(method, params, label="YARA scan")
    result = job.get("result") or {}
    scan = result.get("scan") or {}
    print(f"YARA scan complete: {scan.get('match_count', '?')} match(es).")
    if args.json:
        _print_json(result)
    return 0


def cmd_capa(args: argparse.Namespace) -> int:
    job = _run_job(
        "capa.scan_artifact",
        {"artifact_id": args.artifact_id, "evidence_id": args.evidence_id},
        label="CAPA analysis",
    )
    result = job.get("result") or {}
    scan = result.get("scan") or {}
    print(f"CAPA analysis complete: {scan.get('capability_count', '?')} capabilit(y/ies).")
    if args.json:
        _print_json(result)
    return 0


def cmd_attck(args: argparse.Namespace) -> int:
    result = _call("attck.coverage", {"evidence_id": args.evidence_id})
    if args.json:
        _print_json(result)
        return 0
    techniques = result.get("techniques", [])
    if not techniques:
        print("No ATT&CK-tagged findings for this evidence yet (run capa/yara-scan first).")
        return 0
    print(f"{result['technique_count']} technique(s) observed:")
    for t in techniques:
        names = ", ".join(s.get("name", "?") for s in t["sources"])
        print(f"  {t['technique_id']}  <- {names}")
    return 0


def cmd_gen_rule(args: argparse.Namespace) -> int:
    result = _call(
        "attck.generate_rule",
        {
            "source_kind": args.kind,
            "source_id": args.finding_id,
            "rule_format": args.format,
        },
    )
    print(result["content"])
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    params = {
        "evidence_id": args.evidence_id,
        "format": args.format,
        "scope": args.scope,
    }
    if args.out:
        params["destination"] = args.out
    job = _run_job("export.generate", params, label="Export")
    result = job.get("result") or {}
    path = result.get("primary_path") or result.get("output_dir")
    print(f"Report written: {path}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="memhunter",
        description="MemHunter — local-first memory forensics, headless.",
    )
    parser.add_argument(
        "--data-dir",
        help="Override the data directory (defaults to MEMHUNTER_DATA_DIR / platform default).",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_import = sub.add_parser("import", help="Import a memory image.")
    p_import.add_argument("path", help="Path to the memory image file.")
    p_import.set_defaults(func=cmd_import)

    p_list = sub.add_parser("list", help="List imported evidence.")
    p_list.set_defaults(func=cmd_list)

    p_profiles = sub.add_parser("profiles", help="List analysis profiles and capabilities.")
    p_profiles.set_defaults(func=cmd_profiles)

    p_analyze = sub.add_parser("analyze", help="Run an analysis profile against imported evidence.")
    p_analyze.add_argument("evidence_id")
    p_analyze.add_argument("--profile", choices=["recommended", "full", "custom"], default="full")
    p_analyze.add_argument(
        "--capabilities",
        help="Comma-separated capability IDs (only used with --profile custom).",
    )
    p_analyze.add_argument("--json", action="store_true", help="Print the result as JSON.")
    p_analyze.add_argument(
        "--no-fetch-symbols",
        action="store_true",
        help="Don't auto-download missing Windows kernel symbols (offline/air-gapped use).",
    )
    p_analyze.set_defaults(func=cmd_analyze)

    p_yara = sub.add_parser("yara-scan", help="Run a YARA scan.")
    p_yara.add_argument("evidence_id")
    p_yara.add_argument("--target", choices=["memory", "artifact", "extracted"], default="memory")
    p_yara.add_argument("--artifact-id", help="Required when --target artifact.")
    p_yara.add_argument("--rules", help="Comma-separated rule names (default: all).")
    p_yara.add_argument("--json", action="store_true")
    p_yara.set_defaults(func=cmd_yara_scan)

    p_capa = sub.add_parser("capa", help="Run CAPA against an extracted PE artifact.")
    p_capa.add_argument("evidence_id")
    p_capa.add_argument("artifact_id")
    p_capa.add_argument("--json", action="store_true")
    p_capa.set_defaults(func=cmd_capa)

    p_attck = sub.add_parser("attck", help="Show MITRE ATT&CK technique coverage for evidence.")
    p_attck.add_argument("evidence_id")
    p_attck.add_argument("--json", action="store_true")
    p_attck.set_defaults(func=cmd_attck)

    p_genrule = sub.add_parser("gen-rule", help="Generate a draft detection rule from one finding.")
    p_genrule.add_argument("kind", choices=["yara_match", "capa_capability", "process"])
    p_genrule.add_argument("finding_id")
    p_genrule.add_argument("--format", choices=["sigma", "yara"], default="sigma")
    p_genrule.set_defaults(func=cmd_gen_rule)

    p_report = sub.add_parser("report", help="Export an investigation report.")
    p_report.add_argument("evidence_id")
    p_report.add_argument("--format", choices=["html", "json", "csv", "xlsx"], default="html")
    p_report.add_argument("--scope", choices=["complete", "summary"], default="complete")
    p_report.add_argument("--out", help="Output file path (default: data dir exports/).")
    p_report.set_defaults(func=cmd_report)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        _bootstrap(args.data_dir)
        return args.func(args)
    except AppError as exc:
        print(f"error: {exc.message}", file=sys.stderr)
        if exc.details:
            print(f"  {exc.details}", file=sys.stderr)
        if exc.suggestion:
            print(f"  {exc.suggestion}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
