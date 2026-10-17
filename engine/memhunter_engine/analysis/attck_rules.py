"""Draft detection-rule generation from a single forensic finding.

Produces a **draft** Sigma rule (YAML) or YARA rule stub from one CAPA
capability match, one YARA match, or one flagged process row — pre-filled
from whatever fields are actually available in storage. This is template
substitution, not inference: the generated rule is a starting point for an
analyst to refine and test, exactly as MemHunter already treats YARA/CAPA
results as investigation leads rather than verdicts (see ARCHITECTURE.md /
README.md). Nothing here is written out or submitted anywhere automatically.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from memhunter_engine.errors import AppError
from memhunter_engine.storage import Database

from memhunter_engine.analysis.attck import technique_ids

_SAFE_TITLE_RE = re.compile(r"[^a-zA-Z0-9 _.-]")


def _yaml_str(value: Any) -> str:
    """Minimal, dependency-free YAML scalar/list quoting for the generated
    Sigma draft (the engine deliberately has no PyYAML dependency today).

    Lists render as a flow sequence (``[a, b]``) rather than a block list so
    this never has to reason about the caller's indentation depth."""
    if isinstance(value, list):
        return "[" + ", ".join(_yaml_scalar(v) for v in value) + "]"
    return _yaml_scalar(value)


def _yaml_scalar(value: Any) -> str:
    text = "" if value is None else str(value)
    if text == "" or any(ch in text for ch in ":#{}[]&*!|>'\"%@`") or text != text.strip():
        return json.dumps(text)
    return text


def _sigma_draft(
    *,
    title: str,
    description: str,
    logsource: dict[str, str],
    detection_field: str,
    detection_values: list[str],
    technique_ids: list[str],
    level: str = "medium",
) -> str:
    safe_title = _SAFE_TITLE_RE.sub("", title).strip() or "Untitled finding"
    lines = [
        "title: " + _yaml_scalar(safe_title),
        "id: " + str(uuid4()),
        "status: experimental",
        "description: " + _yaml_scalar(description),
        "date: " + datetime.now(timezone.utc).strftime("%Y/%m/%d"),
        "references:",
        "    - MemHunter draft — generated from a memory-forensics finding, not yet validated",
        "logsource:",
    ]
    for key, value in logsource.items():
        lines.append(f"    {key}: {_yaml_scalar(value)}")
    lines += [
        "detection:",
        "    selection:",
        f"        {detection_field}|contains: {_yaml_str(detection_values)}",
        "    condition: selection",
    ]
    if technique_ids:
        lines.append("tags:")
        for tid in technique_ids:
            lines.append(f"    - attack.{tid.lower()}")
    lines += [
        f"level: {level}",
        "falsepositives:",
        "    - Unreviewed draft — verify against known-good baselines before deploying.",
    ]
    return "\n".join(lines) + "\n"


def _yara_draft(
    *,
    rule_name: str,
    description: str,
    technique_ids: list[str],
    strings: dict[str, str],
    condition: str,
) -> str:
    safe_name = re.sub(r"[^A-Za-z0-9_]", "_", rule_name) or "memhunter_draft_rule"
    if safe_name[0].isdigit():
        safe_name = f"rule_{safe_name}"
    meta_lines = [
        f'        description = "{description}"',
        '        status = "draft"',
        '        source = "MemHunter — generated from a memory-forensics finding, unreviewed"',
    ]
    if technique_ids:
        meta_lines.append(f'        mitre_attack = "{", ".join(technique_ids)}"')
    string_lines = [f'        ${name} = "{value}"' for name, value in strings.items()]
    return (
        f"rule {safe_name}_draft\n"
        "{\n"
        "    meta:\n" + "\n".join(meta_lines) + "\n"
        "    strings:\n" + "\n".join(string_lines) + "\n"
        f"    condition:\n        {condition}\n"
        "}\n"
    )


def draft_from_yara_match(db: Database, match_id: str, *, rule_format: str) -> dict[str, Any]:
    row = db.fetchone(
        """
        SELECT m.*, s.evidence_id
        FROM yara_matches m
        JOIN yara_scans s ON s.id = m.scan_id
        WHERE m.id = ?
        """,
        (match_id,),
    )
    if not row:
        raise AppError(code="not_found", message="YARA match not found.", entity="yara_match")
    meta = json.loads(row.get("meta_json") or "{}")
    techniques = technique_ids(meta.get("mitre_attack") or meta.get("att&ck"))
    description = meta.get("description") or f"Draft derived from YARA match {row['rule_name']}"

    if rule_format == "sigma":
        content = _sigma_draft(
            title=f"Possible {row['rule_name']} activity (from memory forensics)",
            description=description,
            logsource={"category": "process_creation", "product": "windows"},
            detection_field="Image",
            detection_values=[row["rule_name"]],
            technique_ids=techniques,
        )
    else:
        content = _yara_draft(
            rule_name=row["rule_name"],
            description=description,
            technique_ids=techniques,
            strings={"indicator": row["rule_name"]},
            condition="any of them",
        )
    return {"format": rule_format, "source": "yara_match", "source_id": match_id, "content": content}


def draft_from_capa_capability(db: Database, capability_id: str, *, rule_format: str) -> dict[str, Any]:
    row = db.fetchone("SELECT * FROM capa_capabilities WHERE id = ?", (capability_id,))
    if not row:
        raise AppError(code="not_found", message="CAPA capability not found.", entity="capa_capability")
    techniques = technique_ids(json.loads(row.get("attck_json") or "[]"))
    name = row.get("name") or "capability"
    description = row.get("description") or f"Draft derived from CAPA capability: {name}"

    if rule_format == "sigma":
        content = _sigma_draft(
            title=f"Possible capability: {name}",
            description=description,
            logsource={"category": "process_creation", "product": "windows"},
            detection_field="CommandLine",
            detection_values=[name],
            technique_ids=techniques,
        )
    else:
        content = _yara_draft(
            rule_name=name,
            description=description,
            technique_ids=techniques,
            strings={"indicator": name},
            condition="any of them",
        )
    return {"format": rule_format, "source": "capa_capability", "source_id": capability_id, "content": content}


def draft_from_process(db: Database, process_id: str, *, rule_format: str) -> dict[str, Any]:
    row = db.fetchone("SELECT * FROM processes WHERE id = ?", (process_id,))
    if not row:
        raise AppError(code="not_found", message="Process not found.", entity="process")
    name = row.get("name") or "unknown.exe"
    command_line = row.get("command_line") or name
    description = f"Draft derived from a flagged process observed in memory: {name}"

    if rule_format == "sigma":
        content = _sigma_draft(
            title=f"Suspicious process: {name}",
            description=description,
            logsource={"category": "process_creation", "product": "windows"},
            detection_field="CommandLine",
            detection_values=[command_line],
            technique_ids=[],
        )
    else:
        content = _yara_draft(
            rule_name=name,
            description=description,
            technique_ids=[],
            strings={"cmdline": command_line[:200]},
            condition="any of them",
        )
    return {"format": rule_format, "source": "process", "source_id": process_id, "content": content}


DRAFT_SOURCES = {
    "yara_match": draft_from_yara_match,
    "capa_capability": draft_from_capa_capability,
    "process": draft_from_process,
}


def generate_draft(db: Database, *, source_kind: str, source_id: str, rule_format: str) -> dict[str, Any]:
    if source_kind not in DRAFT_SOURCES:
        raise AppError(
            code="invalid_params",
            message=f"Unknown finding kind: {source_kind}",
            suggestion=f"Use one of: {', '.join(DRAFT_SOURCES)}",
        )
    if rule_format not in ("sigma", "yara"):
        raise AppError(code="invalid_params", message="rule_format must be 'sigma' or 'yara'.")
    return DRAFT_SOURCES[source_kind](db, source_id, rule_format=rule_format)
