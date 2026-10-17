"""MITRE ATT&CK technique aggregation.

CAPA already extracts ATT&CK technique mappings per capability (stored in
`capa_capabilities.attck_json`), but nothing downstream ever read that
column — it reached storage and stopped there. YARA's bundled rules did not
carry any ATT&CK tag at all until this module's rules update.

This module does not introduce new scanning. It reads what CAPA and YARA
already produced for a given evidence item and groups it by technique ID,
so a report or the CLI can show "this memory image demonstrates T1055,
T1003, ..." instead of a flat list of unrelated capability/rule names.

Technique IDs are extracted defensively with a regex rather than assuming
one fixed shape, because CAPA's `att&ck` meta field has held both plain
strings (e.g. "Defense Evasion::Process Injection [T1055]") and small dicts
across versions, and a bundled YARA rule's `mitre_attack` meta field is a
hand-written comma-separated string.
"""

from __future__ import annotations

import re
from typing import Any

from memhunter_engine.storage import Database

_TECHNIQUE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


def technique_ids(value: Any) -> list[str]:
    """Pull every ATT&CK technique ID out of a CAPA attck_json entry or a
    YARA rule's mitre_attack meta string, in whatever shape it arrives."""
    found: list[str] = []
    if value is None:
        return found
    if isinstance(value, str):
        found.extend(_TECHNIQUE_RE.findall(value))
    elif isinstance(value, dict):
        for key in ("id", "technique_id", "attack_id"):
            if isinstance(value.get(key), str):
                found.extend(_TECHNIQUE_RE.findall(value[key]))
        for key in ("technique", "name", "label"):
            if isinstance(value.get(key), str):
                found.extend(_TECHNIQUE_RE.findall(value[key]))
    elif isinstance(value, (list, tuple)):
        for item in value:
            found.extend(technique_ids(item))
    return found


def coverage(db: Database, evidence_id: str) -> dict[str, Any]:
    """Aggregate ATT&CK technique coverage for one evidence item.

    Returns ``{"evidence_id", "technique_count", "techniques": [...]}`` where
    each technique entry lists the CAPA capabilities and/or YARA matches that
    produced it, so an analyst (or the rule-generation helper in
    `attck_rules.py`) can trace a technique ID back to the finding that
    justified it.
    """
    by_technique: dict[str, dict[str, Any]] = {}

    capa_rows = db.fetchall(
        """
        SELECT c.id, c.name, c.namespace, c.attck_json, c.artifact_id, c.scan_id
        FROM capa_capabilities c
        JOIN capa_scans s ON s.id = c.scan_id
        WHERE s.evidence_id = ?
        """,
        (evidence_id,),
    )
    import json as _json

    for row in capa_rows:
        try:
            attck_raw = _json.loads(row.get("attck_json") or "[]")
        except (TypeError, ValueError):
            attck_raw = []
        for technique_id in technique_ids(attck_raw):
            entry = by_technique.setdefault(
                technique_id, {"technique_id": technique_id, "sources": []}
            )
            entry["sources"].append(
                {
                    "kind": "capa",
                    "name": row.get("name"),
                    "namespace": row.get("namespace"),
                    "artifact_id": row.get("artifact_id"),
                    "capability_id": row.get("id"),
                }
            )

    yara_rows = db.fetchall(
        """
        SELECT m.id, m.rule_name, m.meta_json, m.artifact_id, m.scan_id
        FROM yara_matches m
        JOIN yara_scans s ON s.id = m.scan_id
        WHERE s.evidence_id = ?
        """,
        (evidence_id,),
    )
    for row in yara_rows:
        try:
            meta = _json.loads(row.get("meta_json") or "{}")
        except (TypeError, ValueError):
            meta = {}
        tag = meta.get("mitre_attack") or meta.get("att&ck") or meta.get("attack")
        for technique_id in technique_ids(tag):
            entry = by_technique.setdefault(
                technique_id, {"technique_id": technique_id, "sources": []}
            )
            entry["sources"].append(
                {
                    "kind": "yara",
                    "name": row.get("rule_name"),
                    "artifact_id": row.get("artifact_id"),
                    "match_id": row.get("id"),
                }
            )

    techniques = sorted(by_technique.values(), key=lambda t: t["technique_id"])
    return {
        "evidence_id": evidence_id,
        "technique_count": len(techniques),
        "techniques": techniques,
    }
