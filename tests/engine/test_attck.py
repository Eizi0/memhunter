"""MITRE ATT&CK coverage aggregation and draft rule generation (no memory dump required)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from memhunter_engine.analysis.attck import coverage, technique_ids
from memhunter_engine.analysis.attck_rules import generate_draft
from memhunter_engine.errors import AppError
from memhunter_engine.storage import Database
from memhunter_engine.storage.schema import MIGRATIONS


def _db(tmp_path: Path) -> Database:
    db = Database(tmp_path / "t.db")
    return db


def test_technique_ids_from_string() -> None:
    assert technique_ids("Defense Evasion::Process Injection [T1055.001]") == ["T1055.001"]


def test_technique_ids_from_dict() -> None:
    assert technique_ids({"id": "T1003.001", "technique": "LSASS Memory"}) == ["T1003.001"]


def test_technique_ids_from_list() -> None:
    assert technique_ids(["T1071.001, T1055"]) == ["T1071.001", "T1055"]


def test_technique_ids_none_and_empty() -> None:
    assert technique_ids(None) == []
    assert technique_ids("") == []
    assert technique_ids({}) == []


def _seed_evidence(db: Database) -> str:
    db.execute(
        """
        INSERT INTO evidence (id, path, filename, size_bytes, sha256, import_timestamp)
        VALUES ('ev1', '/tmp/x.raw', 'x.raw', 10, 'deadbeef', '2024-01-01T00:00:00')
        """
    )
    return "ev1"


def _seed_artifact(db: Database, evidence_id: str, artifact_id: str = "art-1") -> str:
    db.execute(
        """
        INSERT INTO artifacts (
          id, evidence_id, filename, stored_path, sha256, size_bytes,
          extraction_method, extracted_at
        ) VALUES (?, ?, 'evil.exe', '/tmp/evil.exe', 'cafebabe', 10, 'pe_extraction', '2024-01-01T00:00:00')
        """,
        (artifact_id, evidence_id),
    )
    return artifact_id


def test_coverage_aggregates_capa_and_yara(tmp_path: Path) -> None:
    db = _db(tmp_path)
    evidence_id = _seed_evidence(db)
    _seed_artifact(db, evidence_id)

    db.execute(
        """
        INSERT INTO capa_scans (id, evidence_id, artifact_id, status, started_at)
        VALUES ('capa-scan-1', ?, 'art-1', 'completed', '2024-01-01T00:00:00')
        """,
        (evidence_id,),
    )
    db.execute(
        """
        INSERT INTO capa_capabilities (id, scan_id, name, namespace, attck_json, created_at)
        VALUES ('cap-1', 'capa-scan-1', 'inject into remote process', 'nursery', ?, '2024-01-01T00:00:00')
        """,
        (json.dumps(["Defense Evasion::Process Injection [T1055]"]),),
    )

    db.execute(
        """
        INSERT INTO yara_scans (id, evidence_id, artifact_id, status, started_at)
        VALUES ('yara-scan-1', ?, 'art-1', 'completed', '2024-01-01T00:00:00')
        """,
        (evidence_id,),
    )
    db.execute(
        """
        INSERT INTO yara_matches (id, scan_id, evidence_id, artifact_id, rule_name, meta_json, created_at)
        VALUES ('match-1', 'yara-scan-1', ?, 'art-1', 'memhunter_credtheft_mimikatz_memory', ?, '2024-01-01T00:00:00')
        """,
        (evidence_id, json.dumps({"mitre_attack": "T1003.001"})),
    )

    result = coverage(db, evidence_id)
    ids = {t["technique_id"] for t in result["techniques"]}
    assert ids == {"T1055", "T1003.001"}
    by_id = {t["technique_id"]: t for t in result["techniques"]}
    assert by_id["T1055"]["sources"][0]["kind"] == "capa"
    assert by_id["T1003.001"]["sources"][0]["kind"] == "yara"


def test_coverage_empty_when_no_findings(tmp_path: Path) -> None:
    db = _db(tmp_path)
    evidence_id = _seed_evidence(db)
    result = coverage(db, evidence_id)
    assert result == {"evidence_id": evidence_id, "technique_count": 0, "techniques": []}


def test_generate_draft_from_yara_match_sigma(tmp_path: Path) -> None:
    db = _db(tmp_path)
    evidence_id = _seed_evidence(db)
    _seed_artifact(db, evidence_id)
    db.execute(
        """
        INSERT INTO yara_scans (id, evidence_id, artifact_id, status, started_at)
        VALUES ('yara-scan-1', ?, 'art-1', 'completed', '2024-01-01T00:00:00')
        """,
        (evidence_id,),
    )
    db.execute(
        """
        INSERT INTO yara_matches (id, scan_id, evidence_id, artifact_id, rule_name, meta_json, created_at)
        VALUES ('match-1', 'yara-scan-1', ?, 'art-1', 'memhunter_credtheft_mimikatz_memory', ?, '2024-01-01T00:00:00')
        """,
        (evidence_id, json.dumps({"mitre_attack": "T1003.001", "description": "Mimikatz indicators"})),
    )
    draft = generate_draft(db, source_kind="yara_match", source_id="match-1", rule_format="sigma")
    assert draft["format"] == "sigma"
    assert "T1003.001".lower().replace(".", ".") in draft["content"].lower()
    assert "title:" in draft["content"]


def test_generate_draft_from_process_yara(tmp_path: Path) -> None:
    db = _db(tmp_path)
    evidence_id = _seed_evidence(db)
    db.execute(
        """
        INSERT INTO analysis_runs (id, evidence_id, kind, status, started_at, schema_version)
        VALUES ('run-1', ?, 'basic_triage', 'completed', '2024-01-01T00:00:00', 14)
        """,
        (evidence_id,),
    )
    db.execute(
        """
        INSERT INTO processes (id, evidence_id, analysis_run_id, pid, name, command_line, source_plugin)
        VALUES ('proc-1', ?, 'run-1', 1337, 'evil.exe', 'evil.exe -c whoami', 'windows.pslist')
        """,
        (evidence_id,),
    )
    draft = generate_draft(db, source_kind="process", source_id="proc-1", rule_format="yara")
    assert draft["format"] == "yara"
    assert "evil.exe" in draft["content"]
    assert "rule " in draft["content"]


def test_generate_draft_unknown_source_kind(tmp_path: Path) -> None:
    db = _db(tmp_path)
    with pytest.raises(AppError):
        generate_draft(db, source_kind="not_a_real_kind", source_id="x", rule_format="sigma")


def test_generate_draft_missing_finding(tmp_path: Path) -> None:
    db = _db(tmp_path)
    with pytest.raises(AppError):
        generate_draft(db, source_kind="yara_match", source_id="does-not-exist", rule_format="sigma")
