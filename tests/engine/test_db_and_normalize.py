"""Database migration and evidence import tests (no memory dump required)."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from memhunter_engine.analysis.workflows import import_evidence, list_processes, overview
from memhunter_engine.paths import AppPaths
from memhunter_engine.storage import Database
from memhunter_engine.storage.schema import SCHEMA_VERSION
from memhunter_engine.volatility.normalize import (
    normalize_cmdline,
    normalize_dlllist,
    normalize_handles,
    normalize_netscan,
    normalize_pslist,
    normalize_windows_info,
)


def test_schema_migrates_to_v1(tmp_path: Path) -> None:
    db = Database(tmp_path / "t.db")
    assert db.schema_version() == SCHEMA_VERSION
    db.close()


def test_import_evidence_hashes(tmp_path: Path) -> None:
    img = tmp_path / "sample.raw"
    img.write_bytes(b"MEMHUNTER-TEST-BYTES-0123456789")
    db = Database(tmp_path / "t.db")
    ev = import_evidence(db, str(img))
    assert ev["filename"] == "sample.raw"
    assert ev["size_bytes"] == img.stat().st_size
    assert len(ev["sha256"]) == 64
    again = import_evidence(db, str(img))
    assert again["id"] == ev["id"]
    ov = overview(db, ev["id"])
    assert ov["process_count"] == 0
    assert ov["complete_analysis_completed"] is False
    procs = list_processes(db, ev["id"])
    assert procs["total"] == 0
    db.close()


def test_normalize_windows_info_fields() -> None:
    cols = ["Variable", "Value"]
    rows = [
        ["Is64Bit", "True"],
        ["NtMajorVersion", "10"],
        ["NtMinorVersion", "0"],
        ["NtProductType", "WinNT"],
        ["Symbols", "file:///symbols/ntkrnlmp.pdb/..."],
    ]
    meta = normalize_windows_info(cols, rows)
    assert meta["architecture"] == "x64"
    assert meta["symbol_status"] == "resolved"
    assert meta["detected_os"] is not None
    assert "10" in meta["detected_os"]


def test_normalize_pslist_rows() -> None:
    cols = [
        "PID",
        "PPID",
        "ImageFileName",
        "Offset(V)",
        "Threads",
        "Handles",
        "SessionId",
        "Wow64",
        "CreateTime",
        "ExitTime",
        "File output",
    ]
    rows = [
        [4, 0, "System", "0x1234", 100, 0, 0, False, None, None, "Disabled"],
        [100, 4, "smss.exe", "0xabcd", 2, 40, 0, False, "2020-01-01T00:00:00", None, "Disabled"],
    ]
    out = normalize_pslist(
        cols,
        rows,
        evidence_id="e1",
        analysis_run_id="a1",
        source_plugin="windows.pslist",
    )
    assert len(out) == 2
    assert out[0]["pid"] == 4
    assert out[1]["name"] == "smss.exe"
    assert out[1]["ppid"] == 4


def test_normalize_pslist_rows_linux() -> None:
    """linux.pslist's real column set (OFFSET (V)/COMM/CREATION TIME), see
    memhunter_engine/analysis/process_analysis.py::_run_linux_triage."""
    cols = ["OFFSET (V)", "PID", "TID", "PPID", "COMM", "UID", "GID", "EUID", "EGID", "CREATION TIME", "File output"]
    rows = [
        ["0x1234", 1, 1, 0, "systemd", 0, 0, 0, 0, "2020-01-01T00:00:00", "Disabled"],
        ["0xabcd", 100, 100, 1, "sshd", 0, 0, 0, 0, "2020-01-01T00:01:00", "Disabled"],
    ]
    out = normalize_pslist(cols, rows, evidence_id="e1", analysis_run_id="a1", source_plugin="linux.pslist")
    assert len(out) == 2
    assert out[0]["pid"] == 1
    assert out[1]["name"] == "sshd"
    assert out[1]["ppid"] == 1
    assert out[1]["offset_hex"] == "0xabcd"


def test_normalize_cmdline_linux() -> None:
    """linux.psaux's columns: PID, PPID, COMM, ARGS."""
    cols = ["PID", "PPID", "COMM", "ARGS"]
    rows = [[100, 1, "sshd", "/usr/sbin/sshd -D"]]
    out = normalize_cmdline(cols, rows, pid_filter=None)
    assert out == [{"pid": 100, "process": "sshd", "command_line": "/usr/sbin/sshd -D"}]


def test_normalize_dlllist_linux_library_list() -> None:
    """linux.library_list's columns: Name, Pid, LoadAddress, Path."""
    cols = ["Name", "Pid", "LoadAddress", "Path"]
    rows = [["libc.so.6", 100, "0x7f0000000000", "/lib/x86_64-linux-gnu/libc.so.6"]]
    out = normalize_dlllist(
        cols, rows, evidence_id="e1", analysis_run_id="a1", process_id=None, pid_filter=None, source_plugin="linux.library_list"
    )
    assert len(out) == 1
    assert out[0]["pid"] == 100
    assert out[0]["name"] == "libc.so.6"
    assert out[0]["base_address"] == "0x7f0000000000"


def test_normalize_netscan_linux_sockstat() -> None:
    """linux.sockstat's columns include Source/Destination Addr/Port."""
    cols = [
        "NetNS", "Process Name", "PID", "TID", "FD", "Sock Offset", "Family", "Type",
        "Proto", "Source Addr", "Source Port", "Destination Addr", "Destination Port", "State", "Filter",
    ]
    rows = [[1, "sshd", 100, 100, 3, "0x1234", "AF_INET", "STREAM", "TCP", "0.0.0.0", "22", "10.0.0.5", "51514", "LISTEN", ""]]
    out = normalize_netscan(
        cols, rows, evidence_id="e1", analysis_run_id="a1", process_id_by_pid={100: "proc-1"}, pid_filter=None, source_plugin="linux.sockstat"
    )
    assert len(out) == 1
    assert out[0]["local_address"] == "0.0.0.0"
    assert out[0]["local_port"] == 22
    assert out[0]["remote_address"] == "10.0.0.5"
    assert out[0]["remote_port"] == 51514
    assert out[0]["process_id"] == "proc-1"


def test_normalize_handles_linux_lsof() -> None:
    """linux.lsof's columns include FD and Path (no HandleValue/Name)."""
    cols = ["PID", "TID", "Process", "FD", "Path", "Device", "Inode", "Type", "Mode", "Changed", "Modified", "Accessed", "Size"]
    rows = [[100, 100, "sshd", 3, "/var/log/auth.log", "8:1", 123, "REG", "rw-r--r--", None, None, None, 4096]]
    out = normalize_handles(
        cols, rows, evidence_id="e1", analysis_run_id="a1", process_id=None, pid_filter=None, source_plugin="linux.lsof"
    )
    assert len(out) == 1
    assert out[0]["handle_value"] == "3"
    assert out[0]["name"] == "/var/log/auth.log"
    assert out[0]["handle_type"] == "REG"


def test_app_paths_env(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("MEMHUNTER_DATA_DIR", str(tmp_path / "data"))
    paths = AppPaths().ensure()
    assert paths.root == (tmp_path / "data").resolve()
    assert paths.db_path.exists() is False  # only dirs ensured
    assert paths.logs.is_dir()
