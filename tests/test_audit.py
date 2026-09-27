import json
from pathlib import Path
from unittest.mock import patch

from homelab_mcp.audit import AuditLogger


def test_audit_writes_safe_jsonl_event(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    audit = AuditLogger(path)

    audit.record("uptime", True, 0)

    event = json.loads(path.read_text(encoding="utf-8"))
    assert event["tool"] == "uptime"
    assert event["ok"] is True
    assert event["returncode"] == 0
    assert "timestamp" in event
    assert set(event) == {"timestamp", "tool", "ok", "returncode"}


def test_audit_is_disabled_without_configured_path() -> None:
    audit = AuditLogger(None)
    audit.record("health", True)
    assert not audit.enabled


def test_audit_write_failure_is_graceful(tmp_path: Path) -> None:
    audit = AuditLogger(tmp_path / "audit.jsonl")
    with patch.object(Path, "open", side_effect=OSError("read-only filesystem")):
        audit.record("health", True)


def test_audit_malformed_path_is_graceful() -> None:
    # Direct construction is defensive too; a malformed path must not affect tools.
    audit = AuditLogger(Path("."))
    with patch.object(Path, "open", side_effect=ValueError("embedded null byte")):
        audit.record("health", False)
