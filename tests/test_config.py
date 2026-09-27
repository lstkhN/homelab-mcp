from pathlib import Path
from unittest.mock import patch

from homelab_mcp.config import Settings


def settings(tmp_path: Path) -> Settings:
    log = tmp_path / "logs" / "app.log"
    log.parent.mkdir()
    log.touch()
    return Settings(
        allowed_services=frozenset({"nginx.service"}),
        allowed_logs=frozenset({log.resolve()}),
        allowed_disks=frozenset({tmp_path.resolve()}),
        timeout_seconds=1,
        max_output_bytes=100,
        max_log_lines=10,
        audit_log=None,
    )


def test_service_allowlist(tmp_path: Path) -> None:
    config = settings(tmp_path)
    assert config.service_allowed("nginx.service")
    assert not config.service_allowed("nginx.service; reboot")
    assert not config.service_allowed("sshd.service")


def test_environment_parsing_uses_valid_values_and_safe_defaults(monkeypatch, tmp_path: Path) -> None:
    audit_log = tmp_path / "audit.jsonl"
    monkeypatch.setenv("HOMELAB_ALLOWED_SERVICES", " nginx.service , ssh.service ")
    monkeypatch.setenv("HOMELAB_ALLOWED_LOGS", str(tmp_path / "app.log"))
    monkeypatch.setenv("HOMELAB_ALLOWED_DISKS", str(tmp_path))
    monkeypatch.setenv("HOMELAB_COMMAND_TIMEOUT_SECONDS", "7")
    monkeypatch.setenv("HOMELAB_MAX_OUTPUT_BYTES", "invalid")
    monkeypatch.setenv("HOMELAB_MAX_LOG_LINES", "0")
    monkeypatch.setenv("HOMELAB_AUDIT_LOG", str(audit_log))
    monkeypatch.setenv("HOMELAB_DEPLOYMENT_MANIFEST", str(tmp_path / "deployment.json"))

    config = Settings.from_environment()

    assert config.allowed_services == frozenset({"nginx.service", "ssh.service"})
    assert config.timeout_seconds == 7
    assert config.max_output_bytes == 16384
    assert config.max_log_lines == 200
    assert config.audit_log == audit_log.resolve()
    assert config.deployment_manifest == (tmp_path / "deployment.json").resolve()


def test_environment_disables_empty_or_malformed_audit_path(monkeypatch) -> None:
    monkeypatch.setenv("HOMELAB_AUDIT_LOG", "audit.jsonl")
    monkeypatch.setenv("HOMELAB_ALLOWED_LOGS", "")
    monkeypatch.setenv("HOMELAB_ALLOWED_DISKS", "")
    with patch("homelab_mcp.config.Path.resolve", side_effect=ValueError("bad path")):
        assert Settings.from_environment().audit_log is None
    monkeypatch.setenv("HOMELAB_AUDIT_LOG", "   ")
    assert Settings.from_environment().audit_log is None


def test_log_allowlist_rejects_traversal_and_nearby_file(tmp_path: Path) -> None:
    config = settings(tmp_path)
    allowed = next(iter(config.allowed_logs))
    assert config.log_allowed(str(allowed))
    assert not config.log_allowed(str(allowed.parent / ".." / allowed.parent.name / "other.log"))
    assert not config.log_allowed(str(tmp_path / "logs" / "app.log.bak"))
