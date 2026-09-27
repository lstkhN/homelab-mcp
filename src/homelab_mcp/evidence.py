"""Constrained read-only evidence collection; all command arguments are fixed."""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
from typing import Any

from .config import Settings
from .runner import CommandRunner

_HEX_ID = re.compile(r"^[0-9a-fA-F]{12,64}$")


def _result(value: Any) -> dict[str, Any]:
    return {"ok": value.ok, "returncode": value.returncode, "stdout": value.stdout,
            "stderr": value.stderr, "error": value.error}


def collect_disk_evidence(path: str, settings: Settings, runner: CommandRunner) -> dict[str, Any]:
    if not settings.disk_allowed(path):
        return {"ok": False, "limitations": ["disk path is not allowlisted"]}
    # Execute the canonical configured path, never a spelling supplied by a caller.
    canonical_path = str(Path(path).resolve(strict=False))
    df = _result(runner.run(["df", "-P", "--", canonical_path]))
    # du's output is separately bounded to keep directory evidence smaller.
    du_runner = CommandRunner(runner.timeout_seconds, min(runner.max_output_bytes, settings.du_max_output_bytes))
    du = _result(du_runner.run(["du", "-x", "-B1", "--max-depth=2", "--", canonical_path]))
    return {"ok": df["ok"] and du["ok"], "df": df, "du": du, "limitations": []}


def collect_service_evidence(service: str, settings: Settings, runner: CommandRunner) -> dict[str, Any]:
    if not settings.service_allowed(service):
        return {"ok": False, "limitations": ["service is not allowlisted"]}
    show = _result(runner.run(["systemctl", "show", service, "--no-page", "--property=Id,LoadState,ActiveState,SubState,MainPID,UnitFileState"]))
    journal = _result(runner.run(["journalctl", "--no-pager", "--output=short-iso", "--lines=100", "--unit", service]))
    return {"ok": show["ok"] and journal["ok"], "systemctl": show, "journal": journal, "limitations": []}


def collect_container_evidence(settings: Settings, runner: CommandRunner) -> dict[str, Any]:
    ps = _result(runner.run(["docker", "ps", "-a", "--no-trunc", "--format", "{{json .}}"] ))
    records = []
    for line in ps["stdout"].splitlines():
        try:
            parsed = json.loads(line)
            if isinstance(parsed, dict): records.append(parsed)
        except json.JSONDecodeError:
            continue
    ids = [str(x.get("ID", "")) for x in records if _HEX_ID.fullmatch(str(x.get("ID", "")))][:100]
    inspect = _result(runner.run(["docker", "inspect", "--format", "{{.Id}}\\t{{.RestartCount}}\\t{{.State.StartedAt}}", *ids])) if ids else None
    if inspect and inspect["ok"]:
        states = {}
        for line in inspect["stdout"].splitlines():
            parts = line.split("\t", 2)
            if len(parts) == 3 and _HEX_ID.fullmatch(parts[0]):
                states[parts[0]] = {"restart_count": parts[1], "started_at": parts[2]}
        for record in records:
            record.update(states.get(str(record.get("ID", "")), {}))
    return {"ok": ps["ok"] and (inspect is None or inspect["ok"]), "ps": ps, "records": records[:100], "inspect": inspect, "limitations": []}


def collect_backup_evidence(settings: Settings) -> dict[str, Any]:
    records = []
    now = datetime.now(timezone.utc)
    for path in settings.backup_markers:
        try:
            stat = path.stat()
            records.append({"path": str(path), "exists": True, "age_hours": round((now.timestamp() - stat.st_mtime) / 3600, 2)})
        except FileNotFoundError:
            records.append({"path": str(path), "exists": False})
        except OSError:
            records.append({"path": str(path), "exists": True, "unreadable": True})
    return {"ok": True, "markers": records, "limitations": []}


def collect_config_evidence(settings: Settings) -> dict[str, Any]:
    manifest: dict[str, str] = {}
    limitations = []
    if settings.config_manifest:
        try:
            value = json.loads(settings.config_manifest.read_text(encoding="utf-8"))
            if isinstance(value, dict): manifest = {str(k): str(v) for k, v in value.items()}
        except (OSError, ValueError, json.JSONDecodeError): limitations.append("trusted manifest unavailable or invalid")
    records = []
    for path in settings.config_files:
        record = {"path": str(path), "expected_sha256": manifest.get(str(path))}
        try:
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            record.update(status="ok", sha256=digest)
        except FileNotFoundError: record["status"] = "missing"
        except OSError: record["status"] = "unreadable"
        records.append(record)
    return {"ok": True, "files": records, "limitations": limitations}


def collect_deployment_evidence(settings: Settings) -> dict[str, Any]:
    """Read only the deployment-configured manifest, limited to 64 KiB."""
    if settings.deployment_manifest is None:
        return {"ok": False, "manifest": None, "limitations": ["deployment manifest is not configured"]}
    try:
        with settings.deployment_manifest.open("rb") as handle:
            payload = handle.read(65537)
        if len(payload) > 65536:
            return {"ok": False, "manifest": None, "limitations": ["deployment manifest exceeds 64 KiB limit"]}
        value = json.loads(payload.decode("utf-8"))
        if not isinstance(value, dict):
            raise ValueError("manifest must be a JSON object")
    except (OSError, UnicodeDecodeError, ValueError, json.JSONDecodeError):
        return {"ok": False, "manifest": None, "limitations": ["deployment manifest is unavailable or invalid"]}
    return {"ok": True, "manifest": value, "limitations": []}


def collect_package_evidence(settings: Settings, runner: CommandRunner) -> dict[str, Any]:
    packages = sorted(settings.watch_packages)
    if not packages: return {"ok": True, "inventory": [], "limitations": ["no watch packages configured"]}
    dpkg = _result(runner.run(["dpkg-query", "-W", "-f=${Package} ${Version}\\n", *packages]))
    result = dpkg
    if not dpkg["ok"] and dpkg["error"] and "unavailable" in dpkg["error"]:
        result = _result(runner.run(["rpm", "-q", "--qf", "%{NAME} %{VERSION}-%{RELEASE}\\n", *packages]))
    inventory = []
    for line in result["stdout"].splitlines():
        bits = line.split(maxsplit=1)
        if len(bits) == 2: inventory.append({"name": bits[0], "version": bits[1]})
    return {"ok": result["ok"], "inventory": inventory, "command": result, "limitations": []}
