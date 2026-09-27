"""MCP entry point exposing a deliberately small, read-only command surface."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from . import evidence, incident

from mcp.server.fastmcp import FastMCP

from .audit import AuditLogger
from .config import Settings
from .runner import CommandResult, CommandRunner

settings = Settings.from_environment()
runner = CommandRunner(settings.timeout_seconds, settings.max_output_bytes)
audit = AuditLogger(settings.audit_log)
mcp = FastMCP("homelab-readonly")


def _result(result: CommandResult) -> dict[str, Any]:
    return {
        "ok": result.ok,
        "returncode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "error": result.error,
    }


def _audited(tool: str, response: dict[str, Any]) -> dict[str, Any]:
    """Audit fixed tool names and safe result metadata, never caller input/output."""
    returncode = response.get("returncode")
    audit.record(tool, bool(response.get("ok")), returncode if isinstance(returncode, int) else None)
    return response


@mcp.tool()
def health() -> dict[str, Any]:
    """Return server health and the configured read-only capability count."""
    return _audited("health", {
        "ok": True,
        "mode": "read-only",
        "allowed_services": len(settings.allowed_services),
        "allowed_logs": len(settings.allowed_logs),
        "allowed_disks": len(settings.allowed_disks),
        "audit_enabled": audit.enabled,
    })


@mcp.tool()
def uptime() -> dict[str, Any]:
    """Return host uptime using the standard uptime command."""
    return _audited("uptime", _result(runner.run(["uptime"])))


@mcp.tool()
def disk_usage(path: str = "/") -> dict[str, Any]:
    """Report disk usage for an exactly allowlisted mount path."""
    if not settings.disk_allowed(path):
        return _audited("disk_usage", {"ok": False, "error": "disk path is not allowlisted"})
    return _audited("disk_usage", _result(runner.run(["df", "-P", "--", path])))


@mcp.tool()
def memory() -> dict[str, Any]:
    """Return Linux memory usage."""
    return _audited("memory", _result(runner.run(["free", "-b"])))


@mcp.tool()
def service_status(service: str) -> dict[str, Any]:
    """Show selected systemd properties for an allowlisted service only."""
    if not settings.service_allowed(service):
        return _audited("service_status", {"ok": False, "error": "service is not allowlisted"})
    return _audited("service_status", _result(runner.run([
        "systemctl", "show", service, "--no-page",
        "--property=Id,LoadState,ActiveState,SubState,MainPID,UnitFileState",
    ])))


@mcp.tool()
def docker_containers() -> dict[str, Any]:
    """List Docker containers. Returns a normal error result when Docker is absent."""
    return _audited("docker_containers", _result(runner.run([
        "docker", "ps", "-a", "--no-trunc", "--format", "{{json .}}"
    ])))


@mcp.tool()
def tail_logs(path: str, lines: int = 100) -> dict[str, Any]:
    """Read final lines of one exactly allowlisted log file; traversal is rejected."""
    if not settings.log_allowed(path):
        return _audited("tail_logs", {"ok": False, "error": "log path is not allowlisted"})
    lines = max(1, min(lines, settings.max_log_lines))
    return _audited("tail_logs", _result(runner.run(["tail", "-n", str(lines), "--", path])))


def _new_evidence(kind: str, path: str, service: str | None) -> dict[str, Any]:
    if kind == "disk": return evidence.collect_disk_evidence(path, settings, runner)
    if kind == "containers": return evidence.collect_container_evidence(settings, runner)
    if kind == "service": return evidence.collect_service_evidence(service or "", settings, runner)
    if kind == "backups": return evidence.collect_backup_evidence(settings)
    if kind == "config": return evidence.collect_config_evidence(settings)
    if kind == "deployment": return evidence.collect_deployment_evidence(settings)
    if kind == "vulnerabilities": return evidence.collect_package_evidence(settings, runner)
    return {"ok": False, "limitations": ["unsupported incident kind"]}


def _analysis(kind: str, raw: dict[str, Any]) -> dict[str, Any]:
    if kind == "disk": return incident.disk_analysis(raw.get("df", {}).get("stdout", ""), raw.get("du", {}).get("stdout", ""), settings.disk_threshold_percent)
    if kind == "containers": return incident.restart_analysis(raw.get("records", []))
    if kind == "service": return incident.service_analysis(raw.get("systemctl", {}).get("stdout", ""), raw.get("journal", {}).get("stdout", ""))
    if kind == "backups": return incident.backup_analysis(raw.get("markers", []), settings.backup_max_age_hours)
    if kind == "config": return incident.config_analysis(raw.get("files", []))
    if kind == "deployment": return incident.deployment_analysis(raw.get("manifest"))
    if kind == "vulnerabilities":
        db = None
        if settings.advisory_db:
            try:
                loaded = json.loads(settings.advisory_db.read_text(encoding="utf-8"))
                db = loaded if isinstance(loaded, dict) else None
            except (OSError, ValueError): pass
        return incident.vulnerability_analysis(raw.get("inventory", []), db)
    return {"hypotheses": [], "confidence": "unknown"}


def _report(kind: str, raw: dict[str, Any]) -> dict[str, Any]:
    analysis = _analysis(kind, raw)
    plans = {
        "disk": "Validate affected mount and largest directories before planning retention or cleanup.",
        "containers": "Validate container ownership and restart history before planning any restart.",
        "service": "Validate systemd state and journal evidence with the service owner before planning a change.",
        "backups": "Validate backup target, schedule, and restore path before planning a backup action.",
        "config": "Validate expected configuration and rollback source before planning a restore.",
        "deployment": "Validate the trusted deployment diff, release owner, and rollback plan before any change.",
        "vulnerabilities": "Validate local advisory scope and package ownership before planning an update.",
    }
    return {"ok": bool(raw.get("ok")), "evidence": raw, "hypothesis": analysis.get("hypotheses", []),
            "confidence": analysis.get("confidence", "unknown"),
            "recommended_plan": [plans.get(kind, "Review collected evidence and validate scope before any change.")],
            "commands_requiring_confirmation": [],
            "limitations": raw.get("limitations", []) + analysis.get("limitations", [])}


@mcp.tool()
def evidence_snapshot(kind: str, path: str = "/", service: str | None = None) -> dict[str, Any]:
    """Return bounded raw evidence only for a fixed incident category."""
    raw = _new_evidence(kind, path, service)
    return _audited("evidence_snapshot", raw)


@mcp.tool()
def incident_report(kind: str, path: str = "/", service: str | None = None) -> dict[str, Any]:
    """Turn read-only evidence into hypotheses; this tool never remediates."""
    return _audited("incident_report", _report(kind, _new_evidence(kind, path, service)))


@mcp.tool()
def propose_remediation(kind: str, evidence_json: str) -> dict[str, Any]:
    """Propose text-only actions. No proposed command is ever executed here."""
    if kind not in {"disk", "containers", "service", "backups", "config", "deployment", "vulnerabilities"} or len(evidence_json.encode("utf-8")) > 32768:
        return _audited("propose_remediation", {"ok": False, "error": "invalid kind or oversized evidence"})
    try:
        supplied = json.loads(evidence_json)
    except (TypeError, json.JSONDecodeError):
        return _audited("propose_remediation", {"ok": False, "error": "evidence_json must be JSON"})
    commands = {"disk": ["<human-confirmed cleanup command>"], "containers": ["docker restart <validated-container-id>"],
                "service": ["systemctl restart <allowlisted-service>"], "backups": ["<human-confirmed backup job command>"],
                "config": ["<human-confirmed configuration restore command>"], "deployment": ["<human-confirmed deployment rollback command>"],
                "vulnerabilities": ["<human-confirmed package update command>"]}
    return _audited("propose_remediation", {"ok": True, "evidence": {"supplied": bool(supplied)},
        "hypothesis": [{"hypothesis": "human review is required before remediation"}], "confidence": "low",
        "recommended_plan": ["Validate evidence, change window, rollback, and backups with an operator."],
        "commands_requiring_confirmation": commands[kind], "limitations": ["commands are text only and are never passed to CommandRunner"]})


def main() -> None:
    """Run the server over stdio, suitable for MCP clients."""
    mcp.run()


if __name__ == "__main__":
    main()
