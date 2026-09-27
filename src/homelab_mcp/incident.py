"""Pure evidence analysis functions.  They intentionally perform no I/O."""
from __future__ import annotations

from datetime import datetime, timezone
import re
from typing import Any


def disk_analysis(df_output: str, du_output: str, threshold: int = 85) -> dict[str, Any]:
    filesystems: list[dict[str, Any]] = []
    for line in df_output.splitlines()[1:]:
        fields = line.split()
        if len(fields) >= 6 and fields[4].rstrip("%").isdigit():
            used = int(fields[4].rstrip("%"))
            filesystems.append({"filesystem": fields[0], "mount": fields[-1], "used_percent": used,
                                "above_threshold": used >= threshold})
    directories: list[dict[str, Any]] = []
    for line in du_output.splitlines():
        match = re.match(r"^(\d+)\s+(.+)$", line.strip())
        if match:
            directories.append({"bytes": int(match.group(1)), "path": match.group(2)})
    directories.sort(key=lambda item: item["bytes"], reverse=True)
    hypotheses = []
    for item in directories[:10]:
        path = item["path"].lower()
        label = next((x for x in ("logs", "containers", "data") if x in path), None)
        if label:
            hypotheses.append({"hypothesis": f"{label} may contribute to disk use", "evidence": item})
    return {"filesystems": filesystems, "largest_directories": directories[:10],
            "hypotheses": hypotheses, "confidence": "high" if filesystems else "low"}


def restart_analysis(container_records: list[dict[str, Any]], now: datetime | None = None) -> dict[str, Any]:
    now = now or datetime.now(timezone.utc)
    affected = []
    for record in container_records:
        count = int(record.get("restart_count", record.get("RestartCount", 0)) or 0)
        started = record.get("started_at", record.get("StartedAt", ""))
        try:
            age = (now - datetime.fromisoformat(str(started).replace("Z", "+00:00"))).total_seconds()
            recent = 0 <= age <= 86400
        except ValueError:
            recent = False
        if count > 0 or recent:
            affected.append({"id": record.get("id", record.get("ID", "unknown")), "name": record.get("name", record.get("Names", "")),
                             "restart_count": count, "started_at": started, "recent_start": recent})
    return {"containers": affected, "hypotheses": ([{"hypothesis": "container restarts observed"}] if any(x["restart_count"] > 0 for x in affected) else []),
            "confidence": "medium" if affected else "low"}


def service_analysis(systemctl_output: str, journal_output: str) -> dict[str, Any]:
    """Interpret collected systemd properties without running commands."""
    properties: dict[str, str] = {}
    for line in systemctl_output.splitlines():
        key, separator, value = line.partition("=")
        if separator and key in {"ActiveState", "SubState", "LoadState", "UnitFileState"}:
            properties[key] = value.strip()

    missing = [key for key in ("ActiveState", "SubState", "LoadState", "UnitFileState") if key not in properties]
    hypotheses: list[dict[str, Any]] = []
    load_state = properties.get("LoadState")
    active_state = properties.get("ActiveState")
    if load_state == "not-found":
        hypotheses.append({"hypothesis": "systemd unit was not found", "evidence": {"LoadState": load_state}})
    elif active_state == "failed":
        evidence = {key: properties[key] for key in ("ActiveState", "SubState", "LoadState") if key in properties}
        if journal_output.strip():
            evidence["journal_entries_collected"] = len(journal_output.splitlines())
        hypotheses.append({"hypothesis": "service is in a failed state; review collected journal entries", "evidence": evidence})
    elif active_state == "inactive":
        hypotheses.append({"hypothesis": "service is inactive", "evidence": {key: properties[key] for key in ("ActiveState", "SubState", "UnitFileState") if key in properties}})

    limitations = []
    if not properties:
        limitations.append("systemctl state data is unavailable")
    elif missing:
        limitations.append("systemctl state data is incomplete: missing " + ", ".join(missing))
    if not journal_output.strip():
        limitations.append("no journal output was collected; failure cause cannot be inferred from logs")
    return {"states": properties, "hypotheses": hypotheses,
            "confidence": "high" if properties and not missing else ("medium" if properties else "low"),
            "limitations": limitations}


def deployment_analysis(manifest: Any) -> dict[str, Any]:
    """Diff a trusted deployment manifest; malformed data remains unknown."""
    if not isinstance(manifest, dict) or not isinstance(manifest.get("last_deploy"), str) or not manifest["last_deploy"].strip() or not isinstance(manifest.get("before"), dict) or not isinstance(manifest.get("after"), dict):
        return {"status": "unknown", "changed_keys": [], "before": {}, "after": {},
                "hypotheses": [], "confidence": "unknown",
                "limitations": ["deployment manifest is missing required last_deploy, before, or after data"]}
    before = manifest["before"]
    after = manifest["after"]
    changed_keys = sorted(key for key in set(before) | set(after) if before.get(key) != after.get(key))
    return {"status": "ok", "last_deploy": manifest["last_deploy"], "changed_keys": changed_keys,
            "before": {key: before.get(key) for key in changed_keys},
            "after": {key: after.get(key) for key in changed_keys},
            "hypotheses": ([{"hypothesis": "deployment changed configured manifest values", "evidence": {"changed_keys": changed_keys}}] if changed_keys else []),
            "confidence": "high", "limitations": []}


def backup_analysis(marker_records: list[dict[str, Any]], max_age_hours: int, now: datetime | None = None) -> dict[str, Any]:
    now = now or datetime.now(timezone.utc)
    findings = []
    for marker in marker_records:
        if not marker.get("exists"):
            findings.append({"path": marker.get("path"), "status": "missing"})
        elif marker.get("age_hours") is not None and float(marker["age_hours"]) > max_age_hours:
            findings.append({"path": marker.get("path"), "status": "stale", "age_hours": marker["age_hours"]})
    return {"findings": findings, "hypotheses": ([{"hypothesis": "backup freshness requires attention"}] if findings else []),
            "confidence": "high" if findings else "medium"}


def config_analysis(file_records: list[dict[str, Any]]) -> dict[str, Any]:
    findings = []
    for record in file_records:
        status = record.get("status")
        mismatch = bool(record.get("expected_sha256")) and record.get("sha256") != record.get("expected_sha256")
        if status in {"missing", "unreadable"} or mismatch:
            findings.append({"path": record.get("path"), "status": status if status in {"missing", "unreadable"} else "hash_mismatch"})
    return {"findings": findings, "hypotheses": ([{"hypothesis": "configuration integrity needs review"}] if findings else []),
            "confidence": "high" if findings else "medium"}


def vulnerability_analysis(inventory: list[dict[str, Any]], advisory_db: dict[str, Any] | None) -> dict[str, Any]:
    if advisory_db is None:
        return {"status": "unknown", "findings": [], "hypotheses": [], "confidence": "unknown",
                "limitations": ["local advisory database is unavailable; no vulnerability claim is made"]}
    findings = []
    for package in inventory:
        advisories = advisory_db.get(package.get("name", ""), [])
        for advisory in advisories:
            if package.get("version") == advisory.get("version") or package.get("version") in advisory.get("affected_versions", []):
                findings.append({"package": package.get("name"), "version": package.get("version"), "advisory": advisory})
    return {"status": "ok", "findings": findings, "hypotheses": ([{"hypothesis": "locally listed package advisory matches installed version"}] if findings else []), "confidence": "medium"}
