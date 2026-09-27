"""Configuration and allowlist validation."""
from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path


def _csv(name: str, default: str) -> frozenset[str]:
    return frozenset(item.strip() for item in os.getenv(name, default).split(",") if item.strip())


def _positive_int(name: str, default: int) -> int:
    try:
        value = int(os.getenv(name, str(default)))
    except ValueError:
        return default
    return value if value > 0 else default


def _optional_path(name: str) -> Path | None:
    """Return a configured path, treating absent or malformed values as disabled."""
    value = os.getenv(name, "").strip()
    if not value:
        return None
    try:
        return Path(value).resolve(strict=False)
    except (OSError, ValueError):
        return None


@dataclass(frozen=True)
class Settings:
    allowed_services: frozenset[str]
    allowed_logs: frozenset[Path]
    allowed_disks: frozenset[Path]
    timeout_seconds: int
    max_output_bytes: int
    max_log_lines: int
    audit_log: Path | None
    disk_threshold_percent: int = 85
    du_max_output_bytes: int = 16384
    backup_max_age_hours: int = 24
    backup_markers: frozenset[Path] = frozenset()
    config_files: frozenset[Path] = frozenset()
    config_manifest: Path | None = None
    deployment_manifest: Path | None = None
    watch_packages: frozenset[str] = frozenset()
    advisory_db: Path | None = None

    @classmethod
    def from_environment(cls) -> "Settings":
        # resolve() canonicalizes symlinks and removes '..' before comparisons.
        return cls(
            allowed_services=_csv("HOMELAB_ALLOWED_SERVICES", "ssh.service"),
            allowed_logs=frozenset(Path(p).resolve() for p in _csv("HOMELAB_ALLOWED_LOGS", "/var/log/syslog")),
            allowed_disks=frozenset(Path(p).resolve() for p in _csv("HOMELAB_ALLOWED_DISKS", "/")),
            timeout_seconds=_positive_int("HOMELAB_COMMAND_TIMEOUT_SECONDS", 5),
            max_output_bytes=_positive_int("HOMELAB_MAX_OUTPUT_BYTES", 16384),
            max_log_lines=_positive_int("HOMELAB_MAX_LOG_LINES", 200),
            audit_log=_optional_path("HOMELAB_AUDIT_LOG"),
            disk_threshold_percent=min(100, _positive_int("HOMELAB_DISK_THRESHOLD_PERCENT", 85)),
            du_max_output_bytes=_positive_int("HOMELAB_DU_MAX_OUTPUT_BYTES", 16384),
            backup_max_age_hours=_positive_int("HOMELAB_BACKUP_MAX_AGE_HOURS", 24),
            backup_markers=frozenset(Path(p).resolve() for p in _csv("HOMELAB_BACKUP_MARKERS", "")),
            config_files=frozenset(Path(p).resolve() for p in _csv("HOMELAB_CONFIG_FILES", "")),
            config_manifest=_optional_path("HOMELAB_CONFIG_MANIFEST"),
            deployment_manifest=_optional_path("HOMELAB_DEPLOYMENT_MANIFEST"),
            watch_packages=frozenset(p for p in _csv("HOMELAB_WATCH_PACKAGES", "") if _package_name_valid(p)),
            advisory_db=_optional_path("HOMELAB_ADVISORY_DB"),
        )

    def service_allowed(self, service: str) -> bool:
        return service in self.allowed_services

    def log_allowed(self, path: str) -> bool:
        """Only a configured exact canonical log path may be read."""
        try:
            candidate = Path(path).resolve(strict=False)
        except (OSError, ValueError):
            return False
        return candidate in self.allowed_logs

    def disk_allowed(self, path: str) -> bool:
        try:
            return Path(path).resolve(strict=False) in self.allowed_disks
        except (OSError, ValueError):
            return False


def _package_name_valid(value: str) -> bool:
    return bool(re.fullmatch(r"[A-Za-z0-9_.:+-]+", value))
