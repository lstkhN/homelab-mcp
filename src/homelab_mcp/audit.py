"""Best-effort, stdout-free JSONL audit logging for MCP tool invocations."""
from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
from threading import Lock


class AuditLogger:
    """Append a deliberately small, non-sensitive audit event schema.

    The path is supplied only by trusted process configuration. Failures are
    intentionally swallowed: observability must not change a tool's result.
    """

    def __init__(self, path: Path | None) -> None:
        self.path = path
        self._lock = Lock()

    @property
    def enabled(self) -> bool:
        return self.path is not None

    def record(self, tool: str, ok: bool, returncode: int | None = None) -> None:
        """Write an event without recording arguments, output, paths, or errors."""
        if self.path is None:
            return
        event: dict[str, object] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tool": tool,
            "ok": bool(ok),
        }
        # Return codes are bounded operational metadata, not command output.
        if returncode is not None:
            event["returncode"] = int(returncode)
        try:
            line = json.dumps(event, separators=(",", ":"), ensure_ascii=False) + "\n"
            with self._lock:
                with self.path.open("a", encoding="utf-8") as audit_file:
                    audit_file.write(line)
        except (OSError, ValueError, TypeError):
            # Do not emit to stdout/stderr or allow audit storage to break MCP.
            pass
