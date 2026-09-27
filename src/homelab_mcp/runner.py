"""Bounded subprocess execution; commands are always argument lists."""
from __future__ import annotations

import subprocess
from dataclasses import dataclass
from typing import Sequence


@dataclass(frozen=True)
class CommandResult:
    ok: bool
    stdout: str
    stderr: str
    returncode: int | None
    error: str | None = None


class CommandRunner:
    def __init__(self, timeout_seconds: int, max_output_bytes: int) -> None:
        self.timeout_seconds = timeout_seconds
        self.max_output_bytes = max_output_bytes

    def run(self, args: Sequence[str]) -> CommandResult:
        try:
            completed = subprocess.run(
                list(args),
                shell=False,
                check=False,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
            )
        except FileNotFoundError:
            return CommandResult(False, "", "", None, f"command unavailable: {args[0]}")
        except subprocess.TimeoutExpired:
            return CommandResult(False, "", "", None, "command timed out")
        except OSError as exc:
            return CommandResult(False, "", "", None, f"command failed: {exc}")

        return CommandResult(
            ok=completed.returncode == 0,
            stdout=self._truncate(completed.stdout),
            stderr=self._truncate(completed.stderr),
            returncode=completed.returncode,
            error=None,
        )

    def _truncate(self, value: str) -> str:
        encoded = value.encode("utf-8", errors="replace")
        if len(encoded) <= self.max_output_bytes:
            return value
        return encoded[: self.max_output_bytes].decode("utf-8", errors="ignore") + "\n[output truncated]"
