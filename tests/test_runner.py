from unittest.mock import patch
import subprocess

from homelab_mcp.runner import CommandRunner


def test_runner_uses_argument_list_timeout_and_no_shell() -> None:
    completed = subprocess.CompletedProcess(["uptime"], 0, "up", "")
    with patch("homelab_mcp.runner.subprocess.run", return_value=completed) as run:
        result = CommandRunner(3, 100).run(["uptime"])

    assert result.ok
    assert result.stdout == "up"
    assert run.call_args.args[0] == ["uptime"]
    assert run.call_args.kwargs["shell"] is False
    assert run.call_args.kwargs["timeout"] == 3
    assert run.call_args.kwargs["capture_output"] is True


def test_runner_handles_missing_binary_gracefully() -> None:
    with patch("homelab_mcp.runner.subprocess.run", side_effect=FileNotFoundError):
        result = CommandRunner(3, 100).run(["docker"])

    assert not result.ok
    assert result.error == "command unavailable: docker"


def test_runner_truncates_output() -> None:
    completed = subprocess.CompletedProcess(["uptime"], 0, "abcdefgh", "")
    with patch("homelab_mcp.runner.subprocess.run", return_value=completed):
        result = CommandRunner(3, 4).run(["uptime"])

    assert result.stdout == "abcd\n[output truncated]"
