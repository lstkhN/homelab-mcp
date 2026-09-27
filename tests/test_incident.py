from datetime import datetime, timedelta, timezone
from unittest.mock import Mock, patch

from homelab_mcp.config import Settings
from homelab_mcp.evidence import (collect_container_evidence, collect_deployment_evidence,
                                   collect_service_evidence)
from homelab_mcp.incident import (backup_analysis, config_analysis, deployment_analysis,
                                  disk_analysis, restart_analysis, service_analysis,
                                  vulnerability_analysis)
from homelab_mcp.runner import CommandResult


def test_disk_threshold_and_sorting() -> None:
    value = disk_analysis("Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/a 1 1 0 90% /\n", "10 /data\n30 /var/log\n", 85)
    assert value["filesystems"][0]["above_threshold"]
    assert value["largest_directories"][0]["path"] == "/var/log"


def test_disk_hypothesis_needs_path_evidence() -> None:
    assert disk_analysis("header\n", "30 /random\n")["hypotheses"] == []


def test_restart_count_is_detected() -> None:
    assert restart_analysis([{"ID": "a", "RestartCount": 2}])["containers"][0]["restart_count"] == 2


def test_recent_start_is_detected() -> None:
    now = datetime(2024, 1, 2, tzinfo=timezone.utc)
    result = restart_analysis([{"ID": "a", "StartedAt": "2024-01-01T23:00:00Z"}], now)
    assert result["containers"][0]["recent_start"]


def test_old_start_is_not_reported() -> None:
    now = datetime(2024, 1, 3, tzinfo=timezone.utc)
    assert restart_analysis([{"ID": "a", "StartedAt": "2024-01-01T00:00:00Z"}], now)["containers"] == []


def test_stale_and_missing_backup() -> None:
    result = backup_analysis([{"path": "a", "exists": False}, {"path": "b", "exists": True, "age_hours": 30}], 24)
    assert {x["status"] for x in result["findings"]} == {"missing", "stale"}


def test_config_hash_mismatch() -> None:
    assert config_analysis([{"path": "x", "status": "ok", "sha256": "bad", "expected_sha256": "good"}])["findings"][0]["status"] == "hash_mismatch"


def test_config_unreadable() -> None:
    assert config_analysis([{"path": "x", "status": "unreadable"}])["findings"]


def test_no_advisory_db_is_unknown() -> None:
    assert vulnerability_analysis([{"name": "openssl", "version": "1"}], None)["status"] == "unknown"


def test_local_advisory_match() -> None:
    result = vulnerability_analysis([{"name": "openssl", "version": "1"}], {"openssl": [{"affected_versions": ["1"]}]})
    assert result["findings"]


def test_service_failed_analysis_uses_systemd_and_journal_evidence() -> None:
    result = service_analysis("LoadState=loaded\nActiveState=failed\nSubState=exit-code\nUnitFileState=enabled\n", "2024-01-01 failure")
    assert result["states"]["ActiveState"] == "failed"
    assert result["hypotheses"][0]["evidence"]["journal_entries_collected"] == 1
    assert result["confidence"] == "high"


def test_deployment_diff() -> None:
    result = deployment_analysis({"last_deploy": "2024-01-01T00:00:00Z", "before": {"image": "v1", "keep": 1}, "after": {"image": "v2", "keep": 1, "replicas": 2}})
    assert result["changed_keys"] == ["image", "replicas"]
    assert result["before"] == {"image": "v1", "replicas": None}
    assert result["after"] == {"image": "v2", "replicas": 2}


def test_deployment_manifest_missing_or_malformed_is_graceful(tmp_path) -> None:
    missing = Settings(frozenset(), frozenset(), frozenset(), 1, 100, 10, None,
                       deployment_manifest=tmp_path / "missing.json")
    assert not collect_deployment_evidence(missing)["ok"]
    malformed_path = tmp_path / "deployment.json"
    malformed_path.write_text("{bad", encoding="utf-8")
    malformed = Settings(frozenset(), frozenset(), frozenset(), 1, 100, 10, None,
                         deployment_manifest=malformed_path)
    assert not collect_deployment_evidence(malformed)["ok"]


def test_server_deployment_route(tmp_path) -> None:
    from homelab_mcp import server
    manifest = tmp_path / "deployment.json"
    manifest.write_text('{"last_deploy":"now","before":{"image":"v1"},"after":{"image":"v2"}}', encoding="utf-8")
    configured = Settings(frozenset(), frozenset(), frozenset(), 1, 100, 10, None,
                          deployment_manifest=manifest)
    with patch.object(server, "settings", configured):
        response = server.incident_report("deployment")
    assert response["evidence"]["manifest"]["after"]["image"] == "v2"
    assert response["commands_requiring_confirmation"] == []


def test_service_allowlist_prevents_runner(tmp_path) -> None:
    config = Settings(frozenset({"safe.service"}), frozenset(), frozenset(), 1, 100, 10, None)
    runner = Mock()
    result = collect_service_evidence("bad.service", config, runner)
    assert not result["ok"] and not runner.run.called


def test_container_inspect_uses_only_hex_ids() -> None:
    runner = Mock()
    runner.run.side_effect = [CommandResult(True, '{"ID":"a;bad"}\n{"ID":"abcdef123456"}\n', "", 0), CommandResult(True, "{}", "", 0)]
    config = Settings(frozenset(), frozenset(), frozenset(), 1, 100, 10, None)
    collect_container_evidence(config, runner)
    assert runner.run.call_args_list[1].args[0][-1] == "abcdef123456"


def test_container_inspect_tab_output_enriches_restart_count() -> None:
    container_id = "abcdef123456"
    runner = Mock()
    runner.run.side_effect = [
        CommandResult(True, f'{{"ID":"{container_id}"}}\n', "", 0),
        CommandResult(True, f"{container_id}\t3\t2024-01-01T00:00:00Z\n", "", 0),
    ]
    config = Settings(frozenset(), frozenset(), frozenset(), 1, 100, 10, None)

    result = collect_container_evidence(config, runner)

    assert result["records"][0]["restart_count"] == "3"


def test_proposal_never_calls_runner() -> None:
    from homelab_mcp import server
    with patch.object(server.runner, "run") as run:
        response = server.propose_remediation("service", "{}")
    assert response["ok"] and not run.called
