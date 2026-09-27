# homelab-mcp

Portfolio-grade Python [MCP](https://modelcontextprotocol.io/) server for small,
**read-only** Linux homelab diagnostics. It is designed for stdio MCP clients:
it never runs a shell, SSH, state-changing command, or credential flow.

## Tools

- `health` — mode, configured allowlist counts, and audit status;
- `uptime`, `memory`;
- `disk_usage` — exact canonical allowlisted paths only;
- `service_status` — allowlisted systemd units only;
- `docker_containers` — `docker ps -a` (a missing Docker binary is a normal tool error);
- `tail_logs` — exact canonical allowlisted log paths only;
- `incident_report`, `evidence_snapshot`, `propose_remediation` — read-only incident evidence, snapshots, and confirmation-required remediation proposals.

Subprocesses use argument lists (`shell=False`), timeouts, and bounded output.
Log paths are canonicalized before exact allowlist comparison, rejecting traversal,
neighbouring files, and unallowlisted symlink targets.

## Demo / local installation

```bash
cd homelab-mcp
python -m venv .venv
. .venv/bin/activate
pip install -e '.[dev]'
export HOMELAB_ALLOWED_SERVICES='ssh.service,nginx.service'
export HOMELAB_ALLOWED_LOGS='/var/log/syslog'
export HOMELAB_ALLOWED_DISKS='/,/home'
export HOMELAB_AUDIT_LOG="$PWD/audit/homelab-mcp.jsonl" # optional; create directory first
mkdir -p audit
homelab-mcp
```

The MCP SDK does not load `.env` automatically. Pass variables to the server
process through its supervisor or MCP client. `.env.example` lists all settings.

Example stdio client configuration:

```json
{
  "command": "/path/to/.venv/bin/homelab-mcp",
  "env": {
    "HOMELAB_ALLOWED_SERVICES": "ssh.service,nginx.service",
    "HOMELAB_ALLOWED_LOGS": "/var/log/syslog",
    "HOMELAB_ALLOWED_DISKS": "/",
    "HOMELAB_COMMAND_TIMEOUT_SECONDS": "5",
    "HOMELAB_MAX_OUTPUT_BYTES": "16384",
    "HOMELAB_AUDIT_LOG": "/var/lib/homelab-mcp/audit.jsonl"
  }
}
```

## Incident assistant flow

`incident_report` and `evidence_snapshot` collect bounded, read-only evidence for
`disk`, `containers`, `service`, `backups`, `config`, `deployment`, and `vulnerabilities`.
Service reports parse collected `ActiveState`, `SubState`, `LoadState`, and
`UnitFileState`; failed, inactive, and missing units are hypotheses backed by
those fields and bounded journal evidence. Deployment reports read only the
trusted `HOMELAB_DEPLOYMENT_MANIFEST` JSON file (maximum 64 KiB), with the form
`{"last_deploy":"...","before":{...},"after":{...}}`, and show only its diff.
Reports always separate `evidence`, `hypothesis`, `confidence`,
`recommended_plan`, `commands_requiring_confirmation`, and `limitations`.
The workflow is **evidence → hypothesis → plan → human confirmation**.
`propose_remediation` returns commands only as text; it never executes them and
never passes them to `CommandRunner`.

Examples: disk capacity and largest directories (`incident_report("disk")`),
container restart evidence (`incident_report("containers")`), an allowlisted
service's systemd/journal evidence (`incident_report("service", service="ssh.service")`),
configured backup marker ages (`incident_report("backups")`), configured config
file hashes (`incident_report("config")`), trusted deployment manifest changes
(`incident_report("deployment")`), and configured package versions against `HOMELAB_ADVISORY_DB` (`incident_report("vulnerabilities")`). The advisory
database is local/offline JSON only: if it is absent or invalid the result is
`unknown`, never a vulnerability assertion. Backup markers, config files,
manifests, watched packages, and advisory DB are deployment-time environment
settings, never tool arguments. Deployment manifest data is never executed.

## Security and audit

Run under a dedicated unprivileged account with minimal allowlists. The optional
`HOMELAB_AUDIT_LOG` enables append-only JSONL audit events; an empty or malformed
value disables it. Events contain only timestamp, tool, success state, and an
optional return code—never arguments, paths, command output, or errors. Audit
write failures are ignored and never print to stdout, preserving MCP stdio.

See [SECURITY.md](SECURITY.md) for the threat model, boundaries, hardening, and
private disclosure guidance.

## Docker (optional)

Compose is a deployment example, not a requirement for local stdio use. Review
its host mount paths, create `./audit` writable by container UID `10001` when
persisting audit logs, then build/run it:

```bash
docker build -t homelab-mcp .
docker compose run --rm homelab-mcp
```

`docker-compose.yml` uses a read-only root filesystem, `no-new-privileges`,
dropped capabilities, tmpfs, explicit read-only diagnostics mounts, and explicit
environment allowlists. It intentionally does **not** mount the Docker socket.

## CI and development

CI tests Python 3.10–3.13 and installs development dependencies from
`pyproject.toml` using `pip install -e '.[dev]'`.

```bash
pip install -e '.[dev]'
pytest -q
python -m compileall -q src
```

## License

MIT; see [LICENSE](LICENSE).
