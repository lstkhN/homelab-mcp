# Security policy

## Threat model

`homelab-mcp` accepts MCP tool calls from the configured stdio client. Treat that
client, its prompts, and all tool arguments as potentially hostile. The server
limits that input to fixed read-only commands and exact, canonical allowlists for
services, disks, and logs. Subprocesses use argument vectors, `shell=False`,
timeouts, and bounded output.

An attacker with control of the process environment, filesystem mounts, or the
MCP client can still influence what the server can observe. A compromised host or
privileged container runtime is outside the protection offered here.

## Trust boundaries

- **Trusted:** deployment-time environment variables, package artifact, host
  administrator, and explicitly mounted files.
- **Untrusted:** MCP requests, including every path, service name, and line
  count; command output; log contents; and model-generated instructions.
- Audit-log and deployment-manifest locations are deployment configuration only
  and are never derived from a tool argument. The deployment manifest is a
  trusted, read-only JSON file limited to 64 KiB; its contents are diffed only
  and are never executed.

## Incident workflow guarantee

Incident tools follow evidence → hypothesis → plan → human confirmation. They
can collect only configured evidence and formulate recommendations. Even
`propose_remediation` emits command strings solely for a human to review: no
remediation command can be sent to the runner or executed by this server.
Service diagnosis parses only the collected systemd state fields and bounded
journal output; missing evidence remains a stated limitation. Deployment diffs
are limited to the administrator-provided deployment manifest; a missing,
oversized, or invalid manifest produces `unknown` and no deployment claim.
Offline advisory matches are limited to the administrator-provided local JSON
advisory database. Missing or invalid advisory data produces `unknown`, not a
vulnerability finding.

## Non-goals

This project does not provide authentication, authorization, multi-tenant
isolation, SSH execution, secret/credential management, shell access, or any
write operation. A read-only Docker socket is not considered safe enough to
mount: Docker API access can be privilege-equivalent.

## Hardening guidance

Run as a dedicated unprivileged user, expose it only through local stdio, and
use minimal explicit allowlists. Do not allowlist sensitive logs. Keep audit logs
in an administrator-owned directory with appropriate retention and permissions.
For containers, use the supplied optional Compose example's read-only root,
`no-new-privileges`, dropped capabilities, tmpfs, and read-only host mounts.
Review mounts carefully: mounting host paths expands visible data.

Audit JSONL records only UTC timestamp, fixed tool name, success state, and
optional return code. It never records arguments, paths, outputs, or errors, and
logging failures never affect MCP responses or write to stdout.

## Disclosure

Please report vulnerabilities privately to the repository maintainers/security
contact rather than opening a public issue. Include affected version, reproduction
steps, impact, and any suggested mitigation. We will acknowledge receipt, assess
the report, and coordinate a fix and disclosure timeline.
