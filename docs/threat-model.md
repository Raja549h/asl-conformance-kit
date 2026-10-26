# Threat Model

## Assumptions
- **Attacker Profile:** White-box. The attacker (the autonomous agent) has full source code access to ASL, can execute local arbitrary code inside the sandbox, and will actively search for evasion techniques.
- **Environment:** Windows and Linux host environments.

## In-Scope Threats Mitigated
- Path traversal escapes from the workspace.
- NTFS Alternate Data Stream (ADS) policy bypasses.
- Concurrent race conditions on approval logic and the kill-switch.
- Unauthorized egress network connections.
- Modification of the un-hashed audit log.

## Out-of-Scope (Not Mitigated)
- OS-level zero-day container escapes within Docker Desktop.
- Supply chain attacks against the ASL dependencies (though mitigated via pinning).
- Physical access to the host machine.
