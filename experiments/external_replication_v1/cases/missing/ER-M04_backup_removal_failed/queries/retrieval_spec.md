
# ER-M04 retrieval specification

## Scope

- Corpus: CAM-LDS raw step manifestation `3_ssh_healthcheck-31`
- Host: `linuxshare` (model-visible alias `file-server-01.corp.local`)
- Sensor: Linux audit

## Selection

1. Apply `annotations/trigger_spec.json` to the complete declared audit member
   and select the matching recursive backup-removal invocation as `A0`.
2. Use the audit serial only after rule execution to verify replay and retain
   the immediately correlated `unlinkat` result as `EV-001`.
3. Confirm that the wildcard was passed literally and the target operation
   reports `success=no`, `exit=-2` (ENOENT). No successful backup deletion
   occurs in the complete step-level audit log.

Attacker-console output is excluded from model input.
