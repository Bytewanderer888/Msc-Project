
# ER-M03 retrieval specification

## Scope

- Corpus: CAM-LDS raw step manifestation `1_cron_sshkey-34`
- Host: `videoserver` (model-visible alias `server-01.corp.local`)
- Sensor: Linux audit

## Selection

1. Apply `annotations/trigger_spec.json` to the complete declared audit member
   and select the matching `rm` invocation as `A0`.
2. Use the audit serial only after rule execution to verify replay and retain
   the immediately correlated `unlinkat` result as `EV-001`.
3. Confirm that the correlated result reports `success=no`, `exit=-2` (ENOENT),
   rather than a successful target deletion.

The tool-specific source filename is neutralised in model input. Attacker-console output is not included.
