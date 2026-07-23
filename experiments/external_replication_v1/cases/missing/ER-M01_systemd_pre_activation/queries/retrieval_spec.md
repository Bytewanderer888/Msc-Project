
# ER-M01 retrieval specification

## Scope

- Corpus: CAM-LDS raw step manifestations
- Alert-time window: scenario 4 steps 12-13, ending at the daemon reload
- Host: `inetfw` (model-visible alias `gateway-01.corp.local`)
- Sensors: Linux audit and auth logs

## Selection

1. Apply `annotations/trigger_spec.json` to the complete declared auth-log member
   and select `A0` with its deterministic strategy.
2. Use exact line locators only to assert that replay and to retain the
   immediately preceding audit path record as `EV-001`.
3. Search the complete defender logs in the scoped steps for `systemctl enable`,
   `systemctl start`, an active-unit result, and a payload process. None occurs
   inside this alert-time window.

Attacker-side logs and later scenario steps are excluded from model input. They are retained only for provenance and boundary auditing.
