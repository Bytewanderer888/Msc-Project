
# ER-M02 retrieval specification

## Scope

- Corpus: CAM-LDS raw step manifestation `6_macro_cron-20`
- Host: `client` (model-visible alias `workstation-01.corp.local`)
- Sensors: Linux syslog and audit

## Selection

1. Apply `annotations/trigger_spec.json` to the complete declared syslog member
   and select the matching `BEGIN EDIT` record as `A0`.
2. Use exact line locators only to verify replay and retain the matching audit
   `EXECVE` record for `crontab -e` as `EV-001`.
3. Search the complete step-level syslog for `REPLACE` or `END EDIT`, and
   audit/syslog for a cron child executing a newly installed command. No such
   confirmation is present.

No attacker-console output is included in the package.
