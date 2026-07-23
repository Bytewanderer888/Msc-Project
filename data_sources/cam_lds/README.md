# CAM-LDS local source cache

This directory stages the CAM-LDS artefacts used by the separate
`external_replication_v1` experiment. CAM-LDS provides step-scoped raw host and
network logs together with attacker-side execution metadata.

The model-visible packages use only defender-side telemetry from the raw step
manifestations. `attacker/logs/attackmate.*` and `attacker/logs/output.log` are
used only to audit event boundaries and outcomes; they are never included in an
`alert_package.json`.

`manifestations_raw.zip` is a local staging cache rather than an original
SafeSOC artefact. Reproduction can download it from the DOI below and verify it
with `SOURCE_MANIFEST.json`. `labels.json` and `attack_times.csv` are retained as
portable source metadata.

- DOI: `10.5281/zenodo.18861762`
- Source: <https://zenodo.org/records/18861762>
- License: CC BY 4.0
- Retrieved: 2026-07-22

Only `manifestations_raw/steps/` is used for case construction. The `sequences/`
and `techniques/` views duplicate the same underlying events and must not be
counted as independent captures.
