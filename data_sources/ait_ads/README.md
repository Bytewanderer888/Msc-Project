# AIT Alert Data Set staging

This directory stages the public AIT Alert Data Set (AIT-ADS) for candidate
selection in SafeSOC's external replication study.

- DOI: `10.5281/zenodo.8263181`
- Upstream version: 1
- License: CC BY 4.0
- Local retrieval date: 2026-07-22

AIT-ADS contains eight enterprise-style scenarios. Each scenario has Wazuh and
Suricata alerts in one JSONL file, AMiner alerts in another, and an independent
attack-phase timeline in `labels.csv`. The ZIP expands to roughly 2.86 GB, so
SafeSOC reads members as streams rather than extracting the archive. The ZIP is
a local staging cache and is not committed; `labels.csv`, this README, and
`SOURCE_MANIFEST.json` are retained.

## SafeSOC use constraints

Detector fields such as Wazuh `rule`, Suricata `alert.signature/category`, and
AMiner analysis-component names are not ground truth. They are stripped from
model-visible packages. The package may retain neutral raw observations such as
timestamps, endpoints, HTTP method/path/status, process/authentication facts,
and the underlying `full_log` after leakage redaction.

`labels.csv` is used only to establish capture provenance and independently
audit attack timing. Scenario and phase names are never shown to the model.
Multiple alerts from two detectors over the same raw log are not counted as
genuine multi-source fusion; the selected evidence must come from distinct
sensors or log sources observing the same event chain.
