# Third-party data policy

SafeSOC retains only the smallest third-party source material needed for a
portable submission. Every retained or externally retrieved source is linked to
case-level provenance and a SHA-256 manifest.

## Splunk attack_data

The 33 raw logs used by the 31 attack_data-derived cases form a 652 MiB local
staging cache under `_splunk_ingest/`. These files are copies of public upstream
`attack_data` sources, not original SafeSOC benchmark assets. SafeSOC therefore
records their exact upstream locations and hashes instead of treating the cache
as part of the benchmark.

Normal model runs, A3/A4 evaluation, runtime validation, and package rebuilding
from `extracted/*.json` do not require this cache. It is used only for raw-source
reconstruction (`--from-log`), byte-level comparison (`--verify-log`), and
raw-source completeness or absence audits. A reproducer can retrieve the public
sources and set `SAFESOC_DATA`, or stage hash-identical copies under
`_splunk_ingest/`.

`attack_data_staged_manifest.json` records the exact upstream path, staged name,
SHA-256, size, sensor, case, tier, condition, and split for every required log.
See `attack_data/README.md` for retrieval and verification instructions.

## OTRF Security-Datasets

Only the six ZIP files consumed by the ten OTRF-derived cases are retained under
`otrf_selected_raw/`. Their repository-relative paths and hashes are recorded in
`otrf_selected_raw/MANIFEST.json`; the full upstream collection is not bundled.

## External replication source staging

Four public corpora are staged for the separate external replication study:

- `windows_apt_2025/` provides Windows host telemetry and a broad ATT&CK
  candidate pool. Its detector labels are not treated as event-level ground
  truth.
- `ait_ads/` provides eight enterprise-style scenarios, heterogeneous alerts
  from Wazuh, Suricata, and AMiner, normal-user false positives, and independent
  attack-phase labels.
- `ainception_sl100/` provides a multi-stage cyber-physical attack capture with
  endpoint, network, and drone telemetry.
- `cam_lds/` provides step-scoped raw Linux host and network logs. Defender-side
  telemetry is used for packages; attacker execution metadata is retained only
  for source-boundary QA and never shown to the model.

The large ZIP/CSV files are reproducible third-party staging caches and are
excluded by `.gitignore`. Each directory retains a source manifest with the DOI,
license, upstream checksum, local SHA-256, and retrieval date. Formal cases live
under `experiments/external_replication_v1/`; no staged detector label or attack
timeline is exposed to the model.
