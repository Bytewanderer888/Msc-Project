# Windows-APT Dataset 2025 staging

This directory stages the public Windows-APT Dataset 2025 for candidate
selection in SafeSOC's external replication study.

- DOI: `10.17632/b8fmtzvpy8.3`
- Upstream version: 3
- License: CC BY 4.0
- Local retrieval date: 2026-07-22

`combined.csv` is a large reproducible staging cache and is not committed. The
smaller scenario manifest, validation summary, upstream README, checksum file,
and `SOURCE_MANIFEST.json` are retained.

## SafeSOC use constraints

The CSV combines Wazuh/Sysmon-derived records from 36 emulated scenarios. Its
`_source.rule.*` fields contain detector-generated ATT&CK mappings, rule names,
descriptions, and severity. Those fields are candidate-discovery aids only:
they are removed from every model-visible package and cannot establish SafeSOC
ground truth by themselves.

Every accepted case must be audited from the underlying event semantics. Because
`combined.csv` is a Wazuh alert-index export rather than a complete raw-event
archive, it is not used to establish `missing` cases: absence from an alert
stream does not prove absence from the source host. A `counter` case requires
affirmative benign context, not merely a lack of attack follow-on.

See `experiments/external_replication_v1/SOURCE_AUDIT.md` for the current
suitability assessment and leakage controls.
