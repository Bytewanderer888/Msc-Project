# APT29 scenario captures

The `day1/` and `day2/` names are preserved from the OTRF Security-Datasets
repository. They identify the first and second scenarios of the MITRE ATT&CK
APT29 evaluation capture; they are not SafeSOC development/held-out splits,
experiment rounds, or local collection dates.

- `day1/apt29_evals_day1_manual.zip`: used by `GPO-001`, `RTLO-001`, and `UAC-001`.
- `day2/apt29_evals_day2_manual.zip`: used by `RDL-001`, `RUN-001`, and `WMI-001`.

The original repository-relative paths are retained so each case's
`build/case.json:mordor_log` value maps directly to the selected source and its
SHA-256 entry in `data_sources/otrf_selected_raw/MANIFEST.json`.
