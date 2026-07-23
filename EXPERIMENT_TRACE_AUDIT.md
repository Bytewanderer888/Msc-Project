# Experiment Trace Audit

Audit date: 2026-07-15

> Development-set update (2026-07-16): the package and output-completeness statements
> below predate the full 21-case dev raw-source audit. For current dev status, use
> `DEV_RAW_SOURCE_AUDIT_2026-07-16.md` and
> `eval/reports/run_matrix_current.json`. Held-out claims in this file were not
> re-audited as part of that dev-only pass.

## Resolution status

The blocking items identified by this audit were subsequently resolved. All 20 held-out
ground-truth files are confirmed and schema-valid; corrected Gemini and Claude outputs
are present in the canonical directories; every expected run-matrix cell is complete;
and `MANIFEST.json` has been refreshed and verified against the final file set.

## Important trace limitations

- The directory is not currently a Git repository. `MANIFEST.json` proves one snapshot,
  not the history of prompt, schema, package, runner, and rubric revisions. Create a
  versioned private backup before the final freeze.
- Calls made before 2026-07-15 have no API-time prompt/package/schema hashes, response
  IDs, provider-returned model versions, latency, or invocation IDs. Their current
  bindings are explicitly marked retrospective in
  `eval/reports/run_inventory_current.json`.
- Some early Gemini development calls have no matching API-usage record. This does not
  invalidate saved decisions, but exact historical token totals cannot be reconstructed
  from those logs. Do not rerun accuracy experiments only to recover cost.

## Offline records added by this audit

- `eval/run_model.py`: API-time run-event provenance for future calls.
- `eval/snapshot_runs.py`: hashes current outputs, packages, prompts, schema, and harness.
- `eval/cost.py`: separates canonical-output cost from all incurred API calls.
- `eval/pricing_snapshot.json`: dated price source and actual/list-equivalent distinction.
- `eval/stability.py`: terminal plus machine-readable JSON stability reports.
- `requirements.txt`: minimal pinned runtime dependencies.
- `data_sources/otrf_selected_raw/`: local copy and hashes of the six OTRF ZIPs actually used.
- `_splunk_ingest/`: all 33 attack_data source logs; their hashes exactly match the 33
  selected upstream files. `tools/verify_all_packages.py` deliberately disables the
  external attack_data path and proves that these retained copies rebuild the packages.
- `eval/check_run_matrix.py`: explicit experiment-cell completeness report.
- `experiments/evaluation_deepening_v1/`: zero-call secondary analysis over the
  frozen A2/A4 reports (ordinal distance, uncertainty, field-level stability,
  conformance matrix, and a lightweight output-level failure taxonomy).

## Final no-API freeze sequence

```text
python3 -m unittest discover -s eval/tests -p 'test_*.py' -v
python3 eval/snapshot_runs.py
python3 eval/check_run_matrix.py
python3 experiments/evaluation_deepening_v1/run_analysis.py
python3 tools/verify_all_packages.py
python3 eval/stability.py --model <A2_model_tag> --split <split> --json-out <report.json>
python3 eval/cost.py --all --split <split> --json-out <cost_report.json>
python3 tools/check_cases.py --write
python3 tools/check_cases.py
```

The final `MANIFEST.json` and versioned backup should be created only after all intended
outputs and reports are present.
