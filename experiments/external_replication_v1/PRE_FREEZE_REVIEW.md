# External replication freeze review

Review date: 2026-07-22

## Automated checks

The following commands pass on the complete frozen 16-case set:

```bash
python3 experiments/external_replication_v1/verify_sources.py --require-cache
python3 experiments/external_replication_v1/audit_register.py
python3 tools/audit_trigger_rules.py --set external --write-results
python3 experiments/external_replication_v1/qa_built_cases.py
```

Observed results:

- 16 cases, balanced 4/4/4/4 across the four evidence conditions;
- 15 distinct ATT&CK technique IDs;
- four corpora and six genuine multi-source cases;
- all four required operational response families represented;
- 16/16 packages pass schema, leakage, evidence-ID, decision-band, source-hash,
  and selected-record provenance checks;
- all four staged source manifests match their recorded file sizes and SHA-256
  values.
- 16/16 prospective behavioural trigger rules reproduce their retained `A0`
  from the complete declared source scope without labels or exact locators.
- every trigger references a catalogue-validated analytic family and reusable
  pattern; the project-wide catalogue covers exactly 57 case specifications.

## Semantic boundary review

- **Strong:** each case contains a directly observed outcome or completed
  offensive mechanism, not only an upstream detector label.
- **Weak:** each case contains a positive but semantically ambiguous signal;
  none relies on absence from a filtered alert index.
- **Missing:** each case names an observable precursor and a specific absent or
  failed confirmation. ER-M01 is explicitly point-in-time; ER-M02 uses the full
  step scope; ER-M03 and ER-M04 contain native failed syscall results.
- **Counter:** each case retains the suspicious surface and adds affirmative
  routine context rather than treating absence of follow-on as benign proof.

For ER-M03 and ER-M04, the proposition is the **completed deletion outcome**.
The commands remain suspicious and warrant investigation, but native audit
results show that the selected target operation did not complete. The GT does
not claim benign intent or a harmless session.

## Freeze decision

All 16 model-visible packages and GT files received a final wording,
anonymisation, and semantic-boundary review. Their status is
`frozen_pre_model_2026-07-22`. `FREEZE_MANIFEST.json` records the package, GT,
protocol, prompt, schema, evaluator, and run-contract hashes.

Each selected model may now be run once on this separate replication set. No
package, GT, prompt, schema, or evaluator tuning is permitted after observing
model output. No provider call occurred before this freeze.
