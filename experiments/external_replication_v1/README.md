# External replication set v1

This study extends the frozen 41-case SafeSOC benchmark with a separate,
independently sourced held-out replication set. It does not alter the canonical
dev/held-out split, rubric, prompts, output schema, or previously reported model
results.

## Intended contribution

The original benchmark characterises failure modes in carefully curated Windows
SOC evidence packages. The replication set asks whether the same findings hold
across new capture environments, log formats, ATT&CK mechanisms, sensor depths,
and operational response contexts.

The frozen set contains 16 cases: four each for `strong`, `weak`, `missing`,
and `counter`. The number is a stopping rule, not a claim of population
representativeness. All packages passed automated and semantic pre-freeze QA
under `SELECTION_PROTOCOL.md` before any model call.

Every case-level trigger also references the shared SafeSOC trigger-analytic
catalogue. Across the complete 57-case project, 57 executable specifications
instantiate 21 reusable patterns in 9 analytic families. These families index
the primary observable detection mechanism; they do not replace the concrete
predicate or duplicate ATT&CK and evidence-condition labels.

## Important dependency between dimensions

Rubric v1.1 fixes the decision bands by evidence condition. A balanced 16-case
set therefore necessarily contains:

| Condition | n | Verdict | Severity band | Canonical action band |
|---|---:|---|---|---|
| strong | 4 | malicious | high-critical | escalate-isolate |
| weak | 4 | suspicious | low-medium | monitor-investigate |
| missing | 4 | suspicious | low-medium | monitor-investigate |
| counter | 4 | benign | informational-low | close_benign-monitor |

Consequently, verdict, severity, and canonical action are covered but cannot be
independently balanced without changing the frozen rubric. Operational response
families such as endpoint isolation, credential reset, network blocking, and
analyst escalation are recorded separately as deployment metadata. They do not
silently expand the five-value model-output action schema.

## Freeze sequence

1. Select candidates under the predeclared matrix.
2. Write a behavioural `trigger_spec.json` before any model call.
3. Replay the rule over the complete legal source scope and derive `A0` with a
   declared deterministic selection strategy.
4. Extract and neutralise packages; write event-level provenance.
5. Complete security review, leakage checks, and raw-scope audits.
6. Annotate and review ground truth without consulting model output.
7. Freeze packages, trigger rules and audits, ground truth, protocol, prompt,
   and run configuration.
8. Run each selected cloud model once on this replication set.
9. Score with the frozen offline evaluator and report the replication result
   separately from the original 41-case benchmark.

No model call is permitted unless `freeze_set.py --check` passes.

## Local checks

```bash
python3 experiments/external_replication_v1/verify_sources.py
python3 experiments/external_replication_v1/audit_register.py
python3 tools/audit_trigger_rules.py --set external --write-results
python3 experiments/external_replication_v1/qa_built_cases.py
python3 experiments/external_replication_v1/freeze_set.py --check
```

The first command verifies every staged file against its recorded size and
SHA-256. The second checks the predeclared balance, diversity, independence,
sensor-depth, and response-family constraints in `CASE_REGISTER.csv`. The third
executes each behavioural trigger over its complete declared source scope and
checks that deterministic selection reproduces `A0`. The fourth validates every
built package, checks package/GT evidence-ID consistency, scans for answer
leakage, and re-verifies selected upstream archive or CSV records.

Freeze result: source manifests pass, the register satisfies the 16-case
matrix, and 16/16 cases pass package/provenance and semantic QA. The immutable
model-input copies and complete file hashes are recorded in
`FREEZE_MANIFEST.json`. Post-run amendments in that manifest are limited to
schema compatibility or documentation metadata and explicitly record that no
model-visible input, ground truth, or scoring field changed.

## Frozen A2 runs

Run the freeze check immediately before either provider call. The external
manifest permits the 16 new IDs without weakening the canonical 41-case guard.
`--skip-existing` only resumes an interrupted run; it does not create an
additional round.

```bash
python3 experiments/external_replication_v1/freeze_set.py --check

python3 eval/run_model.py \
  --provider gemini \
  --model gemini-2.5-flash \
  --split heldout \
  --prompt evidence \
  --package-dir experiments/external_replication_v1/frozen_inputs \
  --experiment-tag external_replication_v1 \
  --external-freeze-manifest experiments/external_replication_v1/FREEZE_MANIFEST.json \
  --skip-existing

python3 eval/run_model.py \
  --provider anthropic \
  --model claude-sonnet-4-6 \
  --split heldout \
  --prompt evidence \
  --package-dir experiments/external_replication_v1/frozen_inputs \
  --experiment-tag external_replication_v1 \
  --external-freeze-manifest experiments/external_replication_v1/FREEZE_MANIFEST.json \
  --skip-existing
```

Score the saved A2 outputs offline. A3 and A4 do not call either provider:

```bash
python3 eval/validator_v1_1.py \
  --model gemini-2.5-flash__A2_evidence_prompt__EXP_external_replication_v1 \
  --split heldout \
  --case-root experiments/external_replication_v1/cases \
  --checks C1,C2,C3,C4 \
  --json-out experiments/external_replication_v1/reports/gemini_a4.json \
  --csv-out experiments/external_replication_v1/reports/gemini_a4.csv
```
