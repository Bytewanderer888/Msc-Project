# SafeSOC — evidence-sufficiency benchmark and validation framework

A curated diagnostic benchmark and validation framework for **evidence-aware AI-assisted SOC triage**.
Each case = **one alert + its correlated, curated context** (one host + time window), turned into a
**neutral `alert_package.json`** that is the only thing the LLM under test sees (multi-model: Gemini +
Claude via `eval/run_model.py`). Built from **two corpora** — Splunk `attack_data` (Splunk-authoritative)
and **OTRF Security-Datasets** (built direct) — on the corrected multi-source methodology (the old
single-source `data/cases/` is superseded).

## Repository layout — organized by tier → evidence → split

```
SafeSOC/
├── README.md · SELECTION_RATIONALE.md
├── MANIFEST.json               # sha256 inventory of every research asset (integrity baseline)
├── data_sources/
│   ├── attack_data_staged_manifest.json # 33 excluded raw logs: source paths + hashes
│   └── otrf_selected_raw/       # six retained OTRF ZIPs used by ten cases
├── rubric/                     # v1.0 preserved baseline + v1.1 candidate specification
├── eval/
│   ├── run_model.py            # multi-model triage runner (Gemini + Claude, REST; --batch = Anthropic Batch API)
│   ├── validator.py            # preserved v1.0 evaluator
│   ├── validator_v1_1.py       # current fail-closed offline evaluator + JSON/CSV export
│   ├── runtime_validator.py     # deployable GT-free policy checks + routing (zero tokens)
│   ├── compare_runtime_to_oracle.py # offline runtime-vs-A4 research metrics
│   ├── runtime_policy_v1.1.json # frozen experiment policy used by reported runtime results
│   ├── runtime_policy_v1.2.json # demo/runtime maintenance release; same routing, narrower R012 phrase
│   ├── tests/                  # deterministic v1.1 rule tests
│   ├── gemini_triage_prompt.md · llm_output.schema.json
│   └── outputs/<model_tag>/<split>/    # one JSON verdict per case per model
├── experiments/
│   ├── evaluation_deepening_v1/ # ordinal error, uncertainty, stability, conformance
│   ├── outcome_pairs_v1/        # controlled missing -> strong interventions
│   ├── context_pairs_v1/        # controlled weak -> counter interventions
│   └── runtime_policy_validator/# deployable policy-layer study
├── tools/
│   ├── normalize.py            # the unified build engine
│   ├── check_cases.py          # structural audit + MANIFEST verify (--write = new baseline)
│   ├── splunk_export_loader.py
│   └── schema/                 # alert_package / selection_metadata / ground_truth schemas
├── tier1/                      # single-sensor cases
│   ├── strong/  { dev/  heldout/ }
│   ├── weak/    { dev/  heldout/ }
│   ├── missing/ { dev/  heldout/ }
│   └── counter/ { dev/  heldout/ }
├── tier2/                      # genuine multi-sensor fusion cases
│   └── strong/  { dev/  heldout/ }
└── _splunk_ingest/             # optional local attack_data staging cache; gitignored
```

**Cases are grouped by their evidence condition, not by technique** — the ATT&CK technique is metadata
(in `build/case.json`; the case-ID prefix names the surface, e.g. PS=PowerShell, LS=LSASS, INJ=Injection,
ST=Sched-task, SMB=SMB, BF=Brute-force, DISC=Discovery, ING=Ingress, CERT=Certutil, WMI=WMI, RK=Run-key,
RTLO=RTLO-masquerade, UAC=UAC-bypass — full mapping in each case's `build/case.json`).

## Two orthogonal axes describe every case
- **Evidence condition** (property of the package / ground truth): `strong`, `weak`, `missing`, `counter`.
  This is the folder level.
- **Calibration role** (which validator behaviour it probes): over-triage-prone → down-rank · preserve ·
  under-triage-prone (strong-but-subtle) → up-rank. This is metadata (a `strong/` case may be *preserve*
  or *under-triage*).

**Completeness rule:** the **dev** split contains ≥1 of every condition AND every calibration role, so
every rubric rule is developed before freeze; **held-out** is a representative spread.

## Per-case folder
```
<CASE_ID>_<name>/
  build/       case.json               # declarative config — the single source of truth
  queries/     retrieval_spec.md       # the exact step-by-step Splunk runbook    (attack_data cases only)
  extracted/   <case>_events.json      # the Splunk export (authoritative)        (attack_data cases only)
  model_input/ alert_package.json      # the NEUTRAL package — the only LLM input
  annotations/ selection_metadata.json # researcher archive (id map, curation, researcher intent)
               ground_truth.json        # answer key — rubric v1.1 candidate (verdict/severity/action bands)
  source/      provenance.json          # source log path(s) + sha256 + host + tier
```
OTRF cases are built **directly** from the OTRF JSON, so they have no `queries/` or `extracted/` —
five files instead of seven, by design (`tools/check_cases.py` audits both layouts).

## The build engine (`tools/normalize.py`)
One engine, driven by each `build/case.json`. It loads events (Splunk export authoritative by default;
`--from-log` / `--verify-log` cross-check against the raw capture; OTRF/mordor flat NDJSON read direct),
handles **single- and multi-source** (fusion) cases, parses **XML**, **stanza** (`key=value`), and
**mordor JSON** Windows event formats, assigns `A0`/`EV` ids, applies derivations, **neutralizes**
answer-leaking tokens, **anonymizes** hosts/users, and emits the package + metadata + provenance —
validated against the schemas.

```
python3 tools/normalize.py --case tier1/strong/dev/LS-001_lsass_creddump              # from export (default)
python3 tools/normalize.py --case tier1/strong/dev/LS-001_lsass_creddump --verify-log # re-derive from raw, diff
```
- **Self-contained** for from-export builds + schema validation (schemas live in `tools/schema/`).
- `--from-log` / `--verify-log` need the public raw `attack_data` sources. The engine resolves them via
  `SAFESOC_DATA` or a hash-matched `_splunk_ingest/` fallback; the OTRF corpus is resolved via `OTRF_DATA`.
  Every attack_data case is proven **byte-identical** between the export and raw paths.
- `_splunk_ingest/` is an optional 652 MiB local staging cache copied from public `attack_data`; it is not
  an original benchmark asset. Normal model runs, A3/A4, runtime validation, and package rebuilding from
  `extracted/*.json` do not need it. The portable
  `data_sources/attack_data_staged_manifest.json` records all 33 required upstream paths, staged filenames,
  SHA-256 hashes, sizes, and consuming cases. A clean clone can run the model and all evaluators without the
  cache; `--from-log`, `--verify-log`, and raw-source completeness or absence audits require retrieving the
  listed public files or restoring hash-identical staged copies.
- **Neutralisation (anti-leakage):** before writing the model-visible package, MITRE technique IDs
  (`T####[.###]` → `[id]`) and named test frameworks (Atomic Red Team / redcanaryco / PurpleSharp /
  AllTheThings → `[x]`) are redacted. Only these tokens are masked; all evidential content is preserved;
  byte-identity still holds; the true raw is kept in `provenance.json`.
- **Anonymisation:** the model-visible package also gets deterministic host/domain/user rewriting
  (e.g. `SCRANTON` → `host-01`, `dmevals.local` → `corp.local`, users → `user-NN`; well-known accounts
  like SYSTEM/Administrator are kept) — applied to **both** corpora.

## Current state — 41 cases · dual corpus · rubric/guideline v1.1

| condition | tier1 dev | tier1 held-out | tier2 dev | tier2 held-out |
|---|---|---|---|---|
| strong | LS-001, INJ-001, WMI-002, RTLO-001\*, UAC-001\* | LS-003, SMB-001, PS-004, WMI-001\*, RUN-001\*, SVC-001, UQP-001 | AMQ-001 | OD-001 |
| weak | PS-001, PS-002, LS-002, BF-001, CERT-001, FW-001\*, ST-003 | BF-002, DISC-001, COL-001, CRED-001, DISC-003, DISC-004\* | — | — |
| missing | ING-001, ACCT-001, RK-001, ST-002, LGN-002\* | ST-001, ING-002, LOGON-001, EVL-001\* | — | — |
| counter | SMB-002, RDL-001\*, DISC-002 | PS-003, GPO-001\* | — | — |

`*` = OTRF Security-Datasets (10 cases, built direct); unmarked = Splunk `attack_data` (31, export ≡ raw
proven byte-identical). **Dev 21 / held-out 20**; every condition spans both corpora; 26 mapped ATT&CK
technique ids across the kill chain. Tier-2 = genuine Sysmon+Security fusion: **AMQ-001** (ActiveMQ
CVE-2023-46604 RCE → C2, dev) and **OD-001** (Olympic Destroyer destruction fused with the Security `1102`
"log cleared" event, held-out).

### Documented design decisions / data findings
- **Condition totals are strong 14, weak 13, missing 9, counter 5.** `PS-001` is weak under the v1.1
  boundary because suspicious encoded execution and compilation are present but semantically ambiguous;
  unavailable STDIN is not used as a label-switching missing confirmation.
- **Counter remains the scarcest condition** (5 total: dev 3, held-out 2). Clean *benign-but-alarming*
  activity is scarce in an attack corpus — it is usually intermixed with a real attack on the same host, so
  a standalone counter can't be honestly scoped. The OTRF corpus eased this (RDL-001, GPO-001), but held-out
  counter is still thin — a stated methodological limitation.
- **DISC-002 reclassified weak → counter (2026-07-07)** during the dev confirmation pass: all four wmic
  queries are the AWS SSM agent's own inventory burst — decisive benign context, consistent with SMB-002.
  Documented as an annotation refinement in the case's `build/case.json`.
- **ST-002 / WMI-002 boundary audit (2026-07-15):** ST-002 moved strong → missing because Sysmon EID 1
  records only `schtasks /Create` invocation, not registration or firing. WMI-002 moved missing → strong
  because Sysmon EID 19/20/21 `Operation=Created` directly records the consumer, filter, and binding.
  The swap preserves the development-set condition counts while applying one outcome-based rule.
- **SVC-001, UQP-001 corrected missing → weak → strong (final evidence audit 2026-07-15):** both captures go beyond service setup. SVC-001 records a newly configured service binary launched by `services.exe` as SYSTEM; UQP-001 records the planted `C:\program.exe` winning unquoted-path resolution and executing as SYSTEM. Test/example naming and later cleanup remain counter-evidence about authorization and persistence duration, but do not negate the completed privileged-execution mechanism. The benchmark's `malicious` label is behavioural and does not assert that the lab operator was unauthorized.
- **ST-003 reclassified counter → weak (2026-07-14)** during the evidence-discipline review: the tasks are vendor scheduled tasks (Npcap/Aurora/Firefox), but the single-source Security log carries no signature/hash and A0 (Npcap `npcapwatchdog`) has no `Author`, so the package cannot *decisively* confirm benignity — the evidence supports suspicious/investigate, not a benign close. (Not score-neutral: counter→weak shifts the target verdict/band/action.)
- **Injection (T1055) is strong-only** in this corpus (all captures are unbacked shellcode).
- **Sampling is purposive/stratified**, not representative — see `SELECTION_RATIONALE.md`.

## Status — v1.1 scope frozen; model runs complete
- **Rubric v1.0 is preserved** as the original frozen baseline. The implementation audit found three contract
  gaps: GT verdict and confidence were not scored, C3 duplicated decision checks, and C4 could not detect
  under-action. Broad C1 semantic keyword rules were also too brittle for claims such as “command launched”
  versus “operation succeeded.”
- **Rubric v1.1 candidate** (`rubric/evidence_sufficiency_rubric_v1.1.md`) introduces: **C1**
  evidence-reference integrity · **C2** verdict + severity calibration · **C3** counter-evidence
  acknowledgement only · **C4** bidirectional action bands. Free-text semantic over-reach is documented
  through `must_not_assert` audit prompts rather than presented as deterministic NLP. Unchanged packages
  reuse saved outputs; packages changed by the pre-freeze leakage/evidence audit are explicitly re-run.
- **Ground truth:** dev **21/21** and held-out **20/20** are schema-valid under v1.1. In addition to the
  evaluator-contract changes, the pre-freeze evidence audit corrected case labels where observed outcomes
  crossed the fixed condition boundary. Each correction and any required package re-run is documented;
  the final distribution remains dev 21 / held-out 20.
- **Metric names.** *Joint decision correct* counts cases where **C2** holds — verdict and severity
  both inside the admissible band. It is not the same as the demo dashboard's *A4 all-check pass*,
  which requires **C1–C4 together** and is therefore the stricter, lower number: Gemini A1 dev is
  9/21 joint decision correct but 8/21 A4 all-check pass.
- **Gemini v1.1 dev result (three rounds complete):** A1 is **9/21** joint decision correct in every round, with
  `C1=0, C2=12, C3=2, C4=12`. A2 is also **9/21** joint decision correct in every round, with
  `C1=0, C2=12, C3=2/3/3, C4=12`; A4 flags 12/13/13 cases across the three rounds. A3 (C1-only) flags **0/21**.
  A1 exact tuple agreement is **20/21**. A2 exact tuple agreement is **19/21**, severity agreement
  **20/21**, and verdict agreement **21/21**. UAC-001 changes action and WMI-002 changes severity/action;
  the UAC-001 change also changes C3, while both WMI-002 decisions remain acceptable.
- **Gemini v1.1 held-out result (three rounds complete):** all three rounds are identical on the decision
  tuple for **20/20** cases. Each round is **12/20** joint decision correct, with `C1=0, C2=8, C3=0, C4=7`.
  The exact repeatability strengthens reproducibility but does not remove the eight systematic failures.
- **Claude Sonnet 4.6 v1.1 result (three A2 rounds complete):** development is **10/21** joint decision correct
  in every round (`C1=0, C2=11, C3=0, C4=9/9/10`). Held-out is **11/20** in every round
  (`C1=0, C2=9, C3=0, C4=6/5/8`); the check-wise 2-of-3 aggregate is also **11/20**, with
  `C1=0, C2=9, C3=0, C4=7`. Held-out verdicts agree on **20/20** cases, severities on **19/20**, and
  exact verdict/severity/action tuples on **12/20**. Thus the action field is less repeatable, while the
  headline calibration finding and the nine A4-flagged cases are unchanged across rounds.
- **Repeat-run protocol:** the primary A2 config is run **3× per model** under the same
  frozen config (rounds 2–3 via `run_model.py --round N`; agreement measured on the decision fields with
  `eval/stability.py` — rationale wording may vary). If exact agreement is **≥ 20/21 cases** per model,
  **held-out is run once** per the freeze record; otherwise held-out is run 3×. Each round is scored
  independently; the secondary case-level aggregate uses a 2-of-3 majority for each C1-C4 outcome, with
  no synthetic model-output tuple. Full details and the recording date are in `EXPERIMENT_PROTOCOL.md`.
- **Run it:**
```
python3 eval/run_model.py --provider gemini    --split dev            # free tier: add --skip-existing --limit N
python3 eval/run_model.py --provider anthropic --split dev --batch    # Claude via the Batch API (50% off)
python3 eval/validator_v1_1.py --model <model_tag> --split dev
python3 eval/validator_v1_1.py --model <model_tag> --split dev --checks C1  # A3
python3 eval/validator_v1_1.py --model <model_tag> --split dev \
  --json-out /tmp/dev_v1_1.json --csv-out /tmp/dev_v1_1.csv                # A4 + export
python3 eval/aggregate_validator_rounds.py --reports <round1.json> <round2.json> <round3.json> \
  --json-out /tmp/a4_majority.json --csv-out /tmp/a4_majority.csv          # check-wise 2-of-3
python3 eval/runtime_validator.py --model <model_tag> --split dev          # GT-free runtime policy
python3 -m unittest discover -s eval/tests -p 'test_*.py' -v
python3 tools/check_cases.py                                          # structure + MANIFEST integrity
python3 eval/snapshot_runs.py                                        # current hashes + trace coverage
python3 eval/cost.py --all --split dev --json-out eval/reports/cost_dev_current.json
python3 eval/check_run_matrix.py                                    # missing experiment cells
python3 tools/verify_all_packages.py                                # raw source -> package byte identity
python3 experiments/evaluation_deepening_v1/run_analysis.py         # offline depth analysis; zero API calls
```
- **Runtime extension (policy v1.1, frozen on dev):** the zero-token runtime validator checks observable
  package/output contracts and routes consequential recommendations without reading GT. For the deployment-
  safety target, all three Gemini A2 dev rounds contain 7 C2/C4 failures recommending `isolate` or
  `close_benign`; `consequence_gate` routes **7/7 (100%)** at **14/21** human review. Against all C2/C4
  failures it reaches **7/12 (58.3%)**, while `safety_first` reaches **11/12 (91.7%)** at **19/21** review.
  The structurally aligned 7/7 result is a policy-coverage invariant, not independent predictive accuracy;
  the empirical trade-off is 7 exposed errors versus 14 reviews. It does not mean actions were actually
  executed autonomously or guarantee held-out performance. This demonstrates both the deployability and the limit of a
  policy-only layer: internally coherent evidence-sufficiency errors cannot be proven wrong without an
  external reference, and high recall removes most workload savings. See
  `experiments/runtime_policy_validator/README.md`.
- **Frozen runtime held-out result:** every Gemini round gives the same result. Against all eight C2/C4
  failures, `consequence_gate` recalls **4/8 (50.0%)** at **10/20** review and `safety_first` recalls
  **6/8 (75.0%)** at **13/20** review. For the two miscalibrated `isolate/close_benign` recommendations,
  `consequence_gate` routes **2/2** at the same 10/20 review burden. These results were obtained without
  changing the dev-frozen policy.
- **Evaluation deepening (offline, zero new model calls):**
  `experiments/evaluation_deepening_v1/` adds separate ordinal distances for verdict, severity, and action;
  Wilson intervals; an exact paired held-out comparison; field-level three-round stability; and a
  14-scenario validator conformance matrix. On held-out round 1, Gemini is 12/20 and Claude 11/20 on C2;
  the paired risk difference is +5 percentage points with bootstrap 95% CI -20 to +30 and exact McNemar
  `p=1.0`, so no model-superiority claim is supported. All 14/14 conformance scenarios pass. Gemini's
  held-out three-field tuple is stable on 20/20 cases; Claude's is stable on 12/20, with most variation in
  recommended action. These repetitions characterise stability and are not treated as independent samples.
- **Current next step:** integrate the frozen benchmark, controlled-pair, runtime-policy, and evaluation-
  deepening results into the thesis/report and demo narrative. All planned Gemini and Claude model cells
  are complete; remaining evaluator analyses are offline and require no API calls.
