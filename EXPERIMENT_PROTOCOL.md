# SafeSOC Experiment Protocol

Status: final technical scope locked on 2026-07-18. The v1.1 protocol clarification
was first recorded on 2026-07-15, before the remaining corrected-case and repeated
held-out calls. Earlier calls are retained with their historical limitations; this
file does not claim that newly clarified details were recorded before those calls.

## Final research route and system boundary

SafeSOC studies whether an LLM's SOC triage decision is proportionate to the evidence
actually available. The final project has three connected layers:

1. **Benchmark construction:** raw public telemetry is retrieved, normalised, and
   converted into 41 neutral alert packages across four evidence conditions and two
   corpora.
2. **Controlled LLM evaluation:** a basic prompt (A1) and an evidence-aware prompt
   (A2) produce structured verdict, severity, rationale, evidence references,
   confidence, and recommended action.
3. **Validation:** the GT-backed offline evaluator (A3/A4) measures errors for research,
   while a separate GT-free deterministic runtime policy can block explicit integrity
   violations or require human review for consequential recommendations.

```text
public telemetry -> retrieval/normalisation -> neutral alert_package
                                                   |
                                                   v
                                          LLM triage (A1/A2)
                                                   |
                                      structured triage output
                                          /                \
                                         v                  v
                         offline evaluator + GT       runtime policy, no GT
                              A3 / A4 metrics          pass / review / block
```

The research questions are:

- **RQ1:** How accurately and consistently do cloud LLMs calibrate triage decisions
  across strong, weak, missing, and counter evidence?
- **RQ2:** Does evidence-aware prompting improve calibration over a basic structured
  prompt?
- **RQ3:** What diagnostic coverage do the full C1-C4 checks add beyond a
  grounding-only C1 evaluator?
- **RQ4:** Which failures can a zero-token, GT-free policy layer safely intercept at
  runtime, and what human-review workload does that require?

Gemini is the primary completed model. Claude is a secondary cross-model replication;
it is not required to outperform Gemini. The reported system is limited to prompt
comparison, offline evaluator coverage analysis, and the deterministic GT-free runtime
policy. It does not rewrite model decisions or perform adaptive SIEM retrieval.

A1-A4 are **not** a four-stage deployment pipeline or a single cumulative ladder.
A1 versus A2 is one prompt ablation. A3 versus A4 is a separate offline evaluator
coverage analysis over the same saved A2 outputs. Only the runtime policy is intended
to execute without case ground truth.

## Experimental units and splits

- Unit: one neutral `alert_package.json` submitted independently to one model.
- Development: 21 cases, used for prompt/rubric development and stability checks.
- Held-out: 20 cases, used only with the frozen A2 prompt and v1.1 evaluator.
- The four evidence conditions are strong, weak, missing, and counter.

## Arms

- A1: basic structured prompt, no validator. This is the development-set prompt baseline.
- A2: evidence-aware structured prompt, no validator. This is the primary model configuration
  used on development and held-out data.
- A3: offline C1-only pass over the saved A2 output. No new model call.
- A4: offline C1-C4 pass over the same saved A2 output. No new model call.

A1 versus A2 is a prompt ablation. A3 versus A4 is evaluator component-coverage
analysis, not a claim that the offline evaluator rewrites or improves model output.

## Model configuration

| Provider | Requested model | Temperature | Thinking | Max output tokens | Billing used |
|---|---|---:|---|---:|---|
| Google | `gemini-2.5-flash` | 0 | `thinkingBudget=0` | 2048 | free tier |
| Anthropic | `claude-sonnet-4-6` | 0 | no extended-thinking parameter | 2048 | standard real-time |

No explicit seed or `top_p` was sent; those settings remained at provider defaults.
Requests used a 300-second timeout and up to six attempts for HTTP 429/5xx responses.
The model was asked for JSON, then `llm_output.schema.json` was enforced client-side.

The exact prompt, schema, package, runner hashes, provider response metadata, token
usage, latency, and invocation identifier are written to `run_events_<split>.jsonl`
for all future calls. Calls made before 2026-07-15 do not have API-time hashes and are
identified as retrospective bindings by `eval/snapshot_runs.py`.

## Repeat and aggregation rules

1. The primary A2 development configuration is run three times per model.
2. A held-out model is run once if exact A2 decision-tuple agreement on development is
   at least 20/21; otherwise its held-out A2 arm is run three times.
3. Every held-out round is scored independently with the frozen v1.1 evaluator.
4. Primary repeated-run reporting gives each round's metric and the mean plus range.
5. The secondary case-level aggregate applies a 2-of-3 majority separately to each
   binary evaluator outcome (C1-C4). A case is jointly correct only if all four
   majority outcomes pass. No synthetic verdict/severity/action tuple is created.
6. Stability is reported for verdict, severity, action, and their exact tuple.

Gemini A1 was also repeated three times as a supplementary stability check. Claude A1
is a single prompt-baseline run; it is not part of the primary repeat criterion.

## Metrics

- Primary model endpoint: joint correctness, where C1-C4 all pass.
- Primary failure analysis: C2 verdict/severity calibration and C4 bidirectional
  action calibration, reported by evidence condition.
- C1: evidence-reference integrity.
- C3: acknowledgement of decisive counter-evidence when applicable.
- Confidence: exploratory only; it never overrides C1-C4.
- Stability: verdict, severity, action, and exact decision-tuple agreement.

Report counts and proportions by evidence condition, model, arm, corpus, and round.
Given the small purposive benchmark, use descriptive statistics and expose raw case
results rather than presenting population-level significance claims.

## Cost accounting

Report actual study spend separately from paid-tier list-equivalent cost. Canonical
cost covers the latest usage record associated with each current output; incurred cost
also includes invalidated and repeated calls. Prices are frozen in
`eval/pricing_snapshot.json` with access date and official source URLs.

## Runtime policy extension (recorded 2026-07-16)

This extension is separate from A1-A4. The deployable
`eval/runtime_validator.py` reads only one neutral alert package, one LLM output,
and `eval/runtime_policy_v1.1.json`; it must not read annotations, evidence
conditions, expected bands, or ground truth. It uses no additional model calls and
returns `pass`, `review`, or `block`. A pass means only that no observable policy
violation was found.

Hard integrity/contract violations block. Missing or disconnected rationale
citations (`R010`, `R011`) produce review warnings, not blocks. The default
`consequence_gate` requires human approval for `isolate` and `close_benign`.
`escalate` and `investigate` already enter a human workflow; `monitor` is treated
as passive/deferred and is not included in the high-consequence target. These are
recommendations, and the study does not claim that actions were automatically run.

The offline `eval/compare_runtime_to_oracle.py` then compares a completed runtime
report with the frozen A4 report. This comparison harness is used for research
metrics only and is not part of deployment. Report two primary targets:
`high_consequence_miscalibration` (C2/C4 failure plus `isolate` or `close_benign`)
for deployment safety, and any C2/C4 failure for general calibration. Any C1-C4
failure is a supplementary diagnostic target. The harness must reject any oracle
report whose active checks are not exactly C1-C4. Report recall, precision, F1,
deferral rate, and every false negative for each pre-defined routing profile.
Because the high-consequence target and gate use the same action set, its 100%
recall is a policy-coverage invariant rather than independent predictive evidence;
the empirical quantities are the number of exposed errors and the review burden.
General C2/C4 calibration remains the primary effectiveness comparison.

Runtime policy v1.0 was superseded by v1.1 after a dev-only methodological review
and before any runtime-to-A4 held-out comparison. Version 1.1 is developed using
the three Gemini A2 development rounds only. It must then be applied without
case-specific changes to every completed held-out round. Full design, commands,
development results, and non-claims are in
`experiments/runtime_policy_validator/README.md`.

## Freeze rule

Before a final held-out claim: confirm all held-out GT review statuses, resolve stale
case metadata, complete required replacement outputs, regenerate A3/A4 and stability
reports, generate the run inventory, refresh `MANIFEST.json`, verify it, and retain a
versioned off-machine backup.

## Completion rule from this point

- Gemini A1 development and A2 development/held-out calls are complete. Do not make
  further Gemini calls unless a documented integrity failure invalidates an output.
- Complete the nine missing corrected-package Claude outputs in A1 development round
  1 and A2 development rounds 1-3. Then apply the pre-recorded development stability
  threshold to decide whether Claude A2 held-out requires one or three rounds.
- Never run A1 on held-out. A3, A4, stability analysis, cost accounting, and runtime
  policy evaluation reuse saved outputs and require no new model calls.
- After Claude completion, regenerate reports and run inventory, refresh and verify
  `MANIFEST.json`, and freeze the final repository snapshot. No new experiment family
  is added after this point.
