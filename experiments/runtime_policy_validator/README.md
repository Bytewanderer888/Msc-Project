# Policy-based runtime validator

## Purpose

This extension asks a deployment question that the A1-A4 experiment does not:

> What can be checked after an LLM produces a SOC triage decision when case
> ground truth is unavailable?

The deployable component is a zero-token policy layer. It reads only the neutral
`alert_package.json`, the LLM output, and a generic policy. It never reads the
case condition, annotations, expected severity/action bands, or ground truth.

The runtime result has three states:

- `pass`: no machine-verifiable policy issue was found;
- `review`: the output is structurally valid, but its consequence profile requires
  a human decision;
- `block`: an observable integrity or consistency rule failed.

A `pass` is deliberately narrow. It does **not** mean the verdict is factually
correct or that the available evidence is sufficient.

## Architecture

```text
alert package + LLM output
              |
              v
   runtime_validator.py             deployable; no GT; 0 tokens
      | hard contract checks
      | consequence signals
      v
      pass / review / block

frozen runtime report + frozen A4 report
              |
              v
compare_runtime_to_oracle.py        offline research evaluation only
              |
              v
precision / recall / F1 / deferral rate / false-negative list
```

The scripts are intentionally separate. `runtime_validator.py` cannot access A4
labels. `compare_runtime_to_oracle.py` is never part of the deployment path.

## Rules and routing profiles

Policy v1.1 distinguishes failures from warnings. Hard rules block malformed
packages or outputs, invalid evidence references, unsupported decode claims,
broken derivation links, and internally inconsistent verdict/severity/action
combinations. Missing or disconnected rationale citations (`R010`, `R011`) route
the output to review rather than block it: citation quality is inspectable, but
an otherwise accurate prose explanation is not a fabricated evidence reference.

The frozen policy also exposes three routing profiles:

| Profile | Behaviour | Intended interpretation |
|---|---|---|
| `integrity_only` | blocks hard failures and reviews citation warnings | deterministic integrity ceiling |
| `consequence_gate` | also reviews `isolate` and `close_benign` | human approval for high-consequence actions |
| `safety_first` | reviews aggressive claims and benign closures | high-recall sensitivity analysis |

These are policy profiles, not learned classifiers. The profiles are evaluated
side by side; no case-specific rule is permitted.

The model's numeric confidence is retained in the report but is not trusted as a
routing override. It is self-reported rather than calibrated, and the dev errors
are often high-confidence; allowing it to suppress review would therefore weaken
the safety policy merely to make the field appear operationally useful.

### Action boundary

The LLM output contains a **recommended** action; the experiment does not claim
that an action was actually executed autonomously. The deployment policy divides
recommendations into:

- `isolate` and `close_benign`: disruptive or terminal actions that must receive
  human approval before execution;
- `escalate` and `investigate`: actions that already place a human analyst in the
  decision loop;
- `monitor`: passive or deferred handling, kept outside the high-consequence
  target rather than assumed to be an analyst review.

This is why `consequence_gate` does not route every `escalate`: escalation is
already a human-review path, whereas isolation or benign closure could directly
change containment or case state if an organisation enabled automation.

## Development-set result

Two complementary targets are reported. The deployment-safety target is
`high_consequence_miscalibration`: C2 or C4 failed and the model recommended
`isolate` or `close_benign`. It contains 7 of 21 outputs in every Gemini A2 dev
round.

| Profile | TP | FP | FN | Recall | Precision | Human review |
|---|---:|---:|---:|---:|---:|---:|
| `integrity_only` | 0 | 0 | 7 | 0.0% | n/a | 0/21 (0.0%) |
| `consequence_gate` | 7 | 7 | 0 | 100.0% | 50.0% | 14/21 (66.7%) |
| `safety_first` | 7 | 12 | 0 | 100.0% | 36.8% | 19/21 (90.5%) |

Thus, on development data, the default zero-token gate routes all seven
miscalibrated recommendations that would require approval before changing host or
case state. It also routes seven correctly calibrated high-consequence decisions;
those false positives are the cost of requiring approval rather than evidence that
the decisions are wrong.

The 100% figure is a **policy coverage invariant**, not independent predictive
performance: the target is restricted to `isolate/close_benign`, and the gate is
defined to route every `isolate/close_benign`. Its empirical value is to show that
7 such errors occurred on dev and that enforcing the invariant requires 14/21
reviews with 50% precision. It must not replace the broader calibration result.

The broader calibration target contains every C2 or C4 failure, including outputs
that already recommend `escalate` or `investigate`: 12 of 21 in every round.

| Profile | TP | FP | FN | Recall | Precision | Human review |
|---|---:|---:|---:|---:|---:|---:|
| `integrity_only` | 0 | 0 | 12 | 0.0% | n/a | 0/21 (0.0%) |
| `consequence_gate` | 7 | 7 | 5 | 58.3% | 50.0% | 14/21 (66.7%) |
| `safety_first` | 11 | 8 | 1 | 91.7% | 57.9% | 19/21 (90.5%) |

No current Gemini A2 development output triggers a hard runtime failure. The
`integrity_only` result therefore demonstrates an important limit: the observed
severity errors are internally coherent, grounded, schema-valid decisions, so
internal consistency alone cannot detect them. The one calibration false negative
under `safety_first` is `SMB-002`, a moderate `suspicious/medium/investigate`
over-call that has no generic high-consequence signal.

This is not evidence that `safety_first` solves evidence sufficiency. Its 91.7%
recall is obtained by sending 90.5% of outputs to human review, leaving little
automation benefit. The result quantifies the safety-workload trade-off and the
ceiling of a policy-only design.

The five broader-calibration false negatives under `consequence_gate` are four
`escalate` recommendations and one `investigate` recommendation. They remain real
model calibration errors, which is why the 58.3% result is retained, but none
would directly apply the recommended action without a human workflow under the
stated deployment policy.

The supplementary `a4_any` target is diagnostic rather than a headline deployment
metric. It is 12/21 in round 1 and 13/21 in rounds 2-3 because UAC-001's C3 result
varies; a policy layer is not expected to reproduce every GT-backed C1/C3 judgment.

## Reproduce

Run the deployable validator over a saved development round:

```bash
python3 eval/runtime_validator.py \
  --model gemini-2.5-flash__A2_evidence_prompt \
  --split dev \
  --json-out eval/reports/runtime_v1_1_gemini-2.5-flash__A2_evidence_prompt_dev.json \
  --csv-out eval/reports/runtime_v1_1_gemini-2.5-flash__A2_evidence_prompt_dev.csv
```

Run one deployment-style decision:

```bash
python3 eval/runtime_validator.py \
  --package tier1/weak/dev/PS-001_encoded_powershell_benign/model_input/alert_package.json \
  --output eval/outputs/gemini-2.5-flash__A2_evidence_prompt/dev/PS-001.json
```

Compare the frozen runtime report with A4 offline:

```bash
python3 eval/compare_runtime_to_oracle.py \
  --runtime-report eval/reports/runtime_v1_1_gemini-2.5-flash__A2_evidence_prompt_dev.json \
  --oracle-report eval/reports/gemini-2.5-flash__A2_evidence_prompt_dev.json \
  --target high_consequence_miscalibration
```

Run deterministic tests:

```bash
python3 -m unittest discover -s eval/tests -p 'test_*.py' -v
```

## Held-out result

The policy and metrics were developed on `dev` only. Gemini's dev exact agreement
was 19/21, below the 20/21 single-run threshold, so the pre-specified protocol
required three held-out rounds. Policy v1.1 was then applied unchanged to every
round. The model decisions and runtime results were identical across all three
rounds.

For the two held-out high-consequence miscalibrations, `consequence_gate` routes
2/2 at 10/20 review and `safety_first` routes 2/2 at 13/20 review. As on dev, this
is enforcement of the action gate rather than independent classification accuracy.

For the broader target of all eight C2/C4 failures:

| Profile | TP | FP | FN | Recall | Precision | Human review |
|---|---:|---:|---:|---:|---:|---:|
| `integrity_only` | 2 | 1 | 6 | 25.0% | 66.7% | 3/20 (15.0%) |
| `consequence_gate` | 4 | 6 | 4 | 50.0% | 40.0% | 10/20 (50.0%) |
| `safety_first` | 6 | 7 | 2 | 75.0% | 46.2% | 13/20 (65.0%) |

The held-out result confirms the limitation already visible on dev: generic
deterministic rules can enforce contracts and consequence gates, but they do not
recover all semantic evidence-sufficiency errors. No policy change may now replace
the v1.1 held-out result; a changed policy would require a new version and a new
study.

## Claims and limitations

Supported claims:

- the component is deployable without case ground truth or additional model calls;
- it reliably checks explicit contracts and routes decisions according to a frozen
  generic policy;
- the dev experiment quantifies its recall/workload trade-off against A4.

Unsupported claims:

- a policy `pass` proves evidence sufficiency or factual correctness;
- the runtime layer reproduces A4 without GT;
- the runtime layer automatically corrects the LLM output;
- the output recommendation was actually executed autonomously;
- the dev 7/7 result guarantees perfect held-out or production recall;
- the structurally aligned 7/7 policy-coverage result is independent evidence of
  classification accuracy;
- the small purposive benchmark estimates production prevalence.

Policy v1.0 and its reports remain as the initial dev freeze. Version 1.1
superseded it before any held-out runtime evaluation; the change is recorded
rather than silently replacing the earlier result.
