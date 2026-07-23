# Evaluation deepening v1 results

This analysis reuses the frozen A2/A4 reports. It makes no provider calls and does not modify packages, ground truth, or saved outputs.

## Primary held-out results

| Model | C2 joint | Wilson 95% CI | A4 all-pass | Wilson 95% CI |
|---|---:|---:|---:|---:|
| gemini-2.5-flash | 12/20 (60.0%) | 38.7%-78.1% | 12/20 (60.0%) | 38.7%-78.1% |
| claude-sonnet-4-6 | 11/20 (55.0%) | 34.2%-74.2% | 11/20 (55.0%) | 34.2%-74.2% |

C2 remains the headline endpoint. Ordinal distance adds error magnitude: zero is in-band, positive is over-triage, and negative is under-triage.

### Ordinal error magnitude

| Model | Field | In band | Mean signed distance | Mean absolute distance | Errors >=2 steps |
|---|---|---:|---:|---:|---:|
| gemini-2.5-flash | verdict | 13/20 (65.0%) | +0.100 | 0.400 | 1/20 |
| gemini-2.5-flash | severity | 13/20 (65.0%) | +0.250 | 0.450 | 1/20 |
| gemini-2.5-flash | action | 13/20 (65.0%) | +0.150 | 0.450 | 1/20 |
| claude-sonnet-4-6 | verdict | 14/20 (70.0%) | +0.200 | 0.300 | 0/20 |
| claude-sonnet-4-6 | severity | 11/20 (55.0%) | +0.350 | 0.450 | 0/20 |
| claude-sonnet-4-6 | action | 14/20 (70.0%) | +0.250 | 0.350 | 1/20 |

### Condition breakdown (descriptive)

| Model | Condition | n | C2 joint | Mean signed severity distance | Mean signed action distance |
|---|---|---:|---:|---:|---:|
| gemini-2.5-flash | strong | 8 | 6/8 (75.0%) | -0.125 | -0.250 |
| gemini-2.5-flash | weak | 6 | 3/6 (50.0%) | +0.167 | +0.000 |
| gemini-2.5-flash | missing | 4 | 3/4 (75.0%) | +0.250 | +0.250 |
| gemini-2.5-flash | counter | 2 | 0/2 (0.0%) | +2.000 | +2.000 |
| claude-sonnet-4-6 | strong | 8 | 7/8 (87.5%) | -0.125 | -0.125 |
| claude-sonnet-4-6 | weak | 6 | 2/6 (33.3%) | +0.667 | +0.500 |
| claude-sonnet-4-6 | missing | 4 | 1/4 (25.0%) | +0.750 | +0.500 |
| claude-sonnet-4-6 | counter | 2 | 1/2 (50.0%) | +0.500 | +0.500 |

Macro condition averages are descriptive only: they give the small counter stratum the same weight as larger strata.

## Paired model comparison

On the same 20 held-out cases, the paired C2 risk difference (Gemini minus Claude) is +0.050 with bootstrap 95% CI [-0.200, +0.300].
The discordant counts are 4 Gemini-only correct and 3 Claude-only correct; exact two-sided McNemar p = 1.000.
The interval is wide and the paired test does not establish a reliable model advantage; report the observed difference without claiming superiority.

## Three-round stability

| Model | Split | Verdict | Severity | Action | Full tuple | One-field changes | Multi-field changes |
|---|---|---:|---:|---:|---:|---:|---:|
| gemini-2.5-flash | dev | 100.0% | 95.2% | 90.5% | 90.5% | 1 | 1 |
| gemini-2.5-flash | heldout | 100.0% | 100.0% | 100.0% | 100.0% | 0 | 0 |
| claude-sonnet-4-6 | dev | 100.0% | 100.0% | 90.5% | 90.5% | 2 | 0 |
| claude-sonnet-4-6 | heldout | 100.0% | 95.0% | 65.0% | 60.0% | 8 | 0 |

## Runtime uncertainty (Gemini A2 round 1)

| Split | Profile | Recall | Wilson 95% CI | Human review | Wilson 95% CI | Unrouted calibration errors |
|---|---|---:|---:|---:|---:|---:|
| dev | consequence_gate | 7/12 (58.3%) | 31.9%-80.7% | 14/21 (66.7%) | 45.4%-82.8% | 5 |
| dev | safety_first | 11/12 (91.7%) | 64.6%-98.5% | 19/21 (90.5%) | 71.1%-97.4% | 1 |
| heldout | consequence_gate | 4/8 (50.0%) | 21.5%-78.5% | 10/20 (50.0%) | 29.9%-70.1% | 4 |
| heldout | safety_first | 6/8 (75.0%) | 40.9%-92.8% | 13/20 (65.0%) | 43.3%-81.9% | 2 |

## Validator conformance

All 14/14 controlled mutation scenarios produced the predeclared C1-C4 vector.
The suite covers order/confidence/prose invariance, fabricated IDs, unsupported decode claims, verdict and severity changes, counter-citation removal, action changes, and a combined C2+C4 failure.
It tests deterministic implementation behaviour only; semantic truthfulness remains a manual audit boundary.

## Interpretation guardrails

- Held-out round 1 is the primary model comparison; rounds 2 and 3 are stability repetitions, not independent samples.
- Wilson and bootstrap intervals expose the uncertainty caused by 20 held-out cases.
- Verdict, severity, and action distances stay separate; no arbitrary composite score is introduced.
- Confidence remains exploratory and does not affect C1-C4.
- C1/C3 do not provide broad semantic natural-language verification.
