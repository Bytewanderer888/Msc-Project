# SafeSOC validation workbench

A local, interactive SOC validation workbench. Select a case from the frozen 41-case
benchmark, inspect the neutral alert package, review a saved LLM triage output, and run the
**real** ground-truth-free runtime validator against it — then, separately, open Research mode
to compare the same output with the frozen ground truth under the A4 evaluator.

It is a working tool, not a results slideshow, and it demonstrates the deployable pipeline:

```
raw security telemetry
      ↓  reproducible retrieval + normalization
neutral alert package
      ↓  LLM SOC triage (replayed from saved outputs)
ground-truth-free runtime policy validation
      ↓
pass / human review / block
```

A separate research-only path compares the same output against A4 and the benchmark ground
truth. It is never presented as part of the deployable runtime.

## Run it

```bash
python3 demo/build_snapshot.py     # index cases, outputs, evaluations and current usage logs
python3 demo/server.py             # then open http://localhost:8765
```

`build_snapshot.py` only needs re-running when cases, model outputs, evaluator logic, usage
logs, or the offline evaluation-deepening results change. It writes a runtime-neutral startup
index and a separate research payload.

## The two validation modes

|  | Runtime validation | Offline research evaluation |
|---|---|---|
| Purpose | **Deployable** post-hoc check | Benchmark measurement + explanation |
| Reads | neutral `alert_package`, LLM output, frozen generic policy | adds `annotations/ground_truth.json` |
| Module | `eval/runtime_validator.py` (`validate_runtime_case`) | `eval/validator_v1_1.py` (`validate_case`) |
| Endpoint | `POST /api/validate` | `GET /api/research` |
| Output | `pass` / `review` / `block`, findings, signals, routing profile | C1–C4, calibration direction, expected band |
| Token cost | **0** | 0 |

**What a runtime `pass` means:** no machine-verifiable policy problem was found. It does **not**
prove the verdict is factually correct or the evidence sufficient. The drawer states this on
every result, using the policy's own `non_claims`.

The separation is enforced, not just documented. `demo/test_separation.py` instruments every
file read while `/api/validate` runs and fails if any annotation or ground-truth file is
touched. It also verifies that the startup snapshot contains no evidence condition, A4 sweep,
dashboard, research preset, or condition-bearing repository path:

```bash
python3 demo/test_separation.py
```

## Using the workbench

- **Left — case queue.** Filter by tier/split or search by id/dataset/sensor. Case titles are not
  exposed at startup because names such as `routine` or `false positive` can reveal the answer.
  Cases are ordered by id rather than by condition-bearing repository path. The evidence-condition filter
  appears only after Research mode, Dashboard, or **Scenarios** is explicitly opened. It is
  tagged `research` and is never sent to the runtime validator.
- **Centre — alert package.** The triggering alert `A0`, then contextual evidence `EV-xxx` on a
  chronological timeline, then any deterministic derivations `DER-xxx` (shown with a dashed
  marker). Items cited by the current model output are highlighted.
- **Right — LLM triage output.** Verdict, severity, confidence, key evidence, rationale, and
  recommended action. Switch **model**, **arm** (A1 basic / A2 evidence), and **round** to
  inspect stability across repeated runs of the same input.
- **Validate.** Choose a routing profile, then run the real validator. Keyboard: `v`.
- **Runtime validation view.** Validation opens in the right panel with status, triggered policy
  findings, routing signals, outcomes under every profile, and neutral runtime-input identities.
- **Research mode** (tab, or `Esc` to leave). Ground truth, C1–C4, calibration direction, and
  the expected decision — clearly marked as offline-only.
- **Dashboard** (tab). Model performance, held-out Wilson intervals and paired comparison,
  the separate 16-case external replication comparison, signed ordinal error magnitude,
  runtime recall/review uncertainty, behaviour by evidence condition, field-level stability
  across rounds, and token usage/cost. The replication panel reads the frozen Gemini/Claude
  A4 reports and usage logs directly; it is not pooled into the canonical 41-case benchmark.
  The additional depth statistics are loaded from
  `experiments/evaluation_deepening_v1/RESULTS.json`. Everything on this dashboard remains
  research-only.

### Demonstration presets

Click **Scenarios** to opt into the research snapshot, then use the scenario selector
to jump to curated scenarios. They are selected from the data by `build_snapshot.py`, not
hand-asserted, so they stay true if results change:

| Preset | What it shows |
|---|---|
| Correctly calibrated strong case | Decisive evidence, in-band decision — the system is not merely pessimistic |
| Over-triage on insufficient evidence | The dominant failure mode |
| Counter case — benign context should lower it | Decisive benign context present, decision does not come down |
| Under-triage of a strong case (UQP-001) | The mirror failure |
| High-consequence action routed for human approval | The policy gating a disruptive action it cannot verify |
| **Passes runtime validation, fails A4** | The honest limit of a ground-truth-free layer |

The workbench therefore **opens on that state**: first case (ACCT-001), Gemini 2.5 Flash, A2, round 1.
If a case has no Gemini output the model falls back to Claude, then to whatever is saved.

The last preset is the point of the whole tool: ACCT-001 under Gemini is well-formed, its
citations resolve, and verdict/severity/action are internally consistent — so the runtime
policy passes it with zero findings — yet A4 shows it fails C2 and C4, over-triaged in all
three directions. (Switch the routing profile to `safety_first` and the same output *is* routed
for review: the profile choice is a deployment trade-off, not a correctness fix.)

## Model execution

Saved outputs are replayed from `eval/outputs/`. No provider is called, so demonstrations are
deterministic, cost nothing, carry no quota risk, and match the thesis results exactly. A
live-model mode is deliberately out of scope.

## Files

```
demo/
├── server.py            local service; invokes the real validators
├── build_snapshot.py    indexes runtime/research views; reads cost + offline depth analysis
├── index.html           workbench shell
├── app.js               panels, validation calls, research mode, dashboard
├── styles.css           tokens + layout (light default, dark toggle)
├── assets/              local SafeSOC brand image
├── test_separation.py   enforces the runtime/research boundary
├── snapshot.json        generated runtime-neutral startup payload
└── research_snapshot.json  generated GT/A4 payload; loaded only on explicit research access
```

The demo explicitly loads `eval/runtime_policy_v1.2.json`. This is a maintenance release over
the frozen v1.1 experiment policy: it removes the over-broad phrase `decoded content` from the
R012 matcher while preserving all routing profiles and thresholds. Specific unsupported claims
such as `decoded payload` remain blocked. The frozen v1.1 reports are not rewritten.
