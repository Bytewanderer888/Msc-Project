# Evidence-Sufficiency Rubric — v1.1 frozen final specification

**Status:** frozen for final scoring on 2026-07-16, after the final evidence-condition and raw-source
audits and before the final v1.1 replacement/repeated held-out scoring phase. Earlier exploratory or
superseded outputs are not presented as final v1.1 results. Developed from the v1.0 implementation audit
and development-set error analysis; the rules below are condition-level rules, not case-specific patches.

v1.0 remains preserved in `evidence_sufficiency_rubric_v1.0.md`. v1.1 initially re-scored the same saved
model outputs. A pre-freeze evidence audit subsequently corrected two held-out service cases and removed
redundant test-harness parent commands from their packages; those changed packages were re-run before
final scoring.

A second pre-freeze boundary audit on 2026-07-15 corrected ST-002 from strong to missing because its
package records only `schtasks /Create` process invocation, not successful task registration or firing.
WMI-002 was corrected from missing to strong because Sysmon EID 19/20/21 `Operation=Created` directly
records the installed consumer, filter, and binding. This paired correction preserves the development-set
condition counts and applies the same command-versus-observed-outcome rule across the benchmark. ST-002's
model input is unchanged and needs only offline re-scoring; WMI-002's answer-revealing subscription name
was redacted, so that case was re-run before final scoring.

## 1. Scope

The evaluator is a **ground-truth-backed offline evaluator**. It measures whether an LLM's SOC triage
decision is warranted by the evidence package. It is not a runtime SOC correction system because real
deployment does not provide the ground-truth answer key.

The primary question is bidirectional decision calibration:

- prevent over-triage of weak, missing, and counter-evidence cases;
- prevent under-triage of strong cases;
- separate evidence-reference, decision, counter-evidence, and action failures.

## 2. Output contract

The existing model output remains unchanged:

```json
{
  "verdict": "malicious | suspicious | benign",
  "severity": "critical | high | medium | low | informational",
  "confidence": 0.0,
  "key_evidence": ["A0", "EV-003"],
  "rationale": "free-text justification with evidence IDs",
  "recommended_action": "isolate | escalate | investigate | monitor | close_benign"
}
```

Every decision field has an explicit use:

| Output field | Use |
|---|---|
| `verdict` | C2 verdict alignment |
| `severity` | C2 severity-band calibration |
| `confidence` | exploratory dataset-level confidence analysis |
| `key_evidence` | C1 reference integrity and C3 acknowledgement |
| `rationale` | C1/C3 explicit-ID extraction and qualitative semantic audit |
| `recommended_action` | C4 bidirectional action calibration |

## 3. Fixed condition policy

The same policy applies to development and held-out cases:

| Evidence condition | Correct verdict | Acceptable severity | Acceptable actions |
|---|---|---|---|
| Strong | malicious | high–critical | escalate–isolate |
| Weak | suspicious | low–medium | monitor–investigate |
| Missing | suspicious | low–medium | monitor–investigate |
| Counter | benign | informational–low | close_benign–monitor |

Action and severity are bands because adjacent SOC responses can both be proportionate. The bands are
fixed by condition so they cannot be tuned for individual held-out outputs.

For this controlled attack-telemetry benchmark, **malicious** is a behavioural label: the package decisively
evidences successful execution of an offensive security mechanism or a security-relevant outcome. It does
not claim that the operator was unauthorized in the real world. A case is strong when the mechanism reaches
that decisive outcome (for example, code execution as SYSTEM through a planted service path), even if the
capture comes from an authorized simulation and later shows cleanup. Weak and missing remain appropriate
when only a setup, attempt, or indicator is present and the security-relevant outcome is not evidenced.

## 4. The four deterministic checks

### C1 — Evidence-reference integrity

C1 tests only claims that can be checked deterministically:

1. Every ID in `key_evidence` exists in the package.
2. Every explicit `A0`, `EV-xxx`, or `DER-xxx` ID in the rationale exists in the package.
3. `key_evidence` includes at least one ID designated by ground truth as supporting or counter evidence.
4. An explicit claim about decoded/deobfuscated content requires a deterministic derivation in the package.

C1 does **not** use a broad outcome/certainty word list to claim semantic understanding. Free-text claims
such as “the account was successfully created” or “the task executed” require semantic interpretation.
The GT `must_not_assert` entries are therefore emitted as manual audit prompts and used in qualitative
error analysis, not silently converted into brittle substring rules.

### C2 — Decision calibration

C2 has two reported subchecks:

```text
verdict_pass  = model verdict equals GT correct_verdict
severity_pass = model severity is inside GT acceptable_severity
C2_pass       = verdict_pass AND severity_pass
```

Report verdict accuracy, severity in-band rate, and joint decision accuracy separately. Severity remains
directional: below the band is under-triage, above the band is over-triage. Verdict direction follows
`benign < suspicious < malicious`. `C2_pass` is the primary model endpoint; the stricter C1-C4
all-check pass is reported separately as the overall A4 evaluator outcome.

### C3 — Counter-evidence acknowledgement

C3 applies only when GT lists `counter_evidence`. It passes when at least one counter-evidence ID appears
either in `key_evidence` or explicitly in the rationale.

C3 does not re-check verdict or severity. A model may notice counter-evidence but still weight it badly:
in that case C3 passes and C2 fails. This separation identifies whether the failure is evidence omission
or decision calibration.

### C4 — Bidirectional action calibration

Compare `recommended_action` with the condition-level acceptable action band:

- below the band: under-action;
- inside the band: proportional;
- above the band: over-action.

This replaces v1.0's one-sided ceiling, which could detect excessive action but could not detect a strong
case incorrectly closed as benign.

## 5. Confidence analysis

`confidence` is treated as the model's self-reported certainty in its overall triage decision. It does not
override C1–C4 and is not converted into a per-case pass/fail threshold.

The evaluator reports:

- mean confidence for C2-correct and C2-incorrect decisions;
- exploratory Brier score using joint C2 correctness as the binary outcome;
- count of incorrect decisions with confidence at least 0.8.

Because the original prompt did not explicitly elicit a formally calibrated probability, these are
secondary, exploratory metrics. The thesis must not describe them as a full probabilistic-calibration study.

## 6. Scoring and reporting

No weighted total score is used. Report:

- verdict accuracy;
- severity in-band, over-triage, and under-triage counts;
- joint C2 decision accuracy;
- C1 failure rate;
- C3 acknowledgement rate using only applicable cases as its denominator;
- C4 in-band, over-action, and under-action counts;
- union of cases flagged by the active evaluator components;
- exploratory confidence diagnostics.

The CLI fails closed on missing outputs, missing GT, orphan outputs, schema violations, policy mismatches,
or GT evidence IDs absent from the package. `--allow-incomplete` is only for explicitly exploratory work.

## 7. Component analysis

A1 and A2 remain model runs. A3 and A4 remain deterministic analyses over the saved A2 output:

```text
A1  basic prompt, no evaluator
A2  evidence-aware prompt, no evaluator
A3  A2 output + C1 evidence-reference integrity
A4  A2 output + C1–C4 full offline evaluator
```

A3/A4 measure diagnostic coverage. They do not change model responses and must not be described as
improving model accuracy at runtime.

## 8. v1.0 → v1.1 change record

1. C1 is narrowed to deterministic evidence-reference integrity; broad semantic keyword heuristics removed.
2. C2 now uses both `correct_verdict` and `acceptable_severity`.
3. C3 checks acknowledgement only, avoiding duplicate verdict/severity scoring.
4. C4 changes from a one-sided ceiling to a bidirectional action band.
5. `proportional_action` is replaced by condition-level `acceptable_actions`.
6. Self-reported confidence receives explicit exploratory metrics.
7. Schema validation, fail-closed completeness, JSON/CSV exports, and unit tests become required.
8. The pre-freeze evidence audit clarifies the behavioural meaning of `malicious` and corrects SVC-001 and
   UQP-001 from weak to strong: both packages evidence successful SYSTEM-level execution, not setup alone.
