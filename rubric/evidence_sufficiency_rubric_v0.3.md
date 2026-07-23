# Evidence-Sufficiency Rubric — v0.3 (DRAFT, developed on dev)

**Status:** v0.3 working draft — **NOT frozen**. Developed + tuned *only* on the 12 dev cases (see §8);
frozen to v1.0 *after* the dev-iteration loop (including running Gemini on dev), before held-out is ever opened.
This rubric defines what the deterministic **validator** checks about an LLM's triage verdict, relative to
the evidence the neutral `alert_package.json` actually contains.

## 0. The one principle

> **A triage verdict's confidence must not exceed — nor fall below — what the evidence supports.**

Two symmetric failures, both errors:
- **Over-triage** — asserting a compromise the evidence does not confirm (weak / missing / counter cases).
- **Under-triage** — dismissing a real, evidenced compromise because its surface looks benign (subtle-strong cases).

The validator's job is not to decide "is this malicious?" from scratch — it is to check whether the LLM's
claim is *warranted by the package*, and to nudge severity toward the evidence-justified band.

## 1. I/O contract

**Input to the LLM:** exactly one `alert_package.json` (A0 + EV-xxx + derivations; no severity, verdict,
technique, or role — those are stripped/neutralised).

**Required LLM output** (structured JSON, so the validator can parse it deterministically):
```json
{
  "verdict":            "malicious | suspicious | benign",
  "severity":           "critical | high | medium | low | informational",
  "confidence":         0.0-1.0,
  "key_evidence":       ["A0", "EV-003", ...],     // evidence IDs the verdict rests on
  "rationale":          "free text, should reference evidence ids",
  "recommended_action": "isolate | escalate | investigate | monitor | close_benign"
}
```
Severity ordering (for band comparison): `informational < low < medium < high < critical`.
Action ordering (proportionality): `close_benign < monitor < investigate < escalate < isolate`.

## 2. The four validator checks

Each check yields **pass / flag** + a short reason; per-case they aggregate to a verdict-quality score.

**C1 — Grounding.** `key_evidence` must be a non-empty subset of the package's evidence IDs (no fabricated
ids). The verdict must rest on evidence that is *present*. For **missing** cases especially, the LLM must not
assert an outcome the package does not contain (e.g. "the DLL executed", "the account was used"): the
ground-truth's `must_not_assert` list names these; asserting one is a grounding violation.

**C2 — Severity calibration (bidirectional).** Compare the LLM `severity` to the ground-truth
`acceptable_severity` band.
- LLM band **above** the band → **over-call** → validator recommends **down-rank**.
- LLM band **below** the band → **under-call** → validator recommends **up-rank**.
- In band → calibrated (**preserve**).

**C3 — Counter-evidence handling.** If ground-truth lists `counter_evidence`, the LLM must acknowledge it —
cite it in `key_evidence` *and* have its verdict/severity reflect it. Rating a case malicious/high while a
counter set exists and is unaddressed → **counter-evidence-ignored** flag.

**C4 — Action-proportionality.** `recommended_action` must not exceed the action justified by the
ground-truth severity (e.g. `isolate`/`escalate` for a benign/low counter case = over-action; `close_benign`
for a strong case = under-action).

## 3. Evidence-condition → correct behaviour (the calibration table)

| Condition | Correct verdict | Acceptable severity | Role | The trap the case catches | Validator fires | dev exemplars |
|---|---|---|---|---|---|---|
| **strong** (overt) | malicious | high–critical | **preserve** | unnecessarily downgrading a confirmed TP ("just a tool") | under-call → up-rank | LS-001, INJ-001, AMQ-001 |
| **strong** (subtle) | malicious | high–critical | **up-rank** | benign-looking surface hides a real compromise | under-call → up-rank | ST-002 |
| **weak** | suspicious | low–medium | **down-rank** | inflating an *attempt/indicator* into a "confirmed breach" | over-call → down-rank | PS-002, LS-002, BF-001 |
| **missing** | suspicious | low–medium | **down-rank** | fabricating the *absent* confirming outcome | over-call → down-rank **+ C1 grounding** | PS-001, ING-001, ACCT-001 |
| **counter** | benign | informational–low | **down-rank** | ignoring benign counter-evidence, flagging routine activity | over-call → down-rank **+ C3** | ST-003, SMB-002 |

Notes:
- **weak vs missing** share a severity band but differ in *why*: weak has real-but-insufficient indicators
  (the model must not over-read them); missing has the confirming evidence *absent* (the model must not
  invent it — C1). SMB-002/ST-003 differ from weak in that the package carries *contradicting* evidence (C3).
- The band is a **range**, not a point (severity is a judgement); the validator only fires when the LLM lands
  outside the range.

## 4. Ground-truth = the answer key (one per case, built after freeze)

Each case gets an `annotations/ground_truth.json` derived from this rubric:
```json
{
  "case_id": "...",
  "evidence_condition": "strong | weak | missing | counter",
  "calibration_role":   "preserve | up_rank | down_rank",
  "correct_verdict":    "malicious | suspicious | benign",
  "acceptable_severity": ["low","medium"],          // the band C2 checks against
  "grounding": {
    "supporting_evidence": ["A0","EV-001"],          // ids that warrant the correct verdict
    "counter_evidence":    ["EV-003"],               // benign/contradicting ids the LLM must heed (C3)
    "must_not_assert":     ["payload executed","dll loaded"]   // absent facts (C1, mainly for missing)
  },
  "proportional_action": "investigate",              // the ceiling C4 checks against
  "the_trap":   "one line: the specific over/under-triage failure this case probes",
  "rationale":  "annotator's justification (evidence -> verdict), tied to this rubric",
  "annotated_by": "...", "rubric_version": "0.3"
}
```

**Worked example — ST-003 (counter, dev):** a `.bat` run as SYSTEM + SYSTEM auto-updaters *look* like malware
persistence, but the command paths are `C:\Program Files\Npcap|Aurora-Agent|Mozilla` (known vendors).
```
correct_verdict = benign ; acceptable_severity = [informational, low] ; role = down_rank
supporting_evidence = []  ; counter_evidence = [A0, EV-001, EV-002, EV-003]  (the vendor paths/authors)
proportional_action = close_benign ; the_trap = "SYSTEM .bat looks like persistence; vendor path is decisive benign"
```
An LLM that answers `malicious / high / recommended_action=isolate` fails **C2** (over-call → down-rank),
**C3** (ignored the vendor counter-evidence), and **C4** (over-action).

## 5. Per-category notes (technique-specific evidence expectations — light)

These help the annotator decide the band; they do not add checks.
- **LSASS (T1003):** a *completed dump* by a dumping tool (comsvcs/mimikatz/xordump) = strong; a legit tool
  (createdump/taskmgr) or a handle-open with no dump = weak/subtle.
- **Brute force (T1110):** failed logons / connection flood with **no 4624 success** = weak; success from the
  spray source = strong.
- **Discovery (T1087):** recon commands with **no follow-on** (cred access / lateral / exec) = weak.
- **Ingress (T1105) / Account (T1136) / Service (T1543):** an alarming setup (download / new account / new
  service) whose payload is benign/absent or is reverted/deleted with **no execution or use** = missing.
- **Persistence surface vs payload:** the *creation* of a task/service/run-key/account is not itself the
  compromise — the confirming malicious *payload/outcome* is. Absence of the latter caps severity.

## 6. Scoring & metrics (per case → dataset)

Per case, from the 4 checks:
- **Calibration** (C2): over / in-band / under — the headline metric (does the validator move severity the
  right direction?).
- **Grounding rate** (C1), **counter-heed rate** (C3), **action-proportionality rate** (C4): booleans.

Dataset metrics (reported per condition × split, on **held-out** for the final numbers):
- % correctly calibrated; over-triage rate (weak/missing/counter); under-triage rate (subtle-strong);
- grounding-violation rate; counter-ignored rate.
The **validator's value** = it flags the mis-calibrations the raw LLM makes, per condition.

## 7. Resolved decisions (v0.3)
1. **Severity scale:** 5 bands (`informational … critical`). Kept — counter cases need a benign floor
   (`informational`/`low`) distinct from weak/missing (`low`/`medium`).
2. **Grounding (C1):** v0.3 = `key_evidence` subset-validity + a `must_not_assert` list (fully deterministic).
   Rationale claim-checking (LLM-as-judge) is **deferred to v0.4**, once we see how Gemini actually phrases its
   rationale on dev (so we build the check to real output, not a guess).
3. **weak vs missing:** same `low–medium` band; they are separated by the **checks**, not the band — missing
   adds the C1 `must_not_assert` test (don't invent the absent outcome), weak does not.
4. **Action ladder:** the LLM emits the 5-step `close_benign … isolate` action; the validator's **headline
   output** is the calibration direction (**down-rank / preserve / up-rank**) plus the C4 proportionality flag.

## 8. Development & freeze protocol — *the rubric is NOT frozen yet*

v0.3 is a working draft. The **dev** split exists precisely to develop and stress-test this rubric against real
model behaviour *before* the held-out test. The loop:

1. **Annotate dev `ground_truth.json`** with v0.3. This alone tests the rubric: if a dev case can't be annotated
   cleanly, the rubric has a gap → refine it.
2. **Run Gemini** on the 12 dev packages → **run the validator** → inspect: do the four checks fire correctly?
   are the bands right? does C1 catch a fabricated outcome? does C2 move severity the right direction?
3. **Refine** the rubric (v0.4, v0.5 …) on what dev reveals — adjust bands, `must_not_assert` lists, thresholds,
   and (v0.4) add rationale grounding.
4. **Repeat** until the four checks are stable on dev.
5. **Freeze → v1.0**, and *only then* annotate + run **held-out** — the single, unbiased evaluation.

"Freeze before held-out" protects **held-out's** integrity; it does **not** mean freezing before we've tuned on
dev. Held-out packages are never opened until v1.0 is frozen. (This is also why dev is required to contain every
condition × role: every rule must be developable on dev before freeze.)
