# Evidence-Sufficiency Rubric — v1.0 (FROZEN 2026-07-06)

**Status:** v1.0 — **FROZEN 2026-07-06** (§10 = freeze record; §9 = the v0.3→v0.4 changelog). Developed + tuned
*only* on the dev split (see §8); this is the frozen specification against which the deterministic **validator**
(`eval/validator.py`) scores an LLM's triage verdict, relative to the evidence the neutral `alert_package.json`
actually contains. No check logic, band, or scoring rule changes after this line — held-out is annotated and run
**once** against this spec.

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

**C1 — Grounding.** `key_evidence` must be a non-empty subset of the package's valid IDs — `A0`, `EV-xxx`,
**and `DER-xxx`** (derivations are trustworthy grounding, so citing a decoded field is legitimate — v0.4 fix,
after PS-001 correctly cited `DER-001`). The verdict must rest on evidence that is *present*. For **missing**
cases especially, the LLM must not assert an outcome the package does not contain (e.g. "the DLL executed",
"the account was used") — the ground-truth's `must_not_assert` list names these. **v0.4 adds a
rationale-fabrication check:** if the rationale claims decoded/encoded content but the package carries *no*
`deterministic_derivations`, the model invented it — a grounding violation (this caught ACCT-001, where Gemini
fabricated an "Invoke-AtomicTest decoded" command absent from the package). **And a false-certainty check:** in
a non-strong case (evidence insufficient to confirm malice), a rationale asserting a compromising *outcome*
(dump / execute / compromise / inject …) with *certainty* words (confirmed / clearly / proven) and no hedge is
over-asserting — this caught LS-002, which branded a legitimate signed `createdump.exe` a *"confirmed attempt at
OS credential dumping."* Hedged over-reads ("indicative of", "no successful login is evidenced") are correctly
**not** flagged; the calibration check C2 handles those.

**C2 — Severity calibration (bidirectional).** Compare the LLM `severity` to the ground-truth
`acceptable_severity` band.
- LLM band **above** the band → **over-call** → validator recommends **down-rank**.
- LLM band **below** the band → **under-call** → validator recommends **up-rank**.
- In band → calibrated (**preserve**).

**C3 — Counter-evidence handling.** If ground-truth lists `counter_evidence`, the LLM must acknowledge it —
cite it in `key_evidence` *and* have its verdict/severity reflect it. Rating a case malicious/high while a
counter set exists and is unaddressed → **counter-evidence-ignored** flag.

**C4 — Action-proportionality.** `recommended_action` must not exceed the ground-truth `proportional_action`
ceiling (e.g. `isolate`/`escalate` for a benign/low counter case = over-action; `close_benign` for a strong
case = under-action). **v0.4:** for **strong** (confirmed-compromise) cases the ceiling is `isolate` — both
`escalate` and `isolate` are proportional to a confirmed TP — so the check bites only on the weak / missing /
counter cases where the model reaches past `investigate`.

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
  "annotated_by": "...", "rubric_version": "1.0"
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

## 7. Resolved decisions (v0.3 → v0.4)
1. **Severity scale:** 5 bands (`informational … critical`). Kept — counter cases need a benign floor
   (`informational`/`low`) distinct from weak/missing (`low`/`medium`).
2. **Grounding (C1):** v0.3 = `key_evidence` subset-validity + a `must_not_assert` list. **v0.4** extends it:
   `DER-xxx` derivations count as valid grounding, and the rationale is checked for the fabrication pattern
   (asserting decoded content with no derivation present). Full LLM-as-judge claim-checking remains future
   work; the deterministic heuristic catches the observed dev failure (ACCT-001).
3. **weak vs missing:** same `low–medium` band; they are separated by the **checks**, not the band — missing
   adds the C1 `must_not_assert` test (don't invent the absent outcome), weak does not.
4. **Action ladder:** the LLM emits the 5-step `close_benign … isolate` action; the validator's **headline
   output** is the calibration direction (**down-rank / preserve / up-rank**) plus the C4 proportionality flag.
5. **Strong-case action ceiling (v0.4):** raised to `isolate` — for a confirmed compromise both `escalate`
   and `isolate` are proportional, so C4 no longer false-positives on strong cases.

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

## 9. Changelog — v0.3 → v0.4 (what the dev run revealed)

Ran Gemini (`gemini-2.5-flash`, temperature 0) on all 12 dev packages, then the v0.3 validator. Three findings
drove v0.4 — each a *validator* fix surfaced by real model output, not a change to any case or ground-truth:

| # | dev evidence | v0.3 behaviour | v0.4 change |
|---|---|---|---|
| 1 | PS-001 cited `DER-001` (the decoded command) — legitimate grounding | C1 **false fail** (only `A0`/`EV` allowed) | C1 accepts `DER-xxx` |
| 2 | ACCT-001 rated *benign* by asserting an "Invoke-AtomicTest decoded" command **absent** from the package | C1 **missed** the fabrication (cited ids were valid) | C1 flags "decoded/encoded content, no derivation present" |
| 3 | strong INJ-001 / ST-002 recommended `isolate` (proportional for a confirmed TP) | C4 **false fail** (ceiling `escalate`) | strong ceiling raised to `isolate` |
| 4 | LS-002 branded a legitimate signed tool a *"confirmed"* credential dump — false certainty, not just severity | C1 **missed** it (only ids + fabrication checked) | C1 adds a false-certainty check (outcome + certainty + no-hedge, non-strong cases) |

**Model behaviour observed (real, unchanged — the validator's payload).** Gemini calibrates **strong (4/4)**
and **counter (2/2)** correctly, but **over-triages every weak case (3/3) and 2/3 missing** — inflating
unconfirmed indicators (a download cradle, a legitimate `createdump`, an RDP flood, a staged-but-unexecuted
DLL) to malicious / high–critical — and **under-triages ACCT-001** by fabricating a benign attribution. On the
12 dev cases the v0.4 validator flags all **six** miscalibrations (5 over-call → down-rank, 1 under-call →
up-rank), **two grounding violations** (C1: ACCT-001's fabrication + LS-002's false certainty), the **ignored
counter-evidence** (C3, PS-001), and the **four** over-actions (C4), while passing all 4 strong + 2 counter
cases with no false positives.

**Freeze readiness.** The four checks now fire correctly on all 12 dev cases with no false positives. A final
review pass decides whether **v0.4 is the freeze candidate → v1.0**, after which held-out is annotated
and run once (see §10 — frozen 2026-07-06).

## 10. Freeze record — v1.0 (frozen 2026-07-06)

**v1.0 = the v0.4 spec, frozen.** No check logic, band, `must_not_assert` policy, or scoring rule changed
between v0.4 and v1.0 — the four checks converged during the 12-case dev-iteration loop (§9), and this freeze
locks that spec so held-out can be scored once, blind. The reference implementation is `eval/validator.py`
(banner "v1.0"; logic unchanged from v0.4).

**What is frozen:** §0–§7 in full — the four checks (C1 grounding incl. `DER-xxx` + fabrication + false-certainty;
C2 bidirectional calibration; C3 counter-evidence; C4 action-proportionality with the strong = `isolate` ceiling),
the evidence-condition → behaviour table (§3), the ground-truth schema (§4), and the severity/action orderings.

**Dataset at freeze.** The dev split grew from 12 → **21** cases; held-out is **20**. Coverage is cross-corpus —
attack_data (Splunk-authoritative) + OTRF Security-Datasets (built-direct) — with both corpora spanning all four
evidence conditions. All 21 dev `ground_truth.json` are annotated under v1.0 (12 carried over from the v0.3/v0.4
loop, still valid; 9 added for the new dev cases). Held-out packages remain **sealed** — never opened for tuning.

**Freeze-confirmation pass (gate before held-out opens).** Because the dev split expanded *after* the checks
converged, v1.0 is *confirmed*, not *re-developed*, by one pass: run the model(s) on all 21 dev packages and run
`eval/validator.py --split dev`, verifying the four checks still fire with **no false positives** on the 9 added
cases (same conditions/roles as the original 12, so no new rule is expected). Only once that pass is clean is
held-out (20 cases) annotated — blind, from the packages + researcher intent, without looking at any model
output — and run **once**. Any check change the confirmation pass were to force would reopen the freeze as v1.1
(not expected).

**Multi-model evaluation.** The frozen validator is model-agnostic. Dev + held-out are run on ≥2 LLMs — Gemini
(free tier) and an Anthropic Claude tier (e.g. Claude Sonnet 4.6 / Haiku 4.5) — via `eval/run_model.py`, which
writes per-model outputs to `eval/outputs/<model_tag>/<split>/`. The reported metrics are therefore the
validator's behaviour *across models*, not one model's idiosyncrasy.
