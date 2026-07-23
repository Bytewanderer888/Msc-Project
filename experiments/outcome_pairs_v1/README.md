# Outcome-confirmation pairs (v1)

A controlled within-scenario contrast asking the question the condition-level benchmark
cannot: **does the model's assessment actually track evidence *sufficiency*, or does it
merely react to the presence of alarming activity?**

Each pair takes a frozen benchmark case whose maliciousness rests on one decisive
**outcome** event (the configured service binary actually executing, the LSASS dump file
actually appearing, the log actually clearing, …) and builds two neutral-id packages:

- **base** — the outcome event removed: the same setup/precursor evidence, now
  under-supported (expected: `suspicious / low–medium / monitor–investigate`);
- **strong** — the outcome event present (expected: `malicious / high–critical /
  escalate–isolate`).

Shared events are byte-identical between versions; the *sole* manipulated factor is the
predeclared outcome evidence. A sufficiency-sensitive model lands in both bands; a model
running on pattern-alarm gives the same answer twice.

## Experimental design (see `manifest.private.json`)

- 4 outcome-confirmation pairs: OC1 (SVC-001), OC2 (UQP-001), OC5 (RUN-001),
  and OC6 (AMQ-001). These are the completed outcome arm of the controlled paired study.
- Primary endpoint: both versions inside their predeclared bands. Secondary: directional
  movement, citation of the added outcome evidence, confidence delta (exploratory).
- Predeclared exclusions: PS-004, WMI-002-derivation, DISC-002/SMB-002 (different construct).
- The manifest carries expected bands — **analyst-side only, never model-visible**.
- The frozen benchmark is not modified by this experiment (sources verified by sha256).

## Files

- `manifest.private.json` — the pre-registered design (pairs, bands, analysis sets).
- `packages/QE-*.json` — 8 neutral-id model-visible packages.
- `outputs/<provider>__<model>/` — per-case outputs + `usage.retained.jsonl` provenance.
- `score_pairs.py` — integrity audit (source hashes, within-pair byte-diff, leak gate)
  + predeclared-endpoint scoring. Run this before interpreting anything.
- `run_pairs.py` — runs missing cases with the frozen A2 evidence prompt at benchmark
  settings (temp 0, thinking off). Skip-existing.
- `RUN_CONFIG.json` — verified prompt/config hashes for the completed run.
- `provenance/run_safesoc_outcome_pairs_v1.original.py` — retained original primary runner.

## Status (2026-07-19)

- Integrity audit: **clean** (all hashes match, shared events byte-identical, strong-extras
  == declared outcome events, zero leak-regex hits).
- **Completed run** (gemini-2.5-flash, 2026-07-18): endpoint met **1/4** (OC5).
  Directional movement 3/4. Added outcome evidence cited in **4/4** strong rationales.
  - OC1: direction right; base over-called at `high` severity.
  - OC2: base in-band; **strong under-called** (`suspicious/high/investigate`).
  - OC5: full pass (`suspicious/low` → `malicious/high/isolate`, conf 0.6→0.9).
  - OC6: **identical `malicious/high/isolate` @0.9 for both versions** — zero sensitivity;
    the base rationale infers execution from a command-line mention.
  - Reading: the model *sees and uses* added outcome evidence when escalating, but does
    not calibrate downward when that evidence is absent — asymmetric updating, consistent
    with the benchmark's over-triage finding, now shown within-scenario.
- Run configuration confirmed: `load_prompt("evidence")`, temperature 0, 2,048 output
  tokens, and thinking off. The A2 prompt file was last
  modified on 2026-07-09, before the primary run; hashes are recorded in RUN_CONFIG.json.

## Commands

```bash
python3 experiments/outcome_pairs_v1/score_pairs.py                    # audit + scores, offline
python3 experiments/outcome_pairs_v1/run_pairs.py                      # dry-run; currently 0 missing
```
