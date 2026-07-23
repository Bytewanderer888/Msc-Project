#!/usr/bin/env python3
"""
validator.py — the deterministic evidence-sufficiency validator (rubric v1.0, frozen; logic unchanged from v0.4).

Scores an LLM triage output against a case's ground_truth via four checks:
  C1 grounding   — key_evidence are valid ids (incl. DER-xxx); rationale must not fabricate absent evidence
  C2 calibration — LLM severity vs the acceptable band -> over (down-rank) / in-band / under (up-rank)
  C3 counter     — if counter-evidence exists, the LLM must cite it AND land benign/suspicious
  C4 action      — recommended_action must not exceed the proportional ceiling

Run (from SafeSOC/):  python3 eval/validator.py --model <model_tag> --split dev

IMPLEMENTATION FIXES (deterministic re-score only — outputs are never re-run):
  2026-07-14  v1.1 GT compatibility: v1.1 replaces `proportional_action` with `acceptable_actions`.
              When the legacy field is absent, this preserved v1.0 evaluator reconstructs the original
              one-sided ceiling from the evidence condition. The v1.0 scoring rule is unchanged.
  2026-07-14  C1 false positive: merely mentioning a visible encoded command (e.g. "uses an encoded
              command", when the package carries `-encodedcommand` in parent_command_line) was incorrectly
              treated as claiming decoded content. The (a) rule now requires an explicit DECODE_CLAIM
              ("decoded command", "decodes to", "deobfuscated to", ...). Rubric v1.0 logic unchanged.
              Dev effect: gemini A2 C1 2->0 (ACCT-001, RK-001 were observation-only); claude A2 keeps
              ACCT-001 (an explicit ungrounded "decoded command" claim). C2/C3/C4 unaffected.

THE FOUR-ARM ABLATION LADDER
  A1 and A2 are MODEL RUNS (run_model.py). A3 and A4 are THIS validator re-scoring the *same* A2 output with
  a different set of ACTIVE checks (--checks) — deterministic, no model call, so A3/A4 reproduce exactly from
  the committed A2 output files:

    A1  basic prompt,    no validator        python3 eval/run_model.py  --provider gemini --split dev --prompt basic
    A2  evidence prompt, no validator        python3 eval/run_model.py  --provider gemini --split dev
    A3  A2 output + grounding-only  (C1)      python3 eval/validator.py  --model <A2_tag> --split dev --checks C1
    A4  A2 output + full validator  (C1-C4)   python3 eval/validator.py  --model <A2_tag> --split dev

  --checks selects which checks are ACTIVE for the arm's flag/correct decision (default C1,C2,C3,C4 = A4;
  'C1' = A3). Every run prints an "ABLATION ARM" block: the cases the arm flags, the per-check breakdown, and
  (for a subset like A3) the cases it MISSES that the inactive checks would have caught.
"""
import json, argparse, sys, re
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
SEV = ["informational", "low", "medium", "high", "critical"]
ACT = ["close_benign", "monitor", "investigate", "escalate", "isolate"]

# --- C1 rationale-grounding lexicons (v0.4, tuned on dev) ---
# A compromising OUTCOME asserted with CERTAINty and no HEDGE, in a case whose evidence does not
# confirm malice (weak/missing/counter), is an over-assertion -> C1 grounding flag. (§0 operationalised.)
HEDGE   = ("no ", "not ", "n't", "without", "absent", "unconfirm", "potential", "possib", "likely",
           " may ", "might", "could ", "would ", "appears", "indicat", "suggest", "preparation",
           "no successful", "no execution", "no image-load", "no 4624", "no 4625")
CERTAIN = ("confirm", "clearly", "definit", "verified", "proven", "undoubted", " certain")
OUTCOME = ("dump", "exfiltrat", "execut", "compromis", "inject", "backdoor", "lateral movement",
           "command and control", "credential the", "breach", "established persistence")
# An EXPLICIT claim of decoded/deobfuscated content (asserting what an encoded blob decodes to). Merely
# observing that a visible encoded command EXISTS is grounded reporting and must NOT fire (FP fix below).
DECODE_CLAIM = ("decoded command", "decoded payload", "decoded content", "decoded string", "decoded blob",
                "decoded value", "decodes to", "decoded to", "deobfuscated to", "deobfuscates to",
                "deobfuscated command", "deobfuscated payload", "decoding reveals", "upon decoding",
                "after decoding", "base64-decoded", "b64-decoded")

def rationale_flags(rationale, pkg, gt):
    r = rationale.lower(); flags = []
    # (a) fabricated derivation: claims decoded content the package does not carry.
    #     FP fix 2026-07-14 (implementation-level; rubric v1.0 logic unchanged): the v0.4 rule
    #     `("decod" in r or "encoded command" in r)` fired on ANY mention of an encoded command — but in
    #     ACCT-001/RK-001 the package VISIBLY carries `-encodedcommand` in parent_command_line, so stating
    #     that an encoded command exists is a grounded observation, not a fabricated decode (2 dev false
    #     positives). The rule now requires an explicit DECODE_CLAIM. Deterministic re-score only; no re-run.
    if any(p in r for p in DECODE_CLAIM) and not pkg.get("deterministic_derivations"):
        flags.append("asserts decoded content, but the package has no derivation")
    # (b) unwarranted certainty: a confirmed compromising outcome where the evidence is insufficient
    if gt["correct_verdict"] != "malicious":
        for s in re.split(r"(?<=[.!?])\s+", r):
            if any(o in s for o in OUTCOME) and any(c in s for c in CERTAIN) and not any(h in s for h in HEDGE):
                flags.append(f"claims '{next(o for o in OUTCOME if o in s)}' as confirmed, "
                             f"but evidence is insufficient ({gt['evidence_condition']})")
                break
    return flags

def pkg_ids(pkg):
    ids = {pkg["main_alert"]["evidence_id"]} | {e["evidence_id"] for e in pkg["evidence_items"]}
    return ids | {d.get("derivation_id") for d in pkg.get("deterministic_derivations", []) if d.get("derivation_id")}

def validate(pkg, out, gt):
    ids = pkg_ids(pkg)
    # C1 grounding (v0.4: id-validity incl. DER-xxx + rationale must not fabricate / over-assert)
    bad = [k for k in out["key_evidence"] if k not in ids]
    rflags = rationale_flags(out["rationale"], pkg, gt)
    c1 = {"invalid_ids": bad, "rationale_flags": rflags, "pass": (not bad) and (not rflags),
          "must_not_assert": gt["grounding"]["must_not_assert"]}
    # C2 calibration
    li = SEV.index(out["severity"]); band = [SEV.index(s) for s in gt["acceptable_severity"]]
    lo, hi = min(band), max(band)
    direction = "in_band" if lo <= li <= hi else ("over" if li > hi else "under")
    c2 = {"llm": out["severity"], "band": gt["acceptable_severity"], "direction": direction,
          "validator_move": {"over": "down_rank", "under": "up_rank", "in_band": "preserve"}[direction],
          "pass": direction == "in_band"}
    # C3 counter-evidence
    counter = set(gt["grounding"]["counter_evidence"])
    if counter:
        cited = sorted(counter & set(out["key_evidence"]))
        heeded = out["verdict"] in ("benign", "suspicious") and out["severity"] in ("informational", "low", "medium")
        c3 = {"counter_ids": sorted(counter), "cited": cited, "verdict_ok": heeded,
              "pass": bool(cited) and heeded}
    else:
        c3 = {"n/a": True, "pass": True}
    # C4 action-proportionality (strong = confirmed compromise, so isolate is proportional)
    legacy_ceiling = {"weak": "investigate", "missing": "investigate", "counter": "close_benign"}
    ceil = "isolate" if gt["evidence_condition"] == "strong" else gt.get(
        "proportional_action", legacy_ceiling[gt["evidence_condition"]]
    )
    c4 = {"llm": out["recommended_action"], "ceiling": ceil,
          "pass": ACT.index(out["recommended_action"]) <= ACT.index(ceil)}
    return {"C1_grounding": c1, "C2_calibration": c2, "C3_counter": c3, "C4_action": c4}

def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--split", default="dev")
    ap.add_argument("--model", default="gemini-2.5-flash",
                    help="output subdir tag under eval/outputs/ (the model the triage was run on)")
    ap.add_argument("--checks", default="C1,C2,C3,C4",
                    help="ablation arm — which checks are ACTIVE for the flag/correct decision: "
                         "'C1' = arm A3 (grounding-only), 'C1,C2,C3,C4' (default) = arm A4 (full validator)")
    a = ap.parse_args()
    active = [c.strip().upper() for c in a.checks.split(",") if c.strip()]
    if not active or any(c not in ("C1", "C2", "C3", "C4") for c in active):
        sys.exit(f"--checks must be a comma-separated subset of C1,C2,C3,C4 (got {a.checks!r})")
    outdir = HERE / "outputs" / a.model / a.split
    outs = {p.stem: json.loads(p.read_text()) for p in outdir.glob("*.json")}
    if not outs:
        sys.exit(f"no model outputs at {outdir}\n"
                 f"run:  python3 eval/run_model.py --provider <gemini|anthropic> --split {a.split}")
    rows = []
    missing_output, missing_gt = [], []
    for cj in sorted(ROOT.glob(f"tier*/*/{a.split}/*/build/case.json")):
        P = cj.parent.parent
        cid = json.loads(cj.read_text())["case_id"]
        if not (P / "annotations/ground_truth.json").exists():
            missing_gt.append(cid); continue          # case has no answer key yet
        if cid not in outs:
            missing_output.append(cid); continue      # this model produced no triage for this case
        pkg = json.loads((P / "model_input/alert_package.json").read_text())
        gt = json.loads((P / "annotations/ground_truth.json").read_text())
        rows.append((cid, gt, outs[cid], validate(pkg, outs[cid], gt)))

    scored = {cid for cid, *_ in rows}
    orphan_out = sorted(set(outs) - scored - set(missing_gt))   # output files with no matching case in this split
    total = len(rows) + len(missing_output) + len(missing_gt)

    print(f"=== validator v1.0 on {a.model} / {a.split} ({len(rows)}/{total} scored) ===\n")
    if missing_output:
        print(f"!! NO MODEL OUTPUT for {len(missing_output)} case(s) — NOT scored: {sorted(missing_output)}")
        print(f"   re-run:  python3 eval/run_model.py --provider <gemini|anthropic> --split {a.split}")
    if missing_gt:
        print(f"!! NO GROUND_TRUTH for {len(missing_gt)} case(s) — NOT scored: {sorted(missing_gt)}")
    if orphan_out:
        print(f"!! OUTPUT with no matching {a.split} case: {orphan_out}")
    if missing_output or missing_gt or orphan_out:
        print()
    print(f"{'case':9s} {'cond/role':17s} {'GT band':16s} {'LLM sev':13s} {'C2':7s} {'C1':4s} {'C3':4s} {'C4':4s}")
    from collections import Counter
    cal = Counter(); fails = {"C1": 0, "C3": 0, "C4": 0}
    for cid, gt, out, v in rows:
        d = v["C2_calibration"]["direction"]; cal[(gt["evidence_condition"], d)] += 1
        for c in ("C1", "C3", "C4"):
            if not v[f"{c}_grounding" if c == "C1" else f"{c}_counter" if c == "C3" else f"{c}_action"]["pass"]: fails[c] += 1
        mark = {"in_band": "  ok", "over": " OVER", "under": "UNDER"}[d]
        cr = f"{gt['evidence_condition']}/{gt['calibration_role']}"
        p = lambda b: "✓" if b else "✗"
        print(f"{cid:9s} {cr:17s} {str(gt['acceptable_severity']):16s} {out['verdict'][:4]+'/'+out['severity']:13s}"
              f"{mark:7s} {p(v['C1_grounding']['pass']):4s} {p(v['C3_counter']['pass']):4s} {p(v['C4_action']['pass']):4s}")
    print("\n--- calibration by condition (the headline) ---")
    for cond in ["strong", "weak", "missing", "counter"]:
        o, i, u = cal[(cond, "over")], cal[(cond, "in_band")], cal[(cond, "under")]
        print(f"  {cond:8s} over={o} in-band={i} under={u}")
    print(f"\n--- other checks --- C1 grounding fails={fails['C1']}  C3 counter fails={fails['C3']}  C4 action fails={fails['C4']}")

    # ---- ablation arm: the ACTIVE checks (--checks) decide what THIS arm flags for correction ----
    def _flag(v, c):
        return (not v["C1_grounding"]["pass"]) if c == "C1" else \
               (v["C2_calibration"]["direction"] != "in_band") if c == "C2" else \
               (not v["C3_counter"]["pass"]) if c == "C3" else (not v["C4_action"]["pass"])
    arm = {"C1": "A3 (grounding-only)", "C1,C2,C3,C4": "A4 (full validator)"}.get(",".join(active), "custom subset")
    caught = sorted(cid for cid, gt, out, v in rows if any(_flag(v, c) for c in active))
    per = {c: sum(_flag(v, c) for *_ig, v in rows) for c in active}
    full = {cid for cid, gt, out, v in rows if any(_flag(v, c) for c in ("C1", "C2", "C3", "C4"))}
    missed = sorted(full - set(caught))
    print(f"\n=== ABLATION ARM {arm}  —  active checks: {', '.join(active)} ===")
    print(f"  flags for correction: {len(caught)}/{len(rows)} cases  {caught}")
    print("  by active check: " + "  ".join(f"{c}={per[c]}" for c in active))
    if missed:
        print(f"  missed by this arm (only the INACTIVE checks would catch these): {len(missed)}  {missed}")
    print("  reproduce:  python3 eval/validator.py --model " + a.model + " --split " + a.split
          + ("" if ",".join(active) == "C1,C2,C3,C4" else "  --checks " + ",".join(active)))

    print("\n--- C1 grounding flags (invalid ids / fabricated rationale) ---")
    c1any = False
    for cid, gt, out, v in rows:
        f = v["C1_grounding"]
        if not f["pass"]:
            c1any = True
            print(f"  [{cid}] invalid_ids={f['invalid_ids']} rationale_flags={f['rationale_flags']}")
    if not c1any: print("  (none)")
    print("\n--- rationales for mis-calibrated cases ---")
    for cid, gt, out, v in rows:
        if v["C2_calibration"]["direction"] != "in_band":
            print(f"  [{cid} {v['C2_calibration']['direction'].upper()}] {out['rationale'][:180]}")

if __name__ == "__main__":
    main()
