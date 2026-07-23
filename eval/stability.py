#!/usr/bin/env python3
"""
stability.py — run-to-run agreement across repeat rounds of one model on one split.

Repeat rounds live side-by-side under eval/outputs/ (see run_model.py --round):
    <model>/<split>/            round 1 (the baseline)
    <model>_round2/<split>/     round 2
    <model>_round3/<split>/     round 3 ...

Agreement is measured on the DECISION fields — (verdict, severity, recommended_action) —
because those are what the validator scores; free-text rationale wording is expected to vary
and is not compared. Verdict and severity agreement are also reported separately because C2
scores both dimensions against the ground-truth decision policy.

Usage (from SafeSOC/):
    python3 eval/stability.py --model gemini-2.5-flash --split dev
"""
import argparse, glob, json, os, re
from datetime import datetime, timezone
from pathlib import Path

HERE = os.path.dirname(os.path.abspath(__file__))


def load(d):
    out = {}
    for f in glob.glob(os.path.join(d, "*.json")):
        j = json.load(open(f))
        out[os.path.basename(f)[:-5]] = (j["verdict"], j["severity"], j["recommended_action"])
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", required=True, help="base model tag (round 1 dir under eval/outputs/)")
    ap.add_argument("--split", default="dev")
    ap.add_argument("--json-out", type=Path, help="also save a machine-readable stability report")
    a = ap.parse_args()

    dirs = [(1, os.path.join(HERE, "outputs", a.model, a.split))]
    for d in sorted(glob.glob(os.path.join(HERE, "outputs", a.model + "_round*", a.split))):
        m = re.search(r"_round(\d+)", d)
        if m:
            dirs.append((int(m.group(1)), d))
    dirs = [(n, d) for n, d in dirs if os.path.isdir(d)]
    if len(dirs) < 2:
        raise SystemExit(f"need >= 2 rounds under eval/outputs/, found {len(dirs)} for '{a.model}/{a.split}'.\n"
                         f"run round 2 with:  python3 eval/run_model.py --provider <p> --split {a.split} --round 2")

    rounds = {n: load(d) for n, d in dirs}
    ns = sorted(rounds)
    cases = sorted(set.intersection(*(set(rounds[n]) for n in ns)))
    union = set.union(*(set(rounds[n]) for n in ns))
    print(f"=== stability: {a.model} / {a.split} · rounds {ns} · {len(cases)} common cases ===")
    if union - set(cases):
        print(f"  ! not present in every round (skipped): {sorted(union - set(cases))}")

    flips = sev_flips = verd_flips = 0
    case_records = []
    for c in cases:
        vals = [rounds[n][c] for n in ns]
        exact_flip = len(set(vals)) > 1
        severity_flip = len({v[1] for v in vals}) > 1
        verdict_flip = len({v[0] for v in vals}) > 1
        flips += int(exact_flip)
        sev_flips += int(severity_flip)
        verd_flips += int(verdict_flip)
        case_records.append({
            "case": c,
            "decisions": {
                f"round_{n}": {
                    "verdict": rounds[n][c][0],
                    "severity": rounds[n][c][1],
                    "recommended_action": rounds[n][c][2],
                }
                for n in ns
            },
            "exact_flip": exact_flip,
            "severity_flip": severity_flip,
            "verdict_flip": verdict_flip,
        })
        if not exact_flip:
            continue
        per = "  |  ".join(f"r{n}: {'/'.join(rounds[n][c])}" for n in ns)
        print(f"  FLIP {c:10s} {per}")

    n = len(cases)
    print(f"\nexact agreement (verdict+severity+action) : {n - flips}/{n}")
    print(f"severity agreement (drives C2)            : {n - sev_flips}/{n}")
    print(f"verdict agreement                         : {n - verd_flips}/{n}")
    if flips == 0:
        print("  ✓ decision-stable across rounds — single-run held-out scoring is defensible")
    else:
        print("  ! flips present — report each round plus a 2-of-3 majority aggregation"
              " of each validator check; the held-out repeat decision is based on development stability")

    if a.json_out:
        report = {
            "record_schema": "safesoc.stability.v1",
            "generated_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "model_tag": a.model,
            "split": a.split,
            "rounds": ns,
            "round_directories": {str(n): os.path.relpath(d, HERE) for n, d in dirs},
            "common_cases": n,
            "not_present_in_every_round": sorted(union - set(cases)),
            "summary": {
                "exact_agreement_n": n - flips,
                "severity_agreement_n": n - sev_flips,
                "verdict_agreement_n": n - verd_flips,
                "denominator": n,
            },
            "cases": case_records,
        }
        out = a.json_out if a.json_out.is_absolute() else Path.cwd() / a.json_out
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
        print(f"saved JSON: {out}")


if __name__ == "__main__":
    main()
