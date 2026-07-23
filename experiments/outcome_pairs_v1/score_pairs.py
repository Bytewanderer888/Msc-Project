#!/usr/bin/env python3
"""Integrity audit + predeclared-endpoint scoring for the outcome-confirmation pairs.

Reads manifest.private.json (the experiment design: pairs and expected bands) and the
saved model outputs, verifies every integrity invariant, then reports the
primary endpoint (both pair members in their predeclared bands) and the secondary
endpoints (directional movement, added-evidence citation, exploratory confidence).

Offline and deterministic — no API calls. The manifest is analyst-side material (it
encodes expected bands); it must never be shown to a model.

    python3 experiments/outcome_pairs_v1/score_pairs.py
    python3 experiments/outcome_pairs_v1/score_pairs.py --model gemini-2.5-flash --json-out report.json
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import check_cases as cc  # noqa: E402  (canonical LEAK_RX)

SEV = ["informational", "low", "medium", "high", "critical"]
VER = ["benign", "suspicious", "malicious"]
ACT = ["close_benign", "monitor", "investigate", "escalate", "isolate"]
ID_RE = re.compile(r"\b(?:A0|EV-\d{3}|DER-\d{3})\b")


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def items_of(pkg: dict) -> list[dict]:
    return [pkg["main_alert"], *pkg.get("evidence_items", [])]


def audit(man: dict) -> list[str]:
    """Every invariant the design depends on. Returns a list of problems (empty == clean)."""
    problems = []
    for pair in man["pairs"]:
        pid = pair["pair_id"]
        src_path = Path(pair["source_package"])
        if not src_path.exists():
            problems.append(f"{pid}: source package missing: {src_path}")
            continue
        if sha256(src_path) != pair["source_sha256"]:
            problems.append(f"{pid}: source hash mismatch (frozen benchmark drifted?)")
        src_items = {i["evidence_id"]: i for i in items_of(json.loads(src_path.read_text()))}

        loaded = {}
        for v in pair["versions"]:
            path = HERE / "packages" / f"{v['neutral_case_id']}.json"
            raw = path.read_bytes()
            if hashlib.sha256(raw).hexdigest() != v["sha256"]:
                problems.append(f"{pid}/{v['role']}: package hash mismatch vs manifest")
            if cc.LEAK_RX.search(raw.decode()):
                problems.append(f"{pid}/{v['role']}: leak-regex hit")
            pkg = json.loads(raw)
            if len(items_of(pkg)) != v["event_count"]:
                problems.append(f"{pid}/{v['role']}: event_count mismatch")
            vis = {i["evidence_id"]: i for i in items_of(pkg)}
            for sid, vid in v["source_to_visible_evidence_id"].items():
                if vid not in vis:
                    problems.append(f"{pid}/{v['role']}: visible id {vid} missing"); continue
                if (src_items[sid].get("attributes") != vis[vid].get("attributes")
                        or src_items[sid].get("event_time_utc") != vis[vid].get("event_time_utc")):
                    problems.append(f"{pid}/{v['role']}: {sid}->{vid} diverges from source")
            loaded[v["role"]] = (pkg, v)

        base_pkg, base_v = loaded["base"]
        strong_pkg, strong_v = loaded["strong"]
        bmap, smap = base_v["source_to_visible_evidence_id"], strong_v["source_to_visible_evidence_id"]
        bvis = {i["evidence_id"]: i for i in items_of(base_pkg)}
        svis = {i["evidence_id"]: i for i in items_of(strong_pkg)}
        for sid in set(bmap) & set(smap):
            if bvis[bmap[sid]].get("attributes") != svis[smap[sid]].get("attributes"):
                problems.append(f"{pid}: shared event {sid} differs between versions")
        if sorted(set(smap) - set(bmap)) != sorted(pair["outcome_source_event_ids"]):
            problems.append(f"{pid}: strong-version extras != declared outcome events")
    return problems


def score(man: dict, outdir: Path) -> dict:
    pairs_report = []
    for pair in man["pairs"]:
        row = {"pair_id": pair["pair_id"], "source_case": pair["source_case"],
               "analysis_set": "primary",
               "versions": {}, "complete": True}
        for v in pair["versions"]:
            out_path = outdir / f"{v['neutral_case_id']}.json"
            if not out_path.exists():
                row["complete"] = False
                row["versions"][v["role"]] = None
                continue
            o = json.loads(out_path.read_text())
            exp = v["expected"]
            in_band = (o["verdict"] in exp["verdict"] and o["severity"] in exp["severity"]
                       and o["recommended_action"] in exp["action"])
            added_vis = ([v["source_to_visible_evidence_id"][s]
                          for s in pair["outcome_source_event_ids"]
                          if s in v["source_to_visible_evidence_id"]]
                         if v["role"] == "strong" else [])
            cited = set(ID_RE.findall(o.get("rationale", ""))) | set(o.get("key_evidence", []))
            row["versions"][v["role"]] = {
                "case_id": v["neutral_case_id"],
                "output": {k: o[k] for k in ("verdict", "severity", "confidence", "recommended_action")},
                "expected": exp, "in_band": in_band,
                "cites_added_outcome_evidence": (all(a in cited for a in added_vis)
                                                 if added_vis else None),
            }
        if row["complete"]:
            b = row["versions"]["base"]["output"]
            s = row["versions"]["strong"]["output"]
            row["primary_endpoint_met"] = (row["versions"]["base"]["in_band"]
                                           and row["versions"]["strong"]["in_band"])
            deltas = (
                VER.index(s["verdict"]) - VER.index(b["verdict"]),
                SEV.index(s["severity"]) - SEV.index(b["severity"]),
                ACT.index(s["recommended_action"]) - ACT.index(b["recommended_action"]),
            )
            row["directional_movement"] = any(d > 0 for d in deltas) and all(d >= 0 for d in deltas)
            row["identical_outputs"] = (b["verdict"] == s["verdict"] and b["severity"] == s["severity"]
                                        and b["recommended_action"] == s["recommended_action"])
            row["confidence_delta"] = round(s["confidence"] - b["confidence"], 3)
        pairs_report.append(row)
    return {"pairs": pairs_report}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="gemini-2.5-flash")
    ap.add_argument("--provider", default="gemini")
    ap.add_argument("--round", type=int, default=1,
                    help=">1 scores outputs/<provider>__<model>_roundN (benchmark convention)")
    ap.add_argument("--json-out", type=Path)
    args = ap.parse_args()

    man = json.loads((HERE / "manifest.private.json").read_text())
    problems = audit(man)
    print(f"=== integrity audit: {'CLEAN' if not problems else 'PROBLEMS'} ===")
    for p in problems:
        print("  -", p)
    if problems:
        raise SystemExit("fix integrity problems before interpreting any scores")

    round_suffix = f"_round{args.round}" if args.round > 1 else ""
    outdir = HERE / "outputs" / f"{args.provider}__{args.model}{round_suffix}"
    if not outdir.is_dir():
        raise SystemExit(f"no outputs at {outdir} — run run_pairs.py with the same provider/model/round first")
    report = score(man, outdir)
    print(f"\n{'pair':5s} {'set':11s} {'src':8s} {'base (expected mid-band)':32s} "
          f"{'strong (expected strong-band)':32s} {'endpoint':9s} {'moved':6s} ident  dconf")
    for r in report["pairs"]:
        if not r["complete"]:
            print(f"{r['pair_id']:5s} {r['analysis_set']:11s} {r['source_case']:8s} "
                  f"-- not yet run ({', '.join(v['neutral_case_id'] for v in next(p for p in man['pairs'] if p['pair_id']==r['pair_id'])['versions'])}) --")
            continue
        b, s = r["versions"]["base"], r["versions"]["strong"]
        fmt = lambda x: f"{x['output']['verdict']}/{x['output']['severity']}/{x['output']['recommended_action']}" \
                        + (" *" if not x["in_band"] else "")
        print(f"{r['pair_id']:5s} {r['analysis_set']:11s} {r['source_case']:8s} {fmt(b):32.32s} {fmt(s):32.32s} "
              f"{'MET' if r['primary_endpoint_met'] else 'not met':9s} "
              f"{'yes' if r['directional_movement'] else 'NO':6s} "
              f"{'YES' if r['identical_outputs'] else '-':6s} {r['confidence_delta']:+.2f}")
    done = [r for r in report["pairs"] if r["complete"]]
    for set_name in ("primary",):
        subset = [r for r in done if r["analysis_set"] == set_name]
        if not subset:
            continue
        print(f"\n  {set_name} endpoint met: "
              f"{sum(r['primary_endpoint_met'] for r in subset)}/{len(subset)} pairs"
              f"   ·  directional movement: {sum(r['directional_movement'] for r in subset)}/{len(subset)}"
              f"   ·  identical base/strong outputs: {sum(r['identical_outputs'] for r in subset)}")
    print("  (* = outside its predeclared band)")

    if args.json_out:
        args.json_out.write_text(json.dumps(report, indent=2) + "\n")
        print(f"\nwrote {args.json_out}")


if __name__ == "__main__":
    main()
