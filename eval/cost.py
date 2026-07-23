#!/usr/bin/env python3
"""
cost.py — token usage + $ cost per model run, from the usage_<split>.jsonl logs run_model.py appends.

  python3 eval/cost.py --model claude-sonnet-4-6__A2_evidence_prompt --split dev
  python3 eval/cost.py --all --split dev            # every tag with usage recorded

Each recorded token count comes from the provider response. Two views are deliberately separated:

  canonical — the last usage record for each CURRENT output file (cost of the reported artifact)
  incurred  — every append-only usage record, including invalidated/repeated calls (actual experiment spend)

Both actual study spend and paid-tier list-equivalent cost are shown. Prices come from the dated
eval/pricing_snapshot.json; do not silently replace them with later prices when writing the thesis.
"""
import json, argparse
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
OUT = HERE / "outputs"

# Paid-tier list USD per 1,000,000 tokens: (input, output).
PRICING = {
    "claude-opus-4-8":   (5.00, 25.00),
    "claude-opus-4-7":   (5.00, 25.00),
    "claude-sonnet-4-6": (3.00, 15.00),
    "claude-sonnet-5":   (3.00, 15.00),
    "claude-haiku-4-5":  (1.00,  5.00),
    "gemini-2.5-flash":  (0.30,  2.50),
    "gemini-2.5-pro":    (0.00,  0.00),
}
BATCH_DISCOUNT = 0.5
FREE_TIER_MODELS = ("gemini-2.5-flash", "gemini-2.5-pro")


def base_model(tag):
    """'claude-sonnet-4-6__A2_evidence_prompt_round2' -> 'claude-sonnet-4-6'."""
    return tag.split("__")[0].split("_round")[0]


def price(model):
    for k, v in PRICING.items():
        if model.startswith(k):
            return v
    return None


def read_all(tag, split):
    """Return every append-only usage record, or None if no log exists."""
    f = OUT / tag / f"usage_{split}.jsonl"
    if not f.exists():
        return None
    recs = []
    for line in f.read_text().splitlines():
        line = line.strip()
        if line:
            recs.append(json.loads(line))
    return recs


def canonical_records(tag, split, records):
    """Return (last record per current output, current output count, missing usage ids)."""
    output_dir = OUT / tag / split
    output_cases = sorted(path.stem for path in output_dir.glob("*.json")) if output_dir.is_dir() else []
    last = {}
    for record in records:
        last[record["case"]] = record
    missing = sorted(case for case in output_cases if case not in last)
    return [last[case] for case in output_cases if case in last], len(output_cases), missing


def price_records(records, model):
    p = price(model)
    if p is None:
        return None
    tin = tout = list_cost = actual_cost = 0.0
    modes = {}
    for record in records:
        bi, bo = record.get("input_tokens", 0), record.get("output_tokens", 0)
        mode = record.get("billing_mode", "realtime")
        discount = BATCH_DISCOUNT if mode == "batch" else 1.0
        call_list = (bi / 1e6 * p[0] + bo / 1e6 * p[1]) * discount
        list_cost += call_list
        if not any(model.startswith(name) for name in FREE_TIER_MODELS):
            actual_cost += call_list
        tin += bi
        tout += bo
        modes[mode] = modes.get(mode, 0) + 1
    return {
        "calls": len(records), "input": int(tin), "output": int(tout),
        "actual_cost": actual_cost, "list_cost": list_cost, "modes": modes,
    }


def print_view(label, row, coverage=None, missing=None):
    modes = " ".join(f"{key}:{value}" for key, value in sorted(row["modes"].items()))
    covered = f" coverage={row['calls']}/{coverage}" if coverage is not None else ""
    print(
        f"    {label:9s} {row['calls']:3d} calls [{modes}]{covered}  "
        f"in {row['input']:9,}  out {row['output']:8,}  "
        f"actual ${row['actual_cost']:7.3f}  paid-list-equivalent ${row['list_cost']:7.3f}"
    )
    if missing:
        print(f"      ! API usage missing for {len(missing)} current outputs: {', '.join(missing)}")


def report(tag, split):
    all_records = read_all(tag, split)
    if all_records is None:
        print(f"  {tag:46s} — no usage log (run predates usage capture; re-run to record)")
        return None
    model = base_model(tag)
    canonical, output_count, missing = canonical_records(tag, split, all_records)
    canonical_row = price_records(canonical, model)
    incurred_row = price_records(all_records, model)
    if canonical_row is None or incurred_row is None:
        print(f"  {tag:46s} — no price for '{model}' (add to PRICING and pricing_snapshot.json)")
        return None
    print(f"  {tag}  [{model}]")
    print_view("canonical", canonical_row, output_count, missing)
    print_view("incurred", incurred_row)
    return {
        "tag": tag,
        "split": split,
        "model": model,
        "current_outputs": output_count,
        "missing_usage_cases": missing,
        "canonical": canonical_row,
        "incurred": incurred_row,
        "complete": not missing,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", help="one output tag (folder name under eval/outputs/)")
    ap.add_argument("--split", default="dev")
    ap.add_argument("--all", action="store_true", help="every tag with a usage_<split>.jsonl")
    ap.add_argument("--json-out", type=Path, help="also save a machine-readable cost report")
    a = ap.parse_args()

    print(f"=== token usage + cost · split={a.split} · priced per-call by recorded billing_mode ===")
    rows = []
    if a.all:
        tags = sorted(p.parent.name for p in OUT.glob(f"*/usage_{a.split}.jsonl"))
        if not tags:
            print("  (no usage logs yet — run something usage-instrumented first)")
            return
        rows = [row for row in (report(tag, a.split) for tag in tags) if row]
        if rows:
            actual = [row["incurred"] for row in rows]
            print(
                f"  {'TOTAL INCURRED':46s} {sum(row['calls'] for row in actual):3d} calls"
                f"  in {sum(row['input'] for row in actual):9,}  out {sum(row['output'] for row in actual):8,}  "
                f"actual ${sum(row['actual_cost'] for row in actual):7.3f}  "
                f"paid-list-equivalent ${sum(row['list_cost'] for row in actual):7.3f}"
            )
    elif a.model:
        row = report(a.model, a.split)
        rows = [row] if row else []
    else:
        ap.error("give --model <tag>  or  --all")

    if a.json_out:
        totals = {
            "calls": sum(row["incurred"]["calls"] for row in rows),
            "input_tokens": sum(row["incurred"]["input"] for row in rows),
            "output_tokens": sum(row["incurred"]["output"] for row in rows),
            "actual_cost_usd": sum(row["incurred"]["actual_cost"] for row in rows),
            "paid_list_equivalent_usd": sum(row["incurred"]["list_cost"] for row in rows),
        }
        pricing_path = HERE / "pricing_snapshot.json"
        payload = {
            "record_schema": "safesoc.cost_report.v1",
            "generated_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "split": a.split,
            "scope": "all_usage_logs" if a.all else a.model,
            "pricing_snapshot": json.loads(pricing_path.read_text(encoding="utf-8")),
            "rows": rows,
            "total_incurred": totals,
        }
        out = a.json_out if a.json_out.is_absolute() else HERE.parent / a.json_out
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        print(f"saved JSON: {out}")


if __name__ == "__main__":
    main()
