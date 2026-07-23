#!/usr/bin/env python3
"""Compare the declared experiment matrix with current canonical output files."""

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
EVAL = ROOT / "eval"


def split_cases(split):
    cases = set()
    for path in ROOT.glob(f"tier*/*/{split}/*/model_input/alert_package.json"):
        cases.add(json.loads(path.read_text(encoding="utf-8"))["case_id"])
    return cases


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, default=EVAL / "expected_run_matrix.json")
    parser.add_argument("--json-out", type=Path, default=EVAL / "reports/run_matrix_current.json")
    args = parser.parse_args()
    config = json.loads(args.config.read_text(encoding="utf-8"))
    expected = {split: split_cases(split) for split in ("dev", "heldout")}
    rows = []
    for run in config["runs"]:
        output_dir = EVAL / "outputs" / run["model_tag"] / run["split"]
        found = {path.stem for path in output_dir.glob("*.json")} if output_dir.exists() else set()
        missing = sorted(expected[run["split"]] - found)
        unexpected = sorted(found - expected[run["split"]])
        row = {
            **run,
            "expected_n": len(expected[run["split"]]),
            "found_n": len(found & expected[run["split"]]),
            "missing": missing,
            "unexpected": unexpected,
            "complete": not missing and not unexpected,
        }
        rows.append(row)
        detail = f" missing={','.join(missing)}" if missing else ""
        print(f"{'OK' if row['complete'] else 'INCOMPLETE':10s} {run['label']:30s} {row['found_n']:2d}/{row['expected_n']}{detail}")

    report = {
        "record_schema": "safesoc.run_matrix_report.v1",
        "generated_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "config": str(args.config.relative_to(ROOT)),
        "deferred_rule": config.get("deferred_rule"),
        "summary": {
            "runs": len(rows),
            "complete": sum(row["complete"] for row in rows),
            "incomplete": sum(not row["complete"] for row in rows),
        },
        "runs": rows,
    }
    out = args.json_out if args.json_out.is_absolute() else ROOT / args.json_out
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    print(f"saved JSON: {out}")


if __name__ == "__main__":
    main()
