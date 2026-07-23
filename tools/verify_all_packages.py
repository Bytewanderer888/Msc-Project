#!/usr/bin/env python3
"""Verify every delivered package can be re-derived from project-retained raw data."""

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
NORMALIZE = ROOT / "tools" / "normalize.py"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--json-out", type=Path, default=ROOT / "eval/reports/package_rebuild_verification.json")
    args = parser.parse_args()
    case_dirs = sorted(path.parent.parent for path in ROOT.glob("tier*/*/*/*/build/case.json"))
    env = os.environ.copy()
    env["SAFESOC_DATA"] = str(ROOT / "__external_attack_data_disabled__")
    env["OTRF_DATA"] = str(ROOT / "data_sources" / "otrf_selected_raw")
    rows = []
    for case_dir in case_dirs:
        result = subprocess.run(
            [sys.executable, str(NORMALIZE), "--case", str(case_dir), "--verify-log"],
            cwd=ROOT,
            env=env,
            text=True,
            capture_output=True,
        )
        case_id = json.loads((case_dir / "build/case.json").read_text(encoding="utf-8"))["case_id"]
        row = {
            "case": case_id,
            "case_directory": str(case_dir.relative_to(ROOT)),
            "passed": result.returncode == 0,
            "output": (result.stdout + result.stderr).strip(),
        }
        rows.append(row)
        print(f"{'PASS' if row['passed'] else 'FAIL'} {case_id}: {row['output']}")
    report = {
        "record_schema": "safesoc.package_rebuild_verification.v1",
        "generated_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "external_attack_data_disabled": True,
        "otrf_root": "data_sources/otrf_selected_raw",
        "summary": {
            "cases": len(rows),
            "passed": sum(row["passed"] for row in rows),
            "failed": sum(not row["passed"] for row in rows),
        },
        "cases": rows,
    }
    out = args.json_out if args.json_out.is_absolute() else ROOT / args.json_out
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    print(f"saved JSON: {out}")
    raise SystemExit(0 if report["summary"]["failed"] == 0 else 1)


if __name__ == "__main__":
    main()
