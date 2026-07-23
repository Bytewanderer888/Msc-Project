#!/usr/bin/env python3
"""Aggregate three complete A4 reports without synthesising a model decision.

The repeat protocol defines a case-level 2-of-3 majority separately for each
binary C1-C4 result. A case passes the aggregate only when all four majority
outcomes pass.
"""

from __future__ import annotations

import argparse
import csv
import json
from datetime import datetime, timezone
from pathlib import Path


CHECK_KEYS = {
    "C1": "C1_reference_integrity",
    "C2": "C2_decision_calibration",
    "C3": "C3_counter_acknowledgement",
    "C4": "C4_action_calibration",
}
EXPECTED_CHECKS = list(CHECK_KEYS)


class AggregationError(RuntimeError):
    """Raised when reports cannot be safely combined."""


def load_report(path: Path) -> dict:
    try:
        report = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise AggregationError(f"cannot read report {path}: {exc}") from exc
    if report.get("summary", {}).get("active_checks") != EXPECTED_CHECKS:
        raise AggregationError(f"{path} is not a complete C1-C4 (A4) report")
    if not report.get("completeness", {}).get("complete"):
        raise AggregationError(f"{path} is incomplete")
    return report


def aggregate(reports: list[dict], sources: list[str] | None = None) -> dict:
    if len(reports) != 3:
        raise AggregationError(f"the frozen protocol requires exactly 3 reports, got {len(reports)}")

    splits = {report.get("split") for report in reports}
    if len(splits) != 1:
        raise AggregationError(f"reports use different splits: {sorted(splits)}")

    indexed = [{row["case_id"]: row for row in report["cases"]} for report in reports]
    case_sets = [set(rows) for rows in indexed]
    if any(cases != case_sets[0] for cases in case_sets[1:]):
        raise AggregationError("reports do not contain the same case ids")

    rows = []
    for case_id in sorted(case_sets[0]):
        source_rows = [round_rows[case_id] for round_rows in indexed]
        conditions = {row["condition"] for row in source_rows}
        if len(conditions) != 1:
            raise AggregationError(f"{case_id} has inconsistent conditions: {sorted(conditions)}")

        outcomes = {}
        for check, key in CHECK_KEYS.items():
            passes = [bool(row["checks"][key]["pass"]) for row in source_rows]
            outcomes[check] = {
                "round_passes": passes,
                "pass_n": sum(passes),
                "majority_pass": sum(passes) >= 2,
            }
        flagged = [check for check in EXPECTED_CHECKS if not outcomes[check]["majority_pass"]]
        rows.append(
            {
                "case_id": case_id,
                "condition": source_rows[0]["condition"],
                "majority_checks": outcomes,
                "flagged_by_majority": flagged,
                "joint_majority_pass": not flagged,
            }
        )

    n = len(rows)
    per_round = []
    for index, report in enumerate(reports, start=1):
        summary = report["summary"]
        per_round.append(
            {
                "round": index,
                "source": sources[index - 1] if sources else None,
                "model": report.get("model"),
                "all_checks_pass_n": n - summary["active_flagged_n"],
                "check_failure_counts": summary["check_failure_counts"],
            }
        )
    round_pass_counts = [row["all_checks_pass_n"] for row in per_round]

    return {
        "record_schema": "safesoc.validator-majority.v1",
        "generated_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "split": reports[0]["split"],
        "rounds": per_round,
        "summary": {
            "n": n,
            "majority_joint_pass_n": sum(row["joint_majority_pass"] for row in rows),
            "majority_flagged_n": sum(not row["joint_majority_pass"] for row in rows),
            "majority_check_failure_counts": {
                check: sum(not row["majority_checks"][check]["majority_pass"] for row in rows)
                for check in EXPECTED_CHECKS
            },
            "per_round_all_checks_pass_n": round_pass_counts,
            "per_round_mean": round(sum(round_pass_counts) / len(round_pass_counts), 4),
            "per_round_range": [min(round_pass_counts), max(round_pass_counts)],
        },
        "cases": rows,
    }


def write_csv(path: Path, report: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=["case_id", "condition", *EXPECTED_CHECKS, "joint_majority_pass", "flagged"],
        )
        writer.writeheader()
        for row in report["cases"]:
            writer.writerow(
                {
                    "case_id": row["case_id"],
                    "condition": row["condition"],
                    **{
                        check: row["majority_checks"][check]["majority_pass"]
                        for check in EXPECTED_CHECKS
                    },
                    "joint_majority_pass": row["joint_majority_pass"],
                    "flagged": ",".join(row["flagged_by_majority"]),
                }
            )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--reports", type=Path, nargs=3, required=True)
    parser.add_argument("--json-out", type=Path, required=True)
    parser.add_argument("--csv-out", type=Path)
    args = parser.parse_args()

    sources = [str(path) for path in args.reports]
    report = aggregate([load_report(path) for path in args.reports], sources)
    args.json_out.parent.mkdir(parents=True, exist_ok=True)
    args.json_out.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    if args.csv_out:
        write_csv(args.csv_out, report)

    summary = report["summary"]
    print(
        f"2-of-3 A4 majority: {summary['majority_joint_pass_n']}/{summary['n']} pass; "
        f"failures={summary['majority_check_failure_counts']}"
    )
    print(
        f"per-round all-check pass={summary['per_round_all_checks_pass_n']} "
        f"mean={summary['per_round_mean']}/{summary['n']} "
        f"range={summary['per_round_range'][0]}-{summary['per_round_range'][1]}"
    )
    print(f"wrote JSON report: {args.json_out}")
    if args.csv_out:
        print(f"wrote CSV report: {args.csv_out}")


if __name__ == "__main__":
    main()
