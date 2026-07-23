#!/usr/bin/env python3
"""Audit and score the completed Weak-to-Counter context-reveal pairs."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections import Counter
from pathlib import Path

from jsonschema import Draft7Validator

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import check_cases as cc  # noqa: E402

VERDICT_RANK = {"benign": 0, "suspicious": 1, "malicious": 2}
SEVERITY_RANK = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
ACTION_RANK = {"close_benign": 0, "monitor": 1, "investigate": 2, "escalate": 3, "isolate": 4}


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def target_correct(output: dict, expected: dict) -> bool:
    return (
        output["verdict"] in expected["verdict"]
        and output["severity"] in expected["severity"]
        and output["recommended_action"] in expected["action"]
    )


def audit(manifest: dict, outdir: Path) -> list[str]:
    problems = []
    package_schema = json.loads(
        (ROOT / "tools" / "schema" / "alert_package.schema.json").read_text(encoding="utf-8")
    )
    package_validator = Draft7Validator(package_schema)
    expected_ids = set()

    for pair in manifest["pairs"]:
        source_path = Path(pair["source_package"])
        if not source_path.is_absolute():
            source_path = ROOT / source_path
        if not source_path.exists():
            problems.append(f"{pair['pair_id']}: source package missing: {source_path}")
        elif sha256(source_path) != pair["source_sha256"]:
            problems.append(f"{pair['pair_id']}: source package hash mismatch")

        for version in pair["versions"]:
            case_id = version["neutral_case_id"]
            expected_ids.add(case_id)
            path = HERE / version["path"]
            if not path.exists():
                problems.append(f"{pair['pair_id']}/{version['role']}: package missing")
                continue
            if sha256(path) != version["sha256"]:
                problems.append(f"{pair['pair_id']}/{version['role']}: package hash mismatch")
            raw = path.read_text(encoding="utf-8")
            if cc.LEAK_RX.search(raw):
                problems.append(f"{pair['pair_id']}/{version['role']}: leak-regex hit")
            package = json.loads(raw)
            if package.get("case_id") != case_id:
                problems.append(f"{pair['pair_id']}/{version['role']}: neutral case id mismatch")
            event_count = 1 + len(package.get("evidence_items", []))
            if event_count != version["event_count"]:
                problems.append(f"{pair['pair_id']}/{version['role']}: event count mismatch")
            schema_errors = list(package_validator.iter_errors(package))
            if schema_errors:
                problems.append(
                    f"{pair['pair_id']}/{version['role']}: package schema invalid: "
                    f"{schema_errors[0].message}"
                )

    usage_path = outdir / "usage.retained.jsonl"
    if usage_path.exists():
        usage_ids = [
            json.loads(line)["case_id"]
            for line in usage_path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        duplicates = sorted(case_id for case_id, count in Counter(usage_ids).items() if count > 1)
        if duplicates:
            problems.append(f"usage contains duplicate case ids: {duplicates}")
        if set(usage_ids) != expected_ids:
            problems.append(
                f"usage/output design mismatch: missing={sorted(expected_ids - set(usage_ids))}, "
                f"extra={sorted(set(usage_ids) - expected_ids)}"
            )
    return problems


def score(manifest: dict, outdir: Path) -> dict:
    rows = []
    for pair in manifest["pairs"]:
        versions = {version["role"]: version for version in pair["versions"]}
        paths = {
            role: outdir / f"{version['neutral_case_id']}.json"
            for role, version in versions.items()
        }
        if not all(path.exists() for path in paths.values()):
            rows.append({
                "pair_id": pair["pair_id"],
                "source_case": pair["source_case"],
                "complete": False,
                "missing_roles": [role for role, path in paths.items() if not path.exists()],
            })
            continue

        outputs = {
            role: json.loads(path.read_text(encoding="utf-8"))
            for role, path in paths.items()
        }
        weak = outputs["weak"]
        counter = outputs["counter"]
        weak_ok = target_correct(weak, versions["weak"]["expected"])
        counter_ok = target_correct(counter, versions["counter"]["expected"])
        deltas = {
            "verdict": VERDICT_RANK[counter["verdict"]] - VERDICT_RANK[weak["verdict"]],
            "severity": SEVERITY_RANK[counter["severity"]] - SEVERITY_RANK[weak["severity"]],
            "action": (
                ACTION_RANK[counter["recommended_action"]]
                - ACTION_RANK[weak["recommended_action"]]
            ),
        }
        no_reversal = all(delta <= 0 for delta in deltas.values())
        changed = any(delta != 0 for delta in deltas.values())
        context_mentioned = any(
            re.search(re.escape(term), counter.get("rationale", ""), re.IGNORECASE)
            for term in pair["required_context_terms"]
        )

        if weak_ok and counter_ok and no_reversal and changed and context_mentioned:
            result = "correct_transition"
        elif not changed:
            result = "no_response"
        elif not no_reversal:
            result = "reversed_or_mixed_response"
        elif counter_ok and not weak_ok:
            result = "counter_correct_weak_miscall"
        elif weak_ok and not counter_ok:
            result = "weak_correct_counter_not_downranked"
        else:
            result = "target_miss"

        rows.append({
            "pair_id": pair["pair_id"],
            "source_case": pair["source_case"],
            "complete": True,
            "result": result,
            "weak_output": {
                key: weak[key]
                for key in ("verdict", "severity", "confidence", "recommended_action")
            },
            "counter_output": {
                key: counter[key]
                for key in ("verdict", "severity", "confidence", "recommended_action")
            },
            "weak_target_correct": weak_ok,
            "counter_target_correct": counter_ok,
            "primary_endpoint_met": weak_ok and counter_ok and no_reversal and changed,
            "decision_changed": changed,
            "correct_downward_movement": no_reversal and changed,
            "decision_deltas": deltas,
            "context_mentioned_in_counter": context_mentioned,
            "confidence_delta_counter_minus_weak": round(
                counter["confidence"] - weak["confidence"], 4
            ),
        })

    complete = [row for row in rows if row["complete"]]
    summary = {
        "complete_pairs": len(complete),
        "total_pairs": len(rows),
        "primary_endpoint_met": sum(row["primary_endpoint_met"] for row in complete),
        "correct_downward_movement": sum(row["correct_downward_movement"] for row in complete),
        "context_mentioned": sum(row["context_mentioned_in_counter"] for row in complete),
        "no_response": sum(row["result"] == "no_response" for row in complete),
        "reversed_or_mixed": sum(
            row["result"] == "reversed_or_mixed_response" for row in complete
        ),
        "result_counts": dict(Counter(row["result"] for row in complete)),
    }
    return {"summary": summary, "pairs": rows}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--provider", choices=("gemini", "anthropic"), default="gemini")
    parser.add_argument("--model", default="gemini-2.5-flash")
    parser.add_argument("--json-out", type=Path)
    args = parser.parse_args()

    manifest = json.loads((HERE / "manifest.private.json").read_text(encoding="utf-8"))
    outdir = HERE / "outputs" / f"{args.provider}__{args.model}"
    problems = audit(manifest, outdir)
    print(f"=== integrity audit: {'CLEAN' if not problems else 'PROBLEMS'} ===")
    for problem in problems:
        print("  -", problem)
    if problems:
        raise SystemExit("fix integrity problems before interpreting scores")

    report = score(manifest, outdir)
    for row in report["pairs"]:
        if not row["complete"]:
            print(f"{row['pair_id']} {row['source_case']}: INCOMPLETE {row['missing_roles']}")
            continue
        weak = row["weak_output"]
        counter = row["counter_output"]
        print(
            f"{row['pair_id']} {row['source_case']}: {row['result']} | "
            f"{weak['verdict']}/{weak['severity']}/{weak['recommended_action']} -> "
            f"{counter['verdict']}/{counter['severity']}/{counter['recommended_action']} | "
            f"targets={row['weak_target_correct']}/{row['counter_target_correct']} "
            f"context={row['context_mentioned_in_counter']}"
        )
    print("\nsummary:", json.dumps(report["summary"], sort_keys=True))

    if args.json_out:
        args.json_out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(f"wrote {args.json_out}")


if __name__ == "__main__":
    main()
