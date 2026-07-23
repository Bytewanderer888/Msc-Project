#!/usr/bin/env python3
"""Offline comparison of GT-free runtime decisions against the frozen A4 oracle.

This script is an evaluation harness, not a deployable component. It consumes a
completed runtime report and a frozen offline-evaluator report, then measures how
well each routing profile identifies oracle-flagged outputs.
"""

from __future__ import annotations

import argparse
import csv
import json
from datetime import datetime, timezone
from pathlib import Path


VERSION = "1.1"
FULL_A4_CHECKS = ["C1", "C2", "C3", "C4"]
TARGETS = (
    "high_consequence_miscalibration",
    "calibration",
    "a4_any",
    "C1",
    "C2",
    "C3",
    "C4",
)


class ComparisonError(RuntimeError):
    """Raised when two reports cannot be compared without ambiguity."""


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def load_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ComparisonError(f"cannot read valid JSON from {path}: {exc}") from exc


def safe_ratio(numerator: int, denominator: int) -> float | None:
    return round(numerator / denominator, 4) if denominator else None


def target_positive(case: dict, target: str) -> bool:
    active = set(case.get("flagged_by_active_checks", []))
    if target == "high_consequence_miscalibration":
        action = case.get("model_output", {}).get("recommended_action")
        return bool(active & {"C2", "C4"}) and action in {"isolate", "close_benign"}
    if target == "a4_any":
        return bool(active)
    if target == "calibration":
        return bool(active & {"C2", "C4"})
    return target in active


def classification_metrics(labels: dict[str, bool], predictions: dict[str, bool]) -> dict:
    case_ids = sorted(labels)
    tp = [case_id for case_id in case_ids if labels[case_id] and predictions[case_id]]
    fp = [case_id for case_id in case_ids if not labels[case_id] and predictions[case_id]]
    tn = [case_id for case_id in case_ids if not labels[case_id] and not predictions[case_id]]
    fn = [case_id for case_id in case_ids if labels[case_id] and not predictions[case_id]]
    precision = safe_ratio(len(tp), len(tp) + len(fp))
    recall = safe_ratio(len(tp), len(tp) + len(fn))
    f1 = (
        round(2 * precision * recall / (precision + recall), 4)
        if precision is not None and recall is not None and precision + recall
        else None
    )
    return {
        "tp": len(tp),
        "fp": len(fp),
        "tn": len(tn),
        "fn": len(fn),
        "precision": precision,
        "recall": recall,
        "specificity": safe_ratio(len(tn), len(tn) + len(fp)),
        "f1": f1,
        "deferral_n": len(tp) + len(fp),
        "deferral_rate": safe_ratio(len(tp) + len(fp), len(case_ids)),
        "true_positive_cases": tp,
        "false_positive_cases": fp,
        "false_negative_cases": fn,
        "true_negative_cases": tn,
    }


def compare_reports(runtime: dict, oracle: dict, target: str = "a4_any") -> dict:
    if target not in TARGETS:
        raise ComparisonError(f"unknown target {target!r}; choose from {TARGETS}")
    if runtime.get("input_contract") != (
        "alert_package + LLM output only; no annotations or ground truth"
    ):
        raise ComparisonError("runtime report does not declare the GT-free input contract")
    if runtime.get("model") != oracle.get("model"):
        raise ComparisonError(
            f"model mismatch: runtime={runtime.get('model')!r}, oracle={oracle.get('model')!r}"
        )
    if runtime.get("split") != oracle.get("split"):
        raise ComparisonError(
            f"split mismatch: runtime={runtime.get('split')!r}, oracle={oracle.get('split')!r}"
        )
    if not runtime.get("completeness", {}).get("complete"):
        raise ComparisonError("runtime report is incomplete")
    if not oracle.get("completeness", {}).get("complete"):
        raise ComparisonError("oracle report is incomplete")
    active_checks = oracle.get("summary", {}).get("active_checks")
    if active_checks != FULL_A4_CHECKS:
        raise ComparisonError(
            "oracle report is not a full A4 run: "
            f"expected active_checks={FULL_A4_CHECKS}, got {active_checks!r}"
        )

    runtime_cases = {case["case_id"]: case for case in runtime.get("cases", [])}
    oracle_cases = {case["case_id"]: case for case in oracle.get("cases", [])}
    if set(runtime_cases) != set(oracle_cases):
        raise ComparisonError(
            "case-set mismatch: "
            f"runtime_only={sorted(set(runtime_cases) - set(oracle_cases))}, "
            f"oracle_only={sorted(set(oracle_cases) - set(runtime_cases))}"
        )

    decision_fields = ("verdict", "severity", "confidence", "recommended_action")
    decision_mismatches = {}
    for case_id in sorted(runtime_cases):
        runtime_decision = runtime_cases[case_id].get("decision", {})
        oracle_decision = oracle_cases[case_id].get("model_output", {})
        mismatched_fields = [
            field
            for field in decision_fields
            if runtime_decision.get(field) != oracle_decision.get(field)
        ]
        if mismatched_fields:
            decision_mismatches[case_id] = mismatched_fields
    if decision_mismatches:
        raise ComparisonError(
            "runtime and oracle reports do not represent the same saved decisions: "
            f"{decision_mismatches}"
        )

    labels = {
        case_id: target_positive(oracle_cases[case_id], target)
        for case_id in sorted(oracle_cases)
    }
    profiles = list(runtime.get("summary", {}).get("profiles", {}))
    if not profiles:
        raise ComparisonError("runtime report has no routing profiles")

    profile_results = {}
    for profile in profiles:
        predictions = {
            case_id: runtime_cases[case_id]["profile_outcomes"][profile]["status"]
            in {"review", "block"}
            for case_id in sorted(runtime_cases)
        }
        profile_results[profile] = classification_metrics(labels, predictions)

    case_rows = []
    for case_id in sorted(runtime_cases):
        case_rows.append(
            {
                "case_id": case_id,
                "oracle_positive": labels[case_id],
                "oracle_flags": oracle_cases[case_id].get("flagged_by_active_checks", []),
                "runtime_hard_findings": [
                    item["code"] for item in runtime_cases[case_id]["hard_findings"]
                ],
                "runtime_review_findings": [
                    item["code"]
                    for item in runtime_cases[case_id].get("review_findings", [])
                ],
                "recommended_action": oracle_cases[case_id]
                .get("model_output", {})
                .get("recommended_action"),
                "profiles": {
                    profile: runtime_cases[case_id]["profile_outcomes"][profile]["status"]
                    for profile in profiles
                },
            }
        )

    return {
        "evaluator": "SafeSOC runtime-to-oracle comparison harness",
        "evaluator_version": VERSION,
        "generated_utc": utc_now(),
        "scope": "offline research evaluation only; never used for deployment decisions",
        "model": runtime["model"],
        "split": runtime["split"],
        "runtime_validator_version": runtime.get("validator_version"),
        "runtime_policy_version": runtime.get("policy_version"),
        "oracle_rubric_version": oracle.get("rubric_version"),
        "target": target,
        "target_role": {
            "high_consequence_miscalibration": (
                "deployment-policy coverage target; structurally aligned with the gate, "
                "not an independent predictive-performance target"
            ),
            "calibration": "primary general-calibration target",
            "a4_any": "supplementary diagnostic target",
            "C1": "component diagnostic target",
            "C2": "component diagnostic target",
            "C3": "component diagnostic target",
            "C4": "component diagnostic target",
        }[target],
        "target_definition": {
            "high_consequence_miscalibration": (
                "C2 or C4 failed and the recommended action was isolate or close_benign; "
                "these recommendations require human approval before execution"
            ),
            "a4_any": "at least one active A4 check (C1-C4) failed",
            "calibration": "C2 decision calibration or C4 action calibration failed",
            "C1": "C1 reference-integrity check failed",
            "C2": "C2 decision-calibration check failed",
            "C3": "C3 counter-acknowledgement check failed",
            "C4": "C4 action-calibration check failed",
        }[target],
        "n": len(case_rows),
        "oracle_positive_n": sum(labels.values()),
        "token_calls": 0,
        "profiles": profile_results,
        "cases": case_rows,
    }


def print_report(report: dict) -> None:
    print(
        f"=== runtime-to-A4 comparison: {report['model']} / {report['split']} "
        f"target={report['target']} ({report['oracle_positive_n']}/{report['n']} positive) ==="
    )
    print(f"{'profile':18s} {'TP':>3s} {'FP':>3s} {'FN':>3s} {'TN':>3s} {'recall':>8s} {'precision':>9s} {'defer':>8s}")
    for profile, metrics in report["profiles"].items():
        recall = "n/a" if metrics["recall"] is None else f"{metrics['recall']:.1%}"
        precision = "n/a" if metrics["precision"] is None else f"{metrics['precision']:.1%}"
        defer = "n/a" if metrics["deferral_rate"] is None else f"{metrics['deferral_rate']:.1%}"
        print(
            f"{profile:18s} {metrics['tp']:3d} {metrics['fp']:3d} {metrics['fn']:3d} "
            f"{metrics['tn']:3d} {recall:>8s} {precision:>9s} {defer:>8s}"
        )
        if metrics["false_negative_cases"]:
            print(f"  false negatives: {', '.join(metrics['false_negative_cases'])}")


def write_json(report: dict, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")


def write_csv(report: dict, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        fieldnames = [
            "profile",
            "target",
            "n",
            "oracle_positive_n",
            "tp",
            "fp",
            "fn",
            "tn",
            "recall",
            "precision",
            "specificity",
            "f1",
            "deferral_n",
            "deferral_rate",
            "false_negative_cases",
            "false_positive_cases",
        ]
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for profile, metrics in report["profiles"].items():
            writer.writerow(
                {
                    "profile": profile,
                    "target": report["target"],
                    "n": report["n"],
                    "oracle_positive_n": report["oracle_positive_n"],
                    **{
                        key: metrics[key]
                        for key in (
                            "tp",
                            "fp",
                            "fn",
                            "tn",
                            "recall",
                            "precision",
                            "specificity",
                            "f1",
                            "deferral_n",
                            "deferral_rate",
                        )
                    },
                    "false_negative_cases": "|".join(metrics["false_negative_cases"]),
                    "false_positive_cases": "|".join(metrics["false_positive_cases"]),
                }
            )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime-report", type=Path, required=True)
    parser.add_argument("--oracle-report", type=Path, required=True)
    parser.add_argument("--target", choices=TARGETS, default="a4_any")
    parser.add_argument("--json-out", type=Path)
    parser.add_argument("--csv-out", type=Path)
    args = parser.parse_args()
    try:
        report = compare_reports(
            load_json(args.runtime_report),
            load_json(args.oracle_report),
            args.target,
        )
    except ComparisonError as exc:
        raise SystemExit(str(exc)) from exc
    print_report(report)
    if args.json_out:
        write_json(report, args.json_out)
        print(f"wrote JSON report: {args.json_out}")
    if args.csv_out:
        write_csv(report, args.csv_out)
        print(f"wrote CSV report: {args.csv_out}")


if __name__ == "__main__":
    main()
