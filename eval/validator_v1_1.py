#!/usr/bin/env python3
"""SafeSOC ground-truth-backed offline evaluator, rubric v1.1 frozen final specification.

This module intentionally does not modify model outputs. It evaluates the same
saved A2 outputs with four deterministic checks:

  C1 evidence-reference integrity
  C2 verdict and severity calibration
  C3 counter-evidence acknowledgement
  C4 bidirectional action calibration

Free-text semantic truth is not inferred with broad keyword heuristics. The
ground truth's ``must_not_assert`` entries are emitted as manual audit prompts.
Self-reported confidence is analysed at dataset level and never overrides an
otherwise wrong decision.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

try:
    from jsonschema import Draft7Validator
except ImportError as exc:  # pragma: no cover - environment failure path
    raise SystemExit("validator_v1_1.py requires the 'jsonschema' package") from exc


VERSION = "1.1"
HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
SEVERITIES = ["informational", "low", "medium", "high", "critical"]
VERDICTS = ["benign", "suspicious", "malicious"]
ACTIONS = ["close_benign", "monitor", "investigate", "escalate", "isolate"]
ALL_CHECKS = ("C1", "C2", "C3", "C4")

# Condition-level policy is fixed across both splits. This prevents action or
# decision labels from being tuned case by case after outputs are observed.
CONDITION_POLICY = {
    "strong": {
        "verdict": "malicious",
        "severity": ["high", "critical"],
        "actions": ["escalate", "isolate"],
        "roles": {"preserve", "up_rank"},
    },
    "weak": {
        "verdict": "suspicious",
        "severity": ["low", "medium"],
        "actions": ["monitor", "investigate"],
        "roles": {"down_rank"},
    },
    "missing": {
        "verdict": "suspicious",
        "severity": ["low", "medium"],
        "actions": ["monitor", "investigate"],
        "roles": {"down_rank"},
    },
    "counter": {
        "verdict": "benign",
        "severity": ["informational", "low"],
        "actions": ["close_benign", "monitor"],
        "roles": {"down_rank"},
    },
}

EVIDENCE_ID_RE = re.compile(r"\b(?:A0|EV-\d{3}|DER-\d{3})\b", re.IGNORECASE)
DECODE_CLAIMS = (
    "decoded command",
    "decoded payload",
    "decoded string",
    "decoded blob",
    "decoded value",
    "decodes to",
    "decoded to",
    "deobfuscated to",
    "deobfuscates to",
    "deobfuscated command",
    "deobfuscated payload",
    "decoding reveals",
    "upon decoding",
    "after decoding",
    "base64-decoded",
    "b64-decoded",
)

CHECK_RESULT_KEYS = {
    "C1": "C1_reference_integrity",
    "C2": "C2_decision_calibration",
    "C3": "C3_counter_acknowledgement",
    "C4": "C4_action_calibration",
}


class EvaluationError(RuntimeError):
    """Raised when fail-closed preconditions are not satisfied."""


def load_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise EvaluationError(f"cannot read valid JSON from {path}: {exc}") from exc


def load_schemas() -> dict[str, dict]:
    return {
        "package": load_json(ROOT / "tools/schema/alert_package.schema.json"),
        "ground_truth": load_json(ROOT / "tools/schema/ground_truth.schema.json"),
        "output": load_json(HERE / "llm_output.schema.json"),
    }


def schema_errors(instance: dict, schema: dict) -> list[str]:
    validator = Draft7Validator(schema)
    errors = []
    for error in sorted(validator.iter_errors(instance), key=lambda e: list(e.absolute_path)):
        where = ".".join(str(part) for part in error.absolute_path) or "<root>"
        errors.append(f"{where}: {error.message}")
    return errors


def package_ids(package: dict) -> set[str]:
    ids = {package["main_alert"]["evidence_id"]}
    ids.update(item["evidence_id"] for item in package["evidence_items"])
    ids.update(
        item["derivation_id"]
        for item in package.get("deterministic_derivations", [])
        if item.get("derivation_id")
    )
    return ids


def rationale_ids(rationale: str) -> set[str]:
    return {match.group(0).upper() for match in EVIDENCE_ID_RE.finditer(rationale)}


def ground_truth_policy_errors(ground_truth: dict, package: dict) -> list[str]:
    errors = []
    condition = ground_truth["evidence_condition"]
    policy = CONDITION_POLICY[condition]

    if ground_truth["rubric_version"] != VERSION:
        errors.append(
            f"rubric_version must be {VERSION}, got {ground_truth['rubric_version']!r}"
        )
    if ground_truth["correct_verdict"] != policy["verdict"]:
        errors.append(
            f"{condition} verdict must be {policy['verdict']}, "
            f"got {ground_truth['correct_verdict']}"
        )
    if ground_truth["acceptable_severity"] != policy["severity"]:
        errors.append(
            f"{condition} severity band must be {policy['severity']}, "
            f"got {ground_truth['acceptable_severity']}"
        )
    if ground_truth["acceptable_actions"] != policy["actions"]:
        errors.append(
            f"{condition} action band must be {policy['actions']}, "
            f"got {ground_truth['acceptable_actions']}"
        )
    if ground_truth["calibration_role"] not in policy["roles"]:
        errors.append(
            f"{condition} calibration_role must be one of {sorted(policy['roles'])}, "
            f"got {ground_truth['calibration_role']}"
        )

    valid_ids = package_ids(package)
    grounding = ground_truth["grounding"]
    supporting = set(grounding["supporting_evidence"])
    counter = set(grounding["counter_evidence"])
    unknown = sorted((supporting | counter) - valid_ids)
    if unknown:
        errors.append(f"ground-truth evidence ids absent from package: {unknown}")
    overlap = sorted(supporting & counter)
    if overlap:
        errors.append(f"evidence ids cannot be both supporting and counter: {overlap}")
    if not supporting and not counter:
        errors.append("ground truth must designate at least one supporting or counter evidence id")
    return errors


def ordered_direction(value: str, acceptable: list[str], ordering: list[str]) -> str:
    value_index = ordering.index(value)
    band = [ordering.index(item) for item in acceptable]
    if min(band) <= value_index <= max(band):
        return "in_band"
    return "over" if value_index > max(band) else "under"


def validate_case(package: dict, output: dict, ground_truth: dict) -> dict:
    """Return deterministic v1.1 check results for one case."""
    valid_ids = package_ids(package)
    key_ids = set(output["key_evidence"])
    text_ids = rationale_ids(output["rationale"])
    all_cited_ids = key_ids | text_ids
    grounding = ground_truth["grounding"]
    relevant_ids = set(grounding["supporting_evidence"]) | set(grounding["counter_evidence"])

    invalid_key_ids = sorted(key_ids - valid_ids)
    invalid_rationale_ids = sorted(text_ids - valid_ids)
    relevant_key_ids = sorted(key_ids & relevant_ids)
    derivation_claim_without_derivation = (
        any(phrase in output["rationale"].lower() for phrase in DECODE_CLAIMS)
        and not package.get("deterministic_derivations")
    )
    c1 = {
        "invalid_key_evidence_ids": invalid_key_ids,
        "invalid_rationale_ids": invalid_rationale_ids,
        "relevant_key_evidence_ids": relevant_key_ids,
        "derivation_claim_without_derivation": derivation_claim_without_derivation,
        "pass": not invalid_key_ids
        and not invalid_rationale_ids
        and bool(relevant_key_ids)
        and not derivation_claim_without_derivation,
    }

    verdict_direction = ordered_direction(
        output["verdict"], [ground_truth["correct_verdict"]], VERDICTS
    )
    severity_direction = ordered_direction(
        output["severity"], ground_truth["acceptable_severity"], SEVERITIES
    )
    verdict_pass = verdict_direction == "in_band"
    severity_pass = severity_direction == "in_band"
    c2 = {
        "llm_verdict": output["verdict"],
        "expected_verdict": ground_truth["correct_verdict"],
        "verdict_direction": verdict_direction,
        "verdict_pass": verdict_pass,
        "llm_severity": output["severity"],
        "acceptable_severity": ground_truth["acceptable_severity"],
        "severity_direction": severity_direction,
        "severity_pass": severity_pass,
        "pass": verdict_pass and severity_pass,
    }

    counter_ids = set(grounding["counter_evidence"])
    if counter_ids:
        cited_counter_ids = sorted(counter_ids & all_cited_ids)
        c3 = {
            "applicable": True,
            "counter_evidence_ids": sorted(counter_ids),
            "cited_counter_evidence_ids": cited_counter_ids,
            "pass": bool(cited_counter_ids),
        }
    else:
        c3 = {
            "applicable": False,
            "counter_evidence_ids": [],
            "cited_counter_evidence_ids": [],
            "pass": True,
        }

    action_direction = ordered_direction(
        output["recommended_action"], ground_truth["acceptable_actions"], ACTIONS
    )
    c4 = {
        "llm_action": output["recommended_action"],
        "acceptable_actions": ground_truth["acceptable_actions"],
        "direction": action_direction,
        "pass": action_direction == "in_band",
    }

    return {
        "C1_reference_integrity": c1,
        "C2_decision_calibration": c2,
        "C3_counter_acknowledgement": c3,
        "C4_action_calibration": c4,
    }


def check_failed(checks: dict, check: str) -> bool:
    return not checks[CHECK_RESULT_KEYS[check]]["pass"]


def confidence_summary(rows: list[dict], threshold: float = 0.8) -> dict:
    values = [(row["output"]["confidence"], row["checks"]["C2_decision_calibration"]["pass"]) for row in rows]
    if not values:
        return {
            "n": 0,
            "interpretation": "exploratory self-reported confidence; not a primary validator check",
        }

    correct = [confidence for confidence, is_correct in values if is_correct]
    incorrect = [confidence for confidence, is_correct in values if not is_correct]

    def mean(items: list[float]) -> float | None:
        return round(sum(items) / len(items), 4) if items else None

    brier = sum((confidence - int(is_correct)) ** 2 for confidence, is_correct in values) / len(values)
    return {
        "n": len(values),
        "decision_correct_n": len(correct),
        "decision_incorrect_n": len(incorrect),
        "mean_confidence": mean([confidence for confidence, _ in values]),
        "mean_confidence_correct": mean(correct),
        "mean_confidence_incorrect": mean(incorrect),
        "brier_score_exploratory": round(brier, 4),
        "high_confidence_threshold": threshold,
        "high_confidence_error_n": sum(
            not is_correct and confidence >= threshold for confidence, is_correct in values
        ),
        "interpretation": "exploratory self-reported confidence; not a primary validator check",
    }


def discover_cases(split: str, case_root: Path | None = None) -> dict[str, Path]:
    cases: dict[str, Path] = {}
    duplicates = []
    if case_root is None:
        case_files = sorted(ROOT.glob(f"tier*/*/{split}/*/build/case.json"))
    else:
        case_files = sorted(case_root.glob("*/*/build/case.json"))
    for case_json in case_files:
        case_id = load_json(case_json)["case_id"]
        if case_id in cases:
            duplicates.append(case_id)
        cases[case_id] = case_json.parent.parent
    if duplicates:
        raise EvaluationError(f"duplicate case ids in {split}: {sorted(set(duplicates))}")
    if not cases:
        location = case_root if case_root is not None else f"canonical {split} split"
        raise EvaluationError(f"no cases discovered under {location}")
    return cases


def evaluate(
    model: str,
    split: str,
    allow_incomplete: bool = False,
    case_root: Path | None = None,
) -> tuple[list[dict], dict]:
    schemas = load_schemas()
    case_dirs = discover_cases(split, case_root)
    output_dir = HERE / "outputs" / model / split
    if not output_dir.is_dir():
        raise EvaluationError(f"model output directory does not exist: {output_dir}")

    output_paths = {path.stem: path for path in output_dir.glob("*.json")}
    missing_outputs = sorted(set(case_dirs) - set(output_paths))
    orphan_outputs = sorted(set(output_paths) - set(case_dirs))
    missing_ground_truth = sorted(
        case_id
        for case_id, case_dir in case_dirs.items()
        if not (case_dir / "annotations/ground_truth.json").exists()
    )
    precondition_errors = []
    if missing_outputs:
        precondition_errors.append(f"missing model outputs: {missing_outputs}")
    if orphan_outputs:
        precondition_errors.append(f"orphan model outputs: {orphan_outputs}")
    if missing_ground_truth:
        precondition_errors.append(f"missing ground truths: {missing_ground_truth}")

    rows = []
    invalid_cases: dict[str, list[str]] = {}
    for case_id, case_dir in sorted(case_dirs.items()):
        if case_id in missing_outputs or case_id in missing_ground_truth:
            continue
        package = load_json(case_dir / "model_input/alert_package.json")
        ground_truth = load_json(case_dir / "annotations/ground_truth.json")
        output = load_json(output_paths[case_id])

        errors = []
        for label, instance in (
            ("package", package),
            ("ground_truth", ground_truth),
            ("output", output),
        ):
            errors.extend(
                f"{label}.{message}" for message in schema_errors(instance, schemas[label])
            )
        if package.get("case_id") != case_id:
            errors.append(f"package.case_id is {package.get('case_id')!r}, expected {case_id!r}")
        if ground_truth.get("case_id") != case_id:
            errors.append(
                f"ground_truth.case_id is {ground_truth.get('case_id')!r}, expected {case_id!r}"
            )
        if not errors:
            errors.extend(ground_truth_policy_errors(ground_truth, package))
        if errors:
            invalid_cases[case_id] = errors
            continue

        checks = validate_case(package, output, ground_truth)
        rows.append(
            {
                "case_id": case_id,
                "condition": ground_truth["evidence_condition"],
                "calibration_role": ground_truth["calibration_role"],
                "output": output,
                "checks": checks,
                "semantic_audit_prompts": ground_truth["grounding"]["must_not_assert"],
            }
        )

    if invalid_cases:
        for case_id, errors in invalid_cases.items():
            precondition_errors.append(f"{case_id}: " + "; ".join(errors))
    if precondition_errors and not allow_incomplete:
        joined = "\n  - ".join(precondition_errors)
        raise EvaluationError(
            "fail-closed completeness/schema check failed:\n  - " + joined
            + "\nUse --allow-incomplete only for an explicitly exploratory partial run."
        )

    completeness = {
        "expected_cases": len(case_dirs),
        "scored_cases": len(rows),
        "missing_outputs": missing_outputs,
        "missing_ground_truth": missing_ground_truth,
        "orphan_outputs": orphan_outputs,
        "invalid_cases": invalid_cases,
        "complete": not precondition_errors,
    }
    return rows, completeness


def build_summary(rows: list[dict], active_checks: list[str]) -> dict:
    failure_counts = {
        check: sum(check_failed(row["checks"], check) for row in rows) for check in ALL_CHECKS
    }
    counter_applicable = sum(
        row["checks"]["C3_counter_acknowledgement"]["applicable"] for row in rows
    )
    condition_severity = {}
    for condition in CONDITION_POLICY:
        directions = Counter(
            row["checks"]["C2_decision_calibration"]["severity_direction"]
            for row in rows
            if row["condition"] == condition
        )
        condition_severity[condition] = {
            "over": directions["over"],
            "in_band": directions["in_band"],
            "under": directions["under"],
        }

    flagged_cases = sorted(
        row["case_id"]
        for row in rows
        if any(check_failed(row["checks"], check) for check in active_checks)
    )
    return {
        "n": len(rows),
        "verdict_correct_n": sum(
            row["checks"]["C2_decision_calibration"]["verdict_pass"] for row in rows
        ),
        "severity_in_band_n": sum(
            row["checks"]["C2_decision_calibration"]["severity_pass"] for row in rows
        ),
        "joint_decision_correct_n": sum(
            row["checks"]["C2_decision_calibration"]["pass"] for row in rows
        ),
        "check_failure_counts": failure_counts,
        "C3_applicable_n": counter_applicable,
        "severity_by_condition": condition_severity,
        "active_checks": active_checks,
        "active_flagged_n": len(flagged_cases),
        "active_flagged_cases": flagged_cases,
        "confidence": confidence_summary(rows),
    }


def build_report(
    model: str,
    split: str,
    rows: list[dict],
    completeness: dict,
    active_checks: list[str],
) -> dict:
    cases = []
    for row in rows:
        cases.append(
            {
                "case_id": row["case_id"],
                "condition": row["condition"],
                "calibration_role": row["calibration_role"],
                "model_output": {
                    key: row["output"][key]
                    for key in ("verdict", "severity", "confidence", "recommended_action")
                },
                "checks": row["checks"],
                "flagged_by_active_checks": [
                    check for check in active_checks if check_failed(row["checks"], check)
                ],
                "semantic_audit_prompts": row["semantic_audit_prompts"],
            }
        )
    return {
        "evaluator": "SafeSOC offline evaluator",
        "rubric_version": VERSION,
        "generated_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "model": model,
        "split": split,
        "completeness": completeness,
        "summary": build_summary(rows, active_checks),
        "cases": cases,
    }


def print_report(report: dict) -> None:
    summary = report["summary"]
    print(
        f"=== SafeSOC offline evaluator v{VERSION} on {report['model']} / {report['split']} "
        f"({summary['n']}/{report['completeness']['expected_cases']} scored) ===\n"
    )
    print(
        f"{'case':9s} {'condition':9s} {'model decision':20s} "
        f"{'C2v':4s} {'C2s':5s} {'C1':4s} {'C3':4s} {'C4':4s} {'action dir':10s}"
    )
    mark = lambda value: "OK" if value else "X"
    for case in report["cases"]:
        output = case["model_output"]
        checks = case["checks"]
        c2 = checks["C2_decision_calibration"]
        c3 = checks["C3_counter_acknowledgement"]
        c3_mark = mark(c3["pass"]) if c3["applicable"] else "-"
        decision = f"{output['verdict']}/{output['severity']}"
        print(
            f"{case['case_id']:9s} {case['condition']:9s} {decision:20.20s} "
            f"{mark(c2['verdict_pass']):4s} {mark(c2['severity_pass']):5s} "
            f"{mark(checks['C1_reference_integrity']['pass']):4s} {c3_mark:4s} "
            f"{mark(checks['C4_action_calibration']['pass']):4s} "
            f"{checks['C4_action_calibration']['direction']:10s}"
        )

    print("\n--- decision metrics ---")
    print(
        f"  verdict correct       : {summary['verdict_correct_n']}/{summary['n']}\n"
        f"  severity in band      : {summary['severity_in_band_n']}/{summary['n']}\n"
        f"  joint decision correct: {summary['joint_decision_correct_n']}/{summary['n']}"
    )
    print("\n--- check failures ---")
    print("  " + "  ".join(f"{key}={value}" for key, value in summary["check_failure_counts"].items()))
    print(f"  C3 denominator={summary['C3_applicable_n']} applicable cases")

    print("\n--- severity calibration by condition ---")
    for condition, counts in summary["severity_by_condition"].items():
        print(
            f"  {condition:8s} over={counts['over']} "
            f"in-band={counts['in_band']} under={counts['under']}"
        )

    confidence = summary["confidence"]
    print("\n--- exploratory self-reported confidence ---")
    print(
        f"  mean(correct)={confidence.get('mean_confidence_correct')}  "
        f"mean(incorrect)={confidence.get('mean_confidence_incorrect')}  "
        f"Brier={confidence.get('brier_score_exploratory')}  "
        f"high-confidence errors={confidence.get('high_confidence_error_n')}"
    )

    active = ",".join(summary["active_checks"])
    arm = "A3 (C1-only diagnostic)" if active == "C1" else (
        "A4 (full evaluator)" if active == "C1,C2,C3,C4" else "custom subset"
    )
    print(f"\n=== component analysis: {arm} ===")
    print(
        f"  active checks: {active}\n"
        f"  flagged: {summary['active_flagged_n']}/{summary['n']} "
        f"{summary['active_flagged_cases']}"
    )


def write_json_report(report: dict, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")


def write_csv_report(report: dict, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "case_id",
        "condition",
        "calibration_role",
        "verdict",
        "expected_verdict",
        "verdict_pass",
        "severity",
        "acceptable_severity",
        "severity_direction",
        "confidence",
        "recommended_action",
        "acceptable_actions",
        "action_direction",
        "C1_pass",
        "C2_pass",
        "C3_applicable",
        "C3_pass",
        "C4_pass",
        "flagged_by_active_checks",
    ]
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for case in report["cases"]:
            output = case["model_output"]
            checks = case["checks"]
            c2 = checks["C2_decision_calibration"]
            c3 = checks["C3_counter_acknowledgement"]
            c4 = checks["C4_action_calibration"]
            writer.writerow(
                {
                    "case_id": case["case_id"],
                    "condition": case["condition"],
                    "calibration_role": case["calibration_role"],
                    "verdict": output["verdict"],
                    "expected_verdict": c2["expected_verdict"],
                    "verdict_pass": c2["verdict_pass"],
                    "severity": output["severity"],
                    "acceptable_severity": "|".join(c2["acceptable_severity"]),
                    "severity_direction": c2["severity_direction"],
                    "confidence": output["confidence"],
                    "recommended_action": output["recommended_action"],
                    "acceptable_actions": "|".join(c4["acceptable_actions"]),
                    "action_direction": c4["direction"],
                    "C1_pass": checks["C1_reference_integrity"]["pass"],
                    "C2_pass": c2["pass"],
                    "C3_applicable": c3["applicable"],
                    "C3_pass": c3["pass"],
                    "C4_pass": c4["pass"],
                    "flagged_by_active_checks": "|".join(case["flagged_by_active_checks"]),
                }
            )


def parse_checks(raw: str) -> list[str]:
    checks = [part.strip().upper() for part in raw.split(",") if part.strip()]
    if not checks or len(set(checks)) != len(checks) or any(check not in ALL_CHECKS for check in checks):
        raise EvaluationError(
            f"--checks must be a unique comma-separated subset of {','.join(ALL_CHECKS)}; got {raw!r}"
        )
    return checks


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--split", choices=("dev", "heldout"), default="dev")
    parser.add_argument(
        "--model",
        default="gemini-2.5-flash__A2_evidence_prompt",
        help="output directory tag under eval/outputs/",
    )
    parser.add_argument(
        "--checks",
        default="C1,C2,C3,C4",
        help="active component checks; C1 reproduces A3 and all four reproduce A4",
    )
    parser.add_argument(
        "--allow-incomplete",
        action="store_true",
        help="score the valid subset instead of failing on missing/invalid cases",
    )
    parser.add_argument(
        "--case-root",
        type=Path,
        help="optional isolated case-set root laid out as <condition>/<case>/; canonical discovery remains default",
    )
    parser.add_argument("--json-out", type=Path, help="optional machine-readable JSON report path")
    parser.add_argument("--csv-out", type=Path, help="optional per-case CSV report path")
    args = parser.parse_args()
    case_root = None
    if args.case_root is not None:
        case_root = args.case_root.expanduser()
        if not case_root.is_absolute():
            case_root = ROOT / case_root
        case_root = case_root.resolve()
        if not case_root.is_dir():
            raise SystemExit(f"--case-root does not exist or is not a directory: {case_root}")

    try:
        active_checks = parse_checks(args.checks)
        rows, completeness = evaluate(
            args.model, args.split, args.allow_incomplete, case_root
        )
        report = build_report(args.model, args.split, rows, completeness, active_checks)
    except EvaluationError as exc:
        raise SystemExit(str(exc)) from exc

    print_report(report)
    if args.json_out:
        write_json_report(report, args.json_out)
        print(f"\nwrote JSON report: {args.json_out}")
    if args.csv_out:
        write_csv_report(report, args.csv_out)
        print(f"wrote CSV report: {args.csv_out}")


if __name__ == "__main__":
    main()
