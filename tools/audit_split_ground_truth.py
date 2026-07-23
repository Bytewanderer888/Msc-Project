#!/usr/bin/env python3
"""Audit ground-truth and package invariants for one benchmark split."""

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

import jsonschema


ROOT = Path(__file__).resolve().parent.parent
GT_SCHEMA = json.loads(
    (ROOT / "tools/schema/ground_truth.schema.json").read_text(encoding="utf-8")
)

POLICY = {
    "strong": {
        "verdict": "malicious",
        "severity": {"high", "critical"},
        "actions": {"escalate", "isolate"},
        "roles": {"preserve", "up_rank"},
    },
    "weak": {
        "verdict": "suspicious",
        "severity": {"low", "medium"},
        "actions": {"monitor", "investigate"},
        "roles": {"down_rank"},
    },
    "missing": {
        "verdict": "suspicious",
        "severity": {"low", "medium"},
        "actions": {"monitor", "investigate"},
        "roles": {"down_rank"},
    },
    "counter": {
        "verdict": "benign",
        "severity": {"informational", "low"},
        "actions": {"close_benign", "monitor"},
        "roles": {"down_rank"},
    },
}


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def duplicate_values(values: list[str]) -> set[str]:
    return {value for value in values if values.count(value) > 1}


def audit_case(case_dir: Path) -> dict:
    condition = case_dir.parent.parent.name
    config_path = case_dir / "build/case.json"
    package_path = case_dir / "model_input/alert_package.json"
    gt_path = case_dir / "annotations/ground_truth.json"
    metadata_path = case_dir / "annotations/selection_metadata.json"
    errors = []

    config = load(config_path)
    package = load(package_path)
    gt = load(gt_path)
    metadata = load(metadata_path)

    try:
        jsonschema.validate(gt, GT_SCHEMA)
    except jsonschema.ValidationError as exc:
        errors.append(f"ground-truth schema: {exc.message}")

    case_ids = {config.get("case_id"), package.get("case_id"), gt.get("case_id")}
    if len(case_ids) != 1:
        errors.append(f"case-id mismatch: {sorted(str(value) for value in case_ids)}")
    if gt.get("evidence_condition") != condition:
        errors.append(
            f"folder/GT condition mismatch: folder={condition}, GT={gt.get('evidence_condition')}"
        )

    package_ids = [package["main_alert"]["evidence_id"]]
    package_ids += [item["evidence_id"] for item in package.get("evidence_items", [])]
    package_ids += [
        item["derivation_id"] for item in package.get("deterministic_derivations", [])
    ]
    duplicates = duplicate_values(package_ids)
    if duplicates:
        errors.append(f"duplicate package evidence ids: {sorted(duplicates)}")
    expected_count = 1 + len(package.get("evidence_items", []))
    observed_count = package.get("observed_context", {}).get("event_count")
    if observed_count != expected_count:
        errors.append(
            f"event_count mismatch: observed_context={observed_count}, package={expected_count}"
        )
    configured_count = 1 + len(config.get("selection", {}).get("EV", []))
    if configured_count != expected_count:
        errors.append(
            f"selection/package count mismatch: config={configured_count}, package={expected_count}"
        )

    grounding = gt.get("grounding", {})
    supporting = grounding.get("supporting_evidence", [])
    counter = grounding.get("counter_evidence", [])
    for label, values in (("supporting", supporting), ("counter", counter)):
        missing = sorted(set(values) - set(package_ids))
        if missing:
            errors.append(f"unknown {label} evidence ids: {missing}")
        duplicates = duplicate_values(values)
        if duplicates:
            errors.append(f"duplicate {label} evidence ids: {sorted(duplicates)}")
    overlap = sorted(set(supporting) & set(counter))
    if overlap:
        errors.append(f"supporting/counter overlap: {overlap}")

    policy = POLICY[condition]
    if gt.get("correct_verdict") != policy["verdict"]:
        errors.append(
            f"verdict policy mismatch: expected {policy['verdict']}, got {gt.get('correct_verdict')}"
        )
    if set(gt.get("acceptable_severity", [])) != policy["severity"]:
        errors.append("severity band differs from the condition-level policy")
    if set(gt.get("acceptable_actions", [])) != policy["actions"]:
        errors.append("action band differs from the condition-level policy")
    if gt.get("calibration_role") not in policy["roles"]:
        errors.append("calibration role differs from the condition-level policy")
    if condition == "missing" and not (
        config.get("metadata", {}).get("case_scope", {}).get("absence_audit")
    ):
        errors.append("missing case has no metadata.case_scope.absence_audit")
    if condition == "counter" and not counter:
        errors.append("counter case has no counter_evidence ids")

    status = config.get("metadata", {}).get("status", "")
    if not status.startswith("audited_"):
        errors.append(f"case status is not audited: {status or '<missing>'}")
    proposition = config.get("metadata", {}).get("security_proposition", "").strip()
    if not proposition:
        errors.append("case has no fixed metadata.security_proposition")
    if metadata.get("security_proposition") != proposition:
        errors.append("selection metadata does not preserve the fixed security proposition")
    if metadata.get("case_files", {}).get("ground_truth") != "annotations/ground_truth.json":
        errors.append("selection metadata still marks ground truth as pending")
    if metadata.get("versioning", {}).get("review_status") == "dataset_v2_build":
        errors.append("selection metadata still has dataset_v2_build review status")
    review_text = json.dumps(metadata.get("review_required", {}), ensure_ascii=False).lower()
    if any(token in review_text for token in ("not yet built", "pending", "draft", "rubric v1.0")):
        errors.append("selection metadata contains stale review text")

    return {
        "case_id": config["case_id"],
        "condition": condition,
        "case_directory": str(case_dir.relative_to(ROOT)),
        "package_sha256": sha256(package_path),
        "event_count": expected_count,
        "passed": not errors,
        "errors": errors,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--split", choices=("dev", "heldout"), required=True)
    parser.add_argument("--json-out", type=Path)
    args = parser.parse_args()

    case_dirs = sorted(
        path.parent.parent
        for path in ROOT.glob(f"tier*/*/{args.split}/*/build/case.json")
    )
    rows = [audit_case(case_dir) for case_dir in case_dirs]
    for row in rows:
        print(f"{'PASS' if row['passed'] else 'FAIL'} {row['case_id']}")
        for error in row["errors"]:
            print(f"  - {error}")

    report = {
        "record_schema": "safesoc.split_ground_truth_audit.v1",
        "generated_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "split": args.split,
        "summary": {
            "cases": len(rows),
            "passed": sum(row["passed"] for row in rows),
            "failed": sum(not row["passed"] for row in rows),
        },
        "cases": rows,
    }
    if args.json_out:
        out = args.json_out if args.json_out.is_absolute() else ROOT / args.json_out
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(f"saved JSON: {out}")
    raise SystemExit(1 if report["summary"]["failed"] else 0)


if __name__ == "__main__":
    main()
