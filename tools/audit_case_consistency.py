#!/usr/bin/env python3
"""Audit the common structural and authorship contract across all 41 cases."""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

import jsonschema


ROOT = Path(__file__).resolve().parent.parent
SCHEMA_DIR = ROOT / "tools" / "schema"
EXPECTED_COUNT = 41
EXPECTED_KEYS = {
    "package": (
        "schema_version", "case_id", "package_type", "observed_context",
        "main_alert", "evidence_items", "deterministic_derivations",
    ),
    "ground_truth": (
        "case_id", "evidence_condition", "calibration_role", "correct_verdict",
        "acceptable_severity", "acceptable_actions", "grounding", "the_trap",
        "rationale", "annotated_by", "review_status", "rubric_version",
    ),
    "selection_metadata": (
        "schema_version", "case_id", "case_name", "security_proposition",
        "case_directory", "split", "status", "attack_category", "source_provenance",
        "case_files", "case_scope", "main_alert_selection", "related_event_selection",
        "evidence_id_map", "curation_notes", "model_input_controls", "experimental_role",
        "versioning", "review_required",
    ),
    "provenance": ("dataset", "sources", "primary_host", "tier"),
}
RETRIEVAL_SECTIONS = (
    "## Source scope",
    "## Step 0 — Stage and ingest",
    "## Investigation",
    "## Curation record",
    "## Export",
    "## Normalize",
)
STALE_TEXT = (
    "curated_draft",
    "pending_after_rubric_freeze",
    "dataset_v2_build",
    "NOT YET BUILT",
    "DRAFT —",
    "dataset_v2/",
)


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def validate_schema(instance: dict, schema_name: str, errors: list[str]) -> None:
    schema = load(SCHEMA_DIR / schema_name)
    try:
        jsonschema.validate(instance, schema)
    except jsonschema.ValidationError as exc:
        errors.append(f"{schema_name}: {exc.message}")


def audit_export(path: Path, expected_count: int, errors: list[str]) -> None:
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    if len(rows) != expected_count:
        errors.append(f"Splunk export row count {len(rows)} != selected event count {expected_count}")
    seen = set()
    for index, row in enumerate(rows):
        expected_wrapper = {"preview", "result"} | ({"lastrow"} if index == len(rows) - 1 else set())
        if set(row) != expected_wrapper:
            errors.append(f"Splunk export row {index + 1} has non-canonical wrapper keys")
        if row.get("preview") is not False:
            errors.append(f"Splunk export row {index + 1} preview must be false")
        if index == len(rows) - 1 and row.get("lastrow") is not True:
            errors.append("Splunk export final row must have lastrow=true")
        result = row.get("result", {})
        required = {"_time", "EventRecordID", "_raw"}
        if not required.issubset(result):
            errors.append(f"Splunk export row {index + 1} lacks canonical result fields")
            continue
        if set(result) - (required | {"source"}):
            errors.append(f"Splunk export row {index + 1} has unexpected result fields")
        key = (result.get("source", ""), str(result["EventRecordID"]))
        if key in seen:
            errors.append(f"duplicate Splunk export event {key}")
        seen.add(key)


def audit_case(config_path: Path) -> dict:
    case_dir = config_path.parent.parent
    tier_name, condition, split, directory = case_dir.relative_to(ROOT).parts
    errors: list[str] = []
    paths = {
        "package": case_dir / "model_input" / "alert_package.json",
        "ground_truth": case_dir / "annotations" / "ground_truth.json",
        "selection_metadata": case_dir / "annotations" / "selection_metadata.json",
        "provenance": case_dir / "source" / "provenance.json",
    }
    for label, path in paths.items():
        if not path.is_file():
            errors.append(f"missing {path.relative_to(case_dir)}")
    if errors:
        return {"case_id": directory, "passed": False, "errors": errors}

    config = load(config_path)
    package = load(paths["package"])
    gt = load(paths["ground_truth"])
    metadata = load(paths["selection_metadata"])
    provenance = load(paths["provenance"])
    case_id = config.get("case_id", directory)

    validate_schema(config, "case_config.schema.json", errors)
    validate_schema(package, "alert_package.schema.json", errors)
    validate_schema(gt, "ground_truth.schema.json", errors)
    validate_schema(metadata, "selection_metadata.schema.json", errors)
    validate_schema(provenance, "provenance.schema.json", errors)

    for label, instance in (
        ("package", package),
        ("ground_truth", gt),
        ("selection_metadata", metadata),
        ("provenance", provenance),
    ):
        if tuple(instance) != EXPECTED_KEYS[label]:
            errors.append(f"{label} top-level key order/shape differs from the canonical contract")

    if len({config.get("case_id"), package.get("case_id"), gt.get("case_id"), metadata.get("case_id")}) != 1:
        errors.append("case_id differs across config, package, GT, or selection metadata")
    if config.get("split") != split or metadata.get("split") != split:
        errors.append("split differs from the directory split")
    if gt.get("evidence_condition") != condition:
        errors.append("ground-truth condition differs from the directory condition")
    expected_tier = int(tier_name.removeprefix("tier"))
    if config.get("metadata", {}).get("tier", {}).get("tier") != expected_tier:
        errors.append("config tier differs from the directory tier")
    if provenance.get("tier", {}).get("tier") != expected_tier:
        errors.append("provenance tier differs from the directory tier")
    if config.get("metadata", {}).get("case_directory") != directory or metadata.get("case_directory") != directory:
        errors.append("case_directory differs from the actual directory name")
    proposition = config.get("metadata", {}).get("security_proposition")
    if not proposition or metadata.get("security_proposition") != proposition:
        errors.append("fixed security proposition is missing or not preserved")

    selected = [config["selection"]["A0"], *config["selection"]["EV"]]
    if set(config.get("roles", {})) != set(selected):
        errors.append("config role map does not exactly cover the selected source events")
    package_ids = [package["main_alert"]["evidence_id"], *[item["evidence_id"] for item in package["evidence_items"]]]
    if set(metadata.get("evidence_id_map", {})) != set(package_ids):
        errors.append("selection metadata evidence map differs from package evidence ids")
    if any(not row.get("role_note", "").strip() for row in metadata.get("evidence_id_map", {}).values()):
        errors.append("selection metadata contains an empty role_note")
    if package.get("observed_context", {}).get("event_count") != len(package_ids):
        errors.append("package event_count differs from package evidence items")
    if len(selected) != len(package_ids):
        errors.append("selected source-event count differs from package event count")

    is_otrf = "mordor_log" in config
    query_dir = case_dir / "queries"
    extracted_dir = case_dir / "extracted"
    if is_otrf:
        if query_dir.exists() or extracted_dir.exists():
            errors.append("OTRF direct-source case contains Splunk-only queries/ or extracted/")
        if metadata.get("case_files", {}).get("main_alert_query") != "build/case.json":
            errors.append("OTRF query reference must be build/case.json")
    else:
        retrieval_path = query_dir / "retrieval_spec.md"
        export_path = case_dir / config.get("staged_export", "")
        if not retrieval_path.is_file() or not export_path.is_file():
            errors.append("attack_data case lacks its retrieval specification or retained export")
        else:
            text = retrieval_path.read_text(encoding="utf-8")
            if text.splitlines()[0] != f"# {case_id} — Splunk retrieval specification":
                errors.append("retrieval specification title is not canonical")
            missing_sections = [section for section in RETRIEVAL_SECTIONS if section not in text]
            if missing_sections:
                errors.append(f"retrieval specification lacks sections: {missing_sections}")
            if any(token in text for token in STALE_TEXT):
                errors.append("retrieval specification contains stale project/status language")
            audit_export(export_path, len(selected), errors)
        if metadata.get("case_files", {}).get("main_alert_query") != "queries/retrieval_spec.md":
            errors.append("attack_data query reference must be queries/retrieval_spec.md")

    for path in (config_path, paths["ground_truth"], paths["selection_metadata"]):
        text = path.read_text(encoding="utf-8")
        if any(token in text for token in STALE_TEXT):
            errors.append(f"{path.name} contains stale project/status language")

    return {
        "case_id": case_id,
        "directory": str(case_dir.relative_to(ROOT)),
        "package_sha256": sha256(paths["package"]),
        "passed": not errors,
        "errors": errors,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json-out", type=Path)
    args = parser.parse_args()
    configs = sorted(ROOT.glob("tier*/**/build/case.json"))
    rows = [audit_case(path) for path in configs]
    global_errors = []
    if len(rows) != EXPECTED_COUNT:
        global_errors.append(f"expected {EXPECTED_COUNT} cases, found {len(rows)}")
    clutter = sorted(
        path.relative_to(ROOT).as_posix()
        for pattern in ("**/.DS_Store",)
        for path in ROOT.glob(pattern)
    )
    if clutter:
        global_errors.append(f"generated filesystem clutter remains: {clutter}")

    for row in rows:
        print(f"{'PASS' if row['passed'] else 'FAIL'} {row['case_id']}")
        for error in row["errors"]:
            print(f"  - {error}")
    for error in global_errors:
        print(f"FAIL PROJECT\n  - {error}")

    report = {
        "record_schema": "safesoc.case_consistency_audit.v1",
        "generated_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "summary": {
            "cases": len(rows),
            "passed": sum(row["passed"] for row in rows),
            "failed": sum(not row["passed"] for row in rows),
            "project_errors": len(global_errors),
        },
        "project_errors": global_errors,
        "cases": rows,
    }
    if args.json_out:
        output = args.json_out if args.json_out.is_absolute() else ROOT / args.json_out
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(f"saved JSON: {output}")
    raise SystemExit(1 if global_errors or any(not row["passed"] for row in rows) else 0)


if __name__ == "__main__":
    main()
