#!/usr/bin/env python3
"""QA built external-replication cases before any freeze or model call."""

from __future__ import annotations

import csv
import hashlib
import json
import re
import sys
import zipfile
from pathlib import Path
from typing import Any

import jsonschema


ROOT = Path(__file__).resolve().parents[2]
STUDY = Path(__file__).resolve().parent
CASES = STUDY / "cases"
sys.path.insert(0, str(ROOT / "tools"))
from trigger_analytic_taxonomy import (  # noqa: E402
    TriggerTaxonomyError,
    validate_spec_classification,
)
SCHEMA = json.loads((ROOT / "tools/schema/alert_package.schema.json").read_text())
TRIGGER_SCHEMA = json.loads(
    (ROOT / "tools/schema/trigger_spec.schema.json").read_text()
)
FORBIDDEN_MODEL_PATTERNS = {
    "ATT&CK ID": re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.I),
    "decision label": re.compile(
        r"\b(?:strong|weak|missing|counter|malicious|benign|suspicious|ground[_ -]?truth|calibration[_ -]?role)\b",
        re.I,
    ),
    "source/detector identity": re.compile(
        r"\b(?:AIT|AMiner|Wazuh|Suricata|AInception|SL100|Drone Shield|"
        r"russellmitchell|harrison|santos)\b",
        re.I,
    ),
    "source action label": re.compile(r"\battack[_ -]?step[_ -]?\d+\b", re.I),
    "framework identity": re.compile(r"\b(?:Atomic Red Team|Caldera)\b", re.I),
    "known raw credential": re.compile(r"tainox3aedeeSh", re.I),
}

EXPECTED = {
    "strong": ("malicious", ["high", "critical"], ["escalate", "isolate"]),
    "weak": ("suspicious", ["low", "medium"], ["monitor", "investigate"]),
    "missing": ("suspicious", ["low", "medium"], ["monitor", "investigate"]),
    "counter": ("benign", ["informational", "low"], ["close_benign", "monitor"]),
}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def verify_source_records(
    archive: zipfile.ZipFile, provenance: dict[str, Any], failures: list[str]
) -> None:
    by_member: dict[str, list[dict[str, Any]]] = {}
    for record in provenance["selected_records"]:
        by_member.setdefault(record["archive_member"], []).append(record)

    for member, expected_records in by_member.items():
        byte_ranges = [
            record
            for record in expected_records
            if "byte_start" in record and "byte_end" in record
        ]
        line_records = [record for record in expected_records if "line_number" in record]

        if byte_ranges:
            source = archive.read(member)
            for record in byte_ranges:
                start = record["byte_start"]
                end = record["byte_end"]
                if not (0 <= start < end <= len(source)):
                    failures.append(
                        f"{member}:{start}-{end} invalid source byte range"
                    )
                    continue
                actual = sha256(source[start:end])
                if actual != record["record_sha256"]:
                    failures.append(
                        f"{member}:{start}-{end} source-record hash mismatch"
                    )

        if not line_records:
            continue
        expected_lines = {record["line_number"]: record for record in line_records}
        found: set[int] = set()
        with archive.open(member) as handle:
            for line_number, raw in enumerate(handle, start=1):
                if line_number not in expected_lines:
                    continue
                found.add(line_number)
                actual = sha256(raw.rstrip(b"\r\n"))
                expected = expected_lines[line_number]["record_sha256"]
                if actual != expected:
                    failures.append(f"{member}:{line_number} source-record hash mismatch")
                if len(found) == len(expected_lines):
                    break
        for missing in set(expected_lines) - found:
            failures.append(f"{member}:{missing} source record is absent")


def canonical_csv_row(row: dict[str, str]) -> bytes:
    return json.dumps(
        row, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def csv_record_index(source_path: Path) -> dict[int, tuple[str, str]]:
    records: dict[int, tuple[str, str]] = {}
    with source_path.open(newline="", encoding="utf-8-sig") as handle:
        for record_number, row in enumerate(csv.DictReader(handle), start=2):
            records[record_number] = (
                row.get("_id", ""),
                sha256(canonical_csv_row(row)),
            )
    return records


def verify_csv_records(
    source_path: Path,
    provenance: dict[str, Any],
    cache: dict[Path, dict[int, tuple[str, str]]],
    failures: list[str],
) -> None:
    if source_path not in cache:
        cache[source_path] = csv_record_index(source_path)
    actual_records = cache[source_path]
    for record in provenance["selected_records"]:
        record_number = record.get("csv_record_number")
        if record_number not in actual_records:
            failures.append(f"{source_path.name}:{record_number} source record is absent")
            continue
        actual_id, actual_hash = actual_records[record_number]
        if actual_id != record.get("source_record_id"):
            failures.append(
                f"{source_path.name}:{record_number} source _id mismatch"
            )
        if actual_hash != record.get("record_sha256"):
            failures.append(
                f"{source_path.name}:{record_number} source-record hash mismatch"
            )


def main() -> int:
    failures: list[str] = []
    case_dirs = sorted(CASES.glob("*/*"))
    if not case_dirs:
        print("No built cases found")
        return 1

    archives: dict[Path, zipfile.ZipFile] = {}
    checked_source_hashes: set[Path] = set()
    csv_cache: dict[Path, dict[int, tuple[str, str]]] = {}
    try:
        for case_dir in case_dirs:
            package_path = case_dir / "model_input/alert_package.json"
            gt_path = case_dir / "annotations/ground_truth.json"
            selection_path = case_dir / "annotations/selection_metadata.json"
            provenance_path = case_dir / "source/provenance.json"
            trigger_spec_path = case_dir / "annotations/trigger_spec.json"
            trigger_audit_path = case_dir / "annotations/trigger_audit.json"
            runbook_path = case_dir / "queries/retrieval_spec.md"
            required = (
                package_path,
                gt_path,
                selection_path,
                provenance_path,
                trigger_spec_path,
                trigger_audit_path,
                runbook_path,
            )
            if not all(path.exists() for path in required):
                failures.append(f"{case_dir.name}: incomplete case structure")
                continue

            package = load(package_path)
            gt = load(gt_path)
            selection = load(selection_path)
            provenance = load(provenance_path)
            trigger_spec = load(trigger_spec_path)
            trigger_audit = load(trigger_audit_path)
            case_id = package.get("case_id", case_dir.name)

            try:
                jsonschema.validate(trigger_spec, TRIGGER_SCHEMA)
            except jsonschema.ValidationError as exc:
                failures.append(f"{case_id}: trigger schema failure: {exc.message}")
            try:
                validate_spec_classification(trigger_spec)
            except TriggerTaxonomyError as exc:
                failures.append(f"{case_id}: {exc}")
            if trigger_spec.get("formalisation_timing") != "prospective_pre_model":
                failures.append(f"{case_id}: trigger rule is not marked prospective pre-model")
            if not trigger_audit.get("pass"):
                failures.append(f"{case_id}: trigger replay did not pass")
            if trigger_audit.get("selected_record_key") != trigger_spec.get("expected_a0", {}).get("record_key"):
                failures.append(f"{case_id}: trigger audit/spec A0 mismatch")
            for taxonomy_key in ("analytic_family_id", "analytic_pattern_id"):
                if trigger_audit.get(taxonomy_key) != trigger_spec.get(taxonomy_key):
                    failures.append(
                        f"{case_id}: trigger audit/spec {taxonomy_key} mismatch"
                    )
            if "annotations/trigger_spec.json" not in runbook_path.read_text(encoding="utf-8"):
                failures.append(f"{case_id}: runbook does not identify the authoritative trigger rule")

            archive_info = provenance.get("source_archive")
            file_info = provenance.get("source_file")
            if archive_info:
                source_path = ROOT / archive_info.get("path", "")
                source_kind = "archive"
                expected_source_hash = archive_info.get("sha256")
            elif file_info:
                source_path = ROOT / file_info.get("path", "")
                source_kind = "csv"
                expected_source_hash = file_info.get("sha256")
            else:
                failures.append(f"{case_id}: provenance has no source archive/file")
                continue

            if not source_path.is_file():
                failures.append(f"{case_id}: source is absent: {source_path}")
                continue
            if source_path not in checked_source_hashes:
                actual_source_hash = sha256(source_path.read_bytes())
                if actual_source_hash != expected_source_hash:
                    failures.append(f"{case_id}: source hash mismatch")
                checked_source_hashes.add(source_path)
            if source_kind == "archive" and source_path not in archives:
                archives[source_path] = zipfile.ZipFile(source_path)

            try:
                jsonschema.validate(package, SCHEMA)
            except jsonschema.ValidationError as exc:
                failures.append(f"{case_id}: package schema failure: {exc.message}")

            package_text = package_path.read_text(encoding="utf-8")
            for label, pattern in FORBIDDEN_MODEL_PATTERNS.items():
                match = pattern.search(package_text)
                if match:
                    failures.append(f"{case_id}: leaked {label}: {match.group(0)!r}")

            if not (case_id == gt.get("case_id") == selection.get("case_id") == provenance.get("case_id")):
                failures.append(f"{case_id}: case_id mismatch across files")

            evidence_ids = [package["main_alert"]["evidence_id"]]
            evidence_ids.extend(item["evidence_id"] for item in package["evidence_items"])
            derivation_ids = [item["derivation_id"] for item in package["deterministic_derivations"]]
            all_ids = set(evidence_ids + derivation_ids)
            if len(evidence_ids + derivation_ids) != len(all_ids):
                failures.append(f"{case_id}: duplicate evidence/derivation ID")

            grounding = gt.get("grounding", {})
            referenced = set(grounding.get("supporting_evidence", [])) | set(
                grounding.get("counter_evidence", [])
            )
            if not referenced <= all_ids:
                failures.append(f"{case_id}: GT references IDs absent from package: {sorted(referenced - all_ids)}")

            expected_count = 1 + len(package["evidence_items"])
            if package["observed_context"]["event_count"] != expected_count:
                failures.append(f"{case_id}: observed event_count mismatch")

            for item in [package["main_alert"], *package["evidence_items"]]:
                expected_record_id = f"SRC-{item['evidence_id']}"
                if item["source_event"]["event_record_id"] != expected_record_id:
                    failures.append(f"{case_id}: non-neutral event_record_id for {item['evidence_id']}")

            condition = gt.get("evidence_condition")
            actual_decision = (
                gt.get("correct_verdict"),
                gt.get("acceptable_severity"),
                gt.get("acceptable_actions"),
            )
            if condition not in EXPECTED or actual_decision != EXPECTED[condition]:
                failures.append(f"{case_id}: GT decision band violates rubric v1.1")

            provenance_ids = {item["evidence_id"] for item in provenance["selected_records"]}
            if provenance_ids != set(evidence_ids):
                failures.append(f"{case_id}: provenance/package evidence IDs differ")

            if source_kind == "archive":
                verify_source_records(archives[source_path], provenance, failures)
            else:
                verify_csv_records(source_path, provenance, csv_cache, failures)
            print(
                f"{case_id}: schema + leakage + IDs + decision band + provenance checked"
            )
    finally:
        for archive in archives.values():
            archive.close()

    if failures:
        for failure in failures:
            print(f"FAIL: {failure}")
        return 1
    print(f"PASS: {len(case_dirs)} built case(s) passed automated pre-freeze QA")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
