#!/usr/bin/env python3
"""Create or verify the external-replication pre-model freeze."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
STUDY = Path(__file__).resolve().parent
CASES = STUDY / "cases"
FROZEN_INPUTS = STUDY / "frozen_inputs"
MANIFEST = STUDY / "FREEZE_MANIFEST.json"
STATUS = "frozen_pre_model_2026-07-22"

DEPENDENCIES = (
    ROOT / "rubric/evidence_condition_annotation_guideline_v1.1.md",
    ROOT / "rubric/evidence_sufficiency_rubric_v1.1.md",
    ROOT / "rubric/alert_anchor_selection_policy_v1.0.md",
    ROOT / "rubric/trigger_analytic_catalog_v1.0.json",
    ROOT / "rubric/trigger_analytic_catalog_v1.0.md",
    ROOT / "rubric/trigger_analytic_case_map_v1.0.csv",
    ROOT / "eval/gemini_triage_prompt.md",
    ROOT / "eval/llm_output.schema.json",
    ROOT / "eval/run_model.py",
    ROOT / "eval/validator_v1_1.py",
    ROOT / "tools/schema/alert_package.schema.json",
    ROOT / "tools/schema/case_config.schema.json",
    ROOT / "tools/schema/ground_truth.schema.json",
    ROOT / "tools/schema/provenance.schema.json",
    ROOT / "tools/schema/selection_metadata.schema.json",
    ROOT / "tools/schema/trigger_spec.schema.json",
    ROOT / "tools/schema/trigger_analytic_catalog.schema.json",
    ROOT / "tools/audit_trigger_rules.py",
    ROOT / "tools/trigger_analytic_taxonomy.py",
    ROOT / "tools/render_trigger_analytic_catalog.py",
    ROOT / "data_sources/windows_apt_2025/SOURCE_MANIFEST.json",
    ROOT / "data_sources/ainception_sl100/SOURCE_MANIFEST.json",
    ROOT / "data_sources/ait_ads/SOURCE_MANIFEST.json",
    ROOT / "data_sources/cam_lds/SOURCE_MANIFEST.json",
)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def relative(path: Path) -> str:
    return str(path.resolve().relative_to(ROOT))


def file_record(path: Path) -> dict[str, object]:
    return {
        "path": relative(path),
        "size_bytes": path.stat().st_size,
        "sha256": sha256_file(path),
    }


def run_preconditions() -> None:
    commands = (
        [sys.executable, str(STUDY / "verify_sources.py"), "--require-cache"],
        [sys.executable, str(STUDY / "audit_register.py")],
        [
            sys.executable,
            str(ROOT / "tools/audit_trigger_rules.py"),
            "--set",
            "external",
            "--write-results",
        ],
        [sys.executable, str(STUDY / "qa_built_cases.py")],
    )
    for command in commands:
        completed = subprocess.run(command, cwd=ROOT)
        if completed.returncode:
            raise SystemExit(f"freeze precondition failed: {' '.join(command)}")


def case_rows() -> list[dict[str, object]]:
    rows = []
    for case_dir in sorted(CASES.glob("*/*")):
        package_path = case_dir / "model_input/alert_package.json"
        ground_truth_path = case_dir / "annotations/ground_truth.json"
        package = json.loads(package_path.read_text(encoding="utf-8"))
        ground_truth = json.loads(ground_truth_path.read_text(encoding="utf-8"))
        case_id = package["case_id"]
        if ground_truth.get("case_id") != case_id:
            raise SystemExit(f"{case_id}: package/GT case_id mismatch")
        if ground_truth.get("review_status") != STATUS:
            raise SystemExit(
                f"{case_id}: review_status must be {STATUS!r}, got "
                f"{ground_truth.get('review_status')!r}"
            )
        frozen_path = FROZEN_INPUTS / f"{case_id}.json"
        rows.append(
            {
                "case_id": case_id,
                "condition": ground_truth["evidence_condition"],
                "package_path": relative(package_path),
                "package_sha256": sha256_file(package_path),
                "frozen_input_path": relative(frozen_path),
                "ground_truth_path": relative(ground_truth_path),
                "ground_truth_sha256": sha256_file(ground_truth_path),
            }
        )
    if len(rows) != 16 or len({row["case_id"] for row in rows}) != 16:
        raise SystemExit(f"freeze requires 16 unique cases, found {len(rows)}")
    return rows


def stage_inputs(rows: list[dict[str, object]]) -> None:
    FROZEN_INPUTS.mkdir(parents=True, exist_ok=True)
    expected = {f"{row['case_id']}.json" for row in rows}
    for stale in FROZEN_INPUTS.glob("*.json"):
        if stale.name not in expected:
            stale.unlink()
    for row in rows:
        source = ROOT / str(row["package_path"])
        destination = ROOT / str(row["frozen_input_path"])
        shutil.copyfile(source, destination)
        if sha256_file(destination) != row["package_sha256"]:
            raise SystemExit(f"{row['case_id']}: frozen input differs from canonical package")


def tracked_files() -> list[Path]:
    files = []
    for path in STUDY.rglob("*"):
        if not path.is_file() or path == MANIFEST or "__pycache__" in path.parts:
            continue
        files.append(path)
    files.extend(DEPENDENCIES)
    missing = [relative(path) for path in files if not path.is_file()]
    if missing:
        raise SystemExit(f"freeze dependency missing: {missing}")
    return sorted(set(files), key=relative)


def write_manifest() -> None:
    run_preconditions()
    rows = case_rows()
    stage_inputs(rows)
    manifest = {
        "schema": "safesoc.external_replication_freeze.v1",
        "study_id": "external_replication_v1",
        "status": "frozen_pre_model",
        "frozen_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "case_count": len(rows),
        "case_ids": sorted(str(row["case_id"]) for row in rows),
        "run_contract": {
            "split_label": "heldout",
            "prompt_arm": "evidence",
            "prompt_file": "eval/gemini_triage_prompt.md",
            "temperature": 0.0,
            "max_output_tokens": 2048,
            "gemini_thinking": "off",
            "rounds_per_model": 1,
            "models": ["gemini-2.5-flash", "claude-sonnet-4-6"],
            "model_calls_per_model": 16,
            "offline_scoring": "validator_v1_1 C1-C4; no additional model call",
        },
        "cases": rows,
        "files": [file_record(path) for path in tracked_files()],
        "raw_source_note": (
            "Third-party raw caches are represented by their SOURCE_MANIFEST hashes; "
            "the caches themselves are not benchmark artifacts."
        ),
    }
    MANIFEST.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {relative(MANIFEST)} ({len(manifest['files'])} tracked files)")


def check_manifest() -> None:
    if not MANIFEST.is_file():
        raise SystemExit(f"freeze manifest is absent: {relative(MANIFEST)}")
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    if manifest.get("status") != "frozen_pre_model" or manifest.get("case_count") != 16:
        raise SystemExit("freeze manifest status or case count is invalid")

    failures = []
    for record in manifest.get("files", []):
        path = ROOT / record["path"]
        if not path.is_file():
            failures.append(f"missing: {record['path']}")
            continue
        if path.stat().st_size != record["size_bytes"]:
            failures.append(f"size drift: {record['path']}")
            continue
        if sha256_file(path) != record["sha256"]:
            failures.append(f"hash drift: {record['path']}")

    for row in manifest.get("cases", []):
        frozen = ROOT / row["frozen_input_path"]
        package = ROOT / row["package_path"]
        ground_truth = ROOT / row["ground_truth_path"]
        for label, path, expected in (
            ("package", package, row["package_sha256"]),
            ("frozen input", frozen, row["package_sha256"]),
            ("ground truth", ground_truth, row["ground_truth_sha256"]),
        ):
            if not path.is_file() or sha256_file(path) != expected:
                failures.append(f"{row['case_id']}: {label} drift")

    if failures:
        raise SystemExit("freeze verification failed:\n  - " + "\n  - ".join(failures))
    print(
        f"PASS: external_replication_v1 freeze intact "
        f"({manifest['case_count']} cases, {len(manifest['files'])} tracked files)"
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true", help="create the pre-model freeze")
    mode.add_argument("--check", action="store_true", help="fail if any frozen artifact drifted")
    args = parser.parse_args()
    if args.write:
        write_manifest()
    check_manifest()


if __name__ == "__main__":
    main()
