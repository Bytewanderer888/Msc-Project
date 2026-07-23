#!/usr/bin/env python3
"""Create a no-API reproducibility inventory for all current model outputs.

Older SafeSOC calls predate API-time run-event capture. This tool binds their
current output files to the current package and harness artifacts without
pretending those hashes were recorded at call time. Future outputs with a
matching run_events_<split>.jsonl success record are marked api_time_bound.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
EVAL = ROOT / "eval"
OUTPUTS = EVAL / "outputs"
CONTINUITY = EVAL / "artifact_continuity.json"


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def relative(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(ROOT))
    except ValueError:
        return str(path.resolve())


def file_record(path: Path) -> dict:
    stat = path.stat()
    return {
        "path": relative(path),
        "sha256": sha256(path),
        "bytes": stat.st_size,
        "mtime_utc": datetime.fromtimestamp(stat.st_mtime, timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        ),
    }


def read_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def prompt_for_tag(tag: str) -> Path | None:
    if "__A1_basic_prompt" in tag:
        return EVAL / "triage_prompt_basic.md"
    if "__A2_evidence_prompt" in tag:
        return EVAL / "gemini_triage_prompt.md"
    return None


def package_map() -> dict[tuple[str, str], Path]:
    found = {}
    for path in ROOT.glob("tier*/*/*/*/model_input/alert_package.json"):
        package = json.loads(path.read_text(encoding="utf-8"))
        split = path.parents[2].name
        key = (split, package["case_id"])
        if key in found:
            raise SystemExit(f"duplicate package for {key}: {found[key]} and {path}")
        found[key] = path
    return found


def global_artifacts() -> dict:
    paths = {
        "prompt_A1": EVAL / "triage_prompt_basic.md",
        "prompt_A2": EVAL / "gemini_triage_prompt.md",
        "output_schema": EVAL / "llm_output.schema.json",
        "runner": EVAL / "run_model.py",
        "validator": EVAL / "validator_v1_1.py",
        "rubric": ROOT / "rubric/evidence_sufficiency_rubric_v1.1.md",
        "pricing": EVAL / "pricing_snapshot.json",
        "artifact_continuity": CONTINUITY,
        "experiment_protocol": ROOT / "EXPERIMENT_PROTOCOL.md",
        "dependencies": ROOT / "requirements.txt",
    }
    return {name: file_record(path) for name, path in paths.items()}


def continuity_map() -> dict[tuple[str, str, str], dict]:
    if not CONTINUITY.exists():
        return {}
    data = json.loads(CONTINUITY.read_text(encoding="utf-8"))
    return {
        (item["split"], item["case"], item["package_sha256"]): item
        for item in data.get("records", [])
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--out",
        type=Path,
        default=EVAL / "reports/run_inventory_current.json",
        help="output JSON path",
    )
    args = parser.parse_args()

    packages = package_map()
    records = []
    continuity = continuity_map()
    for output_dir in sorted(path for path in OUTPUTS.glob("*/*") if path.is_dir()):
        tag = output_dir.parent.name
        split = output_dir.name
        if split not in {"dev", "heldout"}:
            continue
        usage = read_jsonl(output_dir.parent / f"usage_{split}.jsonl")
        events = read_jsonl(output_dir.parent / f"run_events_{split}.jsonl")
        prompt = prompt_for_tag(tag)
        for output_path in sorted(output_dir.glob("*.json")):
            case = output_path.stem
            package_path = packages.get((split, case))
            if package_path is None:
                raise SystemExit(f"no canonical package for {split}/{case}")
            output = file_record(output_path)
            package = file_record(package_path)
            continuity_record = continuity.get((split, case, package["sha256"]))
            usage_history = [item for item in usage if item.get("case") == case]
            matching_events = [
                item
                for item in events
                if item.get("case") == case
                and item.get("status") == "success"
                and item.get("output_sha256") == output["sha256"]
                and item.get("package_sha256") == package["sha256"]
            ]
            package_newer = package_path.stat().st_mtime > output_path.stat().st_mtime
            if matching_events:
                temporal_status = "api_time_byte_identity"
            elif not package_newer:
                temporal_status = "package_not_newer_than_output"
            elif continuity_record:
                temporal_status = "package_newer_but_byte_identity_documented"
            else:
                temporal_status = "unresolved_package_newer_than_output"
            round_match = re.search(r"_round(\d+)", tag)
            records.append(
                {
                    "model_tag": tag,
                    "requested_model": tag.split("__", 1)[0],
                    "split": split,
                    "round": int(round_match.group(1)) if round_match else 1,
                    "case": case,
                    "output": output,
                    "package": package,
                    "prompt": file_record(prompt) if prompt else None,
                    "usage_history_n": len(usage_history),
                    "latest_usage": usage_history[-1] if usage_history else None,
                    "binding_status": "api_time_bound" if matching_events else "reconstructed_after_run",
                    "matching_run_event": matching_events[-1] if matching_events else None,
                    "temporal_status": temporal_status,
                    "continuity_record": continuity_record,
                }
            )

    summary = {
        "outputs": len(records),
        "api_time_bound": sum(item["binding_status"] == "api_time_bound" for item in records),
        "reconstructed_after_run": sum(
            item["binding_status"] == "reconstructed_after_run" for item in records
        ),
        "outputs_with_api_usage": sum(item["latest_usage"] is not None for item in records),
        "outputs_without_api_usage": sum(item["latest_usage"] is None for item in records),
        "documented_package_continuity": [
            f"{item['model_tag']}/{item['split']}/{item['case']}"
            for item in records
            if item["temporal_status"] == "package_newer_but_byte_identity_documented"
        ],
        "unresolved_package_newer_than_output": [
            f"{item['model_tag']}/{item['split']}/{item['case']}"
            for item in records
            if item["temporal_status"] == "unresolved_package_newer_than_output"
        ],
    }
    report = {
        "record_schema": "safesoc.run_inventory.v1",
        "generated_utc": utc_now(),
        "status": "reconstructed snapshot; API-time hashes are authoritative only when binding_status is api_time_bound",
        "global_artifacts": global_artifacts(),
        "summary": summary,
        "records": records,
    }
    out = args.out if args.out.is_absolute() else ROOT / args.out
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    print(f"wrote {relative(out)}")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
