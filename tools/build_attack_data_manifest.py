#!/usr/bin/env python3
"""Inventory the optional local attack_data staging cache without redistributing it."""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
STAGED = ROOT / "_splunk_ingest"
DEFAULT_OUTPUT = ROOT / "data_sources/attack_data_staged_manifest.json"


class ManifestError(RuntimeError):
    """Raised when provenance and the local cache cannot be matched exactly."""


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(8 * 1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def load_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ManifestError(f"cannot read valid JSON from {path}: {exc}") from exc


def attack_data_cases() -> list[Path]:
    paths = []
    for path in sorted(ROOT.glob("tier*/*/*/*/build/case.json")):
        if "mordor_log" not in load_json(path):
            paths.append(path)
    return paths


def build_manifest() -> dict:
    if not STAGED.is_dir():
        raise ManifestError(
            f"optional staging cache is absent: {STAGED}; generate this manifest before removing it"
        )

    entries = []
    referenced_files = set()
    for case_path in attack_data_cases():
        case_dir = case_path.parent.parent
        config = load_json(case_path)
        provenance = load_json(case_dir / "source/provenance.json")
        sources = provenance.get("sources", [])
        stored_names = [
            item.strip()
            for item in config.get("metadata", {}).get("stored_filename", "").split(" + ")
            if item.strip()
        ]
        if len(stored_names) != len(sources):
            raise ManifestError(
                f"{config.get('case_id')}: stored_filename count {len(stored_names)} "
                f"does not match provenance source count {len(sources)}"
            )

        relative_case = case_dir.relative_to(ROOT)
        tier, condition, split = relative_case.parts[:3]
        for source, stored_name in zip(sources, stored_names):
            staged_path = STAGED / stored_name
            if not staged_path.is_file():
                raise ManifestError(f"{config['case_id']}: staged file is missing: {staged_path}")
            actual_hash = sha256(staged_path)
            expected_hash = source.get("sha256")
            if actual_hash != expected_hash:
                raise ManifestError(
                    f"{config['case_id']}: SHA-256 mismatch for {stored_name}: "
                    f"expected {expected_hash}, got {actual_hash}"
                )
            referenced_files.add(stored_name)
            configured_source = source.get("source_log")
            prefix = "attack_data-master/"
            upstream_repo_path = (
                configured_source[len(prefix) :]
                if configured_source and configured_source.startswith(prefix)
                else configured_source
            )
            entries.append(
                {
                    "staged_filename": stored_name,
                    "bytes": staged_path.stat().st_size,
                    "sha256": actual_hash,
                    "configured_source_path": configured_source,
                    "upstream_repo_path": upstream_repo_path,
                    "sensor": source.get("sensor"),
                    "case_id": config["case_id"],
                    "case_path": str(relative_case),
                    "tier": tier,
                    "condition": condition,
                    "split": split,
                }
            )

    local_files = {path.name for path in STAGED.iterdir() if path.is_file()}
    unreferenced = sorted(local_files - referenced_files)
    missing_from_cache = sorted(referenced_files - local_files)
    if unreferenced or missing_from_cache:
        raise ManifestError(
            "staging cache does not match case provenance exactly: "
            f"unreferenced={unreferenced}, missing={missing_from_cache}"
        )

    entries.sort(key=lambda item: item["staged_filename"])
    return {
        "record_schema": "safesoc.attack_data_staged_sources.v1",
        "generated_utc": utc_now(),
        "distribution_policy": (
            "The optional _splunk_ingest directory is a local staging cache copied from public attack_data "
            "sources, not an original SafeSOC benchmark asset. Normal model and evaluator workflows do not "
            "require it. Retrieve the listed upstream files for --from-log, --verify-log, and raw-source audits."
        ),
        "upstream": {
            "name": "Splunk attack_data",
            "repository": "https://github.com/splunk/attack_data",
            "license": "Apache-2.0",
            "license_copy": "data_sources/licenses/Splunk_attack_data_LICENSE.txt",
            "upstream_distribution_note": "Cloning some raw files may require Git LFS; SafeSOC does not track its staging cache with Git LFS.",
        },
        "local_cache_directory": "_splunk_ingest",
        "file_count": len(entries),
        "total_bytes": sum(item["bytes"] for item in entries),
        "files": entries,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    output = args.output if args.output.is_absolute() else ROOT / args.output
    try:
        manifest = build_manifest()
    except ManifestError as exc:
        raise SystemExit(str(exc)) from exc
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(
        f"wrote {output.relative_to(ROOT)}: {manifest['file_count']} files, "
        f"{manifest['total_bytes']} bytes"
    )


if __name__ == "__main__":
    main()
