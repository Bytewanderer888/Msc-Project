#!/usr/bin/env python3
"""Verify locally staged external-replication sources against their manifests."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MANIFESTS = (
    ROOT / "data_sources/windows_apt_2025/SOURCE_MANIFEST.json",
    ROOT / "data_sources/ainception_sl100/SOURCE_MANIFEST.json",
    ROOT / "data_sources/ait_ads/SOURCE_MANIFEST.json",
    ROOT / "data_sources/cam_lds/SOURCE_MANIFEST.json",
)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--require-cache",
        action="store_true",
        help="fail if a reproducible local_staging_cache is not present",
    )
    args = parser.parse_args()

    failures: list[str] = []
    for manifest_path in MANIFESTS:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        print(f"{manifest['corpus']}:")
        for entry in manifest["files"]:
            path = manifest_path.parent / entry["path"]
            optional_cache = entry["retention"] == "local_staging_cache"
            if not path.exists():
                state = "MISSING-CACHE" if optional_cache else "MISSING"
                print(f"  {state:13} {entry['path']}")
                if args.require_cache or not optional_cache:
                    failures.append(str(path))
                continue

            size_ok = path.stat().st_size == entry["bytes"]
            digest_ok = sha256(path) == entry["sha256"]
            state = "OK" if size_ok and digest_ok else "MISMATCH"
            print(f"  {state:13} {entry['path']} ({path.stat().st_size:,} bytes)")
            if state != "OK":
                failures.append(str(path))

    if failures:
        print(f"FAILED: {len(failures)} source file(s) missing or mismatched")
        return 1
    print("PASS: all required available sources match their manifests")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
