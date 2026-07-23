#!/usr/bin/env python3
"""One-time canonicalization of retained Splunk NDJSON exports."""

from __future__ import annotations

import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
XML_ID = re.compile(r"<EventRecordID>(\d+)</EventRecordID>")
STANZA_ID = re.compile(r"(?m)^RecordNumber=(\d+)\s*$")
XML_TIME = re.compile(r"<TimeCreated SystemTime=['\"]([^'\"]+)['\"]")


def infer_id(raw: str) -> str:
    match = XML_ID.search(raw) or STANZA_ID.search(raw)
    if not match:
        raise ValueError("cannot infer EventRecordID from retained raw event")
    return match.group(1)


def infer_time(raw: str) -> str:
    match = XML_TIME.search(raw)
    if match:
        return match.group(1)
    first = raw.splitlines()[0].strip() if raw.splitlines() else ""
    if first:
        return first
    raise ValueError("cannot infer event time from retained raw event")


def canonicalize(path: Path, expected_count: int) -> tuple[int, int]:
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    output = []
    seen = set()
    for wrapper in rows:
        result = wrapper.get("result", wrapper)
        raw = result.get("_raw")
        if not isinstance(raw, str) or not raw:
            raise ValueError(f"{path}: retained row has no _raw field")
        record_id = str(result.get("EventRecordID") or infer_id(raw))
        source = result.get("source")
        if path.name == "od001_events.json":
            source = "olympic_security.log" if STANZA_ID.search(raw) else "olympic_sysmon.log"
        key = (source or "", record_id)
        if key in seen:
            continue
        seen.add(key)
        canonical_result = {"_time": result.get("_time") or infer_time(raw)}
        if source:
            canonical_result["source"] = source
        canonical_result["EventRecordID"] = record_id
        canonical_result["_raw"] = raw
        output.append({"preview": False, "result": canonical_result})

    if len(output) != expected_count:
        raise ValueError(f"{path}: expected {expected_count} unique rows, found {len(output)}")
    output[-1]["lastrow"] = True
    text = "\n".join(json.dumps(row, ensure_ascii=False, separators=(",", ":")) for row in output) + "\n"
    path.write_text(text, encoding="utf-8")
    return len(rows), len(output)


def main() -> None:
    configs = sorted(ROOT.glob("tier*/**/build/case.json"))
    exports = 0
    removed = 0
    for config_path in configs:
        config = json.loads(config_path.read_text(encoding="utf-8"))
        if "mordor_log" in config:
            continue
        case_dir = config_path.parent.parent
        export_path = case_dir / config["staged_export"]
        before, after = canonicalize(export_path, 1 + len(config["selection"]["EV"]))
        exports += 1
        removed += before - after
    if exports != 31:
        raise SystemExit(f"expected 31 Splunk exports, found {exports}")
    print(f"standardized {exports} Splunk exports; removed {removed} duplicate rows")


if __name__ == "__main__":
    main()
