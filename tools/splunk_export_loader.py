#!/usr/bin/env python3
"""
splunk_export_loader.py — read a Splunk search JSON export and return the raw
Windows-event XML strings (each result's `_raw`), so a case normalizer can parse
them EXACTLY like the raw log. This is the bridge for the Splunk-fed pipeline:
    Splunk SPL  ->  Export (JSON)  ->  this loader  ->  build_case.py  ->  package

Handles the common Splunk export shapes:
  * UI  "Export -> JSON":    a JSON array   [ {..., "_raw": "<Event>..."}, ... ]
  * REST/CLI  -output json:  NDJSON, one  {"preview":..,"result":{...}}  per line
  * {"results":[...]}  or a single  {"result":{...}}  object

Returns a list of `<Event>...</Event>` XML strings (the same content the raw log
holds), in file order. The caller keys them by <EventRecordID> as usual.
"""
import json
from pathlib import Path


def load_events_from_export(path):
    text = Path(path).read_text(encoding="utf-8", errors="ignore").strip()
    if not text:
        return []

    records = []
    try:                                  # whole-file JSON (array or object)
        data = json.loads(text)
        if isinstance(data, list):
            records = data
        elif isinstance(data, dict):
            if isinstance(data.get("results"), list):
                records = data["results"]
            elif "result" in data:
                records = [data["result"]]
            else:
                records = [data]
    except json.JSONDecodeError:          # NDJSON: one object per line
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(obj, dict):
                records.append(obj.get("result", obj))

    raws = []
    for r in records:
        if not isinstance(r, dict):
            continue
        raw = r.get("_raw") or r.get("raw")
        if isinstance(raw, str) and ("<Event" in raw or "EventCode=" in raw):  # XML or stanza (key=value) format
            raws.append(raw)
    return raws


if __name__ == "__main__":
    import sys
    got = load_events_from_export(sys.argv[1])
    print(f"loaded {len(got)} raw events from {sys.argv[1]}")
