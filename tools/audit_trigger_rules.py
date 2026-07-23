#!/usr/bin/env python3
"""Replay SafeSOC A0 trigger rules over complete case source scopes."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import sys
import zipfile
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import jsonschema


ROOT = Path(__file__).resolve().parent.parent
TOOLS = ROOT / "tools"
sys.path.insert(0, str(TOOLS))
import normalize  # noqa: E402
from trigger_analytic_taxonomy import (  # noqa: E402
    TriggerTaxonomyError,
    validate_spec_classification,
)


SCHEMA = json.loads(
    (ROOT / "tools/schema/trigger_spec.schema.json").read_text(encoding="utf-8")
)
FORBIDDEN_FIELD_PARTS = {
    "record_key",
    "record_id",
    "source_record_id",
    "event_record_id",
    "csv_record_number",
    "line_number",
    "block_index",
    "audit_serial",
    "byte_start",
    "byte_end",
    "raw_sha256",
    "sha256",
    "timestamp",
    "event_time",
    "event_time_utc",
    "system_time",
    "condition",
    "ground_truth",
    "model_output",
    "verdict",
    "severity",
    "calibration_role",
}


class TriggerAuditError(RuntimeError):
    pass


_WINDOWS_EXTERNAL_CACHE: dict[Path, list[dict[str, Any]]] = {}


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def discover(case_set: str) -> list[Path]:
    if case_set == "canonical":
        return sorted(
            case_json.parent.parent
            for case_json in ROOT.glob("tier*/*/*/*/build/case.json")
        )
    if case_set == "external":
        return sorted(
            case_json.parent.parent
            for case_json in (ROOT / "experiments/external_replication_v1/cases").glob(
                "*/*/build/case.json"
            )
        )
    return sorted(
        discover("canonical") + discover("external"),
        key=lambda path: load_json(path / "build/case.json")["case_id"],
    )


def raw_canonical_events(case_dir: Path, config: dict[str, Any]) -> tuple[list[dict], str]:
    keyed, description = normalize.load_events(config, case_dir, "log", None)
    events = []
    for record_key, raw in keyed.items():
        event_type, attributes = normalize.project(raw)
        decoded_command = normalize.decode_base64_utf16le(
            attributes.get("command_line", "")
        )
        events.append(
            {
                "record_key": record_key,
                "event_time_utc": normalize.utcz(raw),
                "event_code": int(normalize.code_of(raw) or 0),
                "event_type": event_type,
                "provider": normalize.prov(raw),
                "channel": normalize.chan(raw),
                "computer": normalize.comp(raw),
                "attributes": attributes,
                "derived": (
                    {"decoded_command": decoded_command} if decoded_command else {}
                ),
                "raw_sha256": sha256_bytes(raw.encode("utf-8")),
            }
        )
    return events, description


def snake_case(value: str) -> str:
    value = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", value)
    return re.sub(r"[^A-Za-z0-9]+", "_", value).strip("_").casefold()


def external_event(
    *,
    record_key: str,
    event_time: str = "",
    event_code: int = 0,
    event_type: str = "external_record",
    provider: str = "",
    channel: str = "",
    computer: str = "",
    attributes: dict[str, Any],
    raw: bytes,
) -> dict[str, Any]:
    return {
        "record_key": record_key,
        "event_time_utc": event_time,
        "event_code": event_code,
        "event_type": event_type,
        "provider": provider,
        "channel": channel,
        "computer": computer,
        "attributes": attributes,
        "derived": {},
        "raw_sha256": sha256_bytes(raw),
    }


def windows_external_events(path: Path) -> list[dict[str, Any]]:
    cached = _WINDOWS_EXTERNAL_CACHE.get(path)
    if cached is not None:
        return cached
    type_by_code = {
        1: "process_create",
        3: "network_connection",
        7: "image_load",
        5611: "system_state",
    }
    events: list[dict[str, Any]] = []
    with path.open(newline="", encoding="utf-8-sig") as handle:
        for row in csv.DictReader(handle):
            record_key = row.get("_id", "")
            if not record_key:
                continue
            code_text = row.get("_source.data.win.system.eventID", "").strip()
            event_code = int(code_text) if code_text.isdigit() else 0
            attributes: dict[str, Any] = {
                "source_partition": row.get("_index", ""),
                "full_log": row.get("_source.full_log", ""),
                "message": row.get("_source.data.win.system.message", ""),
                "agent_name": row.get("_source.agent.name", ""),
            }
            prefix = "_source.data.win.eventdata."
            for key, value in row.items():
                if key.startswith(prefix) and value.strip():
                    attributes[snake_case(key[len(prefix) :])] = value.strip().replace(
                        "\\\\", "\\"
                    )
            computer = (
                row.get("_source.data.win.system.computer", "").strip()
                or row.get("_source.agent.name", "").strip()
            )
            event_time = row.get("_source.data.win.system.systemTime", "").strip()
            if not event_time:
                event_time = row.get("_source.@timestamp", "").strip()
            raw = json.dumps(
                row, sort_keys=True, separators=(",", ":"), ensure_ascii=False
            ).encode("utf-8")
            events.append(
                external_event(
                    record_key=record_key,
                    event_time=event_time,
                    event_code=event_code,
                    event_type=type_by_code.get(
                        event_code,
                        "monitoring_status" if "Agent disconnected:" in attributes["full_log"] else "external_record",
                    ),
                    provider=row.get("_source.data.win.system.providerName", ""),
                    channel=row.get("_source.data.win.system.channel", ""),
                    computer=computer,
                    attributes=attributes,
                    raw=raw,
                )
            )
    _WINDOWS_EXTERNAL_CACHE[path] = events
    return events


def resolve_zip_member(archive: zipfile.ZipFile, requested: str) -> str:
    if requested in archive.namelist():
        return requested
    matches = [name for name in archive.namelist() if name.endswith("/" + requested)]
    if len(matches) != 1:
        raise TriggerAuditError(
            f"archive member {requested!r} resolved to {len(matches)} entries"
        )
    return matches[0]


def json_member_events(
    archive: zipfile.ZipFile, requested_member: str
) -> list[dict[str, Any]]:
    member = resolve_zip_member(archive, requested_member)
    events = []
    with archive.open(member) as handle:
        for line_number, raw_line in enumerate(handle, start=1):
            clean = raw_line.rstrip(b"\r\n")
            if not clean:
                continue
            try:
                record = json.loads(clean)
            except json.JSONDecodeError:
                continue
            timestamp = str(record.get("@timestamp", ""))
            computer = str(
                record.get("agent", {}).get("name", "")
                or record.get("AMiner", {}).get("ID", "")
            )
            events.append(
                external_event(
                    record_key=f"{requested_member}:line:{line_number}",
                    event_time=timestamp,
                    computer=computer,
                    attributes={
                        "record": record,
                        "raw_text": clean.decode("utf-8", errors="replace"),
                    },
                    raw=clean,
                )
            )
    return events


def text_member_events(
    archive: zipfile.ZipFile, requested_member: str
) -> list[dict[str, Any]]:
    member = resolve_zip_member(archive, requested_member)
    events = []
    with archive.open(member) as handle:
        for line_number, raw_line in enumerate(handle, start=1):
            clean = raw_line.rstrip(b"\r\n")
            if not clean:
                continue
            text_value = clean.decode("utf-8", errors="replace")
            timestamp = ""
            audit_time = re.search(r"audit\((\d+(?:\.\d+)?):", text_value)
            if audit_time:
                timestamp = datetime.fromtimestamp(
                    float(audit_time.group(1)), tz=timezone.utc
                ).isoformat().replace("+00:00", "Z")
            events.append(
                external_event(
                    record_key=f"{requested_member}:line:{line_number}",
                    event_time=timestamp,
                    attributes={"raw_text": text_value},
                    raw=clean,
                )
            )
    return events


def linux_audit_group_events(
    archive: zipfile.ZipFile, requested_member: str
) -> list[dict[str, Any]]:
    member = resolve_zip_member(archive, requested_member)
    grouped: dict[str, list[bytes]] = {}
    order: list[str] = []
    for raw_line in archive.read(member).splitlines(keepends=True):
        serial_match = re.search(rb"audit\(([^:]+):(\d+)\)", raw_line)
        if not serial_match:
            continue
        serial = serial_match.group(2).decode("ascii")
        if serial not in grouped:
            grouped[serial] = []
            order.append(serial)
        grouped[serial].append(raw_line)
    events = []
    for serial in order:
        raw = b"".join(grouped[serial])
        text_value = raw.decode("utf-8", errors="replace").rstrip()
        epoch_match = re.search(r"audit\((\d+(?:\.\d+)?):", text_value)
        event_time = ""
        if epoch_match:
            event_time = datetime.fromtimestamp(
                float(epoch_match.group(1)), tz=timezone.utc
            ).isoformat().replace("+00:00", "Z")
        syscall_match = re.search(r"\bsyscall=(\d+)\b", text_value)
        events.append(
            external_event(
                record_key=f"{requested_member}:audit:{serial}",
                event_time=event_time,
                event_code=int(syscall_match.group(1)) if syscall_match else 0,
                event_type="linux_audit_group",
                attributes={"raw_text": text_value},
                raw=raw,
            )
        )
    return events


def windows_block_events(
    archive: zipfile.ZipFile, requested_member: str
) -> list[dict[str, Any]]:
    member = resolve_zip_member(archive, requested_member)
    data = archive.read(member)
    starts = [
        match.start()
        for match in re.finditer(rb"(?m)^(?:Information|Error|Warning)\t", data)
    ]
    events = []
    for block_index, start in enumerate(starts, start=1):
        end = starts[block_index] if block_index < len(starts) else len(data)
        raw = data[start:end]
        text_value = raw.decode("utf-8", errors="replace").rstrip()
        code_match = re.search(r"Microsoft-Windows-Sysmon\t(\d+)\t", text_value)
        time_match = re.search(r"(?m)^(\d{4}-\d{2}-\d{2} [0-9:.]+)\s*$", text_value)
        event_time = time_match.group(1).replace(" ", "T") + "Z" if time_match else ""
        events.append(
            external_event(
                record_key=f"{requested_member}:block:{block_index}",
                event_time=event_time,
                event_code=int(code_match.group(1)) if code_match else 0,
                event_type="windows_event_block",
                attributes={"raw_text": text_value},
                raw=raw,
            )
        )
    return events


def raw_external_events(
    case_dir: Path, config: dict[str, Any], spec: dict[str, Any]
) -> tuple[list[dict[str, Any]], str]:
    if config.get("source_file", "").endswith("combined.csv"):
        path = ROOT / config["source_file"]
        return windows_external_events(path), f"external CSV ({path.name})"

    archive_path = ROOT / config["source_archive"]
    source_units = spec["scope"].get("source_units", [])
    if not source_units:
        raise TriggerAuditError("external archive rule has no declared source_units")
    events: list[dict[str, Any]] = []
    with zipfile.ZipFile(archive_path) as archive:
        for member in source_units:
            if config["builder"].endswith("build_ait_cases.py"):
                events.extend(json_member_events(archive, member))
            elif config["builder"].endswith("build_cam_missing_cases.py"):
                events.extend(text_member_events(archive, member))
            elif config["builder"].endswith("build_ainception_cases.py"):
                if member.endswith("audit.log"):
                    events.extend(linux_audit_group_events(archive, member))
                else:
                    events.extend(windows_block_events(archive, member))
            else:
                raise TriggerAuditError(f"unsupported external builder: {config['builder']}")
    return events, f"external archive ({archive_path.name}: {', '.join(source_units)})"


def configured_external_a0_key(case_dir: Path, config: dict[str, Any]) -> str:
    selector = next(
        item for item in config["selectors"] if item.get("evidence_id") == "A0"
    )
    if selector.get("source_record_id"):
        return selector["source_record_id"]
    member = selector.get("archive_member") or selector.get("member")
    if selector.get("audit_serial"):
        return f"{member}:audit:{selector['audit_serial']}"
    if selector.get("block_index"):
        return f"{member}:block:{selector['block_index']}"
    line_number = selector.get("line_number")
    if not line_number:
        records = load_json(case_dir / "extracted/source_records.json")
        a0 = next(
            (item for item in records if item.get("evidence_id") == "A0"), records[0]
        )
        member = member or a0.get("archive_member")
        line_number = a0.get("line_number")
    if member and line_number:
        return f"{member}:line:{line_number}"
    raise TriggerAuditError("cannot derive configured external A0 key")


def get_field(event: dict[str, Any], field: str) -> Any:
    value: Any = event
    for part in field.split("."):
        if not isinstance(value, dict) or part not in value:
            return None
        value = value[part]
    return value


def compare(actual: Any, op: str, expected: Any) -> bool:
    if op == "in":
        return actual in expected if isinstance(expected, list) else False
    if actual is None:
        return False
    if op == "eq":
        return actual == expected
    left = str(actual)
    right = str(expected)
    if op == "ieq":
        return left.casefold() == right.casefold()
    if op == "contains":
        return right in left
    if op == "icontains":
        return right.casefold() in left.casefold()
    if op == "startswith":
        return left.startswith(right)
    if op == "istartswith":
        return left.casefold().startswith(right.casefold())
    if op == "endswith":
        return left.endswith(right)
    if op == "iendswith":
        return left.casefold().endswith(right.casefold())
    if op == "regex":
        return re.search(right, left) is not None
    raise TriggerAuditError(f"unsupported predicate operator: {op}")


def matches(event: dict[str, Any], expression: dict[str, Any]) -> bool:
    if "all" in expression:
        return all(matches(event, child) for child in expression["all"])
    if "any" in expression:
        return any(matches(event, child) for child in expression["any"])
    if "not" in expression:
        return not matches(event, expression["not"])
    return compare(
        get_field(event, expression["field"]), expression["op"], expression["value"]
    )


def predicate_fields(expression: dict[str, Any]) -> list[str]:
    if "all" in expression:
        return [field for child in expression["all"] for field in predicate_fields(child)]
    if "any" in expression:
        return [field for child in expression["any"] for field in predicate_fields(child)]
    if "not" in expression:
        return predicate_fields(expression["not"])
    return [expression["field"]]


def validate_non_circular(spec: dict[str, Any]) -> None:
    errors = sorted(jsonschema.Draft7Validator(SCHEMA).iter_errors(spec), key=lambda e: list(e.path))
    if errors:
        detail = "; ".join(
            f"{'.'.join(str(part) for part in error.path) or '<root>'}: {error.message}"
            for error in errors
        )
        raise TriggerAuditError(f"trigger spec schema failure: {detail}")
    for field in predicate_fields(spec["event_predicate"]):
        parts = {part.casefold() for part in field.split(".")}
        if parts & FORBIDDEN_FIELD_PARTS:
            raise TriggerAuditError(f"prohibited post-hoc predicate field: {field}")
    scope_filter = spec["scope"].get("filter_predicate")
    for field in predicate_fields(scope_filter) if scope_filter else []:
        parts = {part.casefold() for part in field.split(".")}
        if parts & FORBIDDEN_FIELD_PARTS:
            raise TriggerAuditError(f"prohibited scope field: {field}")
    for field in (spec.get("aggregation") or {}).get("group_by", []):
        parts = {part.casefold() for part in field.split(".")}
        if parts & FORBIDDEN_FIELD_PARTS:
            raise TriggerAuditError(f"prohibited aggregation field: {field}")
    distinct_field = (spec.get("aggregation") or {}).get("distinct", {}).get("field")
    if distinct_field:
        parts = {part.casefold() for part in distinct_field.split(".")}
        if parts & FORBIDDEN_FIELD_PARTS:
            raise TriggerAuditError(f"prohibited aggregation field: {distinct_field}")


def validate_taxonomy(spec: dict[str, Any]) -> None:
    try:
        validate_spec_classification(spec)
    except TriggerTaxonomyError as exc:
        raise TriggerAuditError(str(exc)) from exc


def event_sort_key(event: dict[str, Any]) -> tuple[Any, ...]:
    pieces = tuple(
        int(piece) if piece.isdigit() else piece.casefold()
        for piece in re.split(r"(\d+)", event["record_key"])
    )
    raw_time = event.get("event_time_utc", "")
    try:
        parsed = datetime.fromisoformat(raw_time.replace("Z", "+00:00"))
        return 0, parsed.timestamp(), pieces
    except (AttributeError, ValueError):
        return 1, str(raw_time), pieces


def seconds_between(events: list[dict[str, Any]]) -> float:
    timestamps = []
    for event in events:
        value = event.get("event_time_utc", "").replace("Z", "+00:00")
        try:
            timestamps.append(datetime.fromisoformat(value))
        except ValueError:
            return float("inf")
    return (max(timestamps) - min(timestamps)).total_seconds() if timestamps else 0.0


def temporal_sessions(
    events: list[dict[str, Any]], max_gap_seconds: float | None
) -> list[list[dict[str, Any]]]:
    ordered = sorted(events, key=event_sort_key)
    if max_gap_seconds is None or not ordered:
        return [ordered]
    sessions: list[list[dict[str, Any]]] = [[ordered[0]]]
    for event in ordered[1:]:
        previous = sessions[-1][-1]
        if seconds_between([previous, event]) > max_gap_seconds:
            sessions.append([event])
        else:
            sessions[-1].append(event)
    return sessions


def qualifying_groups(
    candidates: list[dict[str, Any]], aggregation: dict[str, Any]
) -> list[list[dict[str, Any]]]:
    groups: dict[tuple[Any, ...], list[dict[str, Any]]] = defaultdict(list)
    for event in candidates:
        key = tuple(get_field(event, field) for field in aggregation["group_by"])
        groups[key].append(event)
    qualifying = []
    for grouped_events in groups.values():
        sessions = temporal_sessions(
            grouped_events, aggregation.get("session_gap_seconds_lte")
        )
        for events in sessions:
            if len(events) < aggregation["count_gte"]:
                continue
            if (
                "within_seconds_lte" in aggregation
                and seconds_between(events) > aggregation["within_seconds_lte"]
            ):
                continue
            distinct = aggregation.get("distinct")
            if distinct:
                values = {get_field(event, distinct["field"]) for event in events}
                if len(values) < distinct["count_gte"]:
                    continue
            qualifying.append(events)
    return qualifying


def select_event(
    candidates: list[dict[str, Any]], spec: dict[str, Any]
) -> tuple[dict[str, Any] | None, int]:
    strategy = spec["selection"]["strategy"]
    aggregation = spec.get("aggregation")
    if aggregation:
        groups = qualifying_groups(candidates, aggregation)
        if not groups:
            return None, 0
        if strategy != "earliest_in_highest_count_group":
            raise TriggerAuditError("aggregate rule must use earliest_in_highest_count_group")
        groups.sort(key=lambda group: (-len(group), event_sort_key(group[0])))
        return groups[0][0], len(groups)
    if strategy not in {"earliest_match", "latest_match"}:
        raise TriggerAuditError("non-aggregate rule must use earliest_match or latest_match")
    ordered = sorted(candidates, key=event_sort_key)
    if not ordered:
        return None, 0
    return (ordered[0] if strategy == "earliest_match" else ordered[-1]), 0


def audit_case(
    case_dir: Path, write_result: bool, include_candidates: bool = False
) -> dict[str, Any]:
    config = load_json(case_dir / "build/case.json")
    case_id = config["case_id"]
    spec_path = case_dir / "annotations/trigger_spec.json"
    if not spec_path.is_file():
        raise TriggerAuditError("trigger_spec.json is absent")
    spec = load_json(spec_path)
    validate_non_circular(spec)
    validate_taxonomy(spec)
    if spec["case_id"] != case_id:
        raise TriggerAuditError("trigger spec case_id mismatch")
    is_external = bool(config.get("builder"))
    if is_external:
        raw_events, source_description = raw_external_events(case_dir, config, spec)
        configured_a0 = configured_external_a0_key(case_dir, config)
    else:
        if "mordor_log" not in config and not config.get("source_log") and not config.get("sources"):
            raise TriggerAuditError("no canonical raw-source configuration is available")
        raw_events, source_description = raw_canonical_events(case_dir, config)
        configured_a0 = str(config["selection"]["A0"])
    scope_filter = spec["scope"].get("filter_predicate")
    events = (
        [event for event in raw_events if matches(event, scope_filter)]
        if scope_filter
        else raw_events
    )
    if not events:
        raise TriggerAuditError("declared legal scope contains no events")
    candidates = [event for event in events if matches(event, spec["event_predicate"])]
    selected, group_count = select_event(candidates, spec)
    expected = spec["expected_a0"]["record_key"]
    selected_key = selected["record_key"] if selected else None
    passed = selected_key == expected == configured_a0
    result = {
        "schema": "safesoc.trigger_audit_result.v1",
        "case_id": case_id,
        "rule_id": spec["rule_id"],
        "analytic_family_id": spec["analytic_family_id"],
        "analytic_pattern_id": spec["analytic_pattern_id"],
        "source_description": source_description,
        "raw_source_event_count": len(raw_events),
        "complete_scope_event_count": len(events),
        "predicate_match_count": len(candidates),
        "qualifying_group_count": group_count,
        "selection_strategy": spec["selection"]["strategy"],
        "selected_record_key": selected_key,
        "expected_record_key": expected,
        "selected_raw_sha256": selected.get("raw_sha256") if selected else None,
        "pass": passed,
    }
    if include_candidates:
        diagnostic_fields = {
            "image",
            "image_loaded",
            "process_id",
            "source_ip",
            "destination_ip",
            "destination_port",
            "initiated",
            "signed",
            "signature",
            "signature_status",
            "message",
            "full_log",
            "raw_text",
        }
        result["candidates"] = [
            {
                "record_key": event["record_key"],
                "event_time_utc": event["event_time_utc"],
                "event_code": event["event_code"],
                "event_type": event["event_type"],
                "computer": event["computer"],
                "attributes": {
                    key: (value[:240] + "..." if isinstance(value, str) and len(value) > 240 else value)
                    for key, value in event["attributes"].items()
                    if key in diagnostic_fields
                },
            }
            for event in sorted(candidates, key=event_sort_key)
        ]
    if write_result:
        (case_dir / "annotations/trigger_audit.json").write_text(
            json.dumps(result, indent=2) + "\n", encoding="utf-8"
        )
    return result


def inventory_case(case_dir: Path) -> dict[str, Any]:
    config = load_json(case_dir / "build/case.json")
    spec_path = case_dir / "annotations/trigger_spec.json"
    spec = load_json(spec_path) if spec_path.is_file() else {"scope": {}}
    if config.get("builder"):
        events, source_description = raw_external_events(case_dir, config, spec)
        a0_key = configured_external_a0_key(case_dir, config)
    else:
        events, source_description = raw_canonical_events(case_dir, config)
        a0_key = str(config["selection"]["A0"])
    by_key = {event["record_key"]: event for event in events}
    if a0_key not in by_key:
        raise TriggerAuditError(f"configured A0 is absent from raw scope: {a0_key}")
    event = by_key[a0_key]
    return {
        "case_id": config["case_id"],
        "source_description": source_description,
        "complete_scope_event_count": len(events),
        "a0": event,
        "documented_method": config.get("metadata", {})
        .get("main_alert_selection", {})
        .get("selection_method"),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--set", choices=("canonical", "external", "all"), default="canonical")
    parser.add_argument("--only", help="comma-separated case IDs")
    parser.add_argument("--inventory", action="store_true")
    parser.add_argument("--show-candidates", action="store_true")
    parser.add_argument("--write-results", action="store_true")
    args = parser.parse_args()
    only = {item.strip() for item in args.only.split(",")} if args.only else None
    failures = []
    processed = 0
    for case_dir in discover(args.set):
        case_id = load_json(case_dir / "build/case.json")["case_id"]
        if only and case_id not in only:
            continue
        try:
            if args.inventory:
                print(json.dumps(inventory_case(case_dir), ensure_ascii=False))
            else:
                result = audit_case(
                    case_dir, args.write_results, include_candidates=args.show_candidates
                )
                mark = "PASS" if result["pass"] else "FAIL"
                print(
                    f"{mark} {case_id:9s} matches={result['predicate_match_count']:4d} "
                    f"selected={result['selected_record_key']} expected={result['expected_record_key']}"
                )
                if not result["pass"]:
                    failures.append(case_id)
                if args.show_candidates:
                    print(json.dumps(result["candidates"], ensure_ascii=False))
            processed += 1
        except Exception as exc:
            failures.append(case_id)
            print(f"FAIL {case_id:9s} {type(exc).__name__}: {exc}")
    if not processed:
        raise SystemExit("no cases selected")
    if failures:
        raise SystemExit(f"trigger audit failed for {len(failures)} case(s): {sorted(set(failures))}")
    if args.inventory:
        print(f"INVENTORY: {processed} configured A0 record(s) found in raw scope")
    else:
        print(f"PASS: {processed} case trigger rule(s) replayed successfully")


if __name__ == "__main__":
    main()
