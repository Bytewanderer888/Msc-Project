#!/usr/bin/env python3
"""Build the two AInception SL100 external-replication candidates."""

from __future__ import annotations

import hashlib
import json
import re
import zipfile
from pathlib import Path
from typing import Any, Callable

import jsonschema


ROOT = Path(__file__).resolve().parents[2]
STUDY = Path(__file__).resolve().parent
ARCHIVE = ROOT / "data_sources/ainception_sl100/SL100.zip"
SCHEMA = json.loads((ROOT / "tools/schema/alert_package.schema.json").read_text())
ARCHIVE_SHA256 = "58eb1ab05a019565cdfb2c9d0403924c8c35188476b7e90829b8c04dcebd0f10"
RAW = "SL100/sl100-raw-data/2nd Data Extraction_with_suricata_netflows"
WINDOWS_HEADER = re.compile(rb"(?m)^(?:Information|Error|Warning)\t")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")


def write_text(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value.rstrip() + "\n", encoding="utf-8")


def source_id(record: dict[str, Any]) -> str:
    return f"SRC-{record['evidence_id']}"


def find_windows_blocks(
    archive: zipfile.ZipFile,
    member: str,
    selectors: dict[str, Callable[[str], bool]],
) -> dict[str, dict[str, Any]]:
    data = archive.read(member)
    starts = [match.start() for match in WINDOWS_HEADER.finditer(data)]
    matches: dict[str, list[dict[str, Any]]] = {key: [] for key in selectors}
    for block_index, start in enumerate(starts, start=1):
        end = starts[block_index] if block_index < len(starts) else len(data)
        raw = data[start:end]
        text = raw.decode("utf-8", errors="replace")
        for evidence_id, predicate in selectors.items():
            if predicate(text):
                matches[evidence_id].append(
                    {
                        "evidence_id": evidence_id,
                        "archive_member": member,
                        "block_index": block_index,
                        "byte_start": start,
                        "byte_end": end,
                        "record_sha256": sha256(raw),
                        "record": text.rstrip(),
                    }
                )

    resolved: dict[str, dict[str, Any]] = {}
    for evidence_id, candidates in matches.items():
        if len(candidates) != 1:
            raise RuntimeError(
                f"{member} selector {evidence_id} matched {len(candidates)} blocks; expected 1"
            )
        resolved[evidence_id] = candidates[0]
    return resolved


def find_text_lines(
    archive: zipfile.ZipFile,
    member: str,
    selectors: dict[str, Callable[[str], bool]],
) -> dict[str, dict[str, Any]]:
    matches: dict[str, list[dict[str, Any]]] = {key: [] for key in selectors}
    with archive.open(member) as handle:
        for line_number, raw in enumerate(handle, start=1):
            clean = raw.rstrip(b"\r\n")
            text = clean.decode("utf-8", errors="replace")
            for evidence_id, predicate in selectors.items():
                if predicate(text):
                    matches[evidence_id].append(
                        {
                            "evidence_id": evidence_id,
                            "archive_member": member,
                            "line_number": line_number,
                            "record_sha256": sha256(clean),
                            "record": text,
                        }
                    )

    resolved: dict[str, dict[str, Any]] = {}
    for evidence_id, candidates in matches.items():
        if len(candidates) != 1:
            raise RuntimeError(
                f"{member} selector {evidence_id} matched {len(candidates)} lines; expected 1"
            )
        resolved[evidence_id] = candidates[0]
    return resolved


def find_audit_group(
    archive: zipfile.ZipFile, member: str, evidence_id: str, audit_serial: str
) -> dict[str, Any]:
    data = archive.read(member)
    lines = data.splitlines(keepends=True)
    token = f":{audit_serial})".encode()
    offsets: list[tuple[int, int, bytes]] = []
    offset = 0
    for raw in lines:
        end = offset + len(raw)
        if token in raw:
            offsets.append((offset, end, raw))
        offset = end
    if not offsets:
        raise RuntimeError(f"audit serial {audit_serial} was not found in {member}")
    if any(offsets[index][1] != offsets[index + 1][0] for index in range(len(offsets) - 1)):
        raise RuntimeError(f"audit serial {audit_serial} is not contiguous in {member}")
    start, end = offsets[0][0], offsets[-1][1]
    raw = data[start:end]
    return {
        "evidence_id": evidence_id,
        "archive_member": member,
        "audit_serial": audit_serial,
        "byte_start": start,
        "byte_end": end,
        "record_sha256": sha256(raw),
        "record": raw.decode("utf-8", errors="replace").rstrip(),
    }


def provenance(case_id: str, records: list[dict[str, Any]]) -> dict[str, Any]:
    selected = []
    for record in records:
        locator = {
            key: record[key]
            for key in (
                "line_number",
                "block_index",
                "byte_start",
                "byte_end",
                "audit_serial",
            )
            if key in record
        }
        selected.append(
            {
                "evidence_id": record["evidence_id"],
                "archive_member": record["archive_member"],
                **locator,
                "record_sha256": record["record_sha256"],
            }
        )
    return {
        "case_id": case_id,
        "status": "candidate_built_pending_qa",
        "source_corpus": "AInception SL100",
        "doi": "10.5281/zenodo.17659656",
        "source_archive": {
            "path": "data_sources/ainception_sl100/SL100.zip",
            "sha256": ARCHIVE_SHA256,
        },
        "selected_records": selected,
        "integrity_note": (
            "Line hashes omit line terminators. Byte-range hashes cover the exact raw bytes "
            "identified by [byte_start, byte_end). The archive hash is pinned in SOURCE_MANIFEST.json."
        ),
    }


def write_case(
    case_dir: Path,
    package: dict[str, Any],
    ground_truth: dict[str, Any],
    selection: dict[str, Any],
    case_config: dict[str, Any],
    records: list[dict[str, Any]],
    retrieval: str,
) -> None:
    jsonschema.validate(package, SCHEMA)
    write_json(case_dir / "extracted/source_records.json", records)
    write_json(case_dir / "source/provenance.json", provenance(package["case_id"], records))
    write_json(case_dir / "model_input/alert_package.json", package)
    write_json(case_dir / "annotations/ground_truth.json", ground_truth)
    write_json(case_dir / "annotations/selection_metadata.json", selection)
    write_json(case_dir / "build/case.json", case_config)
    write_text(case_dir / "queries/retrieval_spec.md", retrieval)


def build_runtime_impact(archive: zipfile.ZipFile) -> None:
    case_id = "ER-S03"
    case_dir = STUDY / "cases/strong/ER-S03_ainception_runtime_impact"
    audit_member = f"{RAW}/audit.log"
    flight_member = f"{RAW}/drone_flight_logs.log"
    a0 = find_audit_group(archive, audit_member, "A0", "626718")
    flight = find_text_lines(
        archive,
        flight_member,
        {
            "EV-001": lambda line: line
            == "2025-01-07 13:50:57 Got COMMAND_ACK: COMPONENT_ARM_DISARM: ACCEPTED",
            "EV-002": lambda line: line == "2025-01-07 13:50:58 DISARMED",
            "EV-003": lambda line: line
            == "2025-01-07 13:51:20 AP: SIM Hit ground at 19.36427 m/s",
        },
    )
    ev1, ev2, ev3 = (flight[key] for key in ("EV-001", "EV-002", "EV-003"))

    package = {
        "schema_version": "1.0",
        "case_id": case_id,
        "package_type": "neutral_security_event_package",
        "observed_context": {
            "computers": ["control-01.corp.local", "vehicle-01"],
            "users": ["user-01", "root"],
            "time_window_utc": {
                "start": "2025-01-07T13:49:56.287000Z",
                "end": "2025-01-07T13:51:20Z",
            },
            "event_count": 4,
            "event_types_present": [
                "process_attachment",
                "control_command_acknowledgement",
                "vehicle_state",
                "physical_impact",
            ],
            "sourcetypes_present": ["linux_audit", "flight_telemetry"],
        },
        "main_alert": {
            "evidence_id": "A0",
            "is_triggering_alert": True,
            "event_time_utc": "2025-01-07T13:49:56.287000Z",
            "event_type": "process_attachment",
            "source_event": {
                "provider": "Linux Audit",
                "channel": "/var/log/audit/audit.log",
                "event_code": 101,
                "event_record_id": source_id(a0),
            },
            "computer": "control-01.corp.local",
            "attributes": {
                "image": "/tmp/session-tool/frida_server",
                "process_id": "1789811",
                "subject_user": "user-01",
                "effective_user": "root",
                "syscall": "ptrace",
                "status": "success",
                "target_process_id": "1561449",
                "target_process_name": "QGroundControl",
            },
        },
        "evidence_items": [
            {
                "evidence_id": "EV-001",
                "event_time_utc": "2025-01-07T13:50:57Z",
                "event_type": "control_command_acknowledgement",
                "source_event": {
                    "provider": "Flight telemetry",
                    "channel": "vehicle-status",
                    "event_code": 0,
                    "event_record_id": source_id(ev1),
                },
                "computer": "vehicle-01",
                "attributes": {
                    "action_command": "COMPONENT_ARM_DISARM",
                    "status": "accepted",
                },
            },
            {
                "evidence_id": "EV-002",
                "event_time_utc": "2025-01-07T13:50:58Z",
                "event_type": "vehicle_state",
                "source_event": {
                    "provider": "Flight telemetry",
                    "channel": "vehicle-status",
                    "event_code": 0,
                    "event_record_id": source_id(ev2),
                },
                "computer": "vehicle-01",
                "attributes": {"status": "disarmed"},
            },
            {
                "evidence_id": "EV-003",
                "event_time_utc": "2025-01-07T13:51:20Z",
                "event_type": "physical_impact",
                "source_event": {
                    "provider": "Flight telemetry",
                    "channel": "vehicle-status",
                    "event_code": 0,
                    "event_record_id": source_id(ev3),
                },
                "computer": "vehicle-01",
                "attributes": {
                    "status": "ground_impact",
                    "impact_speed_mps": "19.36427",
                },
            },
        ],
        "deterministic_derivations": [],
    }

    ground_truth = {
        "case_id": case_id,
        "security_proposition": (
            "A root-capable runtime instrumentation process attached to the flight-control "
            "application and was followed by an accepted mid-flight disarm and ground impact."
        ),
        "evidence_condition": "strong",
        "calibration_role": "up_rank",
        "correct_verdict": "malicious",
        "acceptable_severity": ["high", "critical"],
        "acceptable_actions": ["escalate", "isolate"],
        "operational_response": {
            "family": "network_blocking",
            "note": "Isolate the control endpoint and block its control path under human approval while preserving flight and audit evidence.",
        },
        "grounding": {
            "supporting_evidence": ["A0", "EV-001", "EV-002", "EV-003"],
            "counter_evidence": [],
            "must_not_assert": [
                "the exact in-memory function or bytes modified inside QGroundControl",
                "that the audit record alone proves the later command's complete causal path",
                "that the package concerns real-world hardware rather than a controlled vehicle environment",
                "injury, property damage, or activity outside the selected time window",
            ],
        },
        "the_trap": (
            "The process-attachment record and physical outcome are in different telemetry sources. "
            "The evidence must be fused temporally without inventing unseen in-memory details."
        ),
        "rationale": (
            "A0 records a successful root-effective ptrace operation by frida_server against the "
            "QGroundControl process. Sixty-one seconds later EV-001 records acceptance of a component "
            "arm/disarm command, EV-002 records the disarmed state, and EV-003 records ground impact "
            "at 19.36427 m/s. This is decisive runtime manipulation plus an observed safety impact, "
            "while the exact injected function and full causal implementation remain outside the logs."
        ),
        "annotated_by": "researcher",
        "review_status": "frozen_pre_model_2026-07-22",
        "rubric_version": "1.1",
    }

    selection = {
        "schema_version": "1.0",
        "case_id": case_id,
        "case_name": "ainception_runtime_impact",
        "split": "external_replication_heldout",
        "status": "candidate_built_pending_qa",
        "security_proposition": ground_truth["security_proposition"],
        "attack_category": {
            "category": "Data Manipulation: Runtime Data Manipulation",
            "candidate_attack_mapping": "T1565.003",
            "model_visible": False,
        },
        "source_provenance": {
            "dataset": "AInception SL100",
            "scenario": "continuous SL100 chain",
            "capture_cluster": "sl100-chain",
            "telemetry_depth": "multi_source",
            "sensors": ["Linux audit", "vehicle flight telemetry"],
        },
        "model_input_controls": {
            "excluded": [
                "scenario/action labels and supplied attack timeline",
                "source executable name containing the intended outcome",
                "dataset malicious flags, ATT&CK mappings, and detector output",
                "condition, verdict, severity, action, and calibration role",
            ],
            "deterministic_derivations": [],
        },
        "operational_response_family": "network_blocking",
        "nearest_frozen_case": None,
        "differentiation": "No frozen case combines Linux runtime instrumentation with cyber-physical outcome telemetry.",
    }

    records = [a0, ev1, ev2, ev3]
    case_config = {
        "case_id": case_id,
        "builder": "experiments/external_replication_v1/build_ainception_cases.py",
        "source_archive": "data_sources/ainception_sl100/SL100.zip",
        "selectors": [
            {
                "evidence_id": record["evidence_id"],
                "member": record["archive_member"],
                **{
                    key: record[key]
                    for key in ("line_number", "byte_start", "byte_end", "audit_serial")
                    if key in record
                },
                "record_sha256": record["record_sha256"],
            }
            for record in records
        ],
        "literal_redactions": [
            "source attack executable -> omitted",
            "temporary extraction directory -> /tmp/session-tool",
            "host/user identifiers -> control-01, vehicle-01, user-01",
            "SIM marker -> neutral ground-impact fields",
        ],
    }

    retrieval = f"""# ER-S03 retrieval specification

Source: `SL100.zip`, raw members `{audit_member}` and
`{flight_member}`.

1. Apply `annotations/trigger_spec.json` to every audit group in the complete
   declared audit member and select `A0` deterministically.
2. Use audit serial 626718 only as a post-rule replay assertion and context
   join key; it is not part of the trigger predicate.
3. Retain the successful root-effective `ptrace` group whose `OBJ_PID`
   identifies QGroundControl as the target.
4. Retain the later flight records for accepted `COMPONENT_ARM_DISARM`, the
   disarmed state, and ground impact at 19.36427 m/s.
5. Remove the attack executable name that states the intended outcome, supplied
   malicious flags/timeline prose, dataset identities, and decision labels.
6. Preserve exact raw byte/line locators and hashes in provenance.

The two sensors describe one compatible control-host/vehicle window. Ground
truth uses the observed attachment and outcome, not the inconsistent supplied
timeline metadata.
"""
    write_case(case_dir, package, ground_truth, selection, case_config, records, retrieval)


def build_winrm_pivot(archive: zipfile.ZipFile) -> None:
    case_id = "ER-S04"
    case_dir = STUDY / "cases/strong/ER-S04_ainception_winrm_pivot"
    wsus_member = f"{RAW}/WSUS.txt"
    win2_member = f"{RAW}/WIN2.txt"
    wsus = find_windows_blocks(
        archive,
        wsus_member,
        {
            "A0": lambda block: (
                "Microsoft-Windows-Sysmon\t1\t(1)" in block
                and "2025-01-07 13:14:38.647" in block
                and "3_psremoting_poc.exe" in block
            ),
            "EV-003": lambda block: (
                "Microsoft-Windows-Sysmon\t11\t(11)" in block
                and "2025-01-07 13:14:41.382" in block
                and "C:\\Windows\\Temp\\qgroundvnc.vnc" in block
                and "powershell.exe" in block.lower()
            ),
        },
    )
    win2 = find_windows_blocks(
        archive,
        win2_member,
        {
            "EV-001": lambda block: (
                "Microsoft-Windows-Sysmon\t3\t(3)" in block
                and "2025-01-07 13:14:38.019" in block
                and "192.168.1.10" in block
                and "192.168.1.25" in block
                and "5985" in block
            ),
            "EV-002": lambda block: (
                "Microsoft-Windows-Sysmon\t11\t(11)" in block
                and "2025-01-07 13:14:39.175" in block
                and "wsmprovhost.exe" in block.lower()
                and "__PSScriptPolicyTest_geyjlmwz.bqv.psm1" in block
            ),
        },
    )
    a0, ev1, ev2, ev3 = (
        wsus["A0"],
        win2["EV-001"],
        win2["EV-002"],
        wsus["EV-003"],
    )

    package = {
        "schema_version": "1.0",
        "case_id": case_id,
        "package_type": "neutral_security_event_package",
        "observed_context": {
            "computers": ["server-01.corp.local", "workstation-01.corp.local"],
            "users": ["admin-01"],
            "time_window_utc": {
                "start": "2025-01-07T13:14:38.019000Z",
                "end": "2025-01-07T13:14:41.382000Z",
            },
            "event_count": 4,
            "event_types_present": ["process_create", "network_connect", "file_create"],
            "sourcetypes_present": ["sysmon_source_host", "sysmon_target_host"],
        },
        "main_alert": {
            "evidence_id": "A0",
            "is_triggering_alert": True,
            "event_time_utc": "2025-01-07T13:14:38.647000Z",
            "event_type": "process_create",
            "source_event": {
                "provider": "Microsoft-Windows-Sysmon",
                "channel": "Microsoft-Windows-Sysmon/Operational",
                "event_code": 1,
                "event_record_id": source_id(a0),
            },
            "computer": "server-01.corp.local",
            "attributes": {
                "process_id": "5312",
                "image": "C:\\Users\\admin-01\\Downloads\\remote-client.exe",
                "command_line": "C:\\Users\\admin-01\\Downloads\\remote-client.exe",
                "current_directory": "C:\\Users\\admin-01\\Downloads\\",
                "user": "CORP\\admin-01",
                "integrity_level": "High",
            },
        },
        "evidence_items": [
            {
                "evidence_id": "EV-001",
                "event_time_utc": "2025-01-07T13:14:38.019000Z",
                "event_type": "network_connect",
                "source_event": {
                    "provider": "Microsoft-Windows-Sysmon",
                    "channel": "Microsoft-Windows-Sysmon/Operational",
                    "event_code": 3,
                    "event_record_id": source_id(ev1),
                },
                "computer": "workstation-01.corp.local",
                "attributes": {
                    "image": "System",
                    "source_ip": "server-01.corp.local",
                    "source_port": "62204",
                    "destination_ip": "workstation-01.corp.local",
                    "destination_port": "5985",
                    "protocol": "tcp",
                },
            },
            {
                "evidence_id": "EV-002",
                "event_time_utc": "2025-01-07T13:14:39.175000Z",
                "event_type": "file_create",
                "source_event": {
                    "provider": "Microsoft-Windows-Sysmon",
                    "channel": "Microsoft-Windows-Sysmon/Operational",
                    "event_code": 11,
                    "event_record_id": source_id(ev2),
                },
                "computer": "workstation-01.corp.local",
                "attributes": {
                    "process_id": "6504",
                    "image": "C:\\Windows\\System32\\wsmprovhost.exe",
                    "target_filename": "C:\\Users\\admin-01\\AppData\\Local\\Temp\\__PSScriptPolicyTest_[random].psm1",
                    "user": "CORP\\admin-01",
                },
            },
            {
                "evidence_id": "EV-003",
                "event_time_utc": "2025-01-07T13:14:41.382000Z",
                "event_type": "file_create",
                "source_event": {
                    "provider": "Microsoft-Windows-Sysmon",
                    "channel": "Microsoft-Windows-Sysmon/Operational",
                    "event_code": 11,
                    "event_record_id": source_id(ev3),
                },
                "computer": "server-01.corp.local",
                "attributes": {
                    "process_id": "868",
                    "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    "target_filename": "C:\\Windows\\Temp\\remote-session-output.vnc",
                    "user": "CORP\\admin-01",
                },
            },
        ],
        "deterministic_derivations": [],
    }

    ground_truth = {
        "case_id": case_id,
        "security_proposition": (
            "A custom remote-session client established a WinRM session from server-01, "
            "executed PowerShell activity on workstation-01, and produced a VNC-profile artifact "
            "on the source host."
        ),
        "evidence_condition": "strong",
        "calibration_role": "up_rank",
        "correct_verdict": "malicious",
        "acceptable_severity": ["high", "critical"],
        "acceptable_actions": ["escalate", "isolate"],
        "operational_response": {
            "family": "endpoint_isolation",
            "note": "Isolate both endpoints under human approval and preserve the remote-session and VNC artifacts.",
        },
        "grounding": {
            "supporting_evidence": ["A0", "EV-001", "EV-002", "EV-003"],
            "counter_evidence": [],
            "must_not_assert": [
                "the contents of the VNC profile or that its password was decrypted",
                "that a particular credential source enabled the WinRM session",
                "that the operator remained active after the selected window",
                "that hosts other than server-01 and workstation-01 were accessed",
            ],
        },
        "the_trap": (
            "No single event states remote execution success. The decision depends on correlating "
            "the source tool, target-port session, target wsmprovhost activity, and returned artifact."
        ),
        "rationale": (
            "A0 records a high-integrity custom remote-session client on server-01. EV-001 records a "
            "concurrent TCP session from that host to workstation-01 on port 5985. EV-002 records "
            "wsmprovhost.exe creating a PowerShell policy-test file on the target as the administrator, "
            "which establishes target-side remoting activity. EV-003 then records PowerShell creating "
            "a VNC-profile artifact on the source. Together these establish a completed remote "
            "execution and collection mechanism without proving the artifact's contents or decryption."
        ),
        "annotated_by": "researcher",
        "review_status": "frozen_pre_model_2026-07-22",
        "rubric_version": "1.1",
    }

    selection = {
        "schema_version": "1.0",
        "case_id": case_id,
        "case_name": "ainception_winrm_pivot",
        "split": "external_replication_heldout",
        "status": "candidate_built_pending_qa",
        "security_proposition": ground_truth["security_proposition"],
        "attack_category": {
            "category": "Remote Services: Windows Remote Management",
            "candidate_attack_mapping": "T1021.006",
            "model_visible": False,
        },
        "source_provenance": {
            "dataset": "AInception SL100",
            "scenario": "continuous SL100 chain",
            "capture_cluster": "sl100-chain",
            "telemetry_depth": "multi_source",
            "sensors": ["source-host Sysmon", "target-host Sysmon"],
        },
        "model_input_controls": {
            "excluded": [
                "scenario/action labels and supplied attack timeline",
                "numeric attack-step prefix and all_exes path",
                "dataset malicious flags, ATT&CK mappings, and detector output",
                "condition, verdict, severity, action, and calibration role",
            ],
            "deterministic_derivations": [],
        },
        "operational_response_family": "endpoint_isolation",
        "nearest_frozen_case": None,
        "differentiation": "The frozen set has no cross-host WinRM execution chain with source and target Sysmon correlation.",
    }

    records = [a0, ev1, ev2, ev3]
    case_config = {
        "case_id": case_id,
        "builder": "experiments/external_replication_v1/build_ainception_cases.py",
        "source_archive": "data_sources/ainception_sl100/SL100.zip",
        "selectors": [
            {
                "evidence_id": record["evidence_id"],
                "member": record["archive_member"],
                "block_index": record["block_index"],
                "byte_start": record["byte_start"],
                "byte_end": record["byte_end"],
                "record_sha256": record["record_sha256"],
            }
            for record in records
        ],
        "literal_redactions": [
            "attack-step prefix/path and PoC filename -> remote-client.exe",
            "source/target hosts -> server-01/workstation-01",
            "administrator identity -> admin-01",
            "random policy-test basename -> [random]",
            "qgroundvnc.vnc -> remote-session-output.vnc",
        ],
    }

    retrieval = f"""# ER-S04 retrieval specification

Source: `SL100.zip`, raw members `{wsus_member}` and `{win2_member}`.

1. Apply `annotations/trigger_spec.json` to every event block in the declared
   source member and select `A0` by its deterministic strategy.
2. Use the exact byte ranges in `build/case.json` only as replay assertions and
   context locators, never as trigger predicates.
3. On the source host, retain the high-integrity custom remote-session process
   and the later PowerShell-created VNC-profile artifact.
4. On the target host, retain the source-to-target TCP/5985 connection and the
   `wsmprovhost.exe` PowerShell policy-test file creation in the same window.
5. Remove the numeric attack-step prefix, scenario topology names, supplied
   labels/mappings, and decision labels; anonymise both hosts and the user.
6. Record the exact source-member byte range and SHA-256 of every event block.

This is genuine cross-host correlation: source and target Sysmon independently
observe compatible parts of one remoting session. The package does not use the
inconsistent supplied timeline as outcome proof.
"""
    write_case(case_dir, package, ground_truth, selection, case_config, records, retrieval)


def main() -> None:
    if sha256(ARCHIVE.read_bytes()) != ARCHIVE_SHA256:
        raise RuntimeError("AInception archive hash does not match SOURCE_MANIFEST.json")
    with zipfile.ZipFile(ARCHIVE) as archive:
        build_runtime_impact(archive)
        build_winrm_pivot(archive)
    print("built and schema-validated ER-S03 and ER-S04")


if __name__ == "__main__":
    main()
