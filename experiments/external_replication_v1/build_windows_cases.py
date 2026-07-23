#!/usr/bin/env python3
"""Build defensible Windows-APT weak and counter candidates from event facts."""

from __future__ import annotations

import csv
import hashlib
import json
import re
from pathlib import Path
from typing import Any

import jsonschema


ROOT = Path(__file__).resolve().parents[2]
STUDY = Path(__file__).resolve().parent
SOURCE = ROOT / "data_sources/windows_apt_2025/combined.csv"
SCHEMA = ROOT / "tools/schema/alert_package.schema.json"
SOURCE_SHA256 = "0f7eaa4027482c81cae56a5b759e7058e9e9df225ae060933c7015f6f16e8465"

CASE_RECORDS = {
    "ER-W01": ["QKEIgZMBrrvr6pEbBHVQ"],
    "ER-W02": ["mEqY7ZMBNimV4ECv0YBb"],
    "ER-W03": ["ei2Lg5MBenunWll4wRw3"],
    "ER-C01": [
        "y6E3gZMBrrvr6pEbZnYV",
        "zKE3gZMBrrvr6pEbZnYV",
        "zaE3gZMBrrvr6pEbZnYV",
        "zqE3gZMBrrvr6pEbZnYV",
        "z6E3gZMBrrvr6pEbZnYV",
    ],
    "ER-C02": ["YaHngZMBrrvr6pEbFX2-", "Y6HngZMBrrvr6pEbFX2-"],
    "ER-C03": ["8mQoAJMBUiBtdjxWSF42", "82QoAJMBUiBtdjxWSF42"],
}


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_row(row: dict[str, str]) -> bytes:
    return json.dumps(
        row, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")


def write_text(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value.rstrip() + "\n", encoding="utf-8")


def load_records() -> dict[str, dict[str, Any]]:
    wanted = {record_id for ids in CASE_RECORDS.values() for record_id in ids}
    found: dict[str, dict[str, Any]] = {}
    with SOURCE.open(newline="", encoding="utf-8-sig") as handle:
        for record_number, row in enumerate(csv.DictReader(handle), start=2):
            record_id = row.get("_id", "")
            if record_id not in wanted:
                continue
            if record_id in found:
                raise RuntimeError(f"duplicate source _id: {record_id}")
            found[record_id] = {
                "csv_record_number": record_number,
                "source_record_id": record_id,
                "record_sha256": digest(canonical_row(row)),
                "record": row,
            }
    missing = wanted - found.keys()
    if missing:
        raise RuntimeError(f"source records are absent: {sorted(missing)}")
    return found


def field(selected: dict[str, Any], suffix: str) -> str:
    value = selected["record"].get(f"_source.data.win.{suffix}", "").strip()
    # The flattened CSV stores Windows path separators as JSON-escaped pairs.
    # Restore their event-level representation before building model input.
    return value.replace("\\\\", "\\")


def timestamp(selected: dict[str, Any]) -> str:
    system_time = field(selected, "system.systemTime")
    if system_time:
        return system_time
    raw = selected["record"]["_source.@timestamp"]
    # The only non-Windows-event candidate uses this stable Wazuh timestamp format.
    month, day, year, _, clock = raw.replace("@", "@ ").split()
    months = {
        "Jan": "01", "Feb": "02", "Mar": "03", "Apr": "04",
        "May": "05", "Jun": "06", "Jul": "07", "Aug": "08",
        "Sep": "09", "Oct": "10", "Nov": "11", "Dec": "12",
    }
    return f"{year}-{months[month]}-{int(day.rstrip(',')):02d}T{clock}Z"


def event(
    selected: dict[str, Any],
    evidence_id: str,
    event_type: str,
    computer: str,
    attributes: dict[str, str],
) -> dict[str, Any]:
    provider = field(selected, "system.providerName") or "Endpoint monitoring service"
    channel = field(selected, "system.channel") or "monitoring-status"
    code = field(selected, "system.eventID")
    result = {
        "evidence_id": evidence_id,
        "event_time_utc": timestamp(selected),
        "event_type": event_type,
        "source_event": {
            "provider": provider,
            "channel": channel,
            "event_code": int(code) if code else 0,
            "event_record_id": f"SRC-{evidence_id}",
        },
        "computer": computer,
        "attributes": attributes,
    }
    if evidence_id == "A0":
        result["is_triggering_alert"] = True
    return result


def image_load_attributes(selected: dict[str, Any], *, dism: bool = False) -> dict[str, str]:
    image = field(selected, "eventdata.image")
    loaded = field(selected, "eventdata.imageLoaded")
    if dism:
        guid = re.compile(
            r"(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
        )
        image = guid.sub("[guid]", image)
        loaded = guid.sub("[guid]", loaded)
    return {
        "image": image,
        "image_loaded": loaded,
        "original_file_name": field(selected, "eventdata.originalFileName"),
        "file_version": field(selected, "eventdata.fileVersion"),
        "description": field(selected, "eventdata.description"),
        "product": field(selected, "eventdata.product"),
        "company": field(selected, "eventdata.company"),
        "signed": field(selected, "eventdata.signed").lower(),
        "signature": field(selected, "eventdata.signature"),
        "signature_status": field(selected, "eventdata.signatureStatus"),
        "user": "SYSTEM",
    }


def package(case_id: str, items: list[dict[str, Any]], users: list[str]) -> dict[str, Any]:
    times = [item["event_time_utc"] for item in items]
    return {
        "schema_version": "1.0",
        "case_id": case_id,
        "package_type": "neutral_security_event_package",
        "observed_context": {
            "computers": sorted({item["computer"] for item in items}),
            "users": users,
            "time_window_utc": {"start": min(times), "end": max(times)},
            "event_count": len(items),
            "event_types_present": sorted({item["event_type"] for item in items}),
            "sourcetypes_present": sorted(
                {item["source_event"]["channel"] for item in items}
            ),
        },
        "main_alert": items[0],
        "evidence_items": items[1:],
        "deterministic_derivations": [],
    }


def selected_records(
    records: dict[str, dict[str, Any]], case_id: str
) -> list[dict[str, Any]]:
    result = []
    for index, record_id in enumerate(CASE_RECORDS[case_id]):
        selected = dict(records[record_id])
        selected["evidence_id"] = "A0" if index == 0 else f"EV-{index:03d}"
        result.append(selected)
    return result


def common_provenance(case_id: str, selected: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "case_id": case_id,
        "status": "candidate_built_pending_qa",
        "source_corpus": "Windows-APT Dataset 2025",
        "doi": "10.17632/b8fmtzvpy8.3",
        "source_file": {
            "path": "data_sources/windows_apt_2025/combined.csv",
            "sha256": SOURCE_SHA256,
            "record_format": "CSV with one logical record parsed by csv.DictReader",
        },
        "selected_records": [
            {
                "evidence_id": item["evidence_id"],
                "csv_record_number": item["csv_record_number"],
                "source_record_id": item["source_record_id"],
                "record_sha256": item["record_sha256"],
            }
            for item in selected
        ],
        "integrity_note": (
            "Record hashes cover canonical JSON serialisation of the complete CSV row, "
            "including empty columns. csv_record_number counts the header as record 1."
        ),
    }


def save_case(
    *,
    records: dict[str, dict[str, Any]],
    case_id: str,
    condition: str,
    slug: str,
    package_value: dict[str, Any],
    ground_truth: dict[str, Any],
    attack_category: str,
    attack_mapping: str,
    cluster: str,
    differentiation: str,
    retrieval_note: str,
    literal_redactions: list[str],
) -> None:
    chosen = selected_records(records, case_id)
    case_dir = STUDY / f"cases/{condition}/{case_id}_{slug}"
    jsonschema.validate(package_value, json.loads(SCHEMA.read_text(encoding="utf-8")))

    selection = {
        "schema_version": "1.0",
        "case_id": case_id,
        "case_name": slug,
        "split": "external_replication_heldout",
        "status": "candidate_built_pending_qa",
        "security_proposition": ground_truth["security_proposition"],
        "attack_category": {
            "category": attack_category,
            "candidate_attack_mapping": attack_mapping,
            "model_visible": False,
        },
        "source_provenance": {
            "dataset": "Windows-APT Dataset 2025",
            "scenario": "not authoritatively linkable at event level",
            "capture_cluster": cluster,
            "telemetry_depth": "single_source",
            "sensors": sorted(package_value["observed_context"]["sourcetypes_present"]),
        },
        "model_input_controls": {
            "excluded": [
                "all _source.rule fields, including detector description, severity, and ATT&CK mapping",
                "Sysmon RuleName and system.message copies that contain ATT&CK labels",
                "Wazuh product and manager identity",
                "source agent names, IP addresses, and local account names",
                "condition, verdict, severity, action, and upstream scenario identity",
            ],
            "deterministic_derivations": [],
        },
        "operational_response_family": ground_truth["operational_response"]["family"],
        "nearest_frozen_case": None,
        "differentiation": differentiation,
    }

    provenance = common_provenance(case_id, chosen)
    extracted = [
        {
            "evidence_id": item["evidence_id"],
            "csv_record_number": item["csv_record_number"],
            "source_record_id": item["source_record_id"],
            "record_sha256": item["record_sha256"],
            "record": {key: value for key, value in item["record"].items() if value.strip()},
        }
        for item in chosen
    ]
    build = {
        "case_id": case_id,
        "builder": "experiments/external_replication_v1/build_windows_cases.py",
        "source_file": "data_sources/windows_apt_2025/combined.csv",
        "selectors": [
            {
                "evidence_id": item["evidence_id"],
                "source_record_id": item["source_record_id"],
                "csv_record_number": item["csv_record_number"],
                "record_sha256": item["record_sha256"],
            }
            for item in chosen
        ],
        "literal_redactions": literal_redactions,
    }
    runbook = f"""# {case_id} retrieval specification

Source: `data_sources/windows_apt_2025/combined.csv`.

1. Parse the source with Python's CSV parser; do not use physical line offsets because
   quoted event messages can contain embedded newlines.
2. Apply `annotations/trigger_spec.json` to the complete declared asset and source
   partition. Select `A0` only with its declared deterministic selection strategy.
3. Use `build/case.json` source identifiers only to verify the replayed `A0` and to
   reproduce the retained context; they are not trigger predicates.
4. Retain only the event facts listed in `model_input/alert_package.json` and apply
   the literal anonymisation/redaction rules in `build/case.json`.
5. Exclude every `_source.rule.*` field, Sysmon `RuleName`, copied event messages
   containing technique labels, Wazuh identity, and all decision labels.

{retrieval_note}

This source is a Wazuh alert-index export, not a complete raw event stream. This
case therefore makes no claim that an unobserved follow-on event is absent.
"""

    write_json(case_dir / "model_input/alert_package.json", package_value)
    write_json(case_dir / "annotations/ground_truth.json", ground_truth)
    write_json(case_dir / "annotations/selection_metadata.json", selection)
    write_json(case_dir / "source/provenance.json", provenance)
    write_json(case_dir / "extracted/source_records.json", extracted)
    write_json(case_dir / "build/case.json", build)
    write_text(case_dir / "queries/retrieval_spec.md", runbook)


def gt(
    case_id: str,
    condition: str,
    proposition: str,
    supporting: list[str],
    counter: list[str],
    must_not_assert: list[str],
    trap: str,
    rationale: str,
) -> dict[str, Any]:
    if condition == "weak":
        verdict, severity, actions, role, family = (
            "suspicious", ["low", "medium"], ["monitor", "investigate"],
            "down_rank", "analyst_escalation",
        )
    elif condition == "counter":
        verdict, severity, actions, role, family = (
            "benign", ["informational", "low"], ["close_benign", "monitor"],
            "down_rank", "none",
        )
    else:
        raise ValueError(condition)
    return {
        "case_id": case_id,
        "security_proposition": proposition,
        "evidence_condition": condition,
        "calibration_role": role,
        "correct_verdict": verdict,
        "acceptable_severity": severity,
        "acceptable_actions": actions,
        "operational_response": {
            "family": family,
            "note": (
                "Investigate the signal and surrounding context; no autonomous containment is justified."
                if condition == "weak"
                else "Close or monitor the alert; the affirmative context does not justify containment."
            ),
        },
        "grounding": {
            "supporting_evidence": supporting,
            "counter_evidence": counter,
            "must_not_assert": must_not_assert,
        },
        "the_trap": trap,
        "rationale": rationale,
        "annotated_by": "researcher",
        "review_status": "frozen_pre_model_2026-07-22",
        "rubric_version": "1.1",
    }


def build(records: dict[str, dict[str, Any]]) -> None:
    # ER-W01: a real script-host connection, but no payload or session semantics.
    chosen = selected_records(records, "ER-W01")
    a0 = chosen[0]
    w01 = package("ER-W01", [event(a0, "A0", "network_connection", "host-01", {
        "image": field(a0, "eventdata.image"),
        "process_id": field(a0, "eventdata.processId"),
        "user": "user-01",
        "protocol": field(a0, "eventdata.protocol").lower(),
        "initiated": field(a0, "eventdata.initiated").lower(),
        "source_ip": "host-01",
        "source_port": field(a0, "eventdata.sourcePort"),
        "destination_ip": "external-01",
        "destination_hostname": "external-01",
        "destination_port": field(a0, "eventdata.destinationPort"),
    })], ["user-01"])
    save_case(
        records=records, case_id="ER-W01", condition="weak", slug="script_host_tcp",
        package_value=w01,
        ground_truth=gt(
            "ER-W01", "weak",
            "The script-host connection to the external endpoint represents malicious command-and-control traffic.",
            ["A0"], [],
            [
                "the script content or command line",
                "the application payload or response content",
                "that the remote endpoint was attacker-controlled",
                "that a command-and-control session was established",
            ],
            "A script interpreter made an outbound TCP connection, but the event contains no script, payload, response, or ownership context.",
            "A0 proves that cscript.exe initiated a TCP connection from host-01 to an external endpoint on port 443. That is a real signal worth investigation, but it does not establish what script ran, what protocol or payload was exchanged, who controlled the endpoint, or whether a malicious session succeeded.",
        ),
        attack_category="Non-Application Layer Protocol (candidate hypothesis)",
        attack_mapping="T1095",
        cluster="wapt-DESKTOP-FMI6MML-2024-12-01T07:03Z",
        differentiation="No frozen case isolates a script-host external TCP connection with absent payload and session semantics.",
        retrieval_note="The selected Sysmon Event ID 3 is sufficient for a weak signal, but not for payload or session claims.",
        literal_redactions=["computer/source address -> host-01", "local user -> user-01", "external address and hostname -> external-01"],
    )

    # ER-W02: the raw Windows message proves an inconsistent shutdown, not its cause.
    chosen = selected_records(records, "ER-W02")
    a0 = chosen[0]
    w02 = package("ER-W02", [event(a0, "A0", "system_state", "host-01", {
        "message": field(a0, "system.message"),
    })], [])
    save_case(
        records=records, case_id="ER-W02", condition="weak", slug="inconsistent_shutdown",
        package_value=w02,
        ground_truth=gt(
            "ER-W02", "weak",
            "The inconsistent system shutdown was deliberately caused as a destructive impact action.",
            ["A0"], [],
            [
                "the process, user, or mechanism that caused the shutdown",
                "that malware or an attacker initiated the shutdown",
                "that data destruction or service denial followed",
            ],
            "The shutdown state is real, but its cause is absent and can include failure, power loss, crash, or deliberate action.",
            "A0 records that Windows Management Instrumentation detected an inconsistent system shutdown. The event does not identify a causal process, user, command, or hostile actor, so it supports investigation but not a malicious/high impact verdict.",
        ),
        attack_category="System Shutdown/Reboot (candidate hypothesis)",
        attack_mapping="T1529",
        cluster="wapt-DESKTOP-B37GATP-2024-12-22T09:00Z",
        differentiation="No frozen case tests whether a model attributes an unexplained operating-system shutdown to hostile impact.",
        retrieval_note="The package preserves the native Windows event message and removes the duplicate detector description.",
        literal_redactions=["computer -> host-01"],
    )

    # ER-W03: disconnection is observed; deliberate defence impairment is not.
    chosen = selected_records(records, "ER-W03")
    a0 = chosen[0]
    w03 = package("ER-W03", [event(a0, "A0", "monitoring_status", "host-01", {
        "status": "endpoint monitoring agent disconnected",
    })], [])
    save_case(
        records=records, case_id="ER-W03", condition="weak", slug="monitoring_disconnect",
        package_value=w03,
        ground_truth=gt(
            "ER-W03", "weak",
            "The endpoint monitoring disconnect was deliberately caused to impair security defences.",
            ["A0"], [],
            [
                "that a process stopped or tampered with the agent",
                "that the endpoint itself was offline rather than the network or manager",
                "that telemetry was deleted or defence controls were disabled",
            ],
            "A monitoring gap is operationally relevant, but the status record has no causal endpoint evidence.",
            "A0 records that the endpoint monitoring agent disconnected. It provides no process, command, service-control, or network-causation evidence, so deliberate defence evasion is only one of several possible explanations.",
        ),
        attack_category="Impair Defenses (candidate hypothesis)",
        attack_mapping="T1562.001",
        cluster="wapt-DESKTOP-DS4FBF4-2024-12-01T18:46Z",
        differentiation="No frozen case treats a sensor-health signal as an ambiguous security event rather than proof of tampering.",
        retrieval_note="The neutral status is parsed from the source full_log; the product name and upstream technique label are not exposed.",
        literal_redactions=["agent/computer -> host-01", "product-specific name -> endpoint monitoring agent"],
    )

    # ER-C01: a coherent burst of valid Microsoft DISM modules from one process.
    chosen = selected_records(records, "ER-C01")
    items = [
        event(item, item["evidence_id"], "image_load", "host-01", image_load_attributes(item, dism=True))
        for item in chosen
    ]
    c01 = package("ER-C01", items, ["SYSTEM"])
    c01_ids = [item["evidence_id"] for item in items]
    save_case(
        records=records, case_id="ER-C01", condition="counter", slug="dism_signed_modules",
        package_value=c01,
        ground_truth=gt(
            "ER-C01", "counter",
            "The temporary-directory DLL loads by DismHost represent malicious DLL side-loading.",
            [], c01_ids,
            [
                "that the DismHost executable itself was signature-verified by these events",
                "that every DLL load by DismHost is benign",
                "that activity outside the selected sub-second module-loading burst was reviewed",
            ],
            "A temporary path can look suspicious, but the selected burst is a coherent DISM module set with valid Microsoft signatures and matching product metadata.",
            "A0 and EV-001 through EV-004 show one DismHost process loading five named Windows servicing modules within the same temporary working directory and sub-second window. Every loaded DLL is identified as a Microsoft Windows component with a valid Microsoft signature. This affirmative, internally coherent servicing context defeats the isolated side-loading interpretation for this alert package.",
        ),
        attack_category="DLL Side-Loading false-positive surface",
        attack_mapping="T1574.002",
        cluster="wapt-DESKTOP-QGB4EQH-2024-12-01T07:55Z",
        differentiation="No frozen counter case uses a coherent, signature-verified Windows servicing module burst.",
        retrieval_note="The deterministic rule selects the first matching DISM burst; five retained image-load events share one process ID, one working directory, and a 77-millisecond window.",
        literal_redactions=["computer -> host-01", "temporary directory GUID -> [guid]", "SYSTEM identity retained"],
    )

    # ER-C02: both sides of one WinRM connection are IPv6 loopback on one host.
    chosen = selected_records(records, "ER-C02")
    items = []
    for item in chosen:
        items.append(event(item, item["evidence_id"], "network_connection", "host-01", {
            "image": field(item, "eventdata.image"),
            "process_id": field(item, "eventdata.processId"),
            "user": "SYSTEM",
            "protocol": field(item, "eventdata.protocol").lower(),
            "initiated": field(item, "eventdata.initiated").lower(),
            "source_ip": "::1",
            "source_port": field(item, "eventdata.sourcePort"),
            "destination_ip": "::1",
            "destination_port": field(item, "eventdata.destinationPort"),
        }))
    c02 = package("ER-C02", items, ["SYSTEM"])
    save_case(
        records=records, case_id="ER-C02", condition="counter", slug="loopback_winrm",
        package_value=c02,
        ground_truth=gt(
            "ER-C02", "counter",
            "The WinRM-port connection represents remote lateral movement from another host.",
            [], ["A0", "EV-001"],
            [
                "that a remote peer participated in the connection",
                "that local WinRM use is always authorised or harmless",
                "that a PowerShell command or remote shell was executed",
            ],
            "Port 5985 resembles remote administration, but both network endpoints are the IPv6 loopback address on the same host.",
            "A0 and EV-001 are the initiating and receiving views of one TCP connection on source port 53063 and destination port 5985. Both source and destination are ::1, so no remote peer or cross-host movement is present in this transaction. The package does not prove what local operation caused the loopback request.",
        ),
        attack_category="Windows Remote Management false-positive surface",
        attack_mapping="T1021.006",
        cluster="wapt-DESKTOP-QGB4EQH-2024-12-01T11:07Z",
        differentiation="The frozen strong WinRM case is cross-host execution; this matched counter case contains only a local loopback transaction.",
        retrieval_note="The two records share the same source port and timestamp and expose opposite initiated values; both endpoints are ::1.",
        literal_redactions=["computer -> host-01", "IPv6 loopback and SYSTEM identity retained"],
    )

    # ER-C03: standard spooler driver modules with valid Microsoft signatures.
    chosen = selected_records(records, "ER-C03")
    items = [
        event(item, item["evidence_id"], "image_load", "host-01", image_load_attributes(item))
        for item in chosen
    ]
    c03 = package("ER-C03", items, ["SYSTEM"])
    save_case(
        records=records, case_id="ER-C03", condition="counter", slug="signed_spooler_modules",
        package_value=c03,
        ground_truth=gt(
            "ER-C03", "counter",
            "The spooler DLL loads establish exploitation of the print service.",
            [], ["A0", "EV-001"],
            [
                "that the spooler service cannot be exploited",
                "that every DLL under the spool driver directory is benign",
                "that a remote client, exploit request, or arbitrary DLL was observed",
            ],
            "Spooler image loads can trigger exploit-oriented rules, but these two modules are standard-path Windows print components with valid Microsoft signatures.",
            "A0 and EV-001 show spoolsv.exe loading PrintConfig.dll and mxdwdrv.dll from the standard x64 print-driver directory within 75 milliseconds. Both events identify Microsoft Windows product metadata and valid Microsoft signatures. No remote peer, exploit request, or untrusted DLL is present, so this package is affirmative routine print-driver context rather than mere absence of follow-on.",
        ),
        attack_category="Exploitation of Remote Services false-positive surface",
        attack_mapping="T1210",
        cluster="wapt-DESKTOP-DS4FBF4-2024-11-06T06:27Z",
        differentiation="No frozen counter case uses signature-verified standard Windows print-driver module loads.",
        retrieval_note="The two image loads share the same spoolsv.exe process GUID and occur 75 milliseconds apart.",
        literal_redactions=["computer -> host-01", "SYSTEM identity retained"],
    )


def main() -> int:
    actual_source_hash = digest(SOURCE.read_bytes())
    if actual_source_hash != SOURCE_SHA256:
        raise RuntimeError("Windows-APT combined.csv hash mismatch")
    records = load_records()
    build(records)
    print("Built ER-W01, ER-W02, ER-W03, ER-C01, ER-C02, and ER-C03")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
