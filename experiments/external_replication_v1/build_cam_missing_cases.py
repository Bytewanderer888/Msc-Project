#!/usr/bin/env python3
"""Build four CAM-LDS missing-evidence replication cases reproducibly."""

from __future__ import annotations

import hashlib
import json
import zipfile
from pathlib import Path
from typing import Any

import jsonschema


ROOT = Path(__file__).resolve().parents[2]
STUDY = Path(__file__).resolve().parent
ARCHIVE = ROOT / "data_sources/cam_lds/manifestations_raw.zip"
SCHEMA = ROOT / "tools/schema/alert_package.schema.json"
ARCHIVE_SHA256 = "f9cd31ef5035863e35894a13aeb6d7963dcfa47f4ad7fa257db39298eca7ffc9"


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def select_line(
    archive: zipfile.ZipFile,
    evidence_id: str,
    member: str,
    required_fragments: list[str],
) -> dict[str, Any]:
    matches: list[dict[str, Any]] = []
    with archive.open(member) as handle:
        for line_number, raw in enumerate(handle, start=1):
            text = raw.rstrip(b"\r\n").decode("utf-8", "replace")
            if all(fragment in text for fragment in required_fragments):
                matches.append(
                    {
                        "evidence_id": evidence_id,
                        "archive_member": member,
                        "line_number": line_number,
                        "record_sha256": sha256(raw.rstrip(b"\r\n")),
                        "raw_record": text,
                    }
                )
    if len(matches) != 1:
        raise RuntimeError(
            f"{member} selector {evidence_id} matched {len(matches)} lines; expected 1"
        )
    return matches[0]


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, indent=2, ensure_ascii=True) + "\n", encoding="utf-8"
    )


def write_text(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value.rstrip() + "\n", encoding="utf-8")


def source_event(
    evidence_id: str,
    event_time: str,
    event_type: str,
    provider: str,
    channel: str,
    event_code: int,
    computer: str,
    attributes: dict[str, str],
    *,
    main: bool = False,
) -> dict[str, Any]:
    event = {
        "evidence_id": evidence_id,
        "event_time_utc": event_time,
        "event_type": event_type,
        "source_event": {
            "provider": provider,
            "channel": channel,
            "event_code": event_code,
            "event_record_id": f"SRC-{evidence_id}",
        },
        "computer": computer,
        "attributes": attributes,
    }
    if main:
        event["is_triggering_alert"] = True
    return event


def package(
    case_id: str,
    computers: list[str],
    users: list[str],
    start: str,
    end: str,
    event_types: list[str],
    sourcetypes: list[str],
    main_alert: dict[str, Any],
    evidence_items: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "case_id": case_id,
        "package_type": "neutral_security_event_package",
        "observed_context": {
            "computers": computers,
            "users": users,
            "time_window_utc": {"start": start, "end": end},
            "event_count": 1 + len(evidence_items),
            "event_types_present": event_types,
            "sourcetypes_present": sourcetypes,
        },
        "main_alert": main_alert,
        "evidence_items": evidence_items,
        "deterministic_derivations": [],
    }


def ground_truth(
    case_id: str,
    proposition: str,
    supporting: list[str],
    must_not_assert: list[str],
    trap: str,
    rationale: str,
    response_family: str,
    response_note: str,
) -> dict[str, Any]:
    return {
        "case_id": case_id,
        "security_proposition": proposition,
        "evidence_condition": "missing",
        "calibration_role": "down_rank",
        "correct_verdict": "suspicious",
        "acceptable_severity": ["low", "medium"],
        "acceptable_actions": ["monitor", "investigate"],
        "operational_response": {
            "family": response_family,
            "note": response_note,
        },
        "grounding": {
            "supporting_evidence": supporting,
            "counter_evidence": [],
            "must_not_assert": must_not_assert,
        },
        "the_trap": trap,
        "rationale": rationale,
        "annotated_by": "researcher",
        "review_status": "frozen_pre_model_2026-07-22",
        "rubric_version": "1.1",
    }


def write_case(
    *,
    case_id: str,
    case_name: str,
    attack_name: str,
    attack_id: str,
    capture_cluster: str,
    telemetry_depth: str,
    sensors: list[str],
    differentiation: str,
    package_data: dict[str, Any],
    gt: dict[str, Any],
    selected: list[dict[str, Any]],
    redactions: list[str],
    runbook: str,
) -> None:
    case_dir = STUDY / f"cases/missing/{case_id}_{case_name}"
    jsonschema.validate(package_data, json.loads(SCHEMA.read_text(encoding="utf-8")))

    selection = {
        "schema_version": "1.0",
        "case_id": case_id,
        "case_name": case_name,
        "split": "external_replication_heldout",
        "status": "candidate_built_pending_qa",
        "security_proposition": gt["security_proposition"],
        "attack_category": {
            "category": attack_name,
            "candidate_attack_mapping": attack_id,
            "model_visible": False,
        },
        "source_provenance": {
            "dataset": "CAM-LDS",
            "scenario": capture_cluster,
            "capture_cluster": capture_cluster,
            "telemetry_depth": telemetry_depth,
            "sensors": sensors,
        },
        "model_input_controls": {
            "excluded": [
                "attacker-side AttackMate commands, output, and ATT&CK metadata",
                "source scenario and variant names",
                "condition, verdict, severity, action, and ground truth",
                *redactions,
            ],
            "deterministic_derivations": [],
        },
        "operational_response_family": gt["operational_response"]["family"],
        "nearest_frozen_case": None,
        "differentiation": differentiation,
    }

    provenance = {
        "case_id": case_id,
        "status": "candidate_built_pending_qa",
        "source_corpus": "CAM-LDS",
        "doi": "10.5281/zenodo.18861762",
        "source_archive": {
            "path": "data_sources/cam_lds/manifestations_raw.zip",
            "sha256": ARCHIVE_SHA256,
        },
        "selected_records": [
            {
                "evidence_id": item["evidence_id"],
                "archive_member": item["archive_member"],
                "line_number": item["line_number"],
                "record_sha256": item["record_sha256"],
            }
            for item in selected
        ],
        "integrity_note": (
            "Record hashes cover the exact UTF-8 source line without its line terminator. "
            "Only defender-side host telemetry is selected; attacker logs are used solely "
            "for source audit and are never model-visible."
        ),
    }

    build = {
        "case_id": case_id,
        "builder": "experiments/external_replication_v1/build_cam_missing_cases.py",
        "source_archive": "data_sources/cam_lds/manifestations_raw.zip",
        "selectors": [
            {
                "evidence_id": item["evidence_id"],
                "archive_member": item["archive_member"],
                "line_number": item["line_number"],
                "record_sha256": item["record_sha256"],
            }
            for item in selected
        ],
        "literal_redactions": redactions,
    }

    write_json(case_dir / "model_input/alert_package.json", package_data)
    write_json(case_dir / "annotations/ground_truth.json", gt)
    write_json(case_dir / "annotations/selection_metadata.json", selection)
    write_json(case_dir / "source/provenance.json", provenance)
    write_json(case_dir / "build/case.json", build)
    write_json(case_dir / "extracted/source_records.json", selected)
    write_text(case_dir / "queries/retrieval_spec.md", runbook)


def build_service_pre_activation(archive: zipfile.ZipFile) -> None:
    case_id = "ER-M01"
    selected = [
        select_line(
            archive,
            "A0",
            "manifestations_raw/steps/4-13/inetfw/logs/log/auth.log",
            ["COMMAND=/usr/bin/systemctl daemon-reload"],
        ),
        select_line(
            archive,
            "EV-001",
            "manifestations_raw/steps/4-12/inetfw/logs/log/audit/audit.log",
            ['name="/etc/systemd/system/.auditf.service.swp"', "nametype=DELETE"],
        ),
    ]
    main = source_event(
        "A0",
        "2025-12-15T11:10:06Z",
        "service_manager_reload",
        "Linux authentication log",
        "/var/log/auth.log",
        0,
        "gateway-01.corp.local",
        {
            "user": "root",
            "command_line": "sudo systemctl daemon-reload",
            "working_directory": "/usr/bin",
            "terminal": "pts/1",
        },
        main=True,
    )
    context = source_event(
        "EV-001",
        "2025-12-15T11:09:49.444Z",
        "service_editor_artifact_removed",
        "Linux Audit subsystem",
        "/var/log/audit/audit.log",
        87,
        "gateway-01.corp.local",
        {
            "target_filename": "/etc/systemd/system/.[x].service.swp",
            "operation": "unlink",
            "status": "success=yes",
            "file_role": "editor swap artifact",
        },
    )
    pkg = package(
        case_id,
        ["gateway-01.corp.local"],
        ["root"],
        context["event_time_utc"],
        main["event_time_utc"],
        ["service_editor_artifact_removed", "service_manager_reload"],
        ["linux_audit", "linux_auth"],
        main,
        [context],
    )
    gt = ground_truth(
        case_id,
        "The observed service-management preparation activated a new systemd persistence service.",
        ["A0", "EV-001"],
        [
            "that the service unit contents are present in the package",
            "that the service was enabled or started",
            "that a service payload executed",
            "that later events outside the alert-time window are part of this package",
        ],
        (
            "A service-named editor artifact and a root daemon reload are persistence-relevant "
            "preparation, but neither event is service activation."
        ),
        (
            "EV-001 records removal of an editor swap artifact beneath /etc/systemd/system for "
            "a service-named file. A0 then records root invoking systemctl daemon-reload. The "
            "alert-time package has no enable, start, active-unit, or payload-process evidence, "
            "so active persistence is not established."
        ),
        "endpoint_isolation",
        "Investigate the unit and host; containment would require confirmation or human approval.",
    )
    write_case(
        case_id=case_id,
        case_name="systemd_pre_activation",
        attack_name="Create or Modify System Process: Systemd Service",
        attack_id="T1543.002",
        capture_cluster="cam-s4-systemd",
        telemetry_depth="multi_source",
        sensors=["Linux audit", "Linux auth"],
        differentiation=(
            "Unlike the frozen service-execution cases, this point-in-time package stops at "
            "service-file editing residue and daemon reload, before activation."
        ),
        package_data=pkg,
        gt=gt,
        selected=selected,
        redactions=["service filename auditf -> [x]", "host inetfw -> gateway-01"],
        runbook="""
# ER-M01 retrieval specification

## Scope

- Corpus: CAM-LDS raw step manifestations
- Alert-time window: scenario 4 steps 12-13, ending at the daemon reload
- Host: `inetfw` (model-visible alias `gateway-01.corp.local`)
- Sensors: Linux audit and auth logs

## Selection

1. Apply `annotations/trigger_spec.json` to the complete declared auth-log member
   and select `A0` with its deterministic strategy.
2. Use exact line locators only to assert that replay and to retain the
   immediately preceding audit path record as `EV-001`.
3. Search the complete defender logs in the scoped steps for `systemctl enable`,
   `systemctl start`, an active-unit result, and a payload process. None occurs
   inside this alert-time window.

Attacker-side logs and later scenario steps are excluded from model input. They are retained only for provenance and boundary auditing.
""",
    )


def build_crontab_uncommitted(archive: zipfile.ZipFile) -> None:
    case_id = "ER-M02"
    selected = [
        select_line(
            archive,
            "A0",
            "manifestations_raw/steps/6_macro_cron-20/client/logs/log/syslog",
            ["crontab", "BEGIN EDIT"],
        ),
        select_line(
            archive,
            "EV-001",
            "manifestations_raw/steps/6_macro_cron-20/client/logs/log/audit/audit.log",
            ['type=EXECVE msg=audit(1765361074.224:7191)', 'a0="crontab"', 'a1="-e"'],
        ),
    ]
    main = source_event(
        "A0",
        "2025-12-10T10:04:34Z",
        "crontab_edit_started",
        "Linux syslog",
        "/var/log/syslog",
        0,
        "workstation-01.corp.local",
        {"user": "user-01", "operation": "BEGIN EDIT", "program": "crontab"},
        main=True,
    )
    context = source_event(
        "EV-001",
        "2025-12-10T10:04:34.224Z",
        "process_execution",
        "Linux Audit subsystem",
        "/var/log/audit/audit.log",
        59,
        "workstation-01.corp.local",
        {
            "user": "user-01",
            "image": "/usr/bin/crontab",
            "command_line": "crontab -e",
            "parent_chain": "office_app -> python3 -> dash -> python3 -> bash -> crontab",
            "terminal": "pts1",
            "status": "process execution success",
        },
    )
    pkg = package(
        case_id,
        ["workstation-01.corp.local"],
        ["user-01"],
        main["event_time_utc"],
        context["event_time_utc"],
        ["crontab_edit_started", "process_execution"],
        ["linux_syslog", "linux_audit"],
        main,
        [context],
    )
    gt = ground_truth(
        case_id,
        "The observed crontab editing session installed and activated a persistent scheduled job.",
        ["A0", "EV-001"],
        [
            "that a crontab entry was saved or replaced",
            "that any scheduled command is known",
            "that a cron job fired",
            "that persistence was successfully established",
        ],
        (
            "The office-origin process chain makes the edit attempt worth investigating, but "
            "opening `crontab -e` is not equivalent to installing or firing a job."
        ),
        (
            "A0 records only BEGIN EDIT for user-01. EV-001 confirms execution of crontab -e "
            "from an unusual office-origin process chain. The complete step-level syslog has no "
            "REPLACE or END EDIT record, and the package has no cron-child execution. The setup "
            "attempt is suspicious, while the persistence outcome remains unconfirmed."
        ),
        "analyst_escalation",
        "Inspect the user's crontab and parent process chain before containment.",
    )
    write_case(
        case_id=case_id,
        case_name="crontab_edit_uncommitted",
        attack_name="Scheduled Task/Job: Cron",
        attack_id="T1053.003",
        capture_cluster="cam-s6-macro-cron",
        telemetry_depth="multi_source",
        sensors=["Linux audit", "Linux syslog"],
        differentiation=(
            "This Linux cron case tests edit-start versus installed-job reasoning, unlike the "
            "frozen Windows scheduled-task cases."
        ),
        package_data=pkg,
        gt=gt,
        selected=selected,
        redactions=["user judy -> user-01", "host client -> workstation-01"],
        runbook="""
# ER-M02 retrieval specification

## Scope

- Corpus: CAM-LDS raw step manifestation `6_macro_cron-20`
- Host: `client` (model-visible alias `workstation-01.corp.local`)
- Sensors: Linux syslog and audit

## Selection

1. Apply `annotations/trigger_spec.json` to the complete declared syslog member
   and select the matching `BEGIN EDIT` record as `A0`.
2. Use exact line locators only to verify replay and retain the matching audit
   `EXECVE` record for `crontab -e` as `EV-001`.
3. Search the complete step-level syslog for `REPLACE` or `END EDIT`, and
   audit/syslog for a cron child executing a newly installed command. No such
   confirmation is present.

No attacker-console output is included in the package.
""",
    )


def build_failed_cleanup(archive: zipfile.ZipFile) -> None:
    case_id = "ER-M03"
    member = "manifestations_raw/steps/1_cron_sshkey-34/videoserver/logs/log/audit/audit.log"
    selected = [
        select_line(
            archive,
            "A0",
            member,
            ['type=EXECVE msg=audit(1758696532.324:13583)', 'a0="rm"', 'a1="linpeas.sh"'],
        ),
        select_line(
            archive,
            "EV-001",
            member,
            ['type=SYSCALL msg=audit(1758696532.324:13584)', "success=no", "exit=-2", 'comm="rm"'],
        ),
    ]
    main = source_event(
        "A0",
        "2025-09-24T06:48:52.324Z",
        "file_removal_command",
        "Linux Audit subsystem",
        "/var/log/audit/audit.log",
        59,
        "server-01.corp.local",
        {
            "user": "root",
            "image": "/usr/bin/rm",
            "command_line": "rm [x].sh",
            "target_filename": "[x].sh",
            "terminal": "pts1",
        },
        main=True,
    )
    outcome = source_event(
        "EV-001",
        "2025-09-24T06:48:52.324Z",
        "file_removal_result",
        "Linux Audit subsystem",
        "/var/log/audit/audit.log",
        263,
        "server-01.corp.local",
        {
            "process_name": "rm",
            "operation": "unlinkat",
            "status": "success=no",
            "exit_code": "-2",
            "error": "ENOENT",
        },
    )
    pkg = package(
        case_id,
        ["server-01.corp.local"],
        ["root"],
        main["event_time_utc"],
        main["event_time_utc"],
        ["file_removal_command", "file_removal_result"],
        ["linux_audit"],
        main,
        [outcome],
    )
    gt = ground_truth(
        case_id,
        "The observed cleanup command removed its selected script from the host.",
        ["A0", "EV-001"],
        [
            "that the target script existed at command time",
            "that any file was deleted by this command",
            "that log or forensic evidence was erased",
            "that the command established successful defense evasion",
        ],
        (
            "The command is cleanup-shaped, but the immediately correlated unlinkat result is "
            "success=no with ENOENT. Invocation must not be rewritten as deletion."
        ),
        (
            "A0 records root invoking rm against a script target. EV-001 is the correlated "
            "unlinkat result from the same process and reports success=no, exit -2 (ENOENT). "
            "The cleanup attempt is observable, but target removal did not occur."
        ),
        "analyst_escalation",
        "Investigate the session and surrounding activity; no deletion-based containment claim is justified.",
    )
    write_case(
        case_id=case_id,
        case_name="file_cleanup_failed",
        attack_name="Indicator Removal: File Deletion",
        attack_id="T1070.004",
        capture_cluster="cam-s1-cron-sshkey",
        telemetry_depth="single_source",
        sensors=["Linux audit"],
        differentiation=(
            "No frozen case centers on a Linux unlink result that explicitly disproves successful "
            "completion of the observed cleanup command."
        ),
        package_data=pkg,
        gt=gt,
        selected=selected,
        redactions=["tool-specific filename linpeas.sh -> [x].sh", "host videoserver -> server-01"],
        runbook="""
# ER-M03 retrieval specification

## Scope

- Corpus: CAM-LDS raw step manifestation `1_cron_sshkey-34`
- Host: `videoserver` (model-visible alias `server-01.corp.local`)
- Sensor: Linux audit

## Selection

1. Apply `annotations/trigger_spec.json` to the complete declared audit member
   and select the matching `rm` invocation as `A0`.
2. Use the audit serial only after rule execution to verify replay and retain
   the immediately correlated `unlinkat` result as `EV-001`.
3. Confirm that the correlated result reports `success=no`, `exit=-2` (ENOENT),
   rather than a successful target deletion.

The tool-specific source filename is neutralised in model input. Attacker-console output is not included.
""",
    )


def build_failed_backup_removal(archive: zipfile.ZipFile) -> None:
    case_id = "ER-M04"
    member = "manifestations_raw/steps/3_ssh_healthcheck-31/linuxshare/logs/log/audit/audit.log"
    selected = [
        select_line(
            archive,
            "A0",
            member,
            ['type=EXECVE msg=audit(1765464266.708:11257)', 'a0="rm"', 'a1="-rf"', 'a2="/var/backups/*"'],
        ),
        select_line(
            archive,
            "EV-001",
            member,
            ['type=SYSCALL msg=audit(1765464266.712:11258)', "success=no", "exit=-2", 'comm="rm"'],
        ),
    ]
    main = source_event(
        "A0",
        "2025-12-11T14:44:26.708Z",
        "backup_removal_command",
        "Linux Audit subsystem",
        "/var/log/audit/audit.log",
        59,
        "file-server-01.corp.local",
        {
            "user": "root",
            "image": "/usr/bin/rm",
            "command_line": "rm -rf /var/backups/*",
            "target_filename": "/var/backups/*",
            "terminal": "pts0",
        },
        main=True,
    )
    outcome = source_event(
        "EV-001",
        "2025-12-11T14:44:26.712Z",
        "backup_removal_result",
        "Linux Audit subsystem",
        "/var/log/audit/audit.log",
        263,
        "file-server-01.corp.local",
        {
            "process_name": "rm",
            "operation": "unlinkat",
            "status": "success=no",
            "exit_code": "-2",
            "error": "ENOENT",
            "target_parent": "/var/backups/",
        },
    )
    pkg = package(
        case_id,
        ["file-server-01.corp.local"],
        ["root"],
        main["event_time_utc"],
        outcome["event_time_utc"],
        ["backup_removal_command", "backup_removal_result"],
        ["linux_audit"],
        main,
        [outcome],
    )
    gt = ground_truth(
        case_id,
        "The observed recursive removal command deleted backup material and impaired recovery.",
        ["A0", "EV-001"],
        [
            "that any path matched the wildcard",
            "that backup files were deleted",
            "that recovery capability was impaired",
            "that ransomware or destructive impact completed",
        ],
        (
            "The command expresses a potentially destructive objective, but the only correlated "
            "target operation reports ENOENT; intent-shaped syntax is not a completed impact."
        ),
        (
            "A0 records root invoking recursive removal against /var/backups/*. EV-001 is the "
            "correlated unlinkat result and reports success=no, exit -2 (ENOENT). The package "
            "therefore supports an attempted recovery-impairment precursor, not successful backup deletion."
        ),
        "endpoint_isolation",
        "Urgently investigate the root session; autonomous isolation still requires policy or human approval.",
    )
    write_case(
        case_id=case_id,
        case_name="backup_removal_failed",
        attack_name="Inhibit System Recovery",
        attack_id="T1490",
        capture_cluster="cam-s3-ssh-healthcheck",
        telemetry_depth="single_source",
        sensors=["Linux audit"],
        differentiation=(
            "This case adds Linux recovery-impairment intent with an explicit failed target syscall; "
            "the frozen benchmark has no equivalent backup-removal boundary."
        ),
        package_data=pkg,
        gt=gt,
        selected=selected,
        redactions=["host linuxshare -> file-server-01"],
        runbook="""
# ER-M04 retrieval specification

## Scope

- Corpus: CAM-LDS raw step manifestation `3_ssh_healthcheck-31`
- Host: `linuxshare` (model-visible alias `file-server-01.corp.local`)
- Sensor: Linux audit

## Selection

1. Apply `annotations/trigger_spec.json` to the complete declared audit member
   and select the matching recursive backup-removal invocation as `A0`.
2. Use the audit serial only after rule execution to verify replay and retain
   the immediately correlated `unlinkat` result as `EV-001`.
3. Confirm that the wildcard was passed literally and the target operation
   reports `success=no`, `exit=-2` (ENOENT). No successful backup deletion
   occurs in the complete step-level audit log.

Attacker-console output is excluded from model input.
""",
    )


def main() -> int:
    if sha256(ARCHIVE.read_bytes()) != ARCHIVE_SHA256:
        raise RuntimeError("CAM-LDS source archive hash mismatch")
    with zipfile.ZipFile(ARCHIVE) as archive:
        build_service_pre_activation(archive)
        build_crontab_uncommitted(archive)
        build_failed_cleanup(archive)
        build_failed_backup_removal(archive)
    print("Built ER-M01, ER-M02, ER-M03, and ER-M04")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
