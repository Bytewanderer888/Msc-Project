#!/usr/bin/env python3
"""Build the first AIT-ADS external-replication candidates reproducibly."""

from __future__ import annotations

import base64
import hashlib
import json
import re
import urllib.parse
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

import jsonschema


ROOT = Path(__file__).resolve().parents[2]
STUDY = Path(__file__).resolve().parent
ARCHIVE = ROOT / "data_sources/ait_ads/ait_ads.zip"
SCHEMA = ROOT / "tools/schema/alert_package.schema.json"
ARCHIVE_SHA256 = "9f0595c4ebe56ac9223763881f55369dd4f249a8108064e4ae108eb3309aeeb9"


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def iso_epoch(value: float) -> str:
    return datetime.fromtimestamp(value, tz=timezone.utc).isoformat().replace(
        "+00:00", "Z"
    )


def find_one(
    archive: zipfile.ZipFile,
    member: str,
    predicate: Callable[[dict[str, Any]], bool],
) -> dict[str, Any]:
    with archive.open(member) as handle:
        for line_number, raw in enumerate(handle, start=1):
            record = json.loads(raw)
            if predicate(record):
                return {
                    "archive_member": member,
                    "line_number": line_number,
                    "record_sha256": digest(raw.rstrip(b"\r\n")),
                    "record": record,
                }
    raise RuntimeError(f"selector did not match exactly one required record in {member}")


def find_required(
    archive: zipfile.ZipFile,
    member: str,
    selectors: dict[str, Callable[[dict[str, Any]], bool]],
) -> dict[str, dict[str, Any]]:
    """Resolve several exact selectors in one archive pass and reject ambiguity."""
    matches: dict[str, list[dict[str, Any]]] = {key: [] for key in selectors}
    with archive.open(member) as handle:
        for line_number, raw in enumerate(handle, start=1):
            record = json.loads(raw)
            for evidence_id, predicate in selectors.items():
                if predicate(record):
                    matches[evidence_id].append(
                        {
                            "evidence_id": evidence_id,
                            "archive_member": member,
                            "line_number": line_number,
                            "record_sha256": digest(raw.rstrip(b"\r\n")),
                            "record": record,
                        }
                    )

    resolved: dict[str, dict[str, Any]] = {}
    for evidence_id, candidates in matches.items():
        if len(candidates) != 1:
            raise RuntimeError(
                f"{member} selector {evidence_id} matched {len(candidates)} records; expected 1"
            )
        resolved[evidence_id] = candidates[0]
    return resolved


def source_id(selected: dict[str, Any]) -> str:
    return f"SRC-{selected['evidence_id']}"


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")


def write_text(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value.rstrip() + "\n", encoding="utf-8")


def common_provenance(case_id: str, records: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "case_id": case_id,
        "status": "candidate_built_pending_qa",
        "source_corpus": "AIT Alert Data Set",
        "doi": "10.5281/zenodo.8263181",
        "source_archive": {
            "path": "data_sources/ait_ads/ait_ads.zip",
            "sha256": ARCHIVE_SHA256,
        },
        "selected_records": [
            {
                "evidence_id": record["evidence_id"],
                "archive_member": record["archive_member"],
                "line_number": record["line_number"],
                "record_sha256": record["record_sha256"],
            }
            for record in records
        ],
        "integrity_note": (
            "Record hashes cover the exact UTF-8 JSONL record without its line terminator. "
            "The archive hash is pinned in data_sources/ait_ads/SOURCE_MANIFEST.json."
        ),
    }


def build_webshell(archive: zipfile.ZipFile) -> None:
    case_id = "ER-S01"
    case_dir = STUDY / "cases/strong/ER-S01_ait_webshell_command"
    selected = find_one(
        archive,
        "russellmitchell_aminer.json",
        lambda record: any(
            "ekmkimzkps-1642996700.9285.php?wp_meta=" in line
            for line in record.get("LogData", {}).get("RawLogData", [])
        ),
    )
    raw_log = selected["record"]["LogData"]["RawLogData"][0]
    match = re.search(
        r'^(?P<src>\S+) .*?"(?P<method>\S+) (?P<target>\S+) HTTP/1\.1" '
        r'(?P<status>\d+) (?P<size>\d+) "[^"]*" "(?P<agent>[^"]*)"$',
        raw_log,
    )
    if not match:
        raise RuntimeError("ER-S01 Apache access record did not match the expected format")

    target = urllib.parse.urlsplit(match.group("target"))
    encoded = urllib.parse.parse_qs(target.query)["wp_meta"][0]
    decoded = json.loads(base64.b64decode(encoded).decode("utf-8"))
    if decoded[:3] != ["mysql", "-u", "wordpress"]:
        raise RuntimeError("ER-S01 deterministic decode changed unexpectedly")
    decoded[3] = "-p[redacted-password]"

    selected["evidence_id"] = "A0"
    event_time = iso_epoch(float(selected["record"]["LogData"]["Timestamps"][0]))
    package = {
        "schema_version": "1.0",
        "case_id": case_id,
        "package_type": "neutral_security_event_package",
        "observed_context": {
            "computers": ["web-01.corp.local"],
            "users": [],
            "time_window_utc": {"start": event_time, "end": event_time},
            "event_count": 1,
            "event_types_present": ["http_access"],
            "sourcetypes_present": ["apache_access"],
        },
        "main_alert": {
            "evidence_id": "A0",
            "is_triggering_alert": True,
            "event_time_utc": event_time,
            "event_type": "http_access",
            "source_event": {
                "provider": "Apache HTTP Server",
                "channel": "/var/log/apache2/intranet-access.log",
                "event_code": 0,
                "event_record_id": source_id(selected),
            },
            "computer": "web-01.corp.local",
            "attributes": {
                "source_ip": "external-01",
                "http_method": match.group("method"),
                "url_path": target.path,
                "query_parameter": "wp_meta=[encoded-data]",
                "http_status": match.group("status"),
                "response_bytes": match.group("size"),
                "user_agent": match.group("agent"),
            },
        },
        "evidence_items": [],
        "deterministic_derivations": [
            {
                "derivation_id": "DER-001",
                "derivation_method": "URL-decode wp_meta, then Base64-decode as UTF-8 JSON; redact password argument",
                "source_evidence_id": "A0",
                "source_field": "attributes.query_parameter",
                "derived_field": "decoded_argument_vector",
                "value": json.dumps(decoded, ensure_ascii=True),
            }
        ],
    }

    ground_truth = {
        "case_id": case_id,
        "security_proposition": (
            "A command-capable PHP endpoint under the WordPress uploads path handled "
            "the observed database-query request."
        ),
        "evidence_condition": "strong",
        "calibration_role": "up_rank",
        "correct_verdict": "malicious",
        "acceptable_severity": ["high", "critical"],
        "acceptable_actions": ["escalate", "isolate"],
        "operational_response": {
            "family": "network_blocking",
            "note": "Block access to the endpoint and contain the web host under human approval; this metadata does not expand the model action enum.",
        },
        "grounding": {
            "supporting_evidence": ["A0", "DER-001"],
            "counter_evidence": [],
            "must_not_assert": [
                "that the database credentials were valid",
                "that the SQL query returned WordPress user records because the response body is unavailable",
                "that the package proves when or how the PHP file was uploaded",
                "that persistence or activity outside the selected HTTP transaction is established",
            ],
        },
        "the_trap": (
            "The package is only one HTTP access record, but the uploads-path PHP target, "
            "command-bearing decoded argument vector, successful HTTP status, and large response "
            "make it more than an unconfirmed scan or upload precursor."
        ),
        "rationale": (
            "A0 records an external client requesting a randomly named PHP file under a WordPress "
            "uploads directory with a wp_meta argument. DER-001 decodes that argument to a mysql "
            "command selecting from wp_users, with the password redacted. The server returned HTTP "
            "200 and a 507686-byte response. This decisively establishes handling of a command-bearing "
            "webshell-style request, while not proving the unseen response contents or credential validity."
        ),
        "annotated_by": "researcher",
        "review_status": "frozen_pre_model_2026-07-22",
        "rubric_version": "1.1",
    }

    selection = {
        "schema_version": "1.0",
        "case_id": case_id,
        "case_name": "ait_webshell_command",
        "split": "external_replication_heldout",
        "status": "candidate_built_pending_qa",
        "security_proposition": ground_truth["security_proposition"],
        "attack_category": {
            "category": "Server Software Component: Web Shell",
            "candidate_attack_mapping": "T1505.003",
            "model_visible": False,
        },
        "source_provenance": {
            "dataset": "AIT Alert Data Set",
            "scenario": "russellmitchell",
            "capture_cluster": "ait-russellmitchell",
            "telemetry_depth": "single_source",
            "sensors": ["Apache access log surfaced by AMiner"],
        },
        "model_input_controls": {
            "excluded": [
                "AIT scenario and attack-phase labels",
                "AMiner analysis-component name and message",
                "raw password",
                "condition, verdict, severity, action, ATT&CK mapping",
            ],
            "deterministic_derivations": ["DER-001"],
        },
        "operational_response_family": "network_blocking",
        "nearest_frozen_case": None,
        "differentiation": "No frozen case contains Apache/webshell request evidence or a server-side command endpoint.",
    }

    case_config = {
        "case_id": case_id,
        "builder": "experiments/external_replication_v1/build_ait_cases.py",
        "source_archive": "data_sources/ait_ads/ait_ads.zip",
        "selectors": [
            {
                "evidence_id": "A0",
                "member": "russellmitchell_aminer.json",
                "contains": "ekmkimzkps-1642996700.9285.php?wp_meta=",
            }
        ],
        "literal_redactions": ["database password -> [redacted-password]"],
    }

    retrieval = """# ER-S01 retrieval specification

Source: `ait_ads.zip`, member `russellmitchell_aminer.json`.

1. Stream the JSONL member without extracting the 2.86 GB archive.
2. Apply `annotations/trigger_spec.json` to every record in the declared member
   and select `A0` with its deterministic strategy.
3. Treat the exact line and SHA-256 in `build/case.json` as a replay assertion,
   not as part of the trigger predicate.
4. Parse the underlying Apache access line into timestamp, source, method, URL,
   status, response size, and user agent.
5. URL-decode and Base64-decode `wp_meta` as UTF-8 JSON. Replace the password
   argument with `[redacted-password]` before emitting DER-001.
6. Omit AMiner detector prose, AIT phase labels, scenario identity, and all
   decision labels from the model package.

The selected JSONL line number and SHA-256 are written to `source/provenance.json`.
"""

    jsonschema.validate(package, json.loads(SCHEMA.read_text(encoding="utf-8")))
    write_json(case_dir / "extracted/source_records.json", [selected])
    write_json(case_dir / "source/provenance.json", common_provenance(case_id, [selected]))
    write_json(case_dir / "model_input/alert_package.json", package)
    write_json(case_dir / "annotations/ground_truth.json", ground_truth)
    write_json(case_dir / "annotations/selection_metadata.json", selection)
    write_json(case_dir / "build/case.json", case_config)
    write_text(case_dir / "queries/retrieval_spec.md", retrieval)


def build_privilege_escalation(archive: zipfile.ZipFile) -> None:
    case_id = "ER-S02"
    case_dir = STUDY / "cases/strong/ER-S02_ait_sudo_privilege_escalation"
    a0 = find_one(
        archive,
        "harrison_wazuh.json",
        lambda record: "COMMAND=/bin/cat /etc/shadow"
        in str(record.get("full_log", "")),
    )
    ev1 = find_one(
        archive,
        "harrison_wazuh.json",
        lambda record: "su[28321]: pam_unix(su:session): session opened for user jward by (uid=33)"
        in str(record.get("full_log", "")),
    )
    ev2 = find_one(
        archive,
        "harrison_aminer.json",
        lambda record: any(
            "type=USER_CMD" in line
            and "pid=28346" in line
            and "cmd=636174202F6574632F736861646F77" in line
            and "res=success" in line
            for line in record.get("LogData", {}).get("RawLogData", [])
        ),
    )
    ev3 = find_one(
        archive,
        "harrison_aminer.json",
        lambda record: any(
            "type=USER_START" in line
            and "pid=28346" in line
            and 'acct="root"' in line
            and "res=success" in line
            for line in record.get("LogData", {}).get("RawLogData", [])
        ),
    )
    for evidence_id, record in zip(("A0", "EV-001", "EV-002", "EV-003"), (a0, ev1, ev2, ev3)):
        record["evidence_id"] = evidence_id

    command_hex = "636174202F6574632F736861646F77"
    decoded_command = bytes.fromhex(command_hex).decode("utf-8")
    if decoded_command != "cat /etc/shadow":
        raise RuntimeError("ER-S02 deterministic hex decode changed unexpectedly")

    package = {
        "schema_version": "1.0",
        "case_id": case_id,
        "package_type": "neutral_security_event_package",
        "observed_context": {
            "computers": ["server-01.corp.local"],
            "users": ["svc-web", "user-01", "root"],
            "time_window_utc": {
                "start": "2022-02-08T08:36:38Z",
                "end": "2022-02-08T08:36:57.308000Z",
            },
            "event_count": 4,
            "event_types_present": ["su_session", "sudo_command", "linux_audit"],
            "sourcetypes_present": ["linux_auth", "linux_audit"],
        },
        "main_alert": {
            "evidence_id": "A0",
            "is_triggering_alert": True,
            "event_time_utc": "2022-02-08T08:36:57Z",
            "event_type": "sudo_command",
            "source_event": {
                "provider": "Linux auth",
                "channel": "/var/log/auth.log",
                "event_code": 0,
                "event_record_id": source_id(a0),
            },
            "computer": "server-01.corp.local",
            "attributes": {
                "subject_user": "user-01",
                "target_user": "root",
                "tty": "pts/0",
                "current_directory": "/var/www/intranet.corp.local/wp-content/uploads/2022/02",
                "command_line": "/bin/cat /etc/shadow",
            },
        },
        "evidence_items": [
            {
                "evidence_id": "EV-001",
                "event_time_utc": "2022-02-08T08:36:38Z",
                "event_type": "su_session",
                "source_event": {
                    "provider": "Linux auth",
                    "channel": "/var/log/auth.log",
                    "event_code": 0,
                    "event_record_id": source_id(ev1),
                },
                "computer": "server-01.corp.local",
                "attributes": {
                    "source_user": "svc-web",
                    "target_user": "user-01",
                    "uid": "33",
                    "status": "session_opened",
                    "tty": "pts/0",
                },
            },
            {
                "evidence_id": "EV-002",
                "event_time_utc": "2022-02-08T08:36:57.304000Z",
                "event_type": "linux_audit_user_command",
                "source_event": {
                    "provider": "Linux Audit",
                    "channel": "/var/log/audit/audit.log",
                    "event_code": 0,
                    "event_record_id": source_id(ev2),
                },
                "computer": "server-01.corp.local",
                "attributes": {
                    "process_id": "28346",
                    "uid": "1001",
                    "command_hex": command_hex,
                    "current_directory": "/var/www/intranet.corp.local/wp-content/uploads/2022/02",
                    "tty": "pts/0",
                    "status": "success",
                },
            },
            {
                "evidence_id": "EV-003",
                "event_time_utc": "2022-02-08T08:36:57.308000Z",
                "event_type": "linux_audit_session",
                "source_event": {
                    "provider": "Linux Audit",
                    "channel": "/var/log/audit/audit.log",
                    "event_code": 0,
                    "event_record_id": source_id(ev3),
                },
                "computer": "server-01.corp.local",
                "attributes": {
                    "process_id": "28346",
                    "uid": "0",
                    "target_user": "root",
                    "image": "/usr/bin/sudo",
                    "status": "session_open_success",
                    "tty": "pts/0",
                },
            },
        ],
        "deterministic_derivations": [
            {
                "derivation_id": "DER-001",
                "derivation_method": "hex-decode EV-002 command field as UTF-8",
                "source_evidence_id": "EV-002",
                "source_field": "attributes.command_hex",
                "derived_field": "decoded_command",
                "value": decoded_command,
            }
        ],
    }

    ground_truth = {
        "case_id": case_id,
        "security_proposition": (
            "A session originating from the web-service account successfully executed "
            "root commands through su and sudo."
        ),
        "evidence_condition": "strong",
        "calibration_role": "up_rank",
        "correct_verdict": "malicious",
        "acceptable_severity": ["high", "critical"],
        "acceptable_actions": ["escalate", "isolate"],
        "operational_response": {
            "family": "credential_control",
            "note": "Escalate for root/user credential reset and contain the server under human approval; this metadata does not expand the model action enum.",
        },
        "grounding": {
            "supporting_evidence": ["A0", "EV-001", "EV-002", "EV-003", "DER-001"],
            "counter_evidence": [],
            "must_not_assert": [
                "that /etc/shadow contents were exfiltrated or retained",
                "that the package identifies the initial web compromise mechanism",
                "that unrelated DNS or mail activity elsewhere in the AIT scenario belongs to this host chain",
                "that activity after the selected 19-second window is established",
            ],
        },
        "the_trap": (
            "The records are ordinary Linux authentication and audit formats rather than a branded "
            "attack alert. The decision must follow the service-account-to-user transition, successful "
            "root session, and successful root command rather than detector prose."
        ),
        "rationale": (
            "EV-001 records the web-service account opening an su session as user-01. A0 then records "
            "that user invoking /bin/cat /etc/shadow as root through sudo. EV-002 independently records "
            "the same command in Linux Audit with res=success, and DER-001 decodes its command field. "
            "EV-003 records a successful root sudo session for the same process. This is decisive "
            "privileged command execution from a web-service-originated chain, while not proving "
            "exfiltration of the file contents."
        ),
        "annotated_by": "researcher",
        "review_status": "frozen_pre_model_2026-07-22",
        "rubric_version": "1.1",
    }

    selection = {
        "schema_version": "1.0",
        "case_id": case_id,
        "case_name": "ait_sudo_privilege_escalation",
        "split": "external_replication_heldout",
        "status": "candidate_built_pending_qa",
        "security_proposition": ground_truth["security_proposition"],
        "attack_category": {
            "category": "Abuse Elevation Control Mechanism: Sudo",
            "candidate_attack_mapping": "T1548.003",
            "model_visible": False,
        },
        "source_provenance": {
            "dataset": "AIT Alert Data Set",
            "scenario": "harrison",
            "capture_cluster": "ait-harrison",
            "telemetry_depth": "multi_source",
            "sensors": ["Linux auth.log", "Linux audit.log"],
        },
        "model_input_controls": {
            "excluded": [
                "AIT scenario and attack-phase labels",
                "Wazuh and AMiner detector prose",
                "unrelated mail and DNS alerts in the same phase window",
                "condition, verdict, severity, action, ATT&CK mapping",
            ],
            "deterministic_derivations": ["DER-001"],
        },
        "operational_response_family": "credential_control",
        "nearest_frozen_case": None,
        "differentiation": "No frozen case contains Linux su/sudo/audit evidence or a web-service-to-root chain.",
    }

    records = [a0, ev1, ev2, ev3]
    case_config = {
        "case_id": case_id,
        "builder": "experiments/external_replication_v1/build_ait_cases.py",
        "source_archive": "data_sources/ait_ads/ait_ads.zip",
        "selectors": [
            {"evidence_id": r["evidence_id"], "member": r["archive_member"], "record_sha256": r["record_sha256"]}
            for r in records
        ],
        "literal_redactions": [
            "hostnames -> server-01.corp.local",
            "jward -> user-01",
            "www-data -> svc-web",
            "site domain -> intranet.corp.local",
        ],
    }

    retrieval = """# ER-S02 retrieval specification

Source: `ait_ads.zip`, members `harrison_wazuh.json` and
`harrison_aminer.json`.

1. Apply `annotations/trigger_spec.json` to the complete declared Wazuh member;
   the deterministic match is `A0`.
2. Use exact source locators only to verify that replay and to recover the
   correlated context, not to define the alert.
3. Retain the intranet-server auth records for the `www-data -> jward` su
   session around the matched sudo command.
4. From the AMiner member, retain the Linux Audit `USER_CMD` record for process
   28346 with `res=success` and its matching successful root `USER_START` event.
5. Hex-decode the audit command into DER-001.
6. Exclude detector descriptions, phase labels, unrelated hosts, DNS/mail
   records, and all decision labels. Anonymise the service account, user, host,
   and site domain deterministically.

The two sources observe the same host, command, process, and second, so this is
genuine auth-log + audit-log correlation rather than duplicated detector output.
"""

    jsonschema.validate(package, json.loads(SCHEMA.read_text(encoding="utf-8")))
    write_json(case_dir / "extracted/source_records.json", records)
    write_json(case_dir / "source/provenance.json", common_provenance(case_id, records))
    write_json(case_dir / "model_input/alert_package.json", package)
    write_json(case_dir / "annotations/ground_truth.json", ground_truth)
    write_json(case_dir / "annotations/selection_metadata.json", selection)
    write_json(case_dir / "build/case.json", case_config)
    write_text(case_dir / "queries/retrieval_spec.md", retrieval)


def build_scan_activity(archive: zipfile.ZipFile) -> None:
    case_id = "ER-W04"
    case_dir = STUDY / "cases/weak/ER-W04_ait_scan_activity"
    selected = find_required(
        archive,
        "santos_wazuh.json",
        {
            "A0": lambda record: (
                record.get("@timestamp") == "2022-01-17T11:21:46.000000Z"
                and record.get("location") == "/var/log/apache2/other_vhosts_access.log"
                and str(record.get("full_log", "")).startswith(
                    "cloud.dmz.smith.santos.com:80 172.21.128.119"
                )
                and '"GET /nmaplowercheck1642418506 HTTP/1.1"' in str(record.get("full_log", ""))
            ),
            "EV-001": lambda record: (
                record.get("@timestamp") == "2022-01-17T11:21:46.720864Z"
                and record.get("location") == "/var/log/suricata/eve.json"
                and record.get("data", {}).get("src_ip") == "172.21.128.119"
                and record.get("data", {}).get("dest_ip") == "172.21.128.54"
                and record.get("data", {}).get("http", {}).get("url")
                == "/nmaplowercheck1642418506"
            ),
            "EV-002": lambda record: (
                record.get("@timestamp") == "2022-01-17T11:21:46.000000Z"
                and record.get("location") == "/var/log/apache2/other_vhosts_access.log"
                and str(record.get("full_log", "")).startswith(
                    "cloud.dmz.smith.santos.com:80 172.21.128.119"
                )
                and '"GET /HNAP1 HTTP/1.1"' in str(record.get("full_log", ""))
            ),
            "EV-003": lambda record: (
                record.get("@timestamp") == "2022-01-17T11:21:46.959357Z"
                and record.get("location") == "/var/log/suricata/eve.json"
                and record.get("data", {}).get("src_ip") == "172.21.128.119"
                and record.get("data", {}).get("dest_ip") == "172.21.128.54"
                and record.get("data", {}).get("http", {}).get("url") == "/HNAP1"
            ),
        },
    )
    a0, ev1, ev2, ev3 = (selected[key] for key in ("A0", "EV-001", "EV-002", "EV-003"))
    nmap_agent = "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)"

    def source_event(record: dict[str, Any], provider: str, channel: str) -> dict[str, Any]:
        return {
            "provider": provider,
            "channel": channel,
            "event_code": 0,
            "event_record_id": source_id(record),
        }

    package = {
        "schema_version": "1.0",
        "case_id": case_id,
        "package_type": "neutral_security_event_package",
        "observed_context": {
            "computers": ["web-01.corp.local"],
            "users": [],
            "time_window_utc": {
                "start": "2022-01-17T11:21:46.000000Z",
                "end": "2022-01-17T11:21:46.959357Z",
            },
            "event_count": 4,
            "event_types_present": ["http_access", "network_http"],
            "sourcetypes_present": ["apache_access", "network_http"],
        },
        "main_alert": {
            "evidence_id": "A0",
            "is_triggering_alert": True,
            "event_time_utc": "2022-01-17T11:21:46.000000Z",
            "event_type": "http_access",
            "source_event": source_event(a0, "Apache HTTP Server", "/var/log/apache2/access.log"),
            "computer": "web-01.corp.local",
            "attributes": {
                "source_ip": "client-01",
                "http_method": "GET",
                "url_path": "/nmaplowercheck1642418506",
                "http_status": "404",
                "response_bytes": "7533",
                "user_agent": nmap_agent,
            },
        },
        "evidence_items": [
            {
                "evidence_id": "EV-001",
                "event_time_utc": "2022-01-17T11:21:46.720864Z",
                "event_type": "network_http",
                "source_event": source_event(ev1, "Network sensor", "http"),
                "computer": "web-01.corp.local",
                "attributes": {
                    "source_ip": "client-01",
                    "source_port": "36344",
                    "destination_ip": "web-01.corp.local",
                    "destination_port": "80",
                    "protocol": "HTTP/1.1",
                    "http_method": "GET",
                    "url_path": "/nmaplowercheck1642418506",
                    "http_status": "404",
                    "user_agent": nmap_agent,
                },
            },
            {
                "evidence_id": "EV-002",
                "event_time_utc": "2022-01-17T11:21:46.000000Z",
                "event_type": "http_access",
                "source_event": source_event(ev2, "Apache HTTP Server", "/var/log/apache2/access.log"),
                "computer": "web-01.corp.local",
                "attributes": {
                    "source_ip": "client-01",
                    "http_method": "GET",
                    "url_path": "/HNAP1",
                    "http_status": "404",
                    "response_bytes": "7535",
                    "user_agent": nmap_agent,
                },
            },
            {
                "evidence_id": "EV-003",
                "event_time_utc": "2022-01-17T11:21:46.959357Z",
                "event_type": "network_http",
                "source_event": source_event(ev3, "Network sensor", "http"),
                "computer": "web-01.corp.local",
                "attributes": {
                    "source_ip": "client-01",
                    "source_port": "36386",
                    "destination_ip": "web-01.corp.local",
                    "destination_port": "80",
                    "protocol": "HTTP/1.1",
                    "http_method": "GET",
                    "url_path": "/HNAP1",
                    "http_status": "404",
                    "user_agent": nmap_agent,
                },
            },
        ],
        "deterministic_derivations": [],
    }

    ground_truth = {
        "case_id": case_id,
        "security_proposition": (
            "The scan-like HTTP probes represent hostile reconnaissance rather than an "
            "unconfirmed or authorised scanner."
        ),
        "evidence_condition": "weak",
        "calibration_role": "down_rank",
        "correct_verdict": "suspicious",
        "acceptable_severity": ["low", "medium"],
        "acceptable_actions": ["monitor", "investigate"],
        "operational_response": {
            "family": "analyst_escalation",
            "note": "Investigate the source and scan authorisation; no autonomous containment is justified by this package alone.",
        },
        "grounding": {
            "supporting_evidence": ["A0", "EV-001", "EV-002", "EV-003"],
            "counter_evidence": [],
            "must_not_assert": [
                "that the scanner was unauthorised or attacker-controlled",
                "that an exploit succeeded or a protected resource was accessed",
                "that the two HTTP 404 responses establish compromise",
                "that activity outside the selected one-second window belongs to this case",
            ],
        },
        "the_trap": (
            "The Nmap user agent and repeated probe paths establish scan-like behaviour, but they "
            "do not establish hostile ownership, authorisation status, or a successful outcome."
        ),
        "rationale": (
            "A0 and EV-002 record two Nmap-scripted requests from the same client to the same web "
            "server within one second. EV-001 and EV-003 independently observe the matching HTTP "
            "transactions in network telemetry. Both requests returned 404. The activity is a real "
            "reconnaissance indicator, but the package does not establish whether the scanner was "
            "authorised or whether any exploit or access succeeded."
        ),
        "annotated_by": "researcher",
        "review_status": "frozen_pre_model_2026-07-22",
        "rubric_version": "1.1",
    }

    selection = {
        "schema_version": "1.0",
        "case_id": case_id,
        "case_name": "ait_scan_activity",
        "split": "external_replication_heldout",
        "status": "candidate_built_pending_qa",
        "security_proposition": ground_truth["security_proposition"],
        "attack_category": {
            "category": "Network Service Discovery",
            "candidate_attack_mapping": "T1046",
            "model_visible": False,
        },
        "source_provenance": {
            "dataset": "AIT Alert Data Set",
            "scenario": "santos",
            "capture_cluster": "ait-santos",
            "telemetry_depth": "multi_source",
            "sensors": ["Apache access log", "network HTTP telemetry"],
        },
        "model_input_controls": {
            "excluded": [
                "AIT attack-phase label and scenario identity",
                "Wazuh rule groups, level, and description",
                "network IDS signature, category, severity, and action",
                "duplicated fast.log and mirrored flow records",
                "condition, verdict, severity, action, ATT&CK mapping",
            ],
            "deterministic_derivations": [],
        },
        "operational_response_family": "analyst_escalation",
        "nearest_frozen_case": None,
        "differentiation": "No frozen case contains Linux web-service scan telemetry corroborated by host and network sensors.",
    }

    records = [a0, ev1, ev2, ev3]
    case_config = {
        "case_id": case_id,
        "builder": "experiments/external_replication_v1/build_ait_cases.py",
        "source_archive": "data_sources/ait_ads/ait_ads.zip",
        "selectors": [
            {
                "evidence_id": record["evidence_id"],
                "member": record["archive_member"],
                "line_number": record["line_number"],
                "record_sha256": record["record_sha256"],
            }
            for record in records
        ],
        "literal_redactions": [
            "source address -> client-01",
            "destination host/domain -> web-01.corp.local",
        ],
    }

    retrieval = """# ER-W04 retrieval specification

Source: `ait_ads.zip`, member `santos_wazuh.json`.

1. Apply `annotations/trigger_spec.json` to every record in the declared member
   and select the earliest matching request as `A0`.
2. Use exact line locators only to verify the replayed alert and recover its
   correlated same-transaction context.
3. Retain the two Apache access records from one client to the same web server
   for `/nmaplowercheck1642418506` and `/HNAP1`.
4. Retain the two network HTTP records with the same client, server, paths,
   methods, status codes, and sub-second timestamps.
5. Exclude Wazuh rule prose, IDS signatures/categories, duplicated fast.log
   records, mirrored copies of the same flow, phase labels, and all decision
   labels. Anonymise the client and server consistently.

Apache and network telemetry observe the same two HTTP transactions, so this
is genuine sensor correlation. The package establishes scan-like behaviour but
does not import the corpus phase label as proof of hostile intent.
"""

    jsonschema.validate(package, json.loads(SCHEMA.read_text(encoding="utf-8")))
    write_json(case_dir / "extracted/source_records.json", records)
    write_json(case_dir / "source/provenance.json", common_provenance(case_id, records))
    write_json(case_dir / "model_input/alert_package.json", package)
    write_json(case_dir / "annotations/ground_truth.json", ground_truth)
    write_json(case_dir / "annotations/selection_metadata.json", selection)
    write_json(case_dir / "build/case.json", case_config)
    write_text(case_dir / "queries/retrieval_spec.md", retrieval)


def build_package_update(archive: zipfile.ZipFile) -> None:
    case_id = "ER-C04"
    case_dir = STUDY / "cases/counter/ER-C04_ait_package_update"
    selected = find_required(
        archive,
        "russellmitchell_wazuh.json",
        {
            "A0": lambda record: (
                record.get("@timestamp") == "2022-01-21T00:14:21.369537Z"
                and record.get("location") == "/var/log/suricata/eve.json"
                and record.get("agent", {}).get("ip") == "10.143.0.103"
                and record.get("data", {}).get("http", {}).get("hostname") == "archive.ubuntu.com"
                and record.get("data", {}).get("http", {}).get("url")
                == "/ubuntu/dists/bionic/InRelease"
                and record.get("data", {}).get("http", {}).get("status") == "304"
            ),
            "EV-001": lambda record: (
                record.get("@timestamp") == "2022-01-21T00:14:21.364911Z"
                and record.get("location") == "/var/log/suricata/eve.json"
                and record.get("agent", {}).get("ip") == "10.143.0.103"
                and record.get("data", {}).get("http", {}).get("hostname") == "security.ubuntu.com"
                and record.get("data", {}).get("http", {}).get("url")
                == "/ubuntu/dists/bionic-security/InRelease"
            ),
            "EV-002": lambda record: (
                record.get("@timestamp") == "2022-01-21T00:14:21.397018Z"
                and record.get("location") == "/var/log/suricata/eve.json"
                and record.get("agent", {}).get("ip") == "10.143.0.103"
                and record.get("data", {}).get("http", {}).get("hostname") == "archive.ubuntu.com"
                and record.get("data", {}).get("http", {}).get("url")
                == "/ubuntu/dists/bionic-updates/InRelease"
            ),
        },
    )
    a0, ev1, ev2 = (selected[key] for key in ("A0", "EV-001", "EV-002"))
    apt_agent = "Debian APT-HTTP/1.3 (1.6.12ubuntu0.2)"

    def http_event(
        record: dict[str, Any], evidence_id: str, hostname: str, path: str, status: str | None
    ) -> dict[str, Any]:
        attributes = {
            "source_ip": "internal-01",
            "destination_hostname": hostname,
            "destination_port": "80",
            "protocol": "HTTP/1.1",
            "http_method": "GET",
            "url_path": path,
            "user_agent": apt_agent,
        }
        if status is not None:
            attributes["http_status"] = status
        return {
            "evidence_id": evidence_id,
            "event_time_utc": record["record"]["@timestamp"],
            "event_type": "network_http",
            "source_event": {
                "provider": "Network sensor",
                "channel": "http",
                "event_code": 0,
                "event_record_id": source_id(record),
            },
            "computer": "linux-01.corp.local",
            "attributes": attributes,
        }

    package = {
        "schema_version": "1.0",
        "case_id": case_id,
        "package_type": "neutral_security_event_package",
        "observed_context": {
            "computers": ["linux-01.corp.local"],
            "users": [],
            "time_window_utc": {
                "start": "2022-01-21T00:14:21.364911Z",
                "end": "2022-01-21T00:14:21.397018Z",
            },
            "event_count": 3,
            "event_types_present": ["network_http"],
            "sourcetypes_present": ["network_http"],
        },
        "main_alert": {
            **http_event(
                a0,
                "A0",
                "archive.ubuntu.com",
                "/ubuntu/dists/bionic/InRelease",
                "304",
            ),
            "is_triggering_alert": True,
        },
        "evidence_items": [
            http_event(
                ev1,
                "EV-001",
                "security.ubuntu.com",
                "/ubuntu/dists/bionic-security/InRelease",
                None,
            ),
            http_event(
                ev2,
                "EV-002",
                "archive.ubuntu.com",
                "/ubuntu/dists/bionic-updates/InRelease",
                None,
            ),
        ],
        "deterministic_derivations": [],
    }

    ground_truth = {
        "case_id": case_id,
        "security_proposition": (
            "The outbound HTTP burst represents attacker-directed payload transfer rather than "
            "routine operating-system repository metadata retrieval."
        ),
        "evidence_condition": "counter",
        "calibration_role": "down_rank",
        "correct_verdict": "benign",
        "acceptable_severity": ["informational", "low"],
        "acceptable_actions": ["close_benign", "monitor"],
        "operational_response": {
            "family": "none",
            "note": "Close or monitor this repository-metadata burst; the package does not justify containment.",
        },
        "grounding": {
            "supporting_evidence": [],
            "counter_evidence": ["A0", "EV-001", "EV-002"],
            "must_not_assert": [
                "that any executable package was downloaded or installed",
                "that HTTP 304 proves a complete software update succeeded",
                "that all traffic from the host before or after this 33-millisecond window was routine",
                "that the model package contains an IDS benign classification",
            ],
        },
        "the_trap": (
            "Outbound HTTP can resemble tool transfer, but every selected request uses the Debian "
            "APT client, targets official Ubuntu repositories, and requests distribution metadata; "
            "the base-release request received HTTP 304."
        ),
        "rationale": (
            "A0, EV-001, and EV-002 are a 33-millisecond burst from one Linux host using the same "
            "Debian APT user agent. They request base, security, and update-channel InRelease metadata "
            "from archive.ubuntu.com and security.ubuntu.com. A0 received an HTTP 304 response. "
            "This affirmative context is a coherent routine repository check, not merely an absence "
            "of malicious follow-on, while the package does not establish package installation."
        ),
        "annotated_by": "researcher",
        "review_status": "frozen_pre_model_2026-07-22",
        "rubric_version": "1.1",
    }

    selection = {
        "schema_version": "1.0",
        "case_id": case_id,
        "case_name": "ait_package_update",
        "split": "external_replication_heldout",
        "status": "candidate_built_pending_qa",
        "security_proposition": ground_truth["security_proposition"],
        "attack_category": {
            "category": "Ingress Tool Transfer benign twin",
            "candidate_attack_mapping": "T1105",
            "model_visible": False,
        },
        "source_provenance": {
            "dataset": "AIT Alert Data Set",
            "scenario": "russellmitchell normal window",
            "capture_cluster": "ait-russellmitchell-normal",
            "telemetry_depth": "single_source",
            "sensors": ["network HTTP telemetry"],
        },
        "model_input_controls": {
            "excluded": [
                "AIT scenario and attack-phase labels",
                "Wazuh rule level and description",
                "IDS signature, category, severity, and action",
                "NAT-side duplicate records",
                "condition, verdict, severity, action, ATT&CK mapping",
            ],
            "deterministic_derivations": [],
        },
        "operational_response_family": "none",
        "nearest_frozen_case": None,
        "differentiation": "No frozen counter case uses Linux package-manager traffic or repository metadata as affirmative benign context.",
    }

    records = [a0, ev1, ev2]
    case_config = {
        "case_id": case_id,
        "builder": "experiments/external_replication_v1/build_ait_cases.py",
        "source_archive": "data_sources/ait_ads/ait_ads.zip",
        "selectors": [
            {
                "evidence_id": record["evidence_id"],
                "member": record["archive_member"],
                "line_number": record["line_number"],
                "record_sha256": record["record_sha256"],
            }
            for record in records
        ],
        "literal_redactions": [
            "source address -> internal-01",
            "source host -> linux-01.corp.local",
        ],
    }

    retrieval = """# ER-C04 retrieval specification

Source: `ait_ads.zip`, member `russellmitchell_wazuh.json`.

1. Apply `annotations/trigger_spec.json` to every record in the declared member
   and select the earliest matching package-manager request as `A0`.
2. Use exact line locators only as replay assertions and to retain the
   associated 33-millisecond request burst from the same internal endpoint.
3. Retain the HTTP facts needed to interpret the burst: Debian APT user agent,
   official repository hostnames, `InRelease` paths, and observed status codes.
4. Select only the endpoint-side source address and remove NAT-side duplicates.
5. Exclude the IDS signature, its `Not Suspicious Traffic` category, Wazuh rule
   prose, scenario/phase labels, and all decision labels.

The counter classification follows affirmative model-visible context, not the
corpus label: one package-manager user agent requests base, security, and
update-channel metadata from official Ubuntu repositories, including an HTTP
304 response.
"""

    jsonschema.validate(package, json.loads(SCHEMA.read_text(encoding="utf-8")))
    write_json(case_dir / "extracted/source_records.json", records)
    write_json(case_dir / "source/provenance.json", common_provenance(case_id, records))
    write_json(case_dir / "model_input/alert_package.json", package)
    write_json(case_dir / "annotations/ground_truth.json", ground_truth)
    write_json(case_dir / "annotations/selection_metadata.json", selection)
    write_json(case_dir / "build/case.json", case_config)
    write_text(case_dir / "queries/retrieval_spec.md", retrieval)


def main() -> None:
    if digest(ARCHIVE.read_bytes()) != ARCHIVE_SHA256:
        raise RuntimeError("AIT-ADS archive hash does not match SOURCE_MANIFEST.json")
    with zipfile.ZipFile(ARCHIVE) as archive:
        build_webshell(archive)
        build_privilege_escalation(archive)
        build_scan_activity(archive)
        build_package_update(archive)
    print("built and schema-validated ER-S01, ER-S02, ER-W04, and ER-C04")


if __name__ == "__main__":
    main()
