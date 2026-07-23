#!/usr/bin/env python3
"""Write pre-model trigger rules for the 16-case external replication set."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
STUDY = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "tools"))
from trigger_analytic_taxonomy import classification_for, validate_case_inventory  # noqa: E402


def leaf(field: str, op: str, value: Any) -> dict[str, Any]:
    return {"field": field, "op": op, "value": value}


def all_of(*items: dict[str, Any]) -> dict[str, Any]:
    return {"all": list(items)}


def any_of(*items: dict[str, Any]) -> dict[str, Any]:
    return {"any": list(items)}


EID = lambda value: leaf("event_code", "eq", value)
ATTR = lambda name, op, value: leaf(f"attributes.{name}", op, value)
RAW = lambda op, value: ATTR("raw_text", op, value)


RULES: dict[str, dict[str, Any]] = {
    "ER-C01": {
        "title": "DISM host loads a library from its temporary servicing directory",
        "predicate": all_of(EID(7), ATTR("image", "regex", r"(?i)\\Temp\\[^\\]+\\DismHost\.exe$"), ATTR("image_loaded", "regex", r"(?i)\\Temp\\[^\\]+\\[^\\]+\.dll$")),
        "rationale": "A DISM helper loading a DLL from a temporary servicing directory is the alert surface; signature and vendor fields remain contextual evidence.",
    },
    "ER-C02": {
        "title": "WinRM connection over the local IPv6 loopback interface",
        "predicate": all_of(EID(3), ATTR("destination_port", "eq", "5985"), ATTR("source_ip", "regex", r"(?i)^(?:::1|0:0:0:0:0:0:0:1)$"), ATTR("destination_ip", "regex", r"(?i)^(?:::1|0:0:0:0:0:0:0:1)$"), ATTR("initiated", "ieq", "true")),
        "rationale": "A WinRM-port connection is a plausible remote-services alert even when later context establishes that both endpoints are loopback.",
    },
    "ER-C03": {
        "title": "Print spooler loads a library from the standard driver directory",
        "predicate": all_of(EID(7), ATTR("image", "iendswith", r"\spoolsv.exe"), ATTR("image_loaded", "regex", r"(?i)\\spool\\drivers\\[^\\]+\\[^\\]+\\[^\\]+\.dll$")),
        "aggregation": {
            "group_by": ["attributes.process_id"],
            "count_gte": 2,
            "session_gap_seconds_lte": 1,
            "distinct": {"field": "attributes.image_loaded", "count_gte": 2},
        },
        "selection": "earliest_in_highest_count_group",
        "selection_justification": "The analytic alerts on a short multi-module spooler burst, not on an isolated standard-module load.",
        "rationale": "A DLL loaded by the print spooler is the exploitation alert surface; signing and standard-path provenance are evaluated as context.",
    },
    "ER-C04": {
        "title": "Linux package-manager HTTP metadata request",
        "source_unit": "russellmitchell_wazuh.json",
        "predicate": all_of(leaf("attributes.record.data.http.http_user_agent", "istartswith", "Debian APT-HTTP/"), leaf("attributes.record.data.http.hostname", "ieq", "archive.ubuntu.com"), leaf("attributes.record.data.http.url", "iendswith", "/InRelease")),
        "rationale": "An outbound package-manager HTTP request can resemble tool transfer, while the user agent and repository path provide deterministic routine context.",
    },
    "ER-M01": {
        "title": "Root reloads the systemd manager configuration",
        "source_unit": "manifestations_raw/steps/4-13/inetfw/logs/log/auth.log",
        "predicate": all_of(RAW("icontains", "sudo:"), RAW("regex", r"COMMAND=/usr/bin/systemctl\s+daemon-reload\b")),
        "rationale": "A privileged systemd daemon reload is a persistence-relevant setup alert without asserting that any service was enabled or started.",
    },
    "ER-M02": {
        "title": "Interactive crontab edit session begins",
        "source_unit": "manifestations_raw/steps/6_macro_cron-20/client/logs/log/syslog",
        "predicate": all_of(RAW("regex", r"\bcrontab\[\d+\]:"), RAW("icontains", "BEGIN EDIT")),
        "rationale": "Beginning a crontab edit is a scheduled-persistence precursor, while installation and execution require separate evidence.",
    },
    "ER-M03": {
        "title": "Root removal command targets a shell script",
        "source_unit": "manifestations_raw/steps/1_cron_sshkey-34/videoserver/logs/log/audit/audit.log",
        "predicate": all_of(RAW("icontains", "type=EXECVE"), RAW("regex", r"\ba0=\"rm\""), RAW("regex", r"\ba1=\"[^\"]+\.sh\"")),
        "rationale": "An audited rm invocation targeting a shell script is a deletion alert surface; the separate syscall result determines whether deletion succeeded.",
    },
    "ER-M04": {
        "title": "Recursive removal command targets the backup directory",
        "source_unit": "manifestations_raw/steps/3_ssh_healthcheck-31/linuxshare/logs/log/audit/audit.log",
        "predicate": all_of(RAW("icontains", "type=EXECVE"), RAW("regex", r"\ba0=\"rm\""), RAW("regex", r"\ba1=\"-rf\""), RAW("icontains", "a2=\"/var/backups/*\"")),
        "rationale": "A recursive removal command aimed at backups is a destructive-impact alert surface; success must be established from the audited outcome.",
    },
    "ER-S01": {
        "title": "Uploaded PHP endpoint receives an encoded command parameter",
        "source_unit": "russellmitchell_aminer.json",
        "predicate": all_of(RAW("regex", r"(?i)/wp-content/uploads/[^?\s]+\.php\?wp_meta="), RAW("icontains", "HTTP/1.1"), RAW("regex", r"\"\s+200\s+\d+")),
        "rationale": "A successful request to an uploaded PHP file carrying an encoded command parameter is a web-shell command-execution analytic.",
    },
    "ER-S02": {
        "title": "Sudo executes a protected credential-file read as root",
        "source_unit": "harrison_wazuh.json",
        "predicate": all_of(leaf("attributes.record.data.dstuser", "ieq", "root"), leaf("attributes.record.data.command", "regex", r"(?i)^/bin/cat\s+/etc/shadow$")),
        "rationale": "A non-root subject using sudo to read /etc/shadow as root is a direct privilege and credential-access alert surface.",
    },
    "ER-S03": {
        "title": "Root-capable instrumentation process attaches to flight control",
        "source_unit": "SL100/sl100-raw-data/2nd Data Extraction_with_suricata_netflows/audit.log",
        "source_mode": "linux_audit_groups",
        "predicate": all_of(RAW("regex", r"\bsyscall=101\b"), RAW("icontains", "success=yes"), RAW("regex", r"\beuid=0\b"), RAW("regex", r"\bcomm=\"frida_server\""), RAW("regex", r"\bocomm=\"QGroundControl\"")),
        "rationale": "A successful root-capable ptrace attachment by an instrumentation process to the flight-control application is a direct runtime-manipulation alert.",
    },
    "ER-S04": {
        "title": "High-integrity remote-management executable starts from Downloads",
        "source_unit": "SL100/sl100-raw-data/2nd Data Extraction_with_suricata_netflows/WSUS.txt",
        "source_mode": "windows_blocks",
        "predicate": all_of(EID(1), RAW("regex", r"(?i)\\Users\\[^\\]+\\Downloads\\[^\r\n]*(?:psremoting|winrm|remote)[^\r\n]*\.exe"), RAW("regex", r"(?im)^High\s*$")),
        "rationale": "A high-integrity executable whose filename identifies remote-management behaviour starting from Downloads is a pivot alert; cross-host execution is established by context.",
    },
    "ER-W01": {
        "title": "Windows Script Host opens an outbound TCP connection",
        "predicate": all_of(EID(3), ATTR("image", "iendswith", r"\cscript.exe"), ATTR("protocol", "ieq", "tcp"), ATTR("initiated", "ieq", "true")),
        "rationale": "An outbound TCP connection from cscript.exe is a script-host network alert surface without proving payload or session intent.",
    },
    "ER-W02": {
        "title": "WMI reports an inconsistent system shutdown",
        "predicate": all_of(EID(5611), ATTR("message", "icontains", "inconsistent system shutdown")),
        "rationale": "A WMI event reporting inconsistent shutdown is a reproducible availability alert, while its cause remains unestablished.",
    },
    "ER-W03": {
        "title": "Endpoint monitoring agent disconnect notification",
        "predicate": ATTR("full_log", "regex", r"(?i)Agent disconnected:"),
        "rationale": "A monitoring-agent disconnect is a direct observability-loss alert without by itself proving deliberate tampering.",
    },
    "ER-W04": {
        "title": "Nmap scripting-engine request reaches a web server",
        "source_unit": "santos_wazuh.json",
        "predicate": all_of(leaf("attributes.record.data.protocol", "ieq", "GET"), RAW("icontains", "Nmap Scripting Engine"), leaf("attributes.record.data.id", "eq", "404")),
        "rationale": "A web request carrying the Nmap scripting-engine user agent is a scan-like alert surface without establishing authorisation or harmful outcome.",
    },
}


def load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def source_record(case_dir: Path) -> dict[str, Any]:
    records = load(case_dir / "extracted/source_records.json")
    for record in records:
        if record.get("evidence_id") == "A0":
            return record
    return records[0]


def expected_key(config: dict[str, Any], source: dict[str, Any]) -> str:
    selector = next(item for item in config["selectors"] if item["evidence_id"] == "A0")
    if selector.get("source_record_id"):
        return selector["source_record_id"]
    member = selector.get("archive_member") or selector.get("member") or source.get("archive_member")
    if selector.get("audit_serial"):
        return f"{member}:audit:{selector['audit_serial']}"
    if selector.get("block_index"):
        return f"{member}:block:{selector['block_index']}"
    line = selector.get("line_number") or source.get("line_number")
    if member and line:
        return f"{member}:line:{line}"
    raise RuntimeError(f"cannot derive external A0 key for {config['case_id']}")


def windows_scope(source: dict[str, Any]) -> tuple[dict[str, Any], str]:
    row = source["record"]
    computer = row.get("_source.data.win.system.computer") or row.get("_source.agent.name")
    partition = row["_index"]
    return (
        all_of(leaf("computer", "ieq", computer), ATTR("source_partition", "eq", partition)),
        f"All events for asset {computer} in the corpus-native SIEM partition {partition}; no timestamp or record identifier is used.",
    )


def main() -> None:
    case_dirs = {
        load(path)["case_id"]: path.parent.parent
        for path in STUDY.glob("cases/*/*/build/case.json")
    }
    if set(case_dirs) != set(RULES):
        raise SystemExit(
            f"rule inventory mismatch: missing={sorted(set(case_dirs)-set(RULES))}, "
            f"extra={sorted(set(RULES)-set(case_dirs))}"
        )
    validate_case_inventory(case_dirs)

    for case_id, case_dir in sorted(case_dirs.items()):
        config = load(case_dir / "build/case.json")
        source = source_record(case_dir)
        rule = RULES[case_id]
        classification = classification_for(case_id)
        is_windows = config.get("source_file", "").endswith("combined.csv")
        scope: dict[str, Any] = {
            "basis": "declared_asset_scope" if is_windows else "source_defined_step",
            "complete_legal_scope": True,
            "description": "Every record in the corpus-provided log member or scenario step containing the alert stream.",
        }
        if is_windows:
            scope_filter, description = windows_scope(source)
            scope["filter_predicate"] = scope_filter
            scope["description"] = description
        else:
            scope["source_units"] = [rule["source_unit"]]

        selection = {"strategy": rule.get("selection", "earliest_match")}
        if rule.get("selection_justification"):
            selection["justification"] = rule["selection_justification"]
        spec = {
            "schema_version": "1.0",
            "case_id": case_id,
            "rule_id": f"SAFESOC-TRG-{case_id}",
            **classification,
            "title": rule["title"],
            "formalisation_timing": "prospective_pre_model",
            "rule_origin": {
                "type": "project_analytic",
                "reference": "external_replication_v1 pre-model alert-anchor review under policy v1.0",
            },
            "scope": scope,
            "event_predicate": rule["predicate"],
            "selection": selection,
            "expected_a0": {"record_key": expected_key(config, source)},
            "rationale": rule["rationale"],
        }
        if rule.get("aggregation"):
            spec["aggregation"] = rule["aggregation"]
        target = case_dir / "annotations/trigger_spec.json"
        target.write_text(json.dumps(spec, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
        print(f"wrote {target.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
