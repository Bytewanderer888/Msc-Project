#!/usr/bin/env python3
"""One-time migration that standardizes the 41 canonical case records.

This migration changes researcher-only configuration and annotation metadata. It
does not edit model_input/alert_package.json.
"""

from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]

PROPOSITIONS = {
    "GPO-001": "The observed machine-account SYSVOL reads are adversary-driven SMB reconnaissance or lateral activity rather than routine Group Policy processing.",
    "PS-003": "The obfuscated PowerShell and LSASS-access events are credential-dumping activity rather than a benign test command with ordinary Windows process access.",
    "EVL-001": "The EventLog startup-type registry change caused Windows event logging to become disabled in the retained source window.",
    "ING-002": "The object staged by the observed LOLBin transfer activity subsequently executed.",
    "LOGON-001": "The selected final UserInitMprLogonScript configuration executed its configured target after A0.",
    "ST-001": "The observed scheduled-task creation requests produced a task action that fired in the retained Sysmon window.",
    "LS-003": "Task Manager obtained dump-capable access to LSASS and wrote an LSASS memory dump.",
    "PS-004": "The observed SharpHound execution produced a substantial Active Directory collection artifact set.",
    "RUN-001": "Rundll32 executed a masqueraded DLL-like object through a non-standard export and made an associated outbound connection.",
    "SMB-001": "The observed host executed Impacket-style WMI and service command chains with SYSTEM-level code execution.",
    "SVC-001": "A newly created or hijacked service mechanism executed a non-system binary under services.exe as SYSTEM.",
    "UQP-001": "An unquoted service path was intercepted so that C:\\program.exe executed under services.exe as SYSTEM.",
    "WMI-001": "A complete WMI event-subscription persistence mechanism with an offensively meaningful consumer command was installed.",
    "BF-002": "The rapid multi-username NTLM failure burst is adversary-driven credential spraying.",
    "COL-001": "The observed archive creation is adversary-driven collection activity.",
    "CRED-001": "The observed AutoLogon registry writes are adversary-driven credential exposure or theft.",
    "DISC-001": "The observed domain-account enumeration is adversary-driven reconnaissance.",
    "DISC-003": "The observed local-account enumeration is adversary-driven reconnaissance.",
    "DISC-004": "The isolated Internet Explorer version query is adversary-driven reconnaissance.",
    "OD-001": "A high-integrity destructive and anti-forensic command sequence was launched, including a confirmed Security-log clear.",
}

ATTACK_CATEGORY_DEFAULTS = {
    "RDL-001": {
        "category": "Routine WebDAV access via rundll32 and davclnt",
        "candidate_attack_mapping": "T1218.011",
        "model_visible": False,
        "note": "RESEARCHER-INTENT: evidence_condition = COUNTER. The signed rundll32/davclnt command is repeated with the same Microsoft OneDrive WebDAV endpoint and no offensive follow-on. The routine endpoint and repeated identical activity are decisive benign context. Do not leak to model.",
    },
    "GPO-001": {
        "category": "Routine machine-account SYSVOL Group Policy processing",
        "candidate_attack_mapping": "T1021.002 (surface only)",
        "model_visible": False,
        "note": "RESEARCHER-INTENT: evidence_condition = COUNTER. Machine-account read access to the two default Group Policy objects can resemble SMB reconnaissance, but the subjects, targets, and read-only pattern establish routine Group Policy processing. Do not leak to model.",
    },
    "RTLO-001": {
        "category": "Right-to-left override masquerading and execution",
        "candidate_attack_mapping": "T1036.002",
        "model_visible": False,
        "note": "RESEARCHER-INTENT: evidence_condition = STRONG. The masqueraded screen-saver executable runs, opens an outbound connection, and spawns command shells. The benign-looking filename must not cause under-triage. Do not leak to model.",
    },
    "UAC-001": {
        "category": "sdclt-based UAC bypass",
        "candidate_attack_mapping": "T1548.002",
        "model_visible": False,
        "note": "RESEARCHER-INTENT: evidence_condition = STRONG. The registry hijack and sdclt process chain establish the bypass mechanism and elevated execution. Do not leak to model.",
    },
    "RUN-001": {
        "category": "Rundll32 execution of a masqueraded DLL-like object",
        "candidate_attack_mapping": "T1218.011",
        "model_visible": False,
        "note": "RESEARCHER-INTENT: evidence_condition = STRONG. Rundll32 loads a .lock-named object through a non-standard export and the same process makes an outbound connection. The file-create event does not prove a network download, and the connection alone is not labelled confirmed C2. Do not leak to model.",
    },
    "WMI-001": {
        "category": "WMI event-subscription persistence",
        "candidate_attack_mapping": "T1546.003",
        "model_visible": False,
        "note": "RESEARCHER-INTENT: evidence_condition = STRONG. Native WMI telemetry records the filter, offensively meaningful command-line consumer, and binding as created. Installation of the complete mechanism is decisive even without a later firing event. Do not leak to model.",
    },
}

EXPERIMENTAL_ROLE_DEFAULTS = {
    "RDL-001": {"used_for": ["counter_evidence_exemplar", "cross_corpus_generalisation", "signed_binary_benign_twin"], "eligible_for_final_heldout_metrics": False},
    "GPO-001": {"used_for": ["counter_evidence_heldout", "cross_corpus_generalisation", "routine_gpo_false_positive"], "eligible_for_final_heldout_metrics": True},
    "RTLO-001": {"used_for": ["subtle_strong_exemplar", "cross_corpus_generalisation", "severity_preservation_test"], "eligible_for_final_heldout_metrics": False},
    "UAC-001": {"used_for": ["subtle_strong_exemplar", "cross_corpus_generalisation", "severity_preservation_test"], "eligible_for_final_heldout_metrics": False},
    "RUN-001": {"used_for": ["subtle_strong_heldout", "cross_corpus_generalisation", "severity_preservation_test"], "eligible_for_final_heldout_metrics": True},
    "WMI-001": {"used_for": ["wmi_strong_heldout", "cross_corpus_generalisation", "bidirectional_up_rank_test"], "eligible_for_final_heldout_metrics": True},
}

ROLE_DEFAULTS = {
    "RDL-001": {
        "944437": "triggering alert: signed rundll32 invokes davclnt DavSetCookie for a Microsoft OneDrive WebDAV endpoint",
        "944543": "a second identical rundll32/davclnt invocation provides the repeated routine-access context",
    },
    "SMB-002": {
        "security:309958": "triggering alert: machine-account IPC$ lsarpc access that can resemble directory reconnaissance",
        "security:310058": "the same machine account reads the SYSVOL root, consistent with Group Policy processing",
        "security:310068": "machine-account read of the Default Domain Policy gpt.ini",
        "security:310069": "machine-account read of the Default Domain Controllers Policy gpt.ini",
        "security:310079": "repeated machine-account IPC$ lsarpc access",
        "security:310080": "repeated machine-account IPC$ lsarpc access",
        "security:310081": "repeated machine-account IPC$ lsarpc access",
        "security:310082": "repeated machine-account IPC$ lsarpc access",
    },
    "GPO-001": {
        "151026": "triggering alert: machine-account read access to the SYSVOL Policies path",
        "146551": "machine-account read of the Default Domain Policy gpt.ini",
        "146552": "machine-account read of the Default Domain Controllers Policy gpt.ini",
        "151027": "same-session machine-account read of the domain SYSVOL path",
    },
    "RTLO-001": {
        "346422": "triggering alert: a right-to-left-override screen-saver executable runs from ProgramData",
        "346533": "the masqueraded process initiates an outbound TCP connection",
        "346562": "the masqueraded process spawns cmd.exe",
        "346599": "the masqueraded process also spawns PowerShell",
    },
    "RUN-001": {
        "1000064": "triggering alert: rundll32 loads a .lock-named object through the non-standard VoidFunc export",
        "773293": "certutil creates the .lock-named object; this does not establish a network download",
        "1001598": "the same rundll32 process initiates an outbound connection consistent with a callback, not by itself proof of C2",
    },
    "WMI-001": {
        "790795": "triggering alert: a command-line WMI event consumer with an encoded PowerShell destination is created",
        "790794": "the matching WMI event filter is created",
        "790982": "the filter-to-consumer binding completes the installed WMI subscription mechanism",
    },
}


def ordered(source: dict, preferred: list[str]) -> dict:
    return {key: source[key] for key in preferred if key in source} | {
        key: value for key, value in source.items() if key not in preferred
    }


def update_semantic_metadata(case_id: str, metadata: dict, config: dict) -> None:
    if case_id == "AMQ-001":
        metadata["attack_category"]["category"] = "ActiveMQ RCE foothold with multi-sensor corroboration"
    elif case_id == "PS-004":
        metadata["attack_category"]["note"] = (
            "RESEARCHER-INTENT: evidence_condition = STRONG. SharpHound executes on a domain controller "
            "and produces the expected JSON and ZIP collection artifacts. The package does not contain "
            "an exit status, so it does not claim error-free completion. Do not leak to model."
        )
        metadata["curation_notes"][0]["note"] = (
            "RESEARCHER-PRIVATE: STRONG and under-triage-prone. SharpHound execution plus the attributed "
            "JSON/ZIP artifact set establishes substantial AD collection; an exit status is not present."
        )
        for key, value in list(config["roles"].items()):
            config["roles"][key] = value.replace("all AD ", "AD ").replace("full AD collection", "broad AD collection")
    elif case_id == "RUN-001":
        metadata["curation_notes"] = [
            "Subtle-strong (up-rank): signed rundll32 launched from explorer invites under-triage as routine system activity.",
            "Rundll32 loads a .lock-named object through VoidFunc and the same process opens an outbound connection. The file-create event does not prove network download, and the connection is consistent with a callback rather than labelled confirmed C2.",
        ]
    elif case_id == "SMB-001":
        metadata["attack_category"] = {
            "category": "Impacket-style WMI and service execution on the observed host",
            "candidate_attack_mapping": "T1021.002-style execution surface",
            "model_visible": False,
            "note": "RESEARCHER-INTENT: evidence_condition = STRONG. Two Impacket-style WMI and service command chains establish SYSTEM-level code execution on the observed host. The SMB paths are loopback and no distinct source host is identified, so cross-host lateral movement is not claimed. Do not leak to model.",
        }
        metadata["curation_notes"] = [
            {"topic": "strong_intent", "event_record_id": "", "note": "RESEARCHER-PRIVATE: STRONG / preserve. Correlated WMI- and service-based Impacket-style execution patterns establish code execution on the observed host; loopback paths do not prove cross-host movement."},
            {"topic": "preserve_bait_benign_payload", "event_record_id": "117769,117770", "note": "The payload is calc.exe, but the WMI-to-command execution pattern remains security-significant. The benign demonstration payload must not cause under-triage."},
            {"topic": "impacket_signatures", "event_record_id": "117769,117785", "note": "The package contains wmiexec- and smbexec-style command patterns using loopback ADMIN$/C$ paths. These identify the execution mechanism but not a separate remote source host."},
            {"topic": "single_source_superset", "event_record_id": "", "note": "The selected Sysmon file is the superset on one observed host; the sibling smbexec file is a strict subset."},
        ]
        for key, value in list(config["roles"].items()):
            value = value.replace("remote-shell", "wmiexec-style command")
            value = value.replace("remotely-issued payload", "command-chain payload")
            value = value.replace("SMB service-based remote execution", "smbexec-style service execution")
            config["roles"][key] = value
    elif case_id == "CRED-001":
        metadata["attack_category"]["note"] = (
            "RESEARCHER-INTENT: evidence_condition = WEAK. AutoLogon username and password values are "
            "written to Winlogon. A later event shows DefaultPassword deletion, but deletion of "
            "DefaultUserName is not evidenced. No read, use, exfiltration, or authentication follow-on is "
            "observed. Intent remains ambiguous. Do not leak to model."
        )
        metadata["curation_notes"] = [
            {"topic": "weak_creds", "note": "WEAK / over-triage-prone: AutoLogon values are written and DefaultPassword is later deleted; no read, use, exfiltration, or authentication follow-on is evidenced."}
        ]
    elif case_id == "OD-001":
        metadata["attack_category"]["note"] = (
            "RESEARCHER-INTENT: evidence_condition = STRONG (Tier-2 fusion). Sysmon records high-integrity "
            "vssadmin, bcdedit, and wevtutil command invocations; Security Event 1102 independently confirms "
            "that the Security audit log was cleared and identifies the account. Success of shadow-copy "
            "deletion, BCD changes, and System-log clearing is not asserted without result telemetry. Do not leak to model."
        )
        metadata["curation_notes"][0]["note"] = (
            "RESEARCHER-PRIVATE: STRONG / preserve (Tier-2). The destructive and anti-forensic command burst "
            "is corroborated by a confirmed Security-log clear; other requested outcomes remain bounded."
        )
        config["roles"] = {
            "sysmon:290147": "triggering alert: vssadmin delete shadows /all /quiet is launched; deletion success is not independently recorded",
            "sysmon:290231": "bcdedit is launched to request bootstatuspolicy ignoreallfailures; result status is absent",
            "sysmon:290240": "bcdedit is launched to request recoveryenabled no; result status is absent",
            "sysmon:290266": "wevtutil cl System is launched; System-log clear success is not independently recorded",
            "sysmon:290300": "wevtutil cl Security is launched at the time of the corroborating Security 1102 event",
            "security:324614": "Security Event 1102 confirms that the audit log was cleared and names the account",
        }


def migrate_config(path: Path) -> None:
    config = json.loads(path.read_text(encoding="utf-8"))
    case_dir = path.parent.parent
    split = case_dir.parent.name
    case_id = config["case_id"]
    metadata = config.setdefault("metadata", {})

    config["split"] = split
    config.setdefault("roles", {})
    config.setdefault("derivations", [])
    if case_id in ROLE_DEFAULTS:
        config["roles"] = ROLE_DEFAULTS[case_id]

    metadata["case_directory"] = case_dir.name
    metadata["status"] = f"audited_{split}_2026-07-16"
    metadata["security_proposition"] = metadata.get("security_proposition") or PROPOSITIONS.get(case_id, "")
    metadata["created_date"] = metadata.get("created_date") or ("2026-07-06" if "mordor_log" in config else "2026-07-05")
    metadata["review_status"] = "reviewed_for_benchmark_v1.1"
    metadata["review_required"] = {"ground_truth": "Ground truth reviewed and frozen under benchmark rubric v1.1."}
    if "reclassified" in metadata:
        note = metadata.pop("reclassified")
        metadata.setdefault("curation_notes", []).append({"topic": "annotation_history", "note": note})
    if not metadata.get("attack_category") and case_id in ATTACK_CATEGORY_DEFAULTS:
        metadata["attack_category"] = ATTACK_CATEGORY_DEFAULTS[case_id]
    if not metadata.get("experimental_role") and case_id in EXPERIMENTAL_ROLE_DEFAULTS:
        metadata["experimental_role"] = EXPERIMENTAL_ROLE_DEFAULTS[case_id]

    update_semantic_metadata(case_id, metadata, config)
    selected_ids = [config["selection"]["A0"], *config["selection"]["EV"]]
    for selected_id in selected_ids:
        config["roles"].setdefault(
            selected_id,
            "additional correlated event retained by the fixed selection",
        )

    required_metadata = (
        "case_name", "security_proposition", "case_directory", "status", "dataset",
        "created_date", "attack_category", "tier", "case_scope", "curation_notes",
        "experimental_role", "review_status", "review_required",
    )
    missing = [key for key in required_metadata if not metadata.get(key)]
    if missing:
        raise ValueError(f"{case_id}: missing canonical metadata: {missing}")

    config["metadata"] = ordered(metadata, [
        "case_name", "security_proposition", "case_directory", "status", "dataset",
        "stored_filename", "created_date", "attack_category", "tier", "splunk",
        "case_scope", "main_alert_selection", "correlation_keys", "event_groups",
        "curation_notes", "experimental_role", "review_status", "review_required",
    ])
    config = ordered(config, [
        "case_id", "split", "source_log", "mordor_log", "sources", "computer",
        "staged_export", "sourcetypes_present", "selection", "roles", "derivations",
        "model_visible_attribute_exclusions", "model_visible_literal_redactions", "metadata",
    ])
    path.write_text(json.dumps(config, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def migrate_ground_truth(path: Path) -> None:
    gt = json.loads(path.read_text(encoding="utf-8"))
    gt["review_status"] = "reviewed_for_benchmark_v1.1"
    gt = ordered(gt, [
        "case_id", "evidence_condition", "calibration_role", "correct_verdict",
        "acceptable_severity", "acceptable_actions", "grounding", "the_trap",
        "rationale", "annotated_by", "review_status", "rubric_version",
    ])
    path.write_text(json.dumps(gt, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def main() -> None:
    configs = sorted(ROOT.glob("tier*/**/build/case.json"))
    ground_truths = sorted(ROOT.glob("tier*/**/annotations/ground_truth.json"))
    if len(configs) != 41 or len(ground_truths) != 41:
        raise SystemExit(f"expected 41 configs and GTs, found {len(configs)} and {len(ground_truths)}")
    for path in configs:
        migrate_config(path)
    for path in ground_truths:
        migrate_ground_truth(path)
    print("standardized 41 case configs and 41 ground-truth records")


if __name__ == "__main__":
    main()
