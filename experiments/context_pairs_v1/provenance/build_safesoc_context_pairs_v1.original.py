#!/usr/bin/env python3
"""Build four blinded Weak-to-Counter context-reveal pairs in a temporary directory.

The frozen 41-case benchmark is never modified.  Each pair retains an alarming
surface and reveals source-backed benign context only in the Counter version.

Publication note: machine-specific root and temporary paths in the API-time script
were replaced with portable equivalents. RUN_CONFIG.json preserves its API-time SHA.
"""

from __future__ import annotations

import copy
import hashlib
import json
import shutil
import tempfile
from pathlib import Path

import jsonschema


ROOT = Path(__file__).resolve().parents[3]
OUT = Path(tempfile.gettempdir()) / "safesoc_context_pairs_v1"
PACKAGE_DIR = OUT / "packages"

POLICY = {
    "weak": {
        "verdict": ["suspicious"],
        "severity": ["low", "medium"],
        "action": ["monitor", "investigate"],
    },
    "counter": {
        "verdict": ["benign"],
        "severity": ["informational", "low"],
        "action": ["close_benign", "monitor"],
    },
}

SPECS = [
    {
        "pair_id": "CC1",
        "source_case": "DISC-002",
        "source": "tier1/counter/dev/DISC-002_wmic_system_discovery/model_input/alert_package.json",
        "weak_id": "QC-418",
        "counter_id": "QC-763",
        "operation": "remove_parent_provenance",
        "context_fields": ["parent_process_guid", "parent_process_id", "parent_image", "parent_command_line"],
        "security_proposition": "The rapid WMIC inventory burst represents adversary discovery rather than routine system management.",
        "context_intervention": "Reveal that every unchanged WMIC query was spawned by the Amazon SSM management agent.",
        "required_context_terms": ["SSM"],
        "construct_note": "Same four events and commands in both versions; only parent provenance is hidden in Weak.",
    },
    {
        "pair_id": "CC2",
        "source_case": "RDL-001",
        "source": "tier1/counter/dev/RDL-001_webdav_rundll32_legit/model_input/alert_package.json",
        "weak_id": "QC-205",
        "counter_id": "QC-891",
        "operation": "reveal_webdav_provenance",
        "security_proposition": "The rundll32 process using an external HTTPS URL represents malicious LOLBin execution.",
        "context_intervention": "Reveal the System32 davclnt.dll DavSetCookie command, WebClient service parent, and Microsoft OneDrive destination.",
        "required_context_terms": ["davclnt", "WebClient", "d.docs.live.net"],
        "construct_note": "One source event in both versions; Weak preserves rundll32 plus an external HTTPS surface while benign-specific command and parent details are redacted.",
    },
    {
        "pair_id": "CC3",
        "source_case": "SMB-002",
        "source": "tier1/counter/dev/SMB-002_routine_domain_smb/model_input/alert_package.json",
        "weak_id": "QC-674",
        "counter_id": "QC-132",
        "operation": "reveal_machine_gpo_context",
        "security_proposition": "The repeated IPC$ lsarpc accesses represent adversary-driven domain reconnaissance.",
        "context_intervention": "Reveal the domain-machine-account provenance and same-session default Group Policy reads.",
        "required_context_terms": ["SYSVOL", "gpt.ini", "machine account"],
        "construct_note": "Weak retains all five IPC$/lsarpc observations but with actor/network provenance withheld; Counter restores provenance and the three GPO reads.",
    },
    {
        "pair_id": "CC4",
        "source_case": "PS-003",
        "source": "tier1/counter/heldout/PS-003_obfuscated_powershell/model_input/alert_package.json",
        "weak_id": "QC-957",
        "counter_id": "QC-346",
        "operation": "reveal_benign_command_semantics",
        "security_proposition": "The obfuscated PowerShell expression piped to ieX executes malicious code.",
        "context_intervention": "Reveal the source-backed expression and deterministic reconstruction showing only Write-Host 'Hello, World!'.",
        "required_context_terms": ["DER-001", "Hello, World"],
        "construct_note": "One process event in both versions; Weak preserves an obfuscated ieX surface while payload fragments are redacted, and Counter restores the original source text plus DER-001.",
    },
]


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def all_events(package: dict) -> list[dict]:
    return [package["main_alert"], *package.get("evidence_items", [])]


def event_map(package: dict) -> dict[str, dict]:
    return {event["evidence_id"]: event for event in all_events(package)}


def normalize_selected(source: dict, source_ids: list[str], neutral_id: str) -> tuple[dict, dict[str, str]]:
    by_id = event_map(source)
    unknown = set(source_ids) - set(by_id)
    if unknown:
        raise ValueError(f"Unknown ids: {sorted(unknown)}")
    selected = [copy.deepcopy(by_id[source_id]) for source_id in source_ids]
    mapping = {}
    for index, event in enumerate(selected):
        new_id = "A0" if index == 0 else f"EV-{index:03d}"
        mapping[source_ids[index]] = new_id
        event["evidence_id"] = new_id
        if index == 0:
            event["is_triggering_alert"] = True
        else:
            event.pop("is_triggering_alert", None)

    package = {
        "schema_version": source["schema_version"],
        "case_id": neutral_id,
        "package_type": source["package_type"],
        "observed_context": {},
        "main_alert": selected[0],
        "evidence_items": selected[1:],
        "deterministic_derivations": [],
    }
    return package, mapping


def context_for(events: list[dict]) -> dict:
    users = set()
    channels = set()
    for event in events:
        attributes = event.get("attributes", {})
        if attributes.get("user"):
            users.add(attributes["user"])
        elif attributes.get("subject_user_name"):
            domain = attributes.get("subject_domain_name")
            users.add(f"{domain}\\{attributes['subject_user_name']}" if domain else attributes["subject_user_name"])
        channels.add(event["source_event"]["channel"])
    times = [event["event_time_utc"] for event in events]
    return {
        "computers": sorted({event["computer"] for event in events}),
        "users": sorted(users),
        "time_window_utc": {"start": min(times), "end": max(times)},
        "event_count": len(events),
        "event_types_present": sorted({event["event_type"] for event in events}),
        "sourcetypes_present": sorted(channels),
    }


def finish_package(package: dict) -> dict:
    result = copy.deepcopy(package)
    result["observed_context"] = context_for(all_events(result))
    return result


def build_disc(source: dict, spec: dict) -> tuple[dict, dict]:
    counter = copy.deepcopy(source)
    counter["case_id"] = spec["counter_id"]
    weak = copy.deepcopy(counter)
    weak["case_id"] = spec["weak_id"]
    for event in all_events(weak):
        for field in spec["context_fields"]:
            event.get("attributes", {}).pop(field, None)
    return finish_package(weak), finish_package(counter)


def build_rdl(source: dict, spec: dict) -> tuple[dict, dict]:
    counter, _ = normalize_selected(source, ["A0"], spec["counter_id"])
    weak = copy.deepcopy(counter)
    weak["case_id"] = spec["weak_id"]
    attributes = weak["main_alert"]["attributes"]
    attributes["command_line"] = (
        "rundll32.exe [redacted-module],[redacted-export] "
        "https://[redacted-external-host]/[redacted-resource]"
    )
    for field in ("parent_process_guid", "parent_process_id", "parent_image", "parent_command_line"):
        attributes.pop(field, None)
    return finish_package(weak), finish_package(counter)


def build_smb(source: dict, spec: dict) -> tuple[dict, dict]:
    counter = copy.deepcopy(source)
    counter["case_id"] = spec["counter_id"]
    weak_source_ids = ["A0", "EV-004", "EV-005", "EV-006", "EV-007"]
    weak, _ = normalize_selected(source, weak_source_ids, spec["weak_id"])
    for event in all_events(weak):
        attributes = event.get("attributes", {})
        for field in ("subject_user_name", "subject_domain_name", "ip_address", "ip_port"):
            attributes.pop(field, None)
    return finish_package(weak), finish_package(counter)


def build_ps(source: dict, spec: dict) -> tuple[dict, dict]:
    counter, mapping = normalize_selected(source, ["A0"], spec["counter_id"])
    derivation = copy.deepcopy(source["deterministic_derivations"][0])
    derivation["source_evidence_id"] = mapping[derivation["source_evidence_id"]]
    counter["deterministic_derivations"] = [derivation]

    weak = copy.deepcopy(counter)
    weak["case_id"] = spec["weak_id"]
    weak["deterministic_derivations"] = []
    weak["main_alert"]["attributes"]["command_line"] = (
        "powershell.exe \"([redacted string-concatenation expression]) "
        ".Replace([redacted-token],[char]39) | ieX\""
    )
    return finish_package(weak), finish_package(counter)


BUILDERS = {
    "remove_parent_provenance": build_disc,
    "reveal_webdav_provenance": build_rdl,
    "reveal_machine_gpo_context": build_smb,
    "reveal_benign_command_semantics": build_ps,
}


def version_record(role: str, condition: str, package: dict, path: Path) -> dict:
    text = path.read_text(encoding="utf-8")
    return {
        "role": role,
        "neutral_case_id": package["case_id"],
        "path": str(path),
        "expected_condition": condition,
        "expected": POLICY[condition],
        "sha256": sha256_text(text),
        "utf8_bytes": len(text.encode("utf-8")),
        "event_count": package["observed_context"]["event_count"],
    }


def main() -> None:
    if OUT.exists():
        shutil.rmtree(OUT)
    PACKAGE_DIR.mkdir(parents=True)
    schema = load_json(ROOT / "tools/schema/alert_package.schema.json")
    pairs = []

    for spec in SPECS:
        source_path = ROOT / spec["source"]
        source_text = source_path.read_text(encoding="utf-8")
        source = json.loads(source_text)
        if source["case_id"] != spec["source_case"]:
            raise ValueError(f"Source mismatch for {spec['pair_id']}")
        weak, counter = BUILDERS[spec["operation"]](source, spec)
        weak_path = PACKAGE_DIR / f"{weak['case_id']}.json"
        counter_path = PACKAGE_DIR / f"{counter['case_id']}.json"
        weak_path.write_text(json.dumps(weak, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        counter_path.write_text(json.dumps(counter, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        jsonschema.validate(weak, schema)
        jsonschema.validate(counter, schema)

        pairs.append({
            "pair_id": spec["pair_id"],
            "pair_type": "benign_context_reveal",
            "source_case": spec["source_case"],
            "source_package": str(source_path),
            "source_sha256": sha256_text(source_text),
            "security_proposition": spec["security_proposition"],
            "sole_manipulated_factor": spec["context_intervention"],
            "operation": spec["operation"],
            "required_context_terms": spec["required_context_terms"],
            "construct_note": spec["construct_note"],
            "versions": [
                version_record("weak", "weak", weak, weak_path),
                version_record("counter", "counter", counter, counter_path),
            ],
        })

    manifest = {
        "record_schema": "safesoc.context_reveal_pairs.v1",
        "status": "scratch_protocol_frozen_before_model_run_not_part_of_frozen_benchmark",
        "repository_modified": False,
        "design_scope": "Weak-to-Counter context-reveal pairs; no outcome evidence is manipulated.",
        "primary_endpoint": "Both versions enter their predeclared target bands and the Counter decision is no more aggressive than Weak.",
        "secondary_endpoints": [
            "Counter rationale explicitly uses the revealed benign context",
            "Confidence change is exploratory only",
        ],
        "important_scope_note": "These are source-derived context ablations, not four-condition variants of the Outcome scenarios.",
        "intervention_subtypes_fixed_before_run": {
            "CC1": "parent-provenance field reveal",
            "CC2": "benign command and service-parent reveal",
            "CC3": "actor-provenance plus same-session GPO-context reveal",
            "CC4": "benign command-semantics plus deterministic-derivation reveal",
        },
        "selection_rule": "All four pairs and their Weak/Counter target bands are fixed before viewing any v1 model output and must not be changed in response to results.",
        "package_count": len(list(PACKAGE_DIR.glob("*.json"))),
        "pair_count": len(pairs),
        "pairs": pairs,
    }
    manifest_path = OUT / "manifest.private.json"
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"built {manifest['package_count']} packages / {manifest['pair_count']} pairs")
    print(f"packages: {PACKAGE_DIR}")
    print(f"private manifest: {manifest_path}")


if __name__ == "__main__":
    main()
