#!/usr/bin/env python3
"""Zero-token, ground-truth-free policy validator for SafeSOC triage outputs.

The runtime component reads only a neutral alert package, an LLM output, and a
generic policy. It detects observable contract violations and can route
high-consequence decisions for human review. It does not infer benchmark labels
or claim that a policy pass is factually correct.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

try:
    from jsonschema import Draft7Validator
except ImportError as exc:  # pragma: no cover - environment failure path
    raise SystemExit("runtime_validator.py requires the 'jsonschema' package") from exc


VERSION = "1.2"
SUPPORTED_POLICY_VERSIONS = {"1.0", "1.1", "1.2"}
HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
DEFAULT_POLICY = HERE / "runtime_policy_v1.1.json"
PACKAGE_SCHEMA = ROOT / "tools/schema/alert_package.schema.json"
OUTPUT_SCHEMA = HERE / "llm_output.schema.json"
EVIDENCE_ID_RE = re.compile(r"\b(?:A0|EV-\d{3}|DER-\d{3})\b", re.IGNORECASE)
RUNTIME_STATUSES = ("pass", "review", "block")
FINDING_CODES = {
    f"R{number:03d}_{suffix}"
    for number, suffix in (
        (0, "PACKAGE_SCHEMA_INVALID"),
        (1, "OUTPUT_SCHEMA_INVALID"),
        (2, "CASE_ID_MISMATCH"),
        (3, "MAIN_ALERT_ID_INVALID"),
        (4, "DUPLICATE_PACKAGE_EVIDENCE_ID"),
        (5, "PACKAGE_EVENT_COUNT_MISMATCH"),
        (6, "INVALID_DERIVATION_SOURCE"),
        (7, "DUPLICATE_KEY_EVIDENCE_ID"),
        (8, "INVALID_KEY_EVIDENCE_ID"),
        (9, "INVALID_RATIONALE_EVIDENCE_ID"),
        (10, "RATIONALE_MISSING_EVIDENCE_REFERENCE"),
        (11, "RATIONALE_KEY_EVIDENCE_DISCONNECT"),
        (12, "DERIVATION_CLAIM_WITHOUT_DERIVATION"),
        (13, "DECISION_PROFILE_MISMATCH"),
    )
}


class RuntimeValidationError(RuntimeError):
    """Raised when the runtime harness cannot safely evaluate its inputs."""


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def load_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeValidationError(f"cannot read valid JSON from {path}: {exc}") from exc


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def relative(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(ROOT))
    except ValueError:
        return str(path.resolve())


def schema_errors(instance: object, schema: dict) -> list[str]:
    validator = Draft7Validator(schema)
    errors = []
    for error in sorted(validator.iter_errors(instance), key=lambda item: list(item.absolute_path)):
        where = ".".join(str(part) for part in error.absolute_path) or "<root>"
        errors.append(f"{where}: {error.message}")
    return errors


def load_policy(path: Path = DEFAULT_POLICY) -> dict:
    policy = load_json(path)
    required = {
        "record_schema",
        "policy_version",
        "decision_profiles",
        "decode_claims",
        "signals",
        "routing_profiles",
        "default_profile",
        "non_claims",
    }
    missing = sorted(required - set(policy))
    if missing:
        raise RuntimeValidationError(f"runtime policy is missing fields: {missing}")
    if policy["policy_version"] not in SUPPORTED_POLICY_VERSIONS:
        raise RuntimeValidationError(
            "unsupported runtime policy version "
            f"{policy['policy_version']!r}; supported={sorted(SUPPORTED_POLICY_VERSIONS)}"
        )
    finding_levels = policy.get("finding_levels", {})
    invalid_levels = {
        code: level for code, level in finding_levels.items() if level not in {"block", "review"}
    }
    if invalid_levels:
        raise RuntimeValidationError(f"runtime policy has invalid finding levels: {invalid_levels}")
    if policy["policy_version"] in {"1.1", "1.2"} and set(finding_levels) != FINDING_CODES:
        raise RuntimeValidationError(
            f"runtime policy v{policy['policy_version']} must define every finding level exactly: "
            f"missing={sorted(FINDING_CODES - set(finding_levels))}, "
            f"unknown={sorted(set(finding_levels) - FINDING_CODES)}"
        )
    if policy["default_profile"] not in policy["routing_profiles"]:
        raise RuntimeValidationError("runtime policy default_profile is undefined")
    signal_ids = set(policy["signals"])
    for name, profile in policy["routing_profiles"].items():
        unknown = sorted(set(profile.get("review_on", [])) - signal_ids)
        if unknown:
            raise RuntimeValidationError(f"routing profile {name!r} references unknown signals: {unknown}")
    return policy


def package_ids(package: dict) -> set[str]:
    ids = {package["main_alert"]["evidence_id"].upper()}
    ids.update(item["evidence_id"].upper() for item in package["evidence_items"])
    ids.update(
        item["derivation_id"].upper()
        for item in package.get("deterministic_derivations", [])
        if item.get("derivation_id")
    )
    return ids


def rationale_ids(rationale: str) -> set[str]:
    return {match.group(0).upper() for match in EVIDENCE_ID_RE.finditer(rationale)}


def finding(code: str, message: str, level: str = "block", **details: object) -> dict:
    row = {"code": code, "level": level, "message": message}
    if details:
        row["details"] = details
    return row


def signal_matches(specification: dict, output: dict) -> bool:
    matches = []
    for output_key, policy_key in (
        ("verdict", "verdicts"),
        ("severity", "severities"),
        ("recommended_action", "actions"),
    ):
        allowed = specification.get(policy_key, [])
        if allowed:
            matches.append(output[output_key] in allowed)
    return any(matches)


def finding_level(policy: dict, code: str) -> str:
    """Return the configured level; v1.0 policies default every finding to block."""
    return policy.get("finding_levels", {}).get(code, "block")


def split_findings(findings: list[dict]) -> tuple[list[dict], list[dict]]:
    hard = [item for item in findings if item["level"] == "block"]
    review = [item for item in findings if item["level"] == "review"]
    return hard, review


def apply_finding_levels(policy: dict, findings: list[dict]) -> None:
    for item in findings:
        item["level"] = finding_level(policy, item["code"])


def profile_outcomes(policy: dict, findings: list[dict], signals: list[dict]) -> dict:
    available_signals = {item["code"] for item in signals}
    hard_findings, review_findings = split_findings(findings)
    outcomes = {}
    for name, profile in policy["routing_profiles"].items():
        active_signals = sorted(available_signals & set(profile["review_on"]))
        if hard_findings:
            status = "block"
            reasons = [item["code"] for item in hard_findings]
        elif review_findings or active_signals:
            status = "review"
            reasons = [item["code"] for item in review_findings] + active_signals
        else:
            status = "pass"
            reasons = []
        outcomes[name] = {
            "status": status,
            "requires_human_review": status != "pass",
            "reasons": reasons,
        }
    return outcomes


def validate_runtime_case(
    package: dict,
    output: dict,
    policy: dict,
    package_schema: dict,
    output_schema: dict,
    expected_case_id: str | None = None,
) -> dict:
    """Validate one package/output pair without reading benchmark ground truth."""
    findings = []
    package_schema_errors = schema_errors(package, package_schema)
    output_schema_errors = schema_errors(output, output_schema)
    if package_schema_errors:
        findings.append(
            finding(
                "R000_PACKAGE_SCHEMA_INVALID",
                "The alert package does not satisfy its runtime schema.",
                errors=package_schema_errors,
            )
        )
    if output_schema_errors:
        findings.append(
            finding(
                "R001_OUTPUT_SCHEMA_INVALID",
                "The LLM output does not satisfy its runtime schema.",
                errors=output_schema_errors,
            )
        )

    # Fail closed before field-level checks if either input lacks the required shape.
    if findings:
        apply_finding_levels(policy, findings)
        hard_findings, review_findings = split_findings(findings)
        outcomes = profile_outcomes(policy, findings, [])
        return {
            "case_id": expected_case_id or package.get("case_id") or "unknown",
            "decision": {
                key: output.get(key) if isinstance(output, dict) else None
                for key in ("verdict", "severity", "confidence", "recommended_action")
            },
            "findings": findings,
            "hard_findings": hard_findings,
            "review_findings": review_findings,
            "signals": [],
            "profile_outcomes": outcomes,
        }

    case_id = package["case_id"]
    if expected_case_id and case_id != expected_case_id:
        findings.append(
            finding(
                "R002_CASE_ID_MISMATCH",
                "The package case id does not match the requested case.",
                expected=expected_case_id,
                actual=case_id,
            )
        )

    main_id = package["main_alert"]["evidence_id"].upper()
    event_ids = [main_id]
    event_ids.extend(item["evidence_id"].upper() for item in package["evidence_items"])
    derivation_ids = [
        item["derivation_id"].upper() for item in package.get("deterministic_derivations", [])
    ]
    all_ids = event_ids + derivation_ids
    duplicate_package_ids = sorted(
        evidence_id for evidence_id, count in Counter(all_ids).items() if count > 1
    )
    if main_id != "A0":
        findings.append(
            finding(
                "R003_MAIN_ALERT_ID_INVALID",
                "The triggering alert must use the stable evidence id A0.",
                actual=main_id,
            )
        )
    if duplicate_package_ids:
        findings.append(
            finding(
                "R004_DUPLICATE_PACKAGE_EVIDENCE_ID",
                "Evidence ids in the package must be unique.",
                evidence_ids=duplicate_package_ids,
            )
        )

    expected_event_count = 1 + len(package["evidence_items"])
    actual_event_count = package["observed_context"]["event_count"]
    if actual_event_count != expected_event_count:
        findings.append(
            finding(
                "R005_PACKAGE_EVENT_COUNT_MISMATCH",
                "The package event count does not match A0 plus its evidence items.",
                expected=expected_event_count,
                actual=actual_event_count,
            )
        )

    event_id_set = set(event_ids)
    invalid_derivation_sources = sorted(
        {
            item["source_evidence_id"].upper()
            for item in package.get("deterministic_derivations", [])
            if item["source_evidence_id"].upper() not in event_id_set
        }
    )
    if invalid_derivation_sources:
        findings.append(
            finding(
                "R006_INVALID_DERIVATION_SOURCE",
                "A deterministic derivation references evidence absent from the package.",
                evidence_ids=invalid_derivation_sources,
            )
        )

    valid_ids = package_ids(package)
    key_ids = [item.upper() for item in output["key_evidence"]]
    text_ids = rationale_ids(output["rationale"])
    duplicate_key_ids = sorted(
        evidence_id for evidence_id, count in Counter(key_ids).items() if count > 1
    )
    invalid_key_ids = sorted(set(key_ids) - valid_ids)
    invalid_rationale_ids = sorted(text_ids - valid_ids)
    if duplicate_key_ids:
        findings.append(
            finding(
                "R007_DUPLICATE_KEY_EVIDENCE_ID",
                "The output repeats an evidence id in key_evidence.",
                evidence_ids=duplicate_key_ids,
            )
        )
    if invalid_key_ids:
        findings.append(
            finding(
                "R008_INVALID_KEY_EVIDENCE_ID",
                "The output cites key evidence absent from the package.",
                evidence_ids=invalid_key_ids,
            )
        )
    if invalid_rationale_ids:
        findings.append(
            finding(
                "R009_INVALID_RATIONALE_EVIDENCE_ID",
                "The rationale cites evidence absent from the package.",
                evidence_ids=invalid_rationale_ids,
            )
        )
    if not text_ids:
        findings.append(
            finding(
                "R010_RATIONALE_MISSING_EVIDENCE_REFERENCE",
                "The rationale does not cite an explicit evidence id.",
                level=finding_level(policy, "R010_RATIONALE_MISSING_EVIDENCE_REFERENCE"),
            )
        )
    elif not (set(key_ids) & text_ids):
        findings.append(
            finding(
                "R011_RATIONALE_KEY_EVIDENCE_DISCONNECT",
                "The rationale does not cite any id listed as key evidence.",
                level=finding_level(policy, "R011_RATIONALE_KEY_EVIDENCE_DISCONNECT"),
                key_evidence=sorted(set(key_ids)),
                rationale_evidence=sorted(text_ids),
            )
        )

    rationale_lower = output["rationale"].lower()
    decode_claim = next(
        (phrase for phrase in policy["decode_claims"] if phrase in rationale_lower), None
    )
    if decode_claim and not package["deterministic_derivations"]:
        findings.append(
            finding(
                "R012_DERIVATION_CLAIM_WITHOUT_DERIVATION",
                "The rationale claims decoded content but the package has no deterministic derivation.",
                matched_phrase=decode_claim,
            )
        )

    decision_profile = policy["decision_profiles"][output["verdict"]]
    severity_ok = output["severity"] in decision_profile["severities"]
    action_ok = output["recommended_action"] in decision_profile["actions"]
    if not severity_ok or not action_ok:
        findings.append(
            finding(
                "R013_DECISION_PROFILE_MISMATCH",
                "Verdict, severity, and action are internally inconsistent under the runtime policy.",
                verdict=output["verdict"],
                severity=output["severity"],
                recommended_action=output["recommended_action"],
                allowed_severities=decision_profile["severities"],
                allowed_actions=decision_profile["actions"],
            )
        )

    signals = []
    for code, specification in policy["signals"].items():
        if signal_matches(specification, output):
            signals.append(
                {
                    "code": code,
                    "description": specification["description"],
                }
            )

    apply_finding_levels(policy, findings)
    hard_findings, review_findings = split_findings(findings)
    outcomes = profile_outcomes(policy, findings, signals)
    return {
        "case_id": case_id,
        "decision": {
            key: output[key]
            for key in ("verdict", "severity", "confidence", "recommended_action")
        },
        "findings": findings,
        "hard_findings": hard_findings,
        "review_findings": review_findings,
        "signals": signals,
        "profile_outcomes": outcomes,
    }


def discover_packages(split: str) -> dict[str, Path]:
    packages = {}
    duplicates = []
    for path in sorted(ROOT.glob(f"tier*/*/{split}/*/model_input/alert_package.json")):
        case_id = load_json(path)["case_id"]
        if case_id in packages:
            duplicates.append(case_id)
        packages[case_id] = path
    if duplicates:
        raise RuntimeValidationError(f"duplicate package ids in {split}: {sorted(set(duplicates))}")
    return packages


def evaluate_dataset(
    model: str,
    split: str,
    policy_path: Path = DEFAULT_POLICY,
    allow_incomplete: bool = False,
) -> dict:
    """Evaluate a saved model-output directory without loading annotations or GT."""
    policy = load_policy(policy_path)
    package_schema = load_json(PACKAGE_SCHEMA)
    output_schema = load_json(OUTPUT_SCHEMA)
    packages = discover_packages(split)
    output_dir = HERE / "outputs" / model / split
    if not output_dir.is_dir():
        raise RuntimeValidationError(f"model output directory does not exist: {output_dir}")
    outputs = {path.stem: path for path in output_dir.glob("*.json")}
    missing_outputs = sorted(set(packages) - set(outputs))
    orphan_outputs = sorted(set(outputs) - set(packages))
    if (missing_outputs or orphan_outputs) and not allow_incomplete:
        raise RuntimeValidationError(
            f"runtime completeness check failed: missing={missing_outputs}, orphan={orphan_outputs}"
        )

    rows = []
    for case_id in sorted(set(packages) & set(outputs)):
        package_path = packages[case_id]
        output_path = outputs[case_id]
        result = validate_runtime_case(
            load_json(package_path),
            load_json(output_path),
            policy,
            package_schema,
            output_schema,
            expected_case_id=case_id,
        )
        result["package_path"] = relative(package_path)
        result["package_sha256"] = sha256(package_path)
        result["output_path"] = relative(output_path)
        result["output_sha256"] = sha256(output_path)
        rows.append(result)

    profile_summary = {}
    for profile in policy["routing_profiles"]:
        statuses = Counter(row["profile_outcomes"][profile]["status"] for row in rows)
        review_n = statuses["review"] + statuses["block"]
        profile_summary[profile] = {
            "pass_n": statuses["pass"],
            "review_n": statuses["review"],
            "block_n": statuses["block"],
            "human_review_n": review_n,
            "human_review_rate": round(review_n / len(rows), 4) if rows else None,
        }

    return {
        "validator": "SafeSOC policy-based runtime validator",
        "validator_version": VERSION,
        "generated_utc": utc_now(),
        "model": model,
        "split": split,
        "policy_path": relative(policy_path),
        "policy_sha256": sha256(policy_path),
        "policy_version": policy["policy_version"],
        "default_profile": policy["default_profile"],
        "input_contract": "alert_package + LLM output only; no annotations or ground truth",
        "token_calls": 0,
        "completeness": {
            "expected_cases": len(packages),
            "evaluated_cases": len(rows),
            "missing_outputs": missing_outputs,
            "orphan_outputs": orphan_outputs,
            "complete": not missing_outputs and not orphan_outputs,
        },
        "summary": {
            "n": len(rows),
            "hard_failure_cases_n": sum(bool(row["hard_findings"]) for row in rows),
            "review_finding_cases_n": sum(bool(row["review_findings"]) for row in rows),
            "profiles": profile_summary,
        },
        "non_claims": policy["non_claims"],
        "cases": rows,
    }


def evaluate_single(package_path: Path, output_path: Path, policy_path: Path) -> dict:
    policy = load_policy(policy_path)
    result = validate_runtime_case(
        load_json(package_path),
        load_json(output_path),
        policy,
        load_json(PACKAGE_SCHEMA),
        load_json(OUTPUT_SCHEMA),
    )
    return {
        "validator": "SafeSOC policy-based runtime validator",
        "validator_version": VERSION,
        "generated_utc": utc_now(),
        "policy_path": relative(policy_path),
        "policy_sha256": sha256(policy_path),
        "policy_version": policy["policy_version"],
        "default_profile": policy["default_profile"],
        "input_contract": "alert_package + LLM output only; no annotations or ground truth",
        "token_calls": 0,
        "package_path": relative(package_path),
        "package_sha256": sha256(package_path),
        "output_path": relative(output_path),
        "output_sha256": sha256(output_path),
        "case": result,
        "non_claims": policy["non_claims"],
    }


def print_dataset_report(report: dict) -> None:
    print(
        f"=== runtime validator v{VERSION} on {report['model']} / {report['split']} "
        f"({report['summary']['n']}/{report['completeness']['expected_cases']} evaluated) ==="
    )
    profiles = list(report["summary"]["profiles"])
    print(
        f"{'case':9s} {'decision':29s} {'hard':4s} {'warn':4s} "
        + " ".join(f"{name:16.16s}" for name in profiles)
    )
    for case in report["cases"]:
        decision = case["decision"]
        decision_text = (
            f"{decision['verdict']}/{decision['severity']}/{decision['recommended_action']}"
        )
        statuses = " ".join(
            f"{case['profile_outcomes'][name]['status']:16.16s}" for name in profiles
        )
        print(
            f"{case['case_id']:9s} {decision_text:29.29s} "
            f"{len(case['hard_findings']):4d} {len(case['review_findings']):4d} {statuses}"
        )
    print("\n--- profile routing ---")
    for name, summary in report["summary"]["profiles"].items():
        print(
            f"  {name:18s} review={summary['human_review_n']}/{report['summary']['n']} "
            f"({summary['human_review_rate']:.1%}) block={summary['block_n']}"
        )
    print("  token calls: 0")


def write_json(report: dict, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")


def write_csv(report: dict, path: Path) -> None:
    profiles = list(report["summary"]["profiles"])
    fieldnames = [
        "case_id",
        "verdict",
        "severity",
        "confidence",
        "recommended_action",
        "hard_findings",
        "review_findings",
        "signals",
        *[f"status_{profile}" for profile in profiles],
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for case in report["cases"]:
            decision = case["decision"]
            row = {
                "case_id": case["case_id"],
                **decision,
                "hard_findings": "|".join(item["code"] for item in case["hard_findings"]),
                "review_findings": "|".join(
                    item["code"] for item in case["review_findings"]
                ),
                "signals": "|".join(item["code"] for item in case["signals"]),
            }
            row.update(
                {
                    f"status_{profile}": case["profile_outcomes"][profile]["status"]
                    for profile in profiles
                }
            )
            writer.writerow(row)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", default="gemini-2.5-flash__A2_evidence_prompt")
    parser.add_argument("--split", choices=("dev", "heldout"), default="dev")
    parser.add_argument("--policy", type=Path, default=DEFAULT_POLICY)
    parser.add_argument("--package", type=Path, help="single-package deployment mode")
    parser.add_argument("--output", type=Path, help="single-output deployment mode")
    parser.add_argument("--allow-incomplete", action="store_true")
    parser.add_argument("--json-out", type=Path)
    parser.add_argument("--csv-out", type=Path)
    args = parser.parse_args()

    try:
        if bool(args.package) != bool(args.output):
            raise RuntimeValidationError("--package and --output must be provided together")
        if args.package:
            report = evaluate_single(args.package, args.output, args.policy)
            case = report["case"]
            default = report["default_profile"]
            print(
                f"{case['case_id']}: {case['profile_outcomes'][default]['status']} "
                f"under {default}; hard_findings={len(case['hard_findings'])}; "
                f"review_findings={len(case['review_findings'])}"
            )
        else:
            report = evaluate_dataset(args.model, args.split, args.policy, args.allow_incomplete)
            print_dataset_report(report)
    except RuntimeValidationError as exc:
        raise SystemExit(str(exc)) from exc

    if args.json_out:
        write_json(report, args.json_out)
        print(f"wrote JSON report: {args.json_out}")
    if args.csv_out:
        if "cases" not in report:
            raise SystemExit("--csv-out is available only in dataset mode")
        write_csv(report, args.csv_out)
        print(f"wrote CSV report: {args.csv_out}")


if __name__ == "__main__":
    main()
