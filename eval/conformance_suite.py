#!/usr/bin/env python3
"""Deterministic metamorphic/conformance checks for validator v1.1.

The suite changes one controlled property at a time and records the expected
C1-C4 pass vector.  It is intentionally synthetic: it tests evaluator logic,
not model quality or semantic cybersecurity judgement.
"""

from __future__ import annotations

from copy import deepcopy

import validator_v1_1 as validator


CHECK_KEYS = {
    "C1": "C1_reference_integrity",
    "C2": "C2_decision_calibration",
    "C3": "C3_counter_acknowledgement",
    "C4": "C4_action_calibration",
}


def _package() -> dict:
    return {
        "case_id": "CONF-001",
        "main_alert": {"evidence_id": "A0"},
        "evidence_items": [
            {"evidence_id": "EV-001"},
            {"evidence_id": "EV-002"},
        ],
        "deterministic_derivations": [],
    }


def _ground_truth(condition: str = "weak") -> dict:
    policy = validator.CONDITION_POLICY[condition]
    return {
        "case_id": "CONF-001",
        "evidence_condition": condition,
        "calibration_role": "up_rank" if condition == "strong" else "down_rank",
        "correct_verdict": policy["verdict"],
        "acceptable_severity": policy["severity"],
        "acceptable_actions": policy["actions"],
        "grounding": {
            "supporting_evidence": ["A0"],
            "counter_evidence": ["EV-001"] if condition != "strong" else [],
            "must_not_assert": ["an absent outcome"],
        },
        "rubric_version": "1.1",
    }


def _output(condition: str = "weak") -> dict:
    policy = validator.CONDITION_POLICY[condition]
    return {
        "verdict": policy["verdict"],
        "severity": policy["severity"][-1],
        "confidence": 0.8,
        "key_evidence": ["A0"],
        "rationale": (
            "A0 is the observed signal, while EV-001 supplies mitigating context."
            if condition != "strong"
            else "A0 directly supports the observed malicious outcome."
        ),
        "recommended_action": policy["actions"][-1],
    }


def _scenario(
    scenario_id: str,
    purpose: str,
    expected: dict[str, bool],
    mutate,
    condition: str = "weak",
) -> dict:
    package = _package()
    ground_truth = _ground_truth(condition)
    output = _output(condition)
    mutate(package, output, ground_truth)
    checks = validator.validate_case(package, output, ground_truth)
    observed = {name: checks[key]["pass"] for name, key in CHECK_KEYS.items()}
    return {
        "scenario_id": scenario_id,
        "purpose": purpose,
        "condition": condition,
        "expected": expected,
        "observed": observed,
        "pass": observed == expected,
    }


def run_suite() -> list[dict]:
    all_pass = {"C1": True, "C2": True, "C3": True, "C4": True}
    scenarios = []

    scenarios.append(
        _scenario("BASE", "Unmodified in-band control", all_pass, lambda *_: None)
    )
    scenarios.append(
        _scenario(
            "INV-EVIDENCE-ORDER",
            "Reordering evidence items must not alter any check",
            all_pass,
            lambda package, *_: package["evidence_items"].reverse(),
        )
    )
    scenarios.append(
        _scenario(
            "INV-CONFIDENCE",
            "Confidence is exploratory and must not alter C1-C4",
            all_pass,
            lambda _package, output, _gt: output.update(confidence=0.1),
        )
    )
    scenarios.append(
        _scenario(
            "INV-VALID-IRRELEVANT-ID",
            "Adding a valid irrelevant ID must not matter when a relevant key ID remains",
            all_pass,
            lambda _package, output, _gt: output["key_evidence"].append("EV-002"),
        )
    )
    scenarios.append(
        _scenario(
            "INV-ID-PRESERVING-PROSE",
            "A fixed synonym rewrite that preserves citations must not alter checks",
            all_pass,
            lambda _package, output, _gt: output.update(
                rationale="A0 is the observed indicator; EV-001 provides benign context."
            ),
        )
    )
    scenarios.append(
        _scenario(
            "C1-INVALID-ID",
            "A fabricated evidence identifier must fail C1 only",
            {**all_pass, "C1": False},
            lambda _package, output, _gt: output["key_evidence"].append("EV-999"),
        )
    )
    scenarios.append(
        _scenario(
            "C1-UNSUPPORTED-DECODE",
            "A decoded-value claim without a derivation must fail C1 only",
            {**all_pass, "C1": False},
            lambda _package, output, _gt: output.update(
                rationale="A0 supports the alert and EV-001 mitigates it; the decoded payload is malicious."
            ),
        )
    )
    scenarios.append(
        _scenario(
            "C2-VERDICT-OVER",
            "Changing only the weak-case verdict to malicious must fail C2 only",
            {**all_pass, "C2": False},
            lambda _package, output, _gt: output.update(verdict="malicious"),
        )
    )
    scenarios.append(
        _scenario(
            "C2-SEVERITY-OVER",
            "Changing only weak-case severity to high must fail C2 only",
            {**all_pass, "C2": False},
            lambda _package, output, _gt: output.update(severity="high"),
        )
    )
    scenarios.append(
        _scenario(
            "C2-SEVERITY-UNDER",
            "Changing only strong-case severity to low must fail C2 only",
            {**all_pass, "C2": False},
            lambda _package, output, _gt: output.update(severity="low"),
            condition="strong",
        )
    )
    scenarios.append(
        _scenario(
            "C3-COUNTER-CITATION-REMOVED",
            "Removing the designated counter citation must fail C3 only",
            {**all_pass, "C3": False},
            lambda _package, output, _gt: output.update(
                rationale="A0 is the observed signal and remains inconclusive."
            ),
        )
    )
    scenarios.append(
        _scenario(
            "C4-ACTION-OVER",
            "Changing only weak-case action to isolate must fail C4 only",
            {**all_pass, "C4": False},
            lambda _package, output, _gt: output.update(recommended_action="isolate"),
        )
    )
    scenarios.append(
        _scenario(
            "C4-ACTION-UNDER",
            "Changing only strong-case action to monitor must fail C4 only",
            {**all_pass, "C4": False},
            lambda _package, output, _gt: output.update(recommended_action="monitor"),
            condition="strong",
        )
    )
    scenarios.append(
        _scenario(
            "C2-C4-COMBINED-OVER",
            "Overstating verdict, severity and action must fail C2 and C4 only",
            {**all_pass, "C2": False, "C4": False},
            lambda _package, output, _gt: output.update(
                verdict="malicious", severity="high", recommended_action="isolate"
            ),
        )
    )
    return deepcopy(scenarios)


if __name__ == "__main__":
    failures = [row for row in run_suite() if not row["pass"]]
    for row in run_suite():
        status = "PASS" if row["pass"] else "FAIL"
        print(f"{status:4s} {row['scenario_id']:30s} {row['observed']}")
    raise SystemExit(bool(failures))
