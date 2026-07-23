import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "eval"))

import validator_v1_1 as validator  # noqa: E402


def package():
    return {
        "case_id": "TEST-001",
        "main_alert": {"evidence_id": "A0"},
        "evidence_items": [
            {"evidence_id": "EV-001"},
            {"evidence_id": "EV-002"},
        ],
        "deterministic_derivations": [],
    }


def ground_truth(condition="weak"):
    policy = validator.CONDITION_POLICY[condition]
    return {
        "case_id": "TEST-001",
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


def output():
    return {
        "verdict": "suspicious",
        "severity": "medium",
        "confidence": 0.8,
        "key_evidence": ["A0"],
        "rationale": "A0 is suspicious, while EV-001 is mitigating context.",
        "recommended_action": "investigate",
    }


class ReferenceIntegrityTests(unittest.TestCase):
    def test_valid_relevant_reference_passes(self):
        result = validator.validate_case(package(), output(), ground_truth())
        self.assertTrue(result["C1_reference_integrity"]["pass"])

    def test_invalid_rationale_id_fails(self):
        model_output = output()
        model_output["rationale"] += " EV-999 confirms it."
        result = validator.validate_case(package(), model_output, ground_truth())
        c1 = result["C1_reference_integrity"]
        self.assertFalse(c1["pass"])
        self.assertEqual(c1["invalid_rationale_ids"], ["EV-999"])

    def test_valid_but_irrelevant_key_reference_fails(self):
        model_output = output()
        model_output["key_evidence"] = ["EV-002"]
        result = validator.validate_case(package(), model_output, ground_truth())
        c1 = result["C1_reference_integrity"]
        self.assertFalse(c1["pass"])
        self.assertEqual(c1["relevant_key_evidence_ids"], [])

    def test_decode_claim_requires_derivation(self):
        model_output = output()
        model_output["rationale"] = "A0 decoded payload contains a command."
        result = validator.validate_case(package(), model_output, ground_truth())
        self.assertTrue(
            result["C1_reference_integrity"]["derivation_claim_without_derivation"]
        )

    def test_generic_decoded_content_wording_does_not_claim_a_derived_value(self):
        model_output = output()
        model_output["rationale"] = "EV-001 runs a loader that executes decoded content."
        result = validator.validate_case(package(), model_output, ground_truth())
        self.assertFalse(
            result["C1_reference_integrity"]["derivation_claim_without_derivation"]
        )


class DecisionCalibrationTests(unittest.TestCase):
    def test_verdict_mismatch_fails_even_when_severity_is_in_band(self):
        model_output = output()
        model_output["verdict"] = "benign"
        model_output["severity"] = "low"
        c2 = validator.validate_case(package(), model_output, ground_truth())[
            "C2_decision_calibration"
        ]
        self.assertFalse(c2["verdict_pass"])
        self.assertTrue(c2["severity_pass"])
        self.assertFalse(c2["pass"])

    def test_over_triage_direction_is_reported(self):
        model_output = output()
        model_output["verdict"] = "malicious"
        model_output["severity"] = "high"
        c2 = validator.validate_case(package(), model_output, ground_truth())[
            "C2_decision_calibration"
        ]
        self.assertEqual(c2["verdict_direction"], "over")
        self.assertEqual(c2["severity_direction"], "over")


class CounterEvidenceTests(unittest.TestCase):
    def test_counter_reference_in_rationale_counts(self):
        model_output = output()
        model_output["key_evidence"] = ["A0"]
        c3 = validator.validate_case(package(), model_output, ground_truth())[
            "C3_counter_acknowledgement"
        ]
        self.assertTrue(c3["pass"])
        self.assertEqual(c3["cited_counter_evidence_ids"], ["EV-001"])

    def test_counter_check_is_not_applicable_without_counter_ids(self):
        gt = ground_truth("strong")
        model_output = output()
        model_output.update(
            verdict="malicious", severity="high", recommended_action="escalate"
        )
        c3 = validator.validate_case(package(), model_output, gt)[
            "C3_counter_acknowledgement"
        ]
        self.assertFalse(c3["applicable"])
        self.assertTrue(c3["pass"])


class ActionCalibrationTests(unittest.TestCase):
    def test_action_band_is_bidirectional(self):
        gt = ground_truth()
        for action, expected_direction in (
            ("close_benign", "under"),
            ("monitor", "in_band"),
            ("investigate", "in_band"),
            ("isolate", "over"),
        ):
            with self.subTest(action=action):
                model_output = output()
                model_output["recommended_action"] = action
                c4 = validator.validate_case(package(), model_output, gt)[
                    "C4_action_calibration"
                ]
                self.assertEqual(c4["direction"], expected_direction)
                self.assertEqual(c4["pass"], expected_direction == "in_band")


class ConfidenceTests(unittest.TestCase):
    def test_confidence_is_summarised_against_joint_c2_correctness(self):
        rows = []
        for confidence, correct in ((0.9, True), (0.8, False)):
            rows.append(
                {
                    "output": {"confidence": confidence},
                    "checks": {"C2_decision_calibration": {"pass": correct}},
                }
            )
        summary = validator.confidence_summary(rows)
        self.assertEqual(summary["decision_correct_n"], 1)
        self.assertEqual(summary["decision_incorrect_n"], 1)
        self.assertEqual(summary["mean_confidence_correct"], 0.9)
        self.assertEqual(summary["mean_confidence_incorrect"], 0.8)
        self.assertEqual(summary["high_confidence_error_n"], 1)


class PolicyTests(unittest.TestCase):
    def test_policy_rejects_case_specific_action_band(self):
        gt = ground_truth()
        gt["acceptable_actions"] = ["investigate"]
        errors = validator.ground_truth_policy_errors(gt, package())
        self.assertTrue(any("action band" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
