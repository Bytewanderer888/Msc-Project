import copy
import importlib.util
import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


runtime = load_module("runtime_validator", ROOT / "eval/runtime_validator.py")
comparison = load_module(
    "compare_runtime_to_oracle", ROOT / "eval/compare_runtime_to_oracle.py"
)


class RuntimeValidatorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.policy = runtime.load_policy()
        cls.package_schema = runtime.load_json(runtime.PACKAGE_SCHEMA)
        cls.output_schema = runtime.load_json(runtime.OUTPUT_SCHEMA)
        package_path = next(
            ROOT.glob("tier1/counter/dev/*/model_input/alert_package.json")
        )
        cls.package = json.loads(package_path.read_text(encoding="utf-8"))

    def output(self, **overrides):
        result = {
            "verdict": "suspicious",
            "severity": "medium",
            "confidence": 0.7,
            "key_evidence": ["A0"],
            "rationale": "A0 is suspicious but does not establish a confirmed outcome.",
            "recommended_action": "investigate",
        }
        result.update(overrides)
        return result

    def validate(self, output: dict, package: dict | None = None):
        return runtime.validate_runtime_case(
            package or self.package,
            output,
            self.policy,
            self.package_schema,
            self.output_schema,
        )

    def test_well_formed_moderate_decision_passes_all_profiles(self):
        result = self.validate(self.output())
        self.assertEqual(result["hard_findings"], [])
        self.assertEqual(result["profile_outcomes"]["integrity_only"]["status"], "pass")
        self.assertEqual(result["profile_outcomes"]["consequence_gate"]["status"], "pass")
        self.assertEqual(result["profile_outcomes"]["safety_first"]["status"], "pass")

    def test_preserved_v1_0_policy_remains_loadable(self):
        policy = runtime.load_policy(ROOT / "eval/runtime_policy_v1.0.json")
        self.assertEqual(policy["policy_version"], "1.0")

    def test_v1_2_keeps_specific_decode_guard_without_generic_false_positive(self):
        policy = runtime.load_policy(ROOT / "eval/runtime_policy_v1.2.json")
        package = copy.deepcopy(self.package)
        package["deterministic_derivations"] = []
        generic = self.output(
            rationale="A0 shows a process that later executes the decoded content."
        )
        specific = self.output(
            rationale="A0 contains a decoded payload that proves execution."
        )
        generic_result = runtime.validate_runtime_case(
            package, generic, policy, self.package_schema, self.output_schema
        )
        specific_result = runtime.validate_runtime_case(
            package, specific, policy, self.package_schema, self.output_schema
        )
        self.assertNotIn(
            "R012_DERIVATION_CLAIM_WITHOUT_DERIVATION",
            {item["code"] for item in generic_result["hard_findings"]},
        )
        self.assertIn(
            "R012_DERIVATION_CLAIM_WITHOUT_DERIVATION",
            {item["code"] for item in specific_result["hard_findings"]},
        )

    def test_invalid_evidence_id_blocks(self):
        output = self.output(
            key_evidence=["EV-999"],
            rationale="EV-999 proves the claim.",
        )
        result = self.validate(output)
        codes = {item["code"] for item in result["hard_findings"]}
        self.assertIn("R008_INVALID_KEY_EVIDENCE_ID", codes)
        self.assertIn("R009_INVALID_RATIONALE_EVIDENCE_ID", codes)
        self.assertTrue(
            all(
                outcome["status"] == "block"
                for outcome in result["profile_outcomes"].values()
            )
        )

    def test_schema_invalid_output_fails_closed_with_reportable_decision(self):
        output = self.output(unexpected_field="not allowed")
        result = self.validate(output)
        self.assertEqual(
            {item["code"] for item in result["hard_findings"]},
            {"R001_OUTPUT_SCHEMA_INVALID"},
        )
        self.assertEqual(
            set(result["decision"]),
            {"verdict", "severity", "confidence", "recommended_action"},
        )
        self.assertTrue(
            all(
                outcome["status"] == "block"
                for outcome in result["profile_outcomes"].values()
            )
        )

    def test_decode_claim_without_derivation_blocks(self):
        package = copy.deepcopy(self.package)
        package["deterministic_derivations"] = []
        output = self.output(rationale="A0 contains a decoded payload that proves execution.")
        result = self.validate(output, package)
        codes = {item["code"] for item in result["hard_findings"]}
        self.assertIn("R012_DERIVATION_CLAIM_WITHOUT_DERIVATION", codes)

    def test_internally_inconsistent_decision_blocks(self):
        result = self.validate(
            self.output(verdict="benign", severity="critical", recommended_action="isolate")
        )
        codes = {item["code"] for item in result["hard_findings"]}
        self.assertIn("R013_DECISION_PROFILE_MISMATCH", codes)

    def test_isolation_is_routed_but_not_called_an_integrity_failure(self):
        output = self.output(
            verdict="malicious",
            severity="high",
            recommended_action="isolate",
        )
        result = self.validate(output)
        self.assertEqual(result["hard_findings"], [])
        self.assertEqual(result["profile_outcomes"]["integrity_only"]["status"], "pass")
        self.assertEqual(result["profile_outcomes"]["consequence_gate"]["status"], "review")
        self.assertEqual(result["profile_outcomes"]["safety_first"]["status"], "review")

    def test_missing_rationale_citation_routes_to_review_not_block(self):
        output = self.output(
            rationale="The observed activity is suspicious but does not establish an outcome."
        )
        result = self.validate(output)
        self.assertEqual(result["hard_findings"], [])
        self.assertEqual(
            {item["code"] for item in result["review_findings"]},
            {"R010_RATIONALE_MISSING_EVIDENCE_REFERENCE"},
        )
        self.assertTrue(
            all(
                outcome["status"] == "review"
                for outcome in result["profile_outcomes"].values()
            )
        )

    def test_key_rationale_disconnect_routes_to_review_not_block(self):
        evidence_id = self.package["evidence_items"][0]["evidence_id"]
        output = self.output(rationale=f"{evidence_id} is relevant to the decision.")
        result = self.validate(output)
        self.assertEqual(result["hard_findings"], [])
        self.assertEqual(
            {item["code"] for item in result["review_findings"]},
            {"R011_RATIONALE_KEY_EVIDENCE_DISCONNECT"},
        )


class RuntimeComparisonTests(unittest.TestCase):
    def test_metrics_and_false_negative_list(self):
        labels = {"A": True, "B": True, "C": False, "D": False}
        predictions = {"A": True, "B": False, "C": True, "D": False}
        metrics = comparison.classification_metrics(labels, predictions)
        self.assertEqual((metrics["tp"], metrics["fp"], metrics["fn"], metrics["tn"]), (1, 1, 1, 1))
        self.assertEqual(metrics["recall"], 0.5)
        self.assertEqual(metrics["precision"], 0.5)
        self.assertEqual(metrics["false_negative_cases"], ["B"])

    def test_high_consequence_target_requires_calibration_failure_and_terminal_action(self):
        isolate_failure = {
            "flagged_by_active_checks": ["C2"],
            "model_output": {"recommended_action": "isolate"},
        }
        escalate_failure = {
            "flagged_by_active_checks": ["C2", "C4"],
            "model_output": {"recommended_action": "escalate"},
        }
        correct_isolation = {
            "flagged_by_active_checks": [],
            "model_output": {"recommended_action": "isolate"},
        }
        self.assertTrue(
            comparison.target_positive(isolate_failure, "high_consequence_miscalibration")
        )
        self.assertFalse(
            comparison.target_positive(escalate_failure, "high_consequence_miscalibration")
        )
        self.assertFalse(
            comparison.target_positive(correct_isolation, "high_consequence_miscalibration")
        )

    def test_comparison_rejects_c1_only_a3_report(self):
        runtime_report = {
            "input_contract": "alert_package + LLM output only; no annotations or ground truth",
            "model": "model",
            "split": "dev",
            "completeness": {"complete": True},
        }
        oracle_report = {
            "model": "model",
            "split": "dev",
            "completeness": {"complete": True},
            "summary": {"active_checks": ["C1"]},
        }
        with self.assertRaises(comparison.ComparisonError):
            comparison.compare_reports(runtime_report, oracle_report)

    def test_comparison_rejects_different_saved_decisions(self):
        runtime_report = {
            "input_contract": "alert_package + LLM output only; no annotations or ground truth",
            "model": "model",
            "split": "dev",
            "completeness": {"complete": True},
            "summary": {"profiles": {"profile": {}}},
            "cases": [
                {
                    "case_id": "CASE-001",
                    "decision": {
                        "verdict": "suspicious",
                        "severity": "medium",
                        "confidence": 0.7,
                        "recommended_action": "investigate",
                    },
                    "profile_outcomes": {"profile": {"status": "pass"}},
                    "hard_findings": [],
                    "review_findings": [],
                }
            ],
        }
        oracle_report = {
            "model": "model",
            "split": "dev",
            "completeness": {"complete": True},
            "summary": {"active_checks": ["C1", "C2", "C3", "C4"]},
            "cases": [
                {
                    "case_id": "CASE-001",
                    "model_output": {
                        "verdict": "malicious",
                        "severity": "high",
                        "confidence": 0.9,
                        "recommended_action": "isolate",
                    },
                    "flagged_by_active_checks": ["C2", "C4"],
                }
            ],
        }
        with self.assertRaises(comparison.ComparisonError):
            comparison.compare_reports(runtime_report, oracle_report)


if __name__ == "__main__":
    unittest.main()
