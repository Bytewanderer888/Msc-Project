import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "eval"))

import aggregate_validator_rounds as aggregator  # noqa: E402


def report(round_number, c4_passes):
    cases = []
    for case_id, c4_pass in zip(("A", "B"), c4_passes):
        cases.append(
            {
                "case_id": case_id,
                "condition": "weak",
                "checks": {
                    key: {"pass": c4_pass if check == "C4" else True}
                    for check, key in aggregator.CHECK_KEYS.items()
                },
            }
        )
    return {
        "model": f"model-round-{round_number}",
        "split": "heldout",
        "completeness": {"complete": True},
        "summary": {
            "active_checks": aggregator.EXPECTED_CHECKS,
            "active_flagged_n": sum(not value for value in c4_passes),
            "check_failure_counts": {
                "C1": 0,
                "C2": 0,
                "C3": 0,
                "C4": sum(not value for value in c4_passes),
            },
        },
        "cases": cases,
    }


class AggregateTests(unittest.TestCase):
    def test_majority_is_computed_per_check(self):
        result = aggregator.aggregate(
            [report(1, [True, False]), report(2, [False, False]), report(3, [True, True])]
        )
        rows = {row["case_id"]: row for row in result["cases"]}
        self.assertTrue(rows["A"]["joint_majority_pass"])
        self.assertFalse(rows["B"]["joint_majority_pass"])
        self.assertEqual(rows["B"]["flagged_by_majority"], ["C4"])
        self.assertEqual(result["summary"]["majority_joint_pass_n"], 1)

    def test_requires_exactly_three_reports(self):
        with self.assertRaises(aggregator.AggregationError):
            aggregator.aggregate([report(1, [True, True])])


if __name__ == "__main__":
    unittest.main()
