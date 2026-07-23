import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "eval"))

import conformance_suite  # noqa: E402


class ConformanceSuiteTests(unittest.TestCase):
    def test_every_mutation_has_the_expected_check_vector(self):
        failures = [row for row in conformance_suite.run_suite() if not row["pass"]]
        self.assertEqual(failures, [])

    def test_suite_contains_invariance_and_targeted_failure_controls(self):
        ids = {row["scenario_id"] for row in conformance_suite.run_suite()}
        self.assertTrue(any(item.startswith("INV-") for item in ids))
        for check in ("C1-", "C2-", "C3-", "C4-"):
            self.assertTrue(any(item.startswith(check) for item in ids), check)


if __name__ == "__main__":
    unittest.main()
