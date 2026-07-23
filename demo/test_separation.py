#!/usr/bin/env python3
"""Prove the workbench keeps its two validation paths apart.

The central claim of the demo is that the deployable runtime check never sees benchmark
ground truth. This test enforces it by instrumenting file reads: every path opened while
serving /api/validate is recorded, and the test fails if any of them is an annotation or a
ground-truth file. The research endpoint is the positive control — it must open exactly the
file the runtime path is forbidden to touch.

    python3 demo/test_separation.py        (or: python3 -m pytest demo/test_separation.py)
"""
from __future__ import annotations

import builtins
import io
import json
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[0].parent if HERE.name != "demo" else HERE.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ROOT / "eval"))
import server  # noqa: E402

FORBIDDEN = ("annotations", "ground_truth")
CASE, MODEL, ARM, ROUND = "ACCT-001", "gemini-2.5-flash", "A2_evidence_prompt", 1


class ReadRecorder:
    """Record every path opened.

    Patches builtins.open, io.open, Path.open and Path.read_text/read_bytes. Path.open()
    resolves io.open rather than builtins.open, so omitting either would leave a blind spot —
    and runtime_validator.sha256() genuinely uses `path.open("rb")`, so that blind spot would
    be live in the code this test exists to police.
    """

    def __enter__(self):
        self.paths: list[str] = []
        self._builtin_open, self._io_open = builtins.open, io.open
        self._popen, self._rt, self._rb = Path.open, Path.read_text, Path.read_bytes
        rec = self.paths

        def builtin_open(file, *a, **k):
            rec.append(str(file)); return self._builtin_open(file, *a, **k)

        def io_open(file, *a, **k):
            rec.append(str(file)); return self._io_open(file, *a, **k)

        def path_open(p, *a, **k):
            rec.append(str(p)); return self._popen(p, *a, **k)

        def read_text(p, *a, **k):
            rec.append(str(p)); return self._rt(p, *a, **k)

        def read_bytes(p, *a, **k):
            rec.append(str(p)); return self._rb(p, *a, **k)

        builtins.open, io.open = builtin_open, io_open
        Path.open, Path.read_text, Path.read_bytes = path_open, read_text, read_bytes
        return self

    def __exit__(self, *exc):
        builtins.open, io.open = self._builtin_open, self._io_open
        Path.open, Path.read_text, Path.read_bytes = self._popen, self._rt, self._rb

    def hits(self, needles=FORBIDDEN):
        return [p for p in self.paths if any(n in p for n in needles)]


class RecorderSelfTest(unittest.TestCase):
    """The no-ground-truth proof is only as good as the recorder. Prove it sees every read
    style the validators actually use — Path.open('rb') in particular, which resolves io.open
    and would otherwise be invisible (runtime_validator.sha256 uses exactly that form)."""

    def test_recorder_sees_all_read_styles(self):
        target = Path(__file__)
        for label, read in (
            ("builtins.open", lambda: open(target, "rb").close()),
            ("Path.open", lambda: target.open("rb").close()),
            ("Path.read_text", lambda: target.read_text(encoding="utf-8")),
            ("Path.read_bytes", lambda: target.read_bytes()),
        ):
            with ReadRecorder() as rec:
                read()
            self.assertTrue(any(str(target) in p for p in rec.paths),
                            f"recorder is blind to {label} — the separation proof would be hollow")

    def test_recorder_would_catch_a_ground_truth_read(self):
        gt = ROOT / "tier1" / "missing" / "dev" / "ACCT-001_create_local_account" / \
            "annotations" / "ground_truth.json"
        with ReadRecorder() as rec:
            gt.open("rb").close()          # the exact style that previously slipped through
        self.assertTrue(rec.hits(), "a ground-truth read via Path.open must be detected")


class SeparationTests(unittest.TestCase):
    def setUp(self):
        # Warm caches outside the recorder so cached reads can't mask a real access.
        server.snapshot(); server.runtime_context(); server.package_index()

    # ---- the deployable path ----
    def test_validate_never_reads_ground_truth(self):
        with ReadRecorder() as rec:
            result = server.api_validate({"case_id": CASE, "model": MODEL, "arm": ARM, "round": ROUND})
        self.assertEqual(rec.hits(), [], f"runtime path opened forbidden files: {rec.hits()}")
        self.assertEqual(result["token_calls"], 0)
        self.assertIn("no annotations or ground truth", result["input_contract"])

    def test_validate_reads_only_package_output_policy(self):
        with ReadRecorder() as rec:
            server.api_validate({"case_id": CASE, "model": MODEL, "arm": ARM, "round": ROUND})
        opened = [p for p in rec.paths if p.endswith(".json")]
        for path in opened:
            self.assertTrue(
                any(k in path for k in ("alert_package", "outputs", "runtime_policy",
                                        "schema", "snapshot")),
                f"unexpected file read on the runtime path: {path}",
            )

    def test_validate_result_carries_no_condition_or_expected_bands(self):
        result = server.api_validate({"case_id": CASE, "model": MODEL, "arm": ARM, "round": ROUND})
        blob = json.dumps(result).lower()
        for banned in ("evidence_condition", "correct_verdict", "acceptable_severity",
                       "acceptable_actions", "calibration_role", "must_not_assert"):
            self.assertNotIn(banned, blob, f"runtime result leaked {banned}")

    def test_runtime_result_does_not_expose_condition_bearing_paths(self):
        result = server.api_validate({"case_id": CASE, "model": MODEL, "arm": ARM, "round": ROUND})
        paths = "\n".join(result["inputs_read"]).lower()
        for condition in ("/strong/", "/weak/", "/missing/", "/counter/"):
            self.assertNotIn(condition, paths)
        self.assertIn(f"benchmark/{CASE}/alert_package.json", result["inputs_read"])

    def test_runtime_status_is_a_real_policy_decision(self):
        """ACCT-001/Gemini is the teaching case: clean under the deployable profile."""
        result = server.api_validate({"case_id": CASE, "model": MODEL, "arm": ARM, "round": ROUND})
        case = result["case"]
        default = result["default_profile"]
        self.assertEqual(case["profile_outcomes"][default]["status"], "pass")
        self.assertEqual(case["findings"], [])
        # ...and safety_first, a stricter profile, does flag the same output.
        self.assertEqual(case["profile_outcomes"]["safety_first"]["status"], "review")

    # ---- the research path (positive control) ----
    def test_research_does_read_ground_truth(self):
        with ReadRecorder() as rec:
            research = server.api_research({"case_id": [CASE], "model": [MODEL],
                                            "arm": [ARM], "round": [str(ROUND)]})
        self.assertTrue(rec.hits(), "research path should read ground truth but did not")
        self.assertEqual(research["evidence_condition"], "missing")
        self.assertEqual(sorted(research["failed_checks"]), ["C2", "C4"])
        self.assertFalse(research["a4_ok"])
        self.assertIn("not part of the deployable runtime path", research["scope"])

    def test_the_two_paths_disagree_on_the_teaching_case(self):
        """The demo's core lesson: a runtime pass is not an A4 pass."""
        runtime = server.api_validate({"case_id": CASE, "model": MODEL, "arm": ARM, "round": ROUND})
        research = server.api_research({"case_id": [CASE], "model": [MODEL],
                                        "arm": [ARM], "round": [str(ROUND)]})
        self.assertEqual(runtime["case"]["profile_outcomes"][runtime["default_profile"]]["status"], "pass")
        self.assertFalse(research["a4_ok"])

    # ---- served payloads ----
    def test_case_payload_exposes_no_ground_truth_answer(self):
        """The runtime case payload carries neither condition nor the expected answer."""
        payload = server.api_case({"case_id": [CASE]})
        blob = json.dumps(payload).lower()
        for banned in ("condition", "case_name", "package_rel", "case_dir_rel", "correct_verdict",
                       "acceptable_severity", "acceptable_actions", "must_not_assert",
                       "curation_notes"):
            self.assertNotIn(banned, blob)

    def test_startup_snapshot_contains_no_research_payload(self):
        snap = server.snapshot()
        for banned in ("research", "sweep", "dashboard", "presets", "condition_by_case"):
            self.assertNotIn(banned, snap)
        for case in snap["cases"]:
            for banned in ("condition", "case_name", "package_rel", "case_dir_rel"):
                self.assertNotIn(banned, case)
        self.assertEqual(
            [case["case_id"] for case in snap["cases"]],
            sorted(case["case_id"] for case in snap["cases"]),
            "runtime queue order must not preserve condition-bearing folder order",
        )

    def test_research_snapshot_is_an_explicit_positive_control(self):
        snap = server.research_snapshot()
        self.assertEqual(snap["condition_by_case"][CASE], "missing")
        self.assertIn("dashboard", snap)
        self.assertIn("presets", snap)

    def test_external_replication_stays_research_only_and_complete(self):
        self.assertNotIn("external_replication", json.dumps(server.snapshot()))
        replication = server.research_snapshot()["dashboard"]["external_replication"]
        self.assertEqual(replication["n"], 16)
        self.assertEqual(replication["models"]["gemini-2.5-flash"]["a4_pass_n"], 8)
        self.assertEqual(replication["models"]["claude-sonnet-4-6"]["a4_pass_n"], 13)
        self.assertEqual(replication["paired"]["claude_only_pass"], 5)
        self.assertEqual(replication["paired"]["gemini_only_pass"], 0)

    def test_served_case_records_carry_no_researcher_intent(self):
        """Regression: build/case.json's metadata.attack_category.note states the intended
        condition and required answer and is flagged model_visible:false. It must never reach
        the browser through the snapshot or /api/case."""
        import re
        pattern = re.compile(r"RESEARCHER-INTENT|evidence_condition|do not leak|down-?rank|"
                             r"over-?triage|must[_ ]not[_ ]assert|correct_verdict", re.IGNORECASE)
        snap = server.snapshot()
        for case in snap["cases"]:
            for key, value in case.items():
                self.assertIsNone(pattern.search(json.dumps(value)),
                                  f"snapshot cases[{case['case_id']}].{key} leaks researcher intent")
        for case_id in ("DISC-002", "RDL-001", CASE):
            payload = server.api_case({"case_id": [case_id]})
            self.assertIsNone(pattern.search(json.dumps(payload["case"])),
                              f"/api/case leaks researcher intent for {case_id}")
            self.assertNotIn("attack_category", payload["case"])

    def test_no_model_provider_is_called(self):
        source = (HERE / "server.py").read_text(encoding="utf-8")
        for banned in ("call_gemini", "call_anthropic", "generativelanguage", "api.anthropic"):
            self.assertNotIn(banned, source, "the workbench must replay saved outputs only")


if __name__ == "__main__":
    unittest.main(verbosity=2)
