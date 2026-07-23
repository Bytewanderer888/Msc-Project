import json
import tempfile
import unittest
from pathlib import Path

from eval import run_model


class RunModelExperimentTests(unittest.TestCase):
    def test_custom_package_directory_uses_json_filenames(self):
        with tempfile.TemporaryDirectory() as tmp:
            package = Path(tmp) / "CASE-001.json"
            package.write_text(json.dumps({"case_id": "CASE-001"}), encoding="utf-8")
            rows = list(run_model.packages("dev", Path(tmp)))
        self.assertEqual(rows, [("CASE-001", package)])

    def test_experiment_tag_isolates_output_model_tag(self):
        self.assertEqual(
            run_model.output_model_tag(
                "gemini-2.5-flash", "evidence", experiment_tag="study_variant"
            ),
            "gemini-2.5-flash__A2_evidence_prompt__EXP_study_variant",
        )

    def test_round_and_experiment_tags_can_coexist(self):
        self.assertEqual(
            run_model.output_model_tag(
                "claude-sonnet-4-6", "evidence", round_number=2,
                experiment_tag="study_variant",
            ),
            "claude-sonnet-4-6__A2_evidence_prompt_round2__EXP_study_variant",
        )

    def test_run_event_binds_output_to_package_and_configuration(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            output = root / "CASE-001.json"
            output.write_text('{"verdict":"benign"}', encoding="utf-8")
            log = root / "run_events_dev.jsonl"
            context = {
                "record_schema": "safesoc.run_event.v1",
                "invocation_id": "test-run",
                "requested_model": "model-1",
                "prompt_file_sha256": "prompt-hash",
            }

            run_model.append_run_event(
                log,
                context,
                "CASE-001",
                {"path": "packages/CASE-001.json", "sha256": "package-hash"},
                "success",
                outpath=output,
                usage={
                    "input_tokens": 12,
                    "output_tokens": 8,
                    "response_tokens": 3,
                    "thought_tokens": 5,
                },
                provider_meta={"provider_model_version": "model-1.2"},
                elapsed_seconds=1.25,
            )

            event = json.loads(log.read_text(encoding="utf-8"))
            expected_output_hash = run_model.sha256_file(output)
        self.assertEqual(event["case"], "CASE-001")
        self.assertEqual(event["package_sha256"], "package-hash")
        self.assertEqual(event["prompt_file_sha256"], "prompt-hash")
        self.assertEqual(event["provider_model_version"], "model-1.2")
        self.assertEqual(event["input_tokens"], 12)
        self.assertEqual(event["output_tokens"], 8)
        self.assertNotIn("response_tokens", event)
        self.assertNotIn("thought_tokens", event)
        self.assertEqual(event["output_sha256"], expected_output_hash)


if __name__ == "__main__":
    unittest.main()
