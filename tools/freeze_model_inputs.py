#!/usr/bin/env python3
"""Create or verify the dev model-input freeze used before replacement API calls."""

import argparse
import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path

import jsonschema


ROOT = Path(__file__).resolve().parent.parent
FREEZE = ROOT / "eval/freeze/dev_model_input_freeze_v1.json"
PACKAGE_SCHEMA = ROOT / "tools/schema/alert_package.schema.json"
OUTPUT_SCHEMA = ROOT / "eval/llm_output.schema.json"
RUNNER = ROOT / "eval/run_model.py"
PROMPTS = {
    "A1_basic": ROOT / "eval/triage_prompt_basic.md",
    "A2_evidence": ROOT / "eval/gemini_triage_prompt.md",
}
REQUEST_CONFIG = {
    "provider": "gemini",
    "requested_model": "gemini-2.5-flash",
    "api_version": "v1beta",
    "temperature": 0.0,
    "max_output_tokens": 2048,
    "thinking": "off",
    "thinking_budget": 0,
    "response_mime_type": "application/json",
    "top_p": None,
    "seed": None,
}
REQUEST_TEMPLATE = "{system}\n\n---\n\nAlert package:\n```json\n{package_json}\n```"


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def sha256_json(value) -> str:
    data = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return sha256_bytes(data)


def load_system_prompt(path: Path) -> str:
    text = path.read_text(encoding="utf-8")
    if "---" not in text:
        raise ValueError(f"prompt delimiter missing: {path}")
    return text.split("---", 1)[1].strip()


def verify_minimal_pair(a1: str, a2: str) -> None:
    stripped = re.sub(
        r"\n\nAnalyst discipline \(apply rigorously\):.*?\n\nRespond with",
        "\n\nRespond with",
        a2,
        count=1,
        flags=re.DOTALL,
    )
    if stripped != a1:
        raise ValueError("A1/A2 are no longer a minimal pair outside the discipline block")


def relative(path: Path) -> str:
    return str(path.relative_to(ROOT))


def current_snapshot() -> dict:
    package_schema = json.loads(PACKAGE_SCHEMA.read_text(encoding="utf-8"))
    package_rows = []
    seen = set()
    for path in sorted(ROOT.glob("tier*/*/dev/*/model_input/alert_package.json")):
        package = json.loads(path.read_text(encoding="utf-8"))
        jsonschema.validate(package, package_schema)
        case_id = package.get("case_id")
        if not isinstance(case_id, str) or not re.fullmatch(r"[A-Z]+-\d{3}", case_id):
            raise ValueError(f"invalid case_id in {path}: {case_id!r}")
        if case_id in seen:
            raise ValueError(f"duplicate dev case_id: {case_id}")
        seen.add(case_id)
        package_rows.append(
            {
                "case_id": case_id,
                "path": relative(path),
                "sha256": sha256_file(path),
                "bytes": path.stat().st_size,
                "event_count": package["observed_context"]["event_count"],
            }
        )
    if len(package_rows) != 21:
        raise ValueError(f"expected 21 dev packages, found {len(package_rows)}")

    prompt_rows = {}
    systems = {}
    for arm, path in PROMPTS.items():
        system = load_system_prompt(path)
        systems[arm] = system
        prompt_rows[arm] = {
            "path": relative(path),
            "file_sha256": sha256_file(path),
            "system_prompt_sha256": sha256_bytes(system.encode("utf-8")),
            "system_prompt_bytes": len(system.encode("utf-8")),
        }
    verify_minimal_pair(systems["A1_basic"], systems["A2_evidence"])

    request_inputs = {
        "packages": [{"case_id": row["case_id"], "sha256": row["sha256"]} for row in package_rows],
        "system_prompts": {
            arm: row["system_prompt_sha256"] for arm, row in prompt_rows.items()
        },
        "request_template_sha256": sha256_bytes(REQUEST_TEMPLATE.encode("utf-8")),
        "request_config": REQUEST_CONFIG,
    }
    offline_contract = {
        "output_schema_sha256": sha256_file(OUTPUT_SCHEMA),
        "package_schema_sha256": sha256_file(PACKAGE_SCHEMA),
        "runner_sha256": sha256_file(RUNNER),
    }
    return {
        "record_schema": "safesoc.dev_model_input_freeze.v1",
        "generated_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "split": "dev",
        "case_count": len(package_rows),
        "status": "pre_rerun_input_freeze",
        "packages": package_rows,
        "prompts": prompt_rows,
        "request_template_sha256": request_inputs["request_template_sha256"],
        "request_config": REQUEST_CONFIG,
        "request_inputs_digest": sha256_json(request_inputs),
        "offline_contract": offline_contract,
        "offline_contract_digest": sha256_json(offline_contract),
        "rerun_policy": {
            "requires_api_review": [
                "canonical alert_package bytes change",
                "effective A1 or A2 system prompt changes",
                "request template or Gemini request configuration changes",
                "requested model changes",
            ],
            "does_not_require_api_rerun": [
                "ground-truth wording or labels",
                "rubric or validator logic",
                "A3/A4 scoring and reports",
                "retrieval documentation or staged export when package SHA-256 is unchanged",
            ],
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", action="store_true", help="write the current dev input baseline")
    args = parser.parse_args()
    current = current_snapshot()

    if args.write:
        FREEZE.parent.mkdir(parents=True, exist_ok=True)
        FREEZE.write_text(json.dumps(current, indent=2) + "\n", encoding="utf-8")
        print(f"WROTE {relative(FREEZE)}")
        print(f"  21 packages · request digest {current['request_inputs_digest']}")
        print(f"  offline contract digest {current['offline_contract_digest']}")
        return

    if not FREEZE.exists():
        raise SystemExit(f"freeze record missing: run python3 tools/freeze_model_inputs.py --write")
    frozen = json.loads(FREEZE.read_text(encoding="utf-8"))
    problems = []
    if frozen.get("request_inputs_digest") != current["request_inputs_digest"]:
        problems.append("model-visible request inputs changed")
    if frozen.get("offline_contract_digest") != current["offline_contract_digest"]:
        problems.append("runner or schema contract changed; review before spending API quota")
    if problems:
        print("FAIL dev model-input freeze")
        for problem in problems:
            print(f"  - {problem}")
        raise SystemExit(1)
    print("PASS dev model-input freeze")
    print(f"  21 packages · request digest {current['request_inputs_digest']}")
    print("  A1/A2 minimal pair · package schemas valid · request configuration unchanged")


if __name__ == "__main__":
    main()
