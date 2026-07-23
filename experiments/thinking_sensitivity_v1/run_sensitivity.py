#!/usr/bin/env python3
"""Run the pre-specified Gemini thinking-budget treatment over 16 paired packages."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from jsonschema import Draft7Validator

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / "eval"))
import run_model as rm  # noqa: E402

MODEL = "gemini-2.5-flash"
THINKING_BUDGET = 1024
MAX_OUTPUT_TOKENS = 2048
SEED = 200720

STUDIES = {
    "outcome": ROOT / "experiments" / "outcome_pairs_v1",
    "context": ROOT / "experiments" / "context_pairs_v1",
}


def clean_api_key(value: str) -> str:
    key = value.strip()
    for left, right in (("\"", "\""), ("'", "'"), ("“", "”"), ("‘", "’")):
        if key.startswith(left) and key.endswith(right):
            key = key[len(left):-len(right)].strip()
            break
    if any(ord(character) > 127 for character in key):
        raise SystemExit("GEMINI_API_KEY contains a non-ASCII character; remove smart quotes or spaces")
    return key


def call_gemini_thinking(prompt: str, package_text: str, api_key: str):
    """Experiment-local Gemini caller; the frozen benchmark runner stays unchanged."""
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{MODEL}:generateContent"
    combined = prompt + "\n\n---\n\nAlert package:\n```json\n" + package_text + "\n```"
    generation_config = {
        "temperature": 0.0,
        "responseMimeType": "application/json",
        "maxOutputTokens": MAX_OUTPUT_TOKENS,
        "thinkingConfig": {"thinkingBudget": THINKING_BUDGET},
    }
    response = rm._req(
        "POST",
        url,
        {"x-goog-api-key": api_key, "Content-Type": "application/json"},
        300,
        {
            "contents": [{"parts": [{"text": combined}]}],
            "generationConfig": generation_config,
        },
    )
    response.raise_for_status()
    payload = response.json()
    metadata = payload.get("usageMetadata", {})
    response_tokens = metadata.get("candidatesTokenCount", 0)
    thought_tokens = metadata.get("thoughtsTokenCount", 0)
    usage = {
        "input_tokens": metadata.get("promptTokenCount", 0),
        "response_tokens": response_tokens,
        "thought_tokens": thought_tokens,
        "output_tokens": response_tokens + thought_tokens,
    }
    try:
        candidate = payload["candidates"][0]
        provider_meta = {
            "provider_response_id": payload.get("responseId"),
            "provider_model_version": payload.get("modelVersion"),
            "finish_reason": candidate.get("finishReason"),
        }
        return candidate["content"]["parts"][0]["text"], usage, provider_meta
    except (KeyError, IndexError):
        raise RuntimeError("Gemini returned no usable candidate. Raw: " + json.dumps(payload)[:600])


def package_rows() -> list[dict]:
    rows = []
    for study, directory in STUDIES.items():
        manifest = json.loads((directory / "manifest.private.json").read_text(encoding="utf-8"))
        for pair in manifest["pairs"]:
            for version in pair["versions"]:
                case_id = version["neutral_case_id"]
                rows.append({
                    "study": study,
                    "pair_id": pair["pair_id"],
                    "case_id": case_id,
                    "package_path": directory / "packages" / f"{case_id}.json",
                })
    random.Random(SEED).shuffle(rows)
    return rows


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--only", help="comma-separated QE/QC ids; default = every missing output")
    parser.add_argument("--execute", action="store_true", help="required before API calls")
    args = parser.parse_args()

    rows = package_rows()
    available = {row["case_id"] for row in rows}
    selected = (
        {item.strip() for item in args.only.split(",") if item.strip()}
        if args.only else available
    )
    unknown = sorted(selected - available)
    if unknown:
        raise SystemExit(f"unknown package id(s): {unknown}")

    outroot = HERE / "outputs" / f"gemini__{MODEL}__thinking-budget-{THINKING_BUDGET}"
    todo = []
    for row in rows:
        outpath = outroot / row["study"] / f"{row['case_id']}.json"
        if row["case_id"] in selected and not outpath.exists():
            todo.append((row, outpath))
    print(f"{len(todo)} case(s) to run (skip-existing): {[row['case_id'] for row, _ in todo]}")
    if not args.execute:
        print("DRY RUN ONLY: add --execute to make API calls")
        return
    if not todo:
        return

    api_key = clean_api_key(os.environ.get("GEMINI_API_KEY", ""))
    if not api_key:
        raise SystemExit('GEMINI_API_KEY not set. export GEMINI_API_KEY="..."')

    prompt = rm.load_prompt("evidence")
    prompt_sha256 = hashlib.sha256(prompt.encode("utf-8")).hexdigest()
    schema_sha256 = hashlib.sha256(
        (ROOT / "eval" / "llm_output.schema.json").read_bytes()
    ).hexdigest()
    validator = Draft7Validator(rm.OUT_SCHEMA)
    outroot.mkdir(parents=True, exist_ok=True)
    usage_path = outroot / "usage.retained.jsonl"

    for index, (row, outpath) in enumerate(todo):
        if index:
            time.sleep(6.0)
        package_text = row["package_path"].read_text(encoding="utf-8")
        started = time.monotonic()
        try:
            raw, usage, provider_meta = call_gemini_thinking(prompt, package_text, api_key)
            output = rm.extract_json(raw)
            errors = sorted(error.message for error in validator.iter_errors(output))
            if errors:
                print(f"{row['case_id']}: SCHEMA-INVALID, not saved ({errors[0]})")
                continue
            outpath.parent.mkdir(parents=True, exist_ok=True)
            outpath.write_text(json.dumps(output, indent=2) + "\n", encoding="utf-8")
            completed = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            record = {
                "case_id": row["case_id"],
                "study": row["study"],
                "pair_id": row["pair_id"],
                "usage": usage,
                "provider_meta": provider_meta,
                "elapsed_seconds": round(time.monotonic() - started, 3),
                "run_config": {
                    "prompt_arm": "A2_evidence",
                    "loaded_prompt_sha256": prompt_sha256,
                    "output_schema_sha256": schema_sha256,
                    "provider": "gemini",
                    "model": MODEL,
                    "temperature": 0.0,
                    "max_output_tokens": MAX_OUTPUT_TOKENS,
                    "thinking_budget": THINKING_BUDGET,
                    "randomisation_seed": SEED,
                },
                "package": {
                    "path": str(row["package_path"].relative_to(ROOT)),
                    "sha256": hashlib.sha256(package_text.encode("utf-8")).hexdigest(),
                },
                "completed_utc": completed,
            }
            with usage_path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(record) + "\n")
            print(
                f"{row['case_id']} ({row['pair_id']}): {output['verdict']}/"
                f"{output['severity']}/{output['recommended_action']} "
                f"conf={output['confidence']} tokens={usage.get('input_tokens')}+"
                f"{usage.get('response_tokens')} visible+{usage.get('thought_tokens')} thought"
            )
        except Exception as exc:
            print(f"{row['case_id']}: ERROR {type(exc).__name__}: {str(exc)[:300]}", file=sys.stderr)


if __name__ == "__main__":
    main()
