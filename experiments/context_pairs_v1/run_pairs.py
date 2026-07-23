#!/usr/bin/env python3
"""Run missing context-pair packages with the frozen A2 prompt.

The command is a dry-run unless --execute is supplied. Existing outputs are skipped by
default so a completed experiment cannot consume API quota accidentally.
"""
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


def clean_api_key(value: str) -> str:
    key = value.strip()
    for left, right in (("\"", "\""), ("'", "'"), ("“", "”"), ("‘", "’")):
        if key.startswith(left) and key.endswith(right):
            key = key[len(left):-len(right)].strip()
            break
    if any(ord(character) > 127 for character in key):
        raise SystemExit("API key contains a non-ASCII character; remove smart quotes or spaces")
    return key


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--provider", choices=("gemini", "anthropic"), default="gemini")
    parser.add_argument("--model")
    parser.add_argument("--only", help="comma-separated QC ids; default = every missing output")
    parser.add_argument("--seed", type=int, default=190720)
    parser.add_argument("--execute", action="store_true", help="required before API calls")
    args = parser.parse_args()

    manifest = json.loads((HERE / "manifest.private.json").read_text(encoding="utf-8"))
    pair_of = {
        version["neutral_case_id"]: pair["pair_id"]
        for pair in manifest["pairs"]
        for version in pair["versions"]
    }
    all_ids = list(pair_of)
    random.Random(args.seed).shuffle(all_ids)
    wanted = (
        [case_id.strip() for case_id in args.only.split(",") if case_id.strip()]
        if args.only else all_ids
    )
    unknown = sorted(set(wanted) - set(pair_of))
    if unknown:
        raise SystemExit(f"unknown package id(s): {unknown}")

    default_model = "gemini-2.5-flash" if args.provider == "gemini" else "claude-sonnet-4-6"
    model = args.model or default_model
    outdir = HERE / "outputs" / f"{args.provider}__{model}"
    outdir.mkdir(parents=True, exist_ok=True)
    todo = [case_id for case_id in wanted if not (outdir / f"{case_id}.json").exists()]
    print(f"{len(todo)} case(s) to run (skip-existing): {todo}")
    if not args.execute:
        print("DRY RUN ONLY: add --execute to make API calls")
        return
    if not todo:
        return

    env_name = "GEMINI_API_KEY" if args.provider == "gemini" else "ANTHROPIC_API_KEY"
    api_key = clean_api_key(os.environ.get(env_name, ""))
    if not api_key:
        raise SystemExit(f'{env_name} not set. export {env_name}="..."')

    prompt = rm.load_prompt("evidence")
    prompt_sha256 = hashlib.sha256(prompt.encode("utf-8")).hexdigest()
    validator = Draft7Validator(rm.OUT_SCHEMA)
    usage_path = outdir / "usage.retained.jsonl"

    for index, case_id in enumerate(todo):
        if index:
            time.sleep(6.0 if args.provider == "gemini" else 0.5)
        package_text = (HERE / "packages" / f"{case_id}.json").read_text(encoding="utf-8")
        if args.provider == "gemini":
            raw, usage, provider_meta = rm.call_gemini(
                prompt, package_text, model, api_key, 0.0, rm.GEN_MAX_TOKENS, "off"
            )
        else:
            raw, usage, provider_meta = rm.call_anthropic(
                prompt, package_text, model, api_key, 0.0, rm.GEN_MAX_TOKENS
            )
        output = rm.extract_json(raw)
        errors = sorted(error.message for error in validator.iter_errors(output))
        if errors:
            print(f"{case_id}: SCHEMA-INVALID output, not saved ({errors[0]})")
            continue

        (outdir / f"{case_id}.json").write_text(
            json.dumps(output, indent=2) + "\n", encoding="utf-8"
        )
        usage_row = {
            "case_id": case_id,
            "pair_id": pair_of[case_id],
            "usage": usage,
            "provider_meta": provider_meta,
            "run_config": {
                "prompt_arm": "A2_evidence",
                "loaded_prompt_sha256": prompt_sha256,
                "temperature": 0.0,
                "max_output_tokens": rm.GEN_MAX_TOKENS,
                "thinking": "off" if args.provider == "gemini" else "not_applicable",
                "seed": args.seed,
            },
            "completed_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
        with usage_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(usage_row) + "\n")
        print(
            f"{case_id} ({pair_of[case_id]}): {output['verdict']}/{output['severity']}/"
            f"{output['recommended_action']} conf={output['confidence']} "
            f"tokens={usage.get('input_tokens')}+{usage.get('output_tokens')}"
        )


if __name__ == "__main__":
    main()
