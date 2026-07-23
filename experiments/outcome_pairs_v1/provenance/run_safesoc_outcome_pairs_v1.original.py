#!/usr/bin/env python3
"""Run blinded outcome-confirmation packages; dry-run unless --execute is set."""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import random
import time
from datetime import datetime, timezone
from pathlib import Path

import jsonschema


ROOT = Path("/Users/lalala/Desktop/SafeSOC")
SCRATCH = Path("/private/tmp/safesoc_outcome_pairs_v1")


def load_run_model():
    path = ROOT / "eval/run_model.py"
    spec = importlib.util.spec_from_file_location("safesoc_run_model", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--provider", choices=("gemini", "anthropic"), required=True)
    parser.add_argument("--model")
    parser.add_argument("--pairs", help="comma-separated pair ids; default = all")
    parser.add_argument("--limit", type=int)
    parser.add_argument("--seed", type=int, default=190719)
    parser.add_argument("--skip-existing", action="store_true")
    parser.add_argument("--execute", action="store_true", help="required before API calls")
    args = parser.parse_args()

    manifest = json.loads((SCRATCH / "manifest.private.json").read_text(encoding="utf-8"))
    selected = {value.strip() for value in args.pairs.split(",")} if args.pairs else None
    rows = []
    for pair in manifest["pairs"]:
        if selected and pair["pair_id"] not in selected:
            continue
        for version in pair["versions"]:
            rows.append((pair["pair_id"], version))
    random.Random(args.seed).shuffle(rows)
    if args.limit is not None:
        rows = rows[: args.limit]

    run_model = load_run_model()
    schema = json.loads((ROOT / "eval/llm_output.schema.json").read_text(encoding="utf-8"))
    model = args.model or (
        os.environ.get("GEMINI_MODEL", "gemini-2.5-flash")
        if args.provider == "gemini"
        else os.environ.get("ANTHROPIC_MODEL", "claude-sonnet-4-6")
    )
    output_dir = SCRATCH / "outputs" / f"{args.provider}__{model}"
    output_dir.mkdir(parents=True, exist_ok=True)
    pending = [
        (pair_id, row)
        for pair_id, row in rows
        if not (args.skip_existing and (output_dir / f"{row['neutral_case_id']}.json").exists())
    ]

    print(f"provider={args.provider} model={model} packages={len(pending)} seed={args.seed}")
    for index, (pair_id, row) in enumerate(pending, 1):
        print(f"  {index:02d}. {row['neutral_case_id']} pair={pair_id}")
    if not args.execute:
        print("DRY RUN ONLY: add --execute to make API calls")
        return

    env_name = "GEMINI_API_KEY" if args.provider == "gemini" else "ANTHROPIC_API_KEY"
    api_key = os.environ.get(env_name)
    if not api_key:
        raise SystemExit(f"{env_name} is not set")
    prompt = run_model.load_prompt("evidence")
    usage_path = output_dir / "usage.jsonl"
    for index, (pair_id, row) in enumerate(pending):
        if index:
            time.sleep(6.0 if args.provider == "gemini" else 0.5)
        package_text = Path(row["path"]).read_text(encoding="utf-8")
        if args.provider == "gemini":
            raw, usage, provider_meta = run_model.call_gemini(
                prompt, package_text, model, api_key, 0.0, 2048, "off"
            )
        else:
            raw, usage, provider_meta = run_model.call_anthropic(
                prompt, package_text, model, api_key, 0.0, 2048
            )
        output = run_model.extract_json(raw)
        jsonschema.validate(output, schema)
        output_path = output_dir / f"{row['neutral_case_id']}.json"
        output_path.write_text(json.dumps(output, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        usage_row = {
            "case_id": row["neutral_case_id"],
            "pair_id": pair_id,
            "usage": usage,
            "provider_meta": provider_meta,
            "completed_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
        with usage_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(usage_row, ensure_ascii=False) + "\n")
        print(
            f"{row['neutral_case_id']}: {output['verdict']}/{output['severity']} "
            f"action={output['recommended_action']}"
        )
    print(f"outputs: {output_dir}")


if __name__ == "__main__":
    main()
