#!/usr/bin/env python3
"""Run the outcome-pair packages that have no saved output yet (skip-existing by design).

Uses the frozen benchmark settings: the A2 evidence prompt (rm.load_prompt("evidence")),
temperature 0, thinking off, rm.GEN_MAX_TOKENS — the same configuration as the main
benchmark arms, so pair results are comparable to the established A2 behaviour.

The original experiment runner is retained under provenance/. RUN_CONFIG.json records the
verified prompt and runner hashes used to establish configuration equivalence.

    export GEMINI_API_KEY="..."
    python3 experiments/outcome_pairs_v1/run_pairs.py                 # dry-run: lists missing cases
    python3 experiments/outcome_pairs_v1/run_pairs.py --execute       # runs only missing cases
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / "eval"))
import run_model as rm  # noqa: E402

try:
    from jsonschema import Draft7Validator
except ImportError as exc:  # pragma: no cover
    raise SystemExit("run_pairs.py requires the 'jsonschema' package") from exc


DEFAULT_MODELS = {"gemini": "gemini-2.5-flash", "anthropic": "claude-sonnet-4-6"}
KEY_ENV = {"gemini": "GEMINI_API_KEY", "anthropic": "ANTHROPIC_API_KEY"}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", help="defaults per provider: gemini-2.5-flash / claude-sonnet-4-6")
    ap.add_argument("--provider", choices=("gemini", "anthropic"), default="gemini")
    ap.add_argument("--round", type=int, default=1,
                    help="stability round; >1 appends _roundN to the output dir (benchmark "
                         "convention — Claude action wobble requires x3 majority)")
    ap.add_argument("--only", help="comma-separated QE ids; default = every package without an output")
    ap.add_argument("--execute", action="store_true", help="required before API calls")
    args = ap.parse_args()
    model = args.model or DEFAULT_MODELS[args.provider]

    man = json.loads((HERE / "manifest.private.json").read_text())
    pair_of = {v["neutral_case_id"]: p["pair_id"] for p in man["pairs"] for v in p["versions"]}
    round_suffix = f"_round{args.round}" if args.round > 1 else ""
    outdir = HERE / "outputs" / f"{args.provider}__{model}{round_suffix}"
    validator = Draft7Validator(rm.OUT_SCHEMA)
    system = rm.load_prompt("evidence")          # the frozen A2 analyst prompt

    wanted = ([c.strip() for c in args.only.split(",") if c.strip()] if args.only
              else sorted(pair_of))
    unknown = sorted(set(wanted) - set(pair_of))
    if unknown:
        raise SystemExit(f"unknown package id(s): {unknown}")
    todo = [c for c in wanted if not (outdir / f"{c}.json").exists()]
    print(f"{len(todo)} case(s) to run (skip-existing): {todo}")
    if not args.execute:
        print("DRY RUN ONLY: add --execute to make API calls")
        return

    key_env = KEY_ENV[args.provider]
    key = os.environ.get(key_env, "").strip()
    quote_pairs = (("\"", "\""), ("'", "'"), ("“", "”"), ("‘", "’"))
    for left, right in quote_pairs:
        if key.startswith(left) and key.endswith(right):
            key = key[len(left):-len(right)].strip()
            break
    if not key:
        raise SystemExit(f'{key_env} not set.  export {key_env}="..."')
    if any(ord(character) > 127 for character in key):
        raise SystemExit(f"{key_env} contains a non-ASCII character; remove smart quotes or spaces")

    prompt_sha256 = hashlib.sha256(system.encode("utf-8")).hexdigest()
    outdir.mkdir(parents=True, exist_ok=True)

    for index, cid in enumerate(todo):
        if index:
            time.sleep(6.0)
        pkg_path = HERE / "packages" / f"{cid}.json"
        pkg_text = pkg_path.read_text(encoding="utf-8")
        if args.provider == "gemini":
            text, usage, meta = rm.call_gemini(
                system, pkg_text, model, key,
                temperature=0.0, max_tokens=rm.GEN_MAX_TOKENS, thinking="off",
            )
        else:
            text, usage, meta = rm.call_anthropic(
                system, pkg_text, model, key,
                temperature=0.0, max_tokens=rm.GEN_MAX_TOKENS,
            )
        output = rm.extract_json(text)
        errors = sorted(e.message for e in validator.iter_errors(output))
        if errors:
            print(f"{cid}: SCHEMA-INVALID output, not saved ({errors[0]})")
            continue
        (outdir / f"{cid}.json").write_text(json.dumps(output, indent=2) + "\n", encoding="utf-8")
        with (outdir / "usage.retained.jsonl").open("a", encoding="utf-8") as fh:
            fh.write(json.dumps({
                "case_id": cid, "pair_id": pair_of.get(cid), "usage": usage,
                "provider_meta": meta,
                "run_config": {
                    "prompt_arm": "A2_evidence",
                    "loaded_prompt_sha256": prompt_sha256,
                    "provider": args.provider,
                    "model": model,
                    "round": args.round,
                    "temperature": 0.0,
                    "max_output_tokens": rm.GEN_MAX_TOKENS,
                    **({"thinking": "off"} if args.provider == "gemini" else {}),
                },
                "completed_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            }) + "\n")
        print(f"{cid} ({pair_of.get(cid)}): {output['verdict']}/{output['severity']}/"
              f"{output['recommended_action']}  conf={output['confidence']}  "
              f"tokens={usage.get('input_tokens')}+{usage.get('output_tokens')}")


if __name__ == "__main__":
    main()
