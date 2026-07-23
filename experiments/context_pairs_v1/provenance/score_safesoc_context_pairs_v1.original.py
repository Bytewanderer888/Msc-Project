#!/usr/bin/env python3
"""Score target bands and downward decision sensitivity for context pairs."""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from pathlib import Path


SCRATCH = Path("/private/tmp/safesoc_context_pairs_v1")
VERDICT_RANK = {"benign": 0, "suspicious": 1, "malicious": 2}
SEVERITY_RANK = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
ACTION_RANK = {"close_benign": 0, "monitor": 1, "investigate": 2, "escalate": 3, "isolate": 4}


def target_correct(output: dict, expected: dict) -> bool:
    return (
        output["verdict"] in expected["verdict"]
        and output["severity"] in expected["severity"]
        and output["recommended_action"] in expected["action"]
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--provider", choices=("gemini", "anthropic"), required=True)
    parser.add_argument("--model", required=True)
    args = parser.parse_args()

    manifest = json.loads((SCRATCH / "manifest.private.json").read_text(encoding="utf-8"))
    output_dir = SCRATCH / "outputs" / f"{args.provider}__{args.model}"
    rows = []
    for pair in manifest["pairs"]:
        versions = {version["role"]: version for version in pair["versions"]}
        paths = {
            role: output_dir / f"{version['neutral_case_id']}.json"
            for role, version in versions.items()
        }
        if not all(path.exists() for path in paths.values()):
            missing = [role for role, path in paths.items() if not path.exists()]
            print(f"{pair['pair_id']}: INCOMPLETE missing={missing}")
            continue
        outputs = {role: json.loads(path.read_text(encoding="utf-8")) for role, path in paths.items()}
        weak = outputs["weak"]
        counter = outputs["counter"]
        weak_ok = target_correct(weak, versions["weak"]["expected"])
        counter_ok = target_correct(counter, versions["counter"]["expected"])
        deltas = {
            "verdict": VERDICT_RANK[counter["verdict"]] - VERDICT_RANK[weak["verdict"]],
            "severity": SEVERITY_RANK[counter["severity"]] - SEVERITY_RANK[weak["severity"]],
            "action": ACTION_RANK[counter["recommended_action"]] - ACTION_RANK[weak["recommended_action"]],
        }
        no_reversal = all(delta <= 0 for delta in deltas.values())
        changed = any(delta != 0 for delta in deltas.values())
        rationale = counter.get("rationale", "")
        context_mentioned = any(
            re.search(re.escape(term), rationale, re.IGNORECASE)
            or any(term.lower() in str(value).lower() for value in counter.get("key_evidence", []))
            for term in pair["required_context_terms"]
        )

        if weak_ok and counter_ok and no_reversal and changed and context_mentioned:
            result = "correct_transition"
        elif (weak["verdict"], weak["severity"], weak["recommended_action"]) == (
            counter["verdict"], counter["severity"], counter["recommended_action"]
        ):
            result = "no_response"
        elif not no_reversal:
            result = "reversed_or_mixed_response"
        elif counter_ok and not weak_ok:
            result = "counter_correct_weak_miscall"
        elif weak_ok and not counter_ok:
            result = "weak_correct_counter_not_downranked"
        else:
            result = "target_miss"
        rows.append({
            "pair_id": pair["pair_id"],
            "source_case": pair["source_case"],
            "result": result,
            "weak_target_correct": weak_ok,
            "counter_target_correct": counter_ok,
            "decision_changed": changed,
            "directional_no_reversal": no_reversal,
            "decision_deltas": deltas,
            "context_mentioned_in_counter": context_mentioned,
            "confidence_delta_counter_minus_weak": round(counter["confidence"] - weak["confidence"], 4),
            "manual_semantic_review_required": True,
        })
        print(
            f"{pair['pair_id']} {pair['source_case']}: {result} "
            f"targets={weak_ok}/{counter_ok} changed={changed} context={context_mentioned}"
        )

    print(f"complete pairs: {len(rows)}/{len(manifest['pairs'])}")
    if rows:
        counts = Counter(row["result"] for row in rows)
        print("result counts:", dict(sorted(counts.items())))
        print(f"both targets correct: {sum(row['weak_target_correct'] and row['counter_target_correct'] for row in rows)}/{len(rows)}")


if __name__ == "__main__":
    main()
