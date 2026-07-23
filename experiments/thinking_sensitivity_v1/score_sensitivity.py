#!/usr/bin/env python3
"""Compare thinking-off controls with the fixed-budget paired-package treatment."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
MODEL = "gemini-2.5-flash"
THINKING_BUDGET = 1024


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def tuple_of(output: dict) -> tuple[str, str, str]:
    return output["verdict"], output["severity"], output["recommended_action"]


def main() -> None:
    outcome_dir = ROOT / "experiments" / "outcome_pairs_v1"
    context_dir = ROOT / "experiments" / "context_pairs_v1"
    treatment_root = (
        HERE / "outputs" / f"gemini__{MODEL}__thinking-budget-{THINKING_BUDGET}"
    )
    usage_path = treatment_root / "usage.retained.jsonl"

    outcome = load_module("safesoc_outcome_score", outcome_dir / "score_pairs.py")
    context = load_module("safesoc_context_score", context_dir / "score_pairs.py")
    outcome_manifest = json.loads(
        (outcome_dir / "manifest.private.json").read_text(encoding="utf-8")
    )
    context_manifest = json.loads(
        (context_dir / "manifest.private.json").read_text(encoding="utf-8")
    )
    integrity_problems = outcome.audit(outcome_manifest)
    if integrity_problems:
        raise SystemExit("outcome package integrity failed: " + "; ".join(integrity_problems))

    baseline_outcome_dir = outcome_dir / "outputs" / f"gemini__{MODEL}"
    baseline_context_dir = context_dir / "outputs" / f"gemini__{MODEL}"
    treatment_outcome_dir = treatment_root / "outcome"
    treatment_context_dir = treatment_root / "context"

    expected_treatment = {
        version["neutral_case_id"]
        for manifest in (outcome_manifest, context_manifest)
        for pair in manifest["pairs"]
        for version in pair["versions"]
    }
    present_treatment = {
        path.stem for directory in (treatment_outcome_dir, treatment_context_dir)
        for path in directory.glob("*.json")
    }
    missing = sorted(expected_treatment - present_treatment)
    if missing:
        raise SystemExit(f"treatment incomplete: {len(missing)} missing: {missing}")

    baseline_outcome = outcome.score(outcome_manifest, baseline_outcome_dir)
    treatment_outcome = outcome.score(outcome_manifest, treatment_outcome_dir)
    baseline_context = context.score(context_manifest, baseline_context_dir)
    treatment_context = context.score(context_manifest, treatment_context_dir)

    comparisons = []
    for kind, baseline, treatment in (
        ("outcome", baseline_outcome, treatment_outcome),
        ("context", baseline_context, treatment_context),
    ):
        baseline_rows = {row["pair_id"]: row for row in baseline["pairs"]}
        for treated in treatment["pairs"]:
            control = baseline_rows[treated["pair_id"]]
            if kind == "outcome":
                control_outputs = {
                    role: control["versions"][role]["output"] for role in ("base", "strong")
                }
                treatment_outputs = {
                    role: treated["versions"][role]["output"] for role in ("base", "strong")
                }
                control_direction = control["directional_movement"]
                treatment_direction = treated["directional_movement"]
            else:
                control_outputs = {
                    "weak": control["weak_output"], "counter": control["counter_output"]
                }
                treatment_outputs = {
                    "weak": treated["weak_output"], "counter": treated["counter_output"]
                }
                control_direction = control["correct_downward_movement"]
                treatment_direction = treated["correct_downward_movement"]
            changed_roles = [
                role for role in control_outputs
                if tuple_of(control_outputs[role]) != tuple_of(treatment_outputs[role])
            ]
            comparisons.append({
                "pair_type": kind,
                "pair_id": treated["pair_id"],
                "source_case": treated["source_case"],
                "control_endpoint_met": control["primary_endpoint_met"],
                "treatment_endpoint_met": treated["primary_endpoint_met"],
                "control_direction_correct": control_direction,
                "treatment_direction_correct": treatment_direction,
                "changed_roles": changed_roles,
                "control_outputs": control_outputs,
                "treatment_outputs": treatment_outputs,
            })

    usage_rows = []
    if usage_path.exists():
        usage_rows = [
            json.loads(line) for line in usage_path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
    usage_ids = [row["case_id"] for row in usage_rows]
    if len(usage_ids) != len(set(usage_ids)) or set(usage_ids) != expected_treatment:
        raise SystemExit("usage provenance is incomplete, duplicated, or mismatched")

    summary = {
        "pairs": len(comparisons),
        "packages": len(expected_treatment),
        "control_endpoint_met": sum(row["control_endpoint_met"] for row in comparisons),
        "treatment_endpoint_met": sum(row["treatment_endpoint_met"] for row in comparisons),
        "control_direction_correct": sum(
            row["control_direction_correct"] for row in comparisons
        ),
        "treatment_direction_correct": sum(
            row["treatment_direction_correct"] for row in comparisons
        ),
        "pairs_with_any_decision_change": sum(bool(row["changed_roles"]) for row in comparisons),
        "treatment_usage": {
            "input_tokens": sum(row["usage"].get("input_tokens", 0) for row in usage_rows),
            "response_tokens": sum(row["usage"].get("response_tokens", 0) for row in usage_rows),
            "thought_tokens": sum(row["usage"].get("thought_tokens", 0) for row in usage_rows),
            "elapsed_seconds": round(sum(row.get("elapsed_seconds", 0) for row in usage_rows), 3),
        },
    }
    report = {
        "experiment": "Gemini fixed thinking-budget sensitivity",
        "model": MODEL,
        "control_thinking_budget": 0,
        "treatment_thinking_budget": THINKING_BUDGET,
        "summary": summary,
        "pairs": comparisons,
    }
    results_path = HERE / "RESULTS.json"
    results_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2))
    for row in comparisons:
        print(
            f"{row['pair_id']} ({row['pair_type']}): endpoint "
            f"{row['control_endpoint_met']}->{row['treatment_endpoint_met']} | direction "
            f"{row['control_direction_correct']}->{row['treatment_direction_correct']} | "
            f"changed={row['changed_roles']}"
        )
    print(f"wrote {results_path.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
