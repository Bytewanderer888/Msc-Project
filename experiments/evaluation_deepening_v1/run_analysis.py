#!/usr/bin/env python3
"""Offline evaluation deepening over the frozen SafeSOC A2 reports.

No provider is called and no canonical package, ground truth, or saved model
output is modified.  The script derives ordinal error distances, uncertainty,
paired held-out comparisons, field-level stability, and validator conformance
from the existing reports.
"""

from __future__ import annotations

import csv
import json
import math
import random
import statistics
import sys
from datetime import datetime, timezone
from pathlib import Path


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
EVAL = ROOT / "eval"
REPORTS = EVAL / "reports"
sys.path.insert(0, str(EVAL))

import conformance_suite  # noqa: E402
import validator_v1_1 as validator  # noqa: E402


REPORT_FILES = {
    ("gemini-2.5-flash", "dev", 1): "gemini-2.5-flash__A2_evidence_prompt_dev.json",
    ("gemini-2.5-flash", "dev", 2): "gemini-2.5-flash__A2_evidence_prompt_round2_dev.json",
    ("gemini-2.5-flash", "dev", 3): "gemini-2.5-flash__A2_evidence_prompt_round3_dev.json",
    ("gemini-2.5-flash", "heldout", 1): "gemini-2.5-flash__A2_evidence_prompt_heldout.json",
    ("gemini-2.5-flash", "heldout", 2): "gemini-2.5-flash__A2_evidence_prompt_round2_heldout.json",
    ("gemini-2.5-flash", "heldout", 3): "gemini-2.5-flash__A2_evidence_prompt_round3_heldout.json",
    ("claude-sonnet-4-6", "dev", 1): "claude-sonnet-4-6__A2_evidence_prompt_dev_A4.json",
    ("claude-sonnet-4-6", "dev", 2): "claude-sonnet-4-6__A2_evidence_prompt_round2_dev_A4.json",
    ("claude-sonnet-4-6", "dev", 3): "claude-sonnet-4-6__A2_evidence_prompt_round3_dev_A4.json",
    ("claude-sonnet-4-6", "heldout", 1): "claude-sonnet-4-6__A2_evidence_prompt_heldout_A4.json",
    ("claude-sonnet-4-6", "heldout", 2): "claude-sonnet-4-6__A2_evidence_prompt_round2_heldout_A4.json",
    ("claude-sonnet-4-6", "heldout", 3): "claude-sonnet-4-6__A2_evidence_prompt_round3_heldout_A4.json",
}

RUNTIME_COMPARISON_FILES = {
    "dev": "runtime_v1_1_vs_A4_gemini-2.5-flash__A2_evidence_prompt_dev_calibration.json",
    "heldout": "runtime_v1_1_vs_A4_gemini-2.5-flash__A2_evidence_prompt_heldout_calibration.json",
}

FIELD_ORDER = {
    "verdict": validator.VERDICTS,
    "severity": validator.SEVERITIES,
    "action": validator.ACTIONS,
}
OUTPUT_KEY = {
    "verdict": "verdict",
    "severity": "severity",
    "action": "recommended_action",
}
CHECK_KEY = {
    "C1": "C1_reference_integrity",
    "C2": "C2_decision_calibration",
    "C3": "C3_counter_acknowledgement",
    "C4": "C4_action_calibration",
}


def load_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"cannot read {path}: {exc}") from exc


def ordinal_distance(value: str, acceptable: list[str], ordering: list[str]) -> int:
    """Signed steps from the nearest boundary; zero means in-band."""
    value_index = ordering.index(value)
    band = [ordering.index(item) for item in acceptable]
    lower, upper = min(band), max(band)
    if value_index < lower:
        return value_index - lower
    if value_index > upper:
        return value_index - upper
    return 0


def acceptable_band(condition: str, field: str) -> list[str]:
    policy = validator.CONDITION_POLICY[condition]
    if field == "verdict":
        return [policy["verdict"]]
    if field == "severity":
        return policy["severity"]
    return policy["actions"]


def wilson_interval(successes: int, n: int, z: float = 1.959963984540054) -> list[float]:
    if n == 0:
        return [0.0, 0.0]
    p = successes / n
    denominator = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denominator
    margin = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denominator
    return [round(max(0.0, centre - margin), 4), round(min(1.0, centre + margin), 4)]


def exact_mcnemar(b: int, c: int) -> float:
    discordant = b + c
    if discordant == 0:
        return 1.0
    tail = sum(math.comb(discordant, k) for k in range(min(b, c) + 1)) / (2**discordant)
    return round(min(1.0, 2 * tail), 6)


def bootstrap_mean_ci(values: list[float], seed: int = 20260722, draws: int = 20000) -> list[float]:
    if not values:
        return [0.0, 0.0]
    rng = random.Random(seed)
    n = len(values)
    means = []
    for _ in range(draws):
        means.append(sum(values[rng.randrange(n)] for _ in range(n)) / n)
    means.sort()
    lower = means[int(0.025 * draws)]
    upper = means[min(draws - 1, int(0.975 * draws))]
    return [round(lower, 4), round(upper, 4)]


def load_units() -> tuple[dict[tuple[str, str, int], dict], list[dict]]:
    units = {}
    rows = []
    for key, filename in REPORT_FILES.items():
        model, split, round_number = key
        report = load_json(REPORTS / filename)
        active = report.get("summary", {}).get("active_checks")
        if active != ["C1", "C2", "C3", "C4"]:
            raise SystemExit(f"{filename} is not a complete A4 report: active_checks={active}")
        expected_n = 21 if split == "dev" else 20
        if len(report.get("cases", [])) != expected_n:
            raise SystemExit(f"{filename} has {len(report.get('cases', []))} cases, expected {expected_n}")
        units[key] = report
        for case in report["cases"]:
            condition = case["condition"]
            output = case["model_output"]
            checks = case["checks"]
            distances = {}
            for field, ordering in FIELD_ORDER.items():
                value = output[OUTPUT_KEY[field]]
                distances[field] = ordinal_distance(
                    value, acceptable_band(condition, field), ordering
                )
            check_pass = {name: checks[key_name]["pass"] for name, key_name in CHECK_KEY.items()}
            rows.append(
                {
                    "model": model,
                    "split": split,
                    "round": round_number,
                    "case_id": case["case_id"],
                    "condition": condition,
                    "verdict": output["verdict"],
                    "severity": output["severity"],
                    "action": output["recommended_action"],
                    "confidence": output.get("confidence"),
                    "verdict_distance": distances["verdict"],
                    "severity_distance": distances["severity"],
                    "action_distance": distances["action"],
                    "C1_pass": check_pass["C1"],
                    "C2_pass": check_pass["C2"],
                    "C3_pass": check_pass["C3"],
                    "C4_pass": check_pass["C4"],
                    "A4_pass": all(check_pass.values()),
                }
            )
    return units, rows


def stable_seed(label: str) -> int:
    return 20260722 + sum((index + 1) * ord(char) for index, char in enumerate(label))


def field_summary(unit_rows: list[dict], field: str, label: str) -> dict:
    distances = [row[f"{field}_distance"] for row in unit_rows]
    n = len(distances)
    in_band = sum(distance == 0 for distance in distances)
    severe = sum(abs(distance) >= 2 for distance in distances)
    signed_mean = sum(distances) / n
    absolute_values = [abs(item) for item in distances]
    absolute_mean = sum(absolute_values) / n
    return {
        "in_band_n": in_band,
        "in_band_rate": round(in_band / n, 4),
        "mean_signed_distance": round(signed_mean, 4),
        "mean_signed_distance_bootstrap_95": bootstrap_mean_ci(
            distances, seed=stable_seed(f"{label}:{field}:signed")
        ),
        "mean_absolute_distance": round(absolute_mean, 4),
        "mean_absolute_distance_bootstrap_95": bootstrap_mean_ci(
            absolute_values, seed=stable_seed(f"{label}:{field}:absolute")
        ),
        "severe_error_n": severe,
        "severe_error_rate": round(severe / n, 4),
        "severe_error_wilson_95": wilson_interval(severe, n),
    }


def unit_summaries(rows: list[dict]) -> list[dict]:
    summaries = []
    for model, split, round_number in REPORT_FILES:
        unit_rows = [
            row
            for row in rows
            if row["model"] == model and row["split"] == split and row["round"] == round_number
        ]
        n = len(unit_rows)
        c2_n = sum(row["C2_pass"] for row in unit_rows)
        a4_n = sum(row["A4_pass"] for row in unit_rows)
        any_severe = sum(
            any(abs(row[f"{field}_distance"]) >= 2 for field in FIELD_ORDER)
            for row in unit_rows
        )
        by_condition = {}
        for condition in validator.CONDITION_POLICY:
            condition_rows = [row for row in unit_rows if row["condition"] == condition]
            condition_n = len(condition_rows)
            c2_condition_n = sum(row["C2_pass"] for row in condition_rows)
            a4_condition_n = sum(row["A4_pass"] for row in condition_rows)
            by_condition[condition] = {
                "n": condition_n,
                "C2_joint_n": c2_condition_n,
                "C2_joint_rate": round(c2_condition_n / condition_n, 4),
                "A4_all_pass_n": a4_condition_n,
                "A4_all_pass_rate": round(a4_condition_n / condition_n, 4),
                "fields": {
                    field: field_summary(
                        condition_rows,
                        field,
                        f"{model}:{split}:r{round_number}:{condition}",
                    )
                    for field in FIELD_ORDER
                },
            }
        summaries.append(
            {
                "model": model,
                "split": split,
                "round": round_number,
                "n": n,
                "C2_joint_n": c2_n,
                "C2_joint_rate": round(c2_n / n, 4),
                "C2_wilson_95": wilson_interval(c2_n, n),
                "A4_all_pass_n": a4_n,
                "A4_all_pass_rate": round(a4_n / n, 4),
                "A4_wilson_95": wilson_interval(a4_n, n),
                "any_severe_ordinal_error_n": any_severe,
                "any_severe_ordinal_error_rate": round(any_severe / n, 4),
                "any_severe_ordinal_error_wilson_95": wilson_interval(any_severe, n),
                "macro_condition_C2_rate": round(
                    sum(item["C2_joint_rate"] for item in by_condition.values())
                    / len(by_condition),
                    4,
                ),
                "macro_condition_A4_rate": round(
                    sum(item["A4_all_pass_rate"] for item in by_condition.values())
                    / len(by_condition),
                    4,
                ),
                "fields": {
                    field: field_summary(
                        unit_rows, field, f"{model}:{split}:r{round_number}:all"
                    )
                    for field in FIELD_ORDER
                },
                "by_condition": by_condition,
            }
        )
    return summaries


def paired_heldout_analysis(rows: list[dict]) -> dict:
    by_model = {}
    for model in ("gemini-2.5-flash", "claude-sonnet-4-6"):
        by_model[model] = {
            row["case_id"]: row
            for row in rows
            if row["model"] == model and row["split"] == "heldout" and row["round"] == 1
        }
    gemini = by_model["gemini-2.5-flash"]
    claude = by_model["claude-sonnet-4-6"]
    if set(gemini) != set(claude):
        raise SystemExit("held-out round-1 model reports do not contain the same cases")
    case_ids = sorted(gemini)
    b = sum(gemini[item]["C2_pass"] and not claude[item]["C2_pass"] for item in case_ids)
    c = sum(not gemini[item]["C2_pass"] and claude[item]["C2_pass"] for item in case_ids)
    paired_differences = [
        int(gemini[item]["C2_pass"]) - int(claude[item]["C2_pass"]) for item in case_ids
    ]
    result = {
        "endpoint": "C2 joint decision correctness",
        "scope": "heldout round 1 only",
        "n_pairs": len(case_ids),
        "gemini_pass_claude_fail": b,
        "gemini_fail_claude_pass": c,
        "paired_risk_difference_gemini_minus_claude": round(
            sum(paired_differences) / len(paired_differences), 4
        ),
        "paired_risk_difference_bootstrap_95": bootstrap_mean_ci(paired_differences),
        "mcnemar_exact_two_sided_p": exact_mcnemar(b, c),
        "ordinal_absolute_distance_difference": {},
        "discordant_cases": {
            "gemini_only_correct": [
                item for item in case_ids if gemini[item]["C2_pass"] and not claude[item]["C2_pass"]
            ],
            "claude_only_correct": [
                item for item in case_ids if not gemini[item]["C2_pass"] and claude[item]["C2_pass"]
            ],
        },
    }
    for index, field in enumerate(FIELD_ORDER):
        differences = [
            abs(gemini[item][f"{field}_distance"]) - abs(claude[item][f"{field}_distance"])
            for item in case_ids
        ]
        result["ordinal_absolute_distance_difference"][field] = {
            "mean_gemini_minus_claude": round(sum(differences) / len(differences), 4),
            "median_gemini_minus_claude": round(statistics.median(differences), 4),
            "bootstrap_95": bootstrap_mean_ci(differences, seed=20260722 + index + 1),
            "interpretation": "negative favours Gemini; positive favours Claude",
        }
    return result


def runtime_uncertainty() -> list[dict]:
    rows = []
    for split, filename in RUNTIME_COMPARISON_FILES.items():
        report = load_json(REPORTS / filename)
        if report.get("target") != "calibration":
            raise SystemExit(f"{filename} is not the calibration-target runtime report")
        n = report["n"]
        positives = report["oracle_positive_n"]
        for profile_name, profile in report["profiles"].items():
            recall_n = profile["tp"]
            deferral_n = profile["deferral_n"]
            rows.append(
                {
                    "model": report["model"],
                    "split": split,
                    "target": "C2/C4 calibration-positive",
                    "profile": profile_name,
                    "oracle_positive_n": positives,
                    "recall_n": recall_n,
                    "recall_rate": round(recall_n / positives, 4),
                    "recall_wilson_95": wilson_interval(recall_n, positives),
                    "review_n": deferral_n,
                    "review_rate": round(deferral_n / n, 4),
                    "review_wilson_95": wilson_interval(deferral_n, n),
                    "unrouted_error_n": profile["fn"],
                }
            )
    return rows


def stability_analysis(rows: list[dict]) -> list[dict]:
    results = []
    fields = ("verdict", "severity", "action")
    for model in ("gemini-2.5-flash", "claude-sonnet-4-6"):
        for split in ("dev", "heldout"):
            round_maps = {
                round_number: {
                    row["case_id"]: row
                    for row in rows
                    if row["model"] == model
                    and row["split"] == split
                    and row["round"] == round_number
                }
                for round_number in (1, 2, 3)
            }
            common = set.intersection(*(set(items) for items in round_maps.values()))
            if any(set(items) != common for items in round_maps.values()):
                raise SystemExit(f"incomplete stability cell for {model} {split}")
            cases = []
            field_agreement = {field: 0 for field in fields}
            exact_agreement = 0
            one_field_variation = 0
            multi_field_variation = 0
            for case_id in sorted(common):
                values = {
                    field: [round_maps[round_number][case_id][field] for round_number in (1, 2, 3)]
                    for field in fields
                }
                stable_fields = {field: len(set(field_values)) == 1 for field, field_values in values.items()}
                for field in fields:
                    field_agreement[field] += stable_fields[field]
                varied = [field for field in fields if not stable_fields[field]]
                if not varied:
                    exact_agreement += 1
                elif len(varied) == 1:
                    one_field_variation += 1
                else:
                    multi_field_variation += 1
                cases.append(
                    {
                        "case_id": case_id,
                        "stable": not varied,
                        "varied_fields": varied,
                        "values": values,
                    }
                )
            pairwise = {}
            for left, right in ((1, 2), (1, 3), (2, 3)):
                pairwise[f"round_{left}_vs_{right}"] = {
                    field: round(
                        sum(
                            round_maps[left][case_id][field] == round_maps[right][case_id][field]
                            for case_id in common
                        )
                        / len(common),
                        4,
                    )
                    for field in fields
                }
                pairwise[f"round_{left}_vs_{right}"]["tuple"] = round(
                    sum(
                        all(
                            round_maps[left][case_id][field] == round_maps[right][case_id][field]
                            for field in fields
                        )
                        for case_id in common
                    )
                    / len(common),
                    4,
                )
            results.append(
                {
                    "model": model,
                    "split": split,
                    "n": len(common),
                    "all_three_rounds_agree": {
                        **{field: field_agreement[field] for field in fields},
                        "tuple": exact_agreement,
                    },
                    "all_three_rounds_agree_rate": {
                        **{field: round(field_agreement[field] / len(common), 4) for field in fields},
                        "tuple": round(exact_agreement / len(common), 4),
                    },
                    "one_field_variation_n": one_field_variation,
                    "multi_field_variation_n": multi_field_variation,
                    "pairwise_agreement_rate": pairwise,
                    "unstable_cases": [case for case in cases if not case["stable"]],
                }
            )
    return results


def write_case_csv(rows: list[dict]) -> None:
    fields = list(rows[0])
    with (HERE / "case_metrics.csv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def pct(value: float) -> str:
    return f"{100 * value:.1f}%"


def render_markdown(results: dict) -> str:
    summaries = results["unit_summaries"]
    main = [row for row in summaries if row["split"] == "heldout" and row["round"] == 1]
    paired = results["paired_heldout_round1"]
    lines = [
        "# Evaluation deepening v1 results",
        "",
        "This analysis reuses the frozen A2/A4 reports. It makes no provider calls and does not modify packages, ground truth, or saved outputs.",
        "",
        "## Primary held-out results",
        "",
        "| Model | C2 joint | Wilson 95% CI | A4 all-pass | Wilson 95% CI |",
        "|---|---:|---:|---:|---:|",
    ]
    for row in main:
        lines.append(
            f"| {row['model']} | {row['C2_joint_n']}/{row['n']} ({pct(row['C2_joint_rate'])}) "
            f"| {pct(row['C2_wilson_95'][0])}-{pct(row['C2_wilson_95'][1])} "
            f"| {row['A4_all_pass_n']}/{row['n']} ({pct(row['A4_all_pass_rate'])}) "
            f"| {pct(row['A4_wilson_95'][0])}-{pct(row['A4_wilson_95'][1])} |"
        )
    lines.extend(
        [
            "",
            "C2 remains the headline endpoint. Ordinal distance adds error magnitude: zero is in-band, positive is over-triage, and negative is under-triage.",
            "",
            "### Ordinal error magnitude",
            "",
            "| Model | Field | In band | Mean signed distance | Mean absolute distance | Errors >=2 steps |",
            "|---|---|---:|---:|---:|---:|",
        ]
    )
    for row in main:
        for field in FIELD_ORDER:
            metrics = row["fields"][field]
            lines.append(
                f"| {row['model']} | {field} | {metrics['in_band_n']}/{row['n']} ({pct(metrics['in_band_rate'])}) "
                f"| {metrics['mean_signed_distance']:+.3f} | {metrics['mean_absolute_distance']:.3f} "
                f"| {metrics['severe_error_n']}/{row['n']} |"
            )
    lines.extend(
        [
            "",
            "### Condition breakdown (descriptive)",
            "",
            "| Model | Condition | n | C2 joint | Mean signed severity distance | Mean signed action distance |",
            "|---|---|---:|---:|---:|---:|",
        ]
    )
    for row in main:
        for condition, metrics in row["by_condition"].items():
            lines.append(
                f"| {row['model']} | {condition} | {metrics['n']} "
                f"| {metrics['C2_joint_n']}/{metrics['n']} ({pct(metrics['C2_joint_rate'])}) "
                f"| {metrics['fields']['severity']['mean_signed_distance']:+.3f} "
                f"| {metrics['fields']['action']['mean_signed_distance']:+.3f} |"
            )
    lines.extend(
        [
            "",
            "Macro condition averages are descriptive only: they give the small counter stratum the same weight as larger strata.",
            "",
            "## Paired model comparison",
            "",
            f"On the same 20 held-out cases, the paired C2 risk difference (Gemini minus Claude) is {paired['paired_risk_difference_gemini_minus_claude']:+.3f} "
            f"with bootstrap 95% CI [{paired['paired_risk_difference_bootstrap_95'][0]:+.3f}, {paired['paired_risk_difference_bootstrap_95'][1]:+.3f}].",
            f"The discordant counts are {paired['gemini_pass_claude_fail']} Gemini-only correct and {paired['gemini_fail_claude_pass']} Claude-only correct; "
            f"exact two-sided McNemar p = {paired['mcnemar_exact_two_sided_p']:.3f}.",
            "The interval is wide and the paired test does not establish a reliable model advantage; report the observed difference without claiming superiority.",
            "",
            "## Three-round stability",
            "",
            "| Model | Split | Verdict | Severity | Action | Full tuple | One-field changes | Multi-field changes |",
            "|---|---|---:|---:|---:|---:|---:|---:|",
        ]
    )
    for row in results["stability"]:
        rates = row["all_three_rounds_agree_rate"]
        lines.append(
            f"| {row['model']} | {row['split']} | {pct(rates['verdict'])} | {pct(rates['severity'])} "
            f"| {pct(rates['action'])} | {pct(rates['tuple'])} | {row['one_field_variation_n']} | {row['multi_field_variation_n']} |"
        )
    lines.extend(
        [
            "",
            "## Runtime uncertainty (Gemini A2 round 1)",
            "",
            "| Split | Profile | Recall | Wilson 95% CI | Human review | Wilson 95% CI | Unrouted calibration errors |",
            "|---|---|---:|---:|---:|---:|---:|",
        ]
    )
    for row in results["runtime_uncertainty"]:
        if row["profile"] not in {"consequence_gate", "safety_first"}:
            continue
        lines.append(
            f"| {row['split']} | {row['profile']} "
            f"| {row['recall_n']}/{row['oracle_positive_n']} ({pct(row['recall_rate'])}) "
            f"| {pct(row['recall_wilson_95'][0])}-{pct(row['recall_wilson_95'][1])} "
            f"| {row['review_n']}/{21 if row['split'] == 'dev' else 20} ({pct(row['review_rate'])}) "
            f"| {pct(row['review_wilson_95'][0])}-{pct(row['review_wilson_95'][1])} "
            f"| {row['unrouted_error_n']} |"
        )
    conformance = results["conformance"]
    lines.extend(
        [
            "",
            "## Validator conformance",
            "",
            f"All {conformance['passed_n']}/{conformance['n']} controlled mutation scenarios produced the predeclared C1-C4 vector.",
            "The suite covers order/confidence/prose invariance, fabricated IDs, unsupported decode claims, verdict and severity changes, counter-citation removal, action changes, and a combined C2+C4 failure.",
            "It tests deterministic implementation behaviour only; semantic truthfulness remains a manual audit boundary.",
            "",
            "## Interpretation guardrails",
            "",
            "- Held-out round 1 is the primary model comparison; rounds 2 and 3 are stability repetitions, not independent samples.",
            "- Wilson and bootstrap intervals expose the uncertainty caused by 20 held-out cases.",
            "- Verdict, severity, and action distances stay separate; no arbitrary composite score is introduced.",
            "- Confidence remains exploratory and does not affect C1-C4.",
            "- C1/C3 do not provide broad semantic natural-language verification.",
            "",
        ]
    )
    return "\n".join(lines)


def render_conformance(rows: list[dict]) -> str:
    lines = [
        "# Validator v1.1 conformance matrix",
        "",
        "| Scenario | Purpose | Expected C1/C2/C3/C4 | Observed | Result |",
        "|---|---|---|---|---:|",
    ]
    for row in rows:
        expected = "/".join("P" if row["expected"][check] else "F" for check in CHECK_KEY)
        observed = "/".join("P" if row["observed"][check] else "F" for check in CHECK_KEY)
        lines.append(
            f"| {row['scenario_id']} | {row['purpose']} | {expected} | {observed} | {'PASS' if row['pass'] else 'FAIL'} |"
        )
    lines.extend(
        [
            "",
            "Scope note: the suite checks deterministic check isolation and metamorphic invariance. It deliberately does not claim that C1 can detect every unsupported free-text assertion or that C3 understands the meaning of counter-evidence prose.",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> None:
    _units, rows = load_units()
    conformance_rows = conformance_suite.run_suite()
    results = {
        "analysis_version": "1.0",
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "source": "12 complete frozen A2/A4 report cells (2 models x 2 splits x 3 rounds)",
        "model_calls": 0,
        "case_output_rows": len(rows),
        "unit_summaries": unit_summaries(rows),
        "paired_heldout_round1": paired_heldout_analysis(rows),
        "stability": stability_analysis(rows),
        "runtime_uncertainty": runtime_uncertainty(),
        "conformance": {
            "n": len(conformance_rows),
            "passed_n": sum(row["pass"] for row in conformance_rows),
            "all_pass": all(row["pass"] for row in conformance_rows),
            "scenarios": conformance_rows,
        },
    }
    write_case_csv(rows)
    (HERE / "RESULTS.json").write_text(
        json.dumps(results, indent=2, ensure_ascii=True) + "\n", encoding="utf-8"
    )
    (HERE / "RESULTS.md").write_text(render_markdown(results), encoding="utf-8")
    (HERE / "CONFORMANCE_MATRIX.md").write_text(
        render_conformance(conformance_rows), encoding="utf-8"
    )
    print(f"wrote {HERE / 'RESULTS.json'}")
    print(f"wrote {HERE / 'RESULTS.md'}")
    print(f"wrote {HERE / 'case_metrics.csv'} ({len(rows)} rows)")
    print(
        f"conformance: {results['conformance']['passed_n']}/{results['conformance']['n']} passed"
    )


if __name__ == "__main__":
    main()
