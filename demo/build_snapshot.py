#!/usr/bin/env python3
"""Index the frozen benchmark for the SafeSOC validation workbench.

Walks the 41 frozen cases, every saved model-output arm/round, and runs both evaluators
offline to precompute the dashboard:

  * runtime  — runtime_validator.validate_runtime_case  (package + output + policy only)
  * research — validator_v1_1.validate_case             (adds frozen ground truth, A4)

Writes two intentionally separate browser payloads:

  * demo/snapshot.json          — runtime-neutral index loaded at startup
  * demo/research_snapshot.json — GT-derived results loaded only on explicit research access

Nothing here calls a model API; the workbench replays saved outputs. Re-run whenever
cases, outputs, or usage logs change.

    python3 demo/build_snapshot.py
"""
from __future__ import annotations

import json
import math
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT / "eval"))
import runtime_validator as rv   # noqa: E402  the deployable policy layer
import validator_v1_1 as vv      # noqa: E402  the offline A4 oracle
import cost as cost_eval         # noqa: E402  current usage-log aggregation

TAG_RE = re.compile(r"^(?P<model>.+?)__(?P<arm>A\d_[a-z_]+?)(?:_round(?P<round>\d+))?$")
SEV_ORDER = ["informational", "low", "medium", "high", "critical"]
SKIP_TAG_MARKERS = ("__EXP_", "_void", "_VOID")
DEMO_POLICY = ROOT / "eval" / "runtime_policy_v1.2.json"
DEEPENING_RESULTS = ROOT / "experiments" / "evaluation_deepening_v1" / "RESULTS.json"
EXTERNAL_STUDY = ROOT / "experiments" / "external_replication_v1"
EXTERNAL_RUNS = {
    "gemini-2.5-flash": {
        "report": EXTERNAL_STUDY / "reports/gemini_a4.json",
        "tag": "gemini-2.5-flash__A2_evidence_prompt__EXP_external_replication_v1",
        "canonical_report": ROOT / "eval/reports/gemini-2.5-flash__A2_evidence_prompt_heldout.json",
    },
    "claude-sonnet-4-6": {
        "report": EXTERNAL_STUDY / "reports/claude_a4.json",
        "tag": "claude-sonnet-4-6__A2_evidence_prompt__EXP_external_replication_v1",
        "canonical_report": ROOT / "eval/reports/claude-sonnet-4-6__A2_evidence_prompt_heldout_A4.json",
    },
}


def jload(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def parse_tag(tag: str):
    m = TAG_RE.match(tag)
    if not m:
        return None
    return {"model": m.group("model"), "arm": m.group("arm"), "round": int(m.group("round") or 1)}


# build/case.json carries researcher-side material — curation_notes, experimental_role, and an
# `attack_category` object whose `note` states the intended condition and required answer and is
# explicitly flagged model_visible:false / "do not leak". The snapshot is served to the browser,
# so metadata is copied by strict ALLOWLIST (scalar strings only), never wholesale.
SAFE_META_FIELDS = ("dataset",)
# Case records are rendered outside Research mode, so they must stay neutral: no researcher
# intent, no expected answer, no calibration language.
CASE_LEAK_PATTERN = re.compile(
    r"RESEARCHER-INTENT|evidence_condition|do not leak|down-?rank|up-?rank|over-?triage|"
    r"under-?triage|must[_ ]not[_ ]assert|correct_verdict|acceptable_(severity|actions)",
    re.IGNORECASE,
)
# Preset captions are authored demo narration and legitimately name the phenomenon being
# demonstrated; only verbatim researcher-side artefacts are forbidden there.
ARTIFACT_LEAK_PATTERN = re.compile(
    r"RESEARCHER-INTENT|do not leak|must[_ ]not[_ ]assert|correct_verdict|"
    r"acceptable_(severity|actions)|curation_notes",
    re.IGNORECASE,
)


def discover_cases() -> list[dict]:
    """Every frozen case with its navigation metadata. Condition comes from the tier path."""
    cases = []
    for pkg_path in sorted(ROOT.glob("tier*/*/*/*/model_input/alert_package.json")):
        rel = pkg_path.relative_to(ROOT)
        tier, condition, split = rel.parts[0], rel.parts[1], rel.parts[2]
        case_dir = pkg_path.parents[1]
        pkg = jload(pkg_path)
        meta = {}
        cfg_path = case_dir / "build" / "case.json"
        if cfg_path.exists():
            meta = jload(cfg_path).get("metadata", {})
        safe = {k: meta[k] for k in SAFE_META_FIELDS if isinstance(meta.get(k), str)}
        cases.append({
            "case_id": pkg["case_id"],
            "tier": tier,
            "condition": condition,          # research-side metadata (navigation only)
            "split": split,
            "dataset": safe.get("dataset", "—"),
            "sourcetypes": pkg["observed_context"].get("sourcetypes_present", []),
            "event_count": pkg["observed_context"].get("event_count"),
            "derivation_count": len(pkg.get("deterministic_derivations", [])),
            "package_rel": str(rel),
            "case_dir_rel": str(case_dir.relative_to(ROOT)),
        })
    return cases


def discover_outputs() -> dict:
    """case_id -> model -> arm -> {round: output_rel_path}."""
    index = defaultdict(lambda: defaultdict(lambda: defaultdict(dict)))
    out_root = ROOT / "eval" / "outputs"
    for tag_dir in sorted(p for p in out_root.iterdir() if p.is_dir()):
        tag = tag_dir.name
        if any(marker in tag for marker in SKIP_TAG_MARKERS):
            continue
        parsed = parse_tag(tag)
        if not parsed:
            continue
        for split_dir in sorted(p for p in tag_dir.iterdir() if p.is_dir()):
            for out_path in sorted(split_dir.glob("*.json")):
                index[out_path.stem][parsed["model"]][parsed["arm"]][parsed["round"]] = \
                    str(out_path.relative_to(ROOT))
    return index


def current_cost(split: str) -> dict:
    """Aggregate the current append-only usage logs instead of copying a stale report."""
    rows = []
    for usage_path in sorted(cost_eval.OUT.glob(f"*/usage_{split}.jsonl")):
        tag = usage_path.parent.name
        records = cost_eval.read_all(tag, split) or []
        model = cost_eval.base_model(tag)
        canonical, output_count, missing = cost_eval.canonical_records(tag, split, records)
        canonical_row = cost_eval.price_records(canonical, model)
        incurred_row = cost_eval.price_records(records, model)
        if canonical_row is None or incurred_row is None:
            continue
        rows.append({
            "tag": tag,
            "model": model,
            "current_outputs": output_count,
            "missing_usage_cases": missing,
            "canonical": canonical_row,
            "incurred": incurred_row,
            "complete": not missing,
        })
    totals = {
        "calls": sum(row["incurred"]["calls"] for row in rows),
        "input_tokens": sum(row["incurred"]["input"] for row in rows),
        "output_tokens": sum(row["incurred"]["output"] for row in rows),
        "actual_cost_usd": sum(row["incurred"]["actual_cost"] for row in rows),
        "paid_list_equivalent_usd": sum(row["incurred"]["list_cost"] for row in rows),
    }
    return {
        "source": "current append-only usage logs read during snapshot build",
        "total": totals,
        "rows": rows,
        "incomplete_tags": [row["tag"] for row in rows if not row["complete"]],
    }


def wilson_interval(successes: int, n: int, z: float = 1.959963984540054) -> list[float]:
    if not n:
        return [0.0, 0.0]
    p = successes / n
    denominator = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denominator
    margin = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denominator
    return [round(max(0.0, centre - margin), 4), round(min(1.0, centre + margin), 4)]


def exact_mcnemar_two_sided(left_only: int, right_only: int) -> float:
    discordant = left_only + right_only
    if not discordant:
        return 1.0
    tail = min(left_only, right_only)
    probability = 2 * sum(math.comb(discordant, i) for i in range(tail + 1)) / (2 ** discordant)
    return round(min(1.0, probability), 6)


def external_replication_summary() -> dict:
    """Build the separately reported 16-case replication comparison."""
    models = {}
    pass_maps = {}
    for model, paths in EXTERNAL_RUNS.items():
        report = jload(paths["report"])
        completeness = report["completeness"]
        summary = report["summary"]
        if not completeness.get("complete") or summary["n"] != 16:
            raise SystemExit(f"external replication report is incomplete: {paths['report']}")
        if summary.get("active_checks") != ["C1", "C2", "C3", "C4"]:
            raise SystemExit(f"external replication report is not full A4: {paths['report']}")

        conditions = {}
        case_pass = {}
        for case in report["cases"]:
            passed = not case["flagged_by_active_checks"]
            case_pass[case["case_id"]] = passed
            slot = conditions.setdefault(case["condition"], {"n": 0, "a4_pass_n": 0})
            slot["n"] += 1
            slot["a4_pass_n"] += int(passed)
        for slot in conditions.values():
            slot["a4_rate"] = round(slot["a4_pass_n"] / slot["n"], 4)

        usage = cost_eval.read_all(paths["tag"], "heldout")
        if usage is None:
            raise SystemExit(f"external replication usage log is absent: {paths['tag']}")
        canonical_usage, output_count, missing = cost_eval.canonical_records(
            paths["tag"], "heldout", usage
        )
        priced = cost_eval.price_records(canonical_usage, model)
        if output_count != 16 or missing or priced is None or priced["calls"] != 16:
            raise SystemExit(
                f"external replication usage is incomplete for {model}: "
                f"outputs={output_count}, calls={priced and priced['calls']}, missing={missing}"
            )

        canonical = jload(paths["canonical_report"])["summary"]
        canonical_pass = canonical["n"] - canonical["active_flagged_n"]
        external_pass = summary["n"] - summary["active_flagged_n"]
        models[model] = {
            "n": summary["n"],
            "a4_pass_n": external_pass,
            "a4_rate": round(external_pass / summary["n"], 4),
            "a4_wilson_95": wilson_interval(external_pass, summary["n"]),
            "verdict_correct_n": summary["verdict_correct_n"],
            "severity_in_band_n": summary["severity_in_band_n"],
            "check_failure_counts": summary["check_failure_counts"],
            "high_confidence_error_n": summary["confidence"]["high_confidence_error_n"],
            "conditions": conditions,
            "tokens": {"input": priced["input"], "output": priced["output"]},
            "cost": {
                "actual_usd": round(priced["actual_cost"], 6),
                "paid_list_equivalent_usd": round(priced["list_cost"], 6),
            },
            "canonical_heldout": {
                "n": canonical["n"],
                "a4_pass_n": canonical_pass,
                "a4_rate": round(canonical_pass / canonical["n"], 4),
            },
        }
        pass_maps[model] = case_pass

    gemini = pass_maps["gemini-2.5-flash"]
    claude = pass_maps["claude-sonnet-4-6"]
    if set(gemini) != set(claude) or len(gemini) != 16:
        raise SystemExit("external model reports do not contain the same 16 case IDs")
    both_pass = sum(gemini[cid] and claude[cid] for cid in gemini)
    claude_only = sum(not gemini[cid] and claude[cid] for cid in gemini)
    gemini_only = sum(gemini[cid] and not claude[cid] for cid in gemini)
    both_fail = sum(not gemini[cid] and not claude[cid] for cid in gemini)

    return {
        "study_id": "external_replication_v1",
        "n": 16,
        "model_calls": 32,
        "design": "one frozen A2 round per model; independently sourced cases; four per evidence condition",
        "models": models,
        "paired": {
            "both_pass": both_pass,
            "claude_only_pass": claude_only,
            "gemini_only_pass": gemini_only,
            "both_fail": both_fail,
            "mcnemar_exact_two_sided_p": exact_mcnemar_two_sided(claude_only, gemini_only),
            "claude_minus_gemini_pp": round(
                100 * (models["claude-sonnet-4-6"]["a4_rate"]
                       - models["gemini-2.5-flash"]["a4_rate"]), 1
            ),
        },
    }


def main() -> None:
    policy = rv.load_policy(DEMO_POLICY)
    package_schema = jload(rv.PACKAGE_SCHEMA)
    output_schema = jload(rv.OUTPUT_SCHEMA)
    schemas = vv.load_schemas()

    cases = discover_cases()
    outputs = discover_outputs()

    # ---- sweep: run BOTH evaluators over every saved (case, model, arm, round) ----
    sweep = []
    for case in cases:
        cid = case["case_id"]
        package = jload(ROOT / case["package_rel"])
        gt_path = ROOT / case["case_dir_rel"] / "annotations" / "ground_truth.json"
        gt = jload(gt_path) if gt_path.exists() else None
        for model, arms in outputs.get(cid, {}).items():
            for arm, rounds in arms.items():
                for rnd, out_rel in sorted(rounds.items()):
                    output = jload(ROOT / out_rel)
                    runtime = rv.validate_runtime_case(
                        package, output, policy, package_schema, output_schema, expected_case_id=cid)
                    row = {
                        "case_id": cid, "model": model, "arm": arm, "round": rnd,
                        "split": case["split"], "condition": case["condition"],
                        "decision": runtime["decision"],
                        "runtime": {
                            "statuses": {p: o["status"] for p, o in runtime["profile_outcomes"].items()},
                            "hard_n": len(runtime["hard_findings"]),
                            "review_n": len(runtime["review_findings"]),
                            "signals": [s["code"] for s in runtime["signals"]],
                        },
                    }
                    if gt and not vv.schema_errors(gt, schemas["ground_truth"]):
                        checks = vv.validate_case(package, output, gt)
                        failed = [c for c in vv.ALL_CHECKS if vv.check_failed(checks, c)]
                        c2 = checks["C2_decision_calibration"]
                        row["research"] = {
                            "failed": failed, "a4_ok": not failed,
                            "joint": bool(c2["pass"]),
                            "severity_direction": c2["severity_direction"],
                            "verdict_direction": c2["verdict_direction"],
                            "action_direction": checks["C4_action_calibration"]["direction"],
                        }
                    sweep.append(row)

    # ---- dashboard aggregates ----
    default_profile = policy["default_profile"]
    models = {}
    for row in sweep:
        key = f"{row['model']}__{row['arm']}"
        bucket = models.setdefault(key, {
            "model": row["model"], "arm": row["arm"],
            "splits": defaultdict(lambda: {"rounds": defaultdict(lambda: {
                "n": 0, "a4_ok": 0, "joint": 0, "runtime_pass": 0, "runtime_review": 0,
                "runtime_block": 0, "over": 0, "under": 0, "in_band": 0,
                "pass_but_a4_fail": 0})})})
        slot = bucket["splits"][row["split"]]["rounds"][row["round"]]
        slot["n"] += 1
        status = row["runtime"]["statuses"][default_profile]
        slot[f"runtime_{status}"] += 1
        res = row.get("research")
        if res:
            slot["a4_ok"] += res["a4_ok"]
            slot["joint"] += res["joint"]
            direction = res["severity_direction"]
            slot[direction if direction in ("over", "under") else "in_band"] += 1
            if status == "pass" and not res["a4_ok"]:
                slot["pass_but_a4_fail"] += 1

    def undefault(obj):
        if isinstance(obj, defaultdict):
            obj = {k: undefault(v) for k, v in obj.items()}
        elif isinstance(obj, dict):
            obj = {k: undefault(v) for k, v in obj.items()}
        return obj

    # runtime routing profile summary (default arm, per split)
    # One bucket per (split, model): pooling models would double the denominator and report a
    # blended human-review rate for a split that has only 21 (or 20) cases.
    routing = {}
    for split in ("dev", "heldout"):
        for model in sorted({r["model"] for r in sweep}):
            rows = [r for r in sweep if r["split"] == split and r["model"] == model
                    and r["arm"] == "A2_evidence_prompt" and r["round"] == 1]
            if not rows:
                continue
            bucket = {}
            for profile in policy["routing_profiles"]:
                counts = Counter(r["runtime"]["statuses"][profile] for r in rows)
                total = sum(counts.values()) or 1
                bucket[profile] = {
                    "pass": counts["pass"], "review": counts["review"], "block": counts["block"],
                    "human_review_rate": round((counts["review"] + counts["block"]) / total, 3),
                    "n": sum(counts.values()),
                }
            routing[f"{split} · {model}"] = bucket

    stability = []
    for path in sorted((ROOT / "eval" / "reports").glob("stability_*current.json")):
        d = jload(path)
        stability.append({"model_tag": d["model_tag"], "split": d["split"],
                          "rounds": d.get("rounds"), **d["summary"]})
    cost = {split: current_cost(split) for split in ("dev", "heldout")}

    # Secondary, zero-call analysis over the frozen A2/A4 reports. Keep only the
    # aggregate pieces the dashboard renders; case-level metrics remain in the
    # experiment directory and never enter the runtime-neutral startup payload.
    deepening_source = jload(DEEPENING_RESULTS)
    deepening = {
        "analysis_version": deepening_source["analysis_version"],
        "model_calls": deepening_source["model_calls"],
        "unit_summaries": [
            row for row in deepening_source["unit_summaries"]
            if row["split"] == "heldout" and row["round"] == 1
        ],
        "paired_heldout_round1": deepening_source["paired_heldout_round1"],
        "stability": deepening_source["stability"],
        "runtime_uncertainty": deepening_source["runtime_uncertainty"],
        "conformance": {
            key: deepening_source["conformance"][key]
            for key in ("n", "passed_n", "all_pass")
        },
    }
    external_replication = external_replication_summary()

    # ---- curated demonstration presets, derived from the sweep (never hand-asserted) ----
    A2, R1 = "A2_evidence_prompt", 1
    # Gemini is the primary study model, so it leads the curated presets when it qualifies.
    candidates = sorted(
        (r for r in sweep if r["arm"] == A2 and r["round"] == R1),
        key=lambda r: (0 if r["model"].startswith("gemini") else 1, r["case_id"]),
    )
    def find(pred):
        return next((r for r in candidates if pred(r)), None)
    presets = []
    def add(key, title, teaching, row):
        if row:
            presets.append({"key": key, "title": title, "teaching": teaching,
                            "case_id": row["case_id"], "model": row["model"],
                            "arm": row["arm"], "round": row["round"]})
    add("strong_ok", "Correctly calibrated strong case",
        "Decisive evidence, confident verdict, in band — the system is not simply pessimistic.",
        find(lambda r: r["condition"] == "strong" and r.get("research", {}).get("a4_ok")))
    add("over_triage", "Over-triage on insufficient evidence",
        "The dominant failure: a confident malicious call the evidence does not support.",
        find(lambda r: r["condition"] in ("weak", "missing")
             and r.get("research", {}).get("severity_direction") == "over"))
    add("counter_missed", "Counter case — benign context should lower it",
        "Decisive benign context is present, yet the decision does not come down.",
        find(lambda r: r["condition"] == "counter"
             and r.get("research", {}).get("severity_direction") == "over")
        or find(lambda r: r["condition"] == "counter" and r.get("research")
                and not r["research"]["a4_ok"]))
    under = (find(lambda r: r["case_id"] == "UQP-001"
                  and r.get("research", {}).get("severity_direction") == "under")
             or find(lambda r: r["condition"] == "strong"
                     and r.get("research", {}).get("severity_direction") == "under")
             or find(lambda r: r.get("research", {}).get("severity_direction") == "under"))
    add("under_triage",
        f"Under-triage of a strong case ({under['case_id']})" if under else "Under-triage",
        "The mirror failure: decisive evidence present, decision too low.", under)
    add("consequence_routed", "High-consequence action routed for human approval",
        "The runtime policy cannot know if the verdict is right — but it can refuse to let a "
        "disruptive action fire unreviewed.",
        find(lambda r: r["decision"]["recommended_action"] == "isolate")
        or find(lambda r: "S001_HIGH_CONSEQUENCE_ACTION" in r["runtime"]["signals"]))
    add("pass_but_wrong", "Passes runtime validation, fails A4",
        "The honest limit of a ground-truth-free layer: internally consistent, well-formed, "
        "correctly cited — and still miscalibrated.",
        find(lambda r: r["runtime"]["statuses"][default_profile] == "pass"
             and r.get("research") and not r["research"]["a4_ok"]))

    generated_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    safe_cases = sorted([{
        key: case[key] for key in (
            "case_id", "tier", "split", "dataset", "sourcetypes",
            "event_count", "derivation_count",
        )
    } for case in cases], key=lambda case: case["case_id"])
    runtime_snapshot = {
        "record_schema": "safesoc.demo_runtime_snapshot.v2",
        "generated_utc": generated_utc,
        "runtime": {
            "validator_version": rv.VERSION,
            "policy_version": policy["policy_version"],
            "default_profile": default_profile,
            "profiles": {n: {"description": p.get("description", ""), "review_on": p.get("review_on", [])}
                         for n, p in policy["routing_profiles"].items()},
            "signals": {c: s.get("description", "") for c, s in policy["signals"].items()},
            "finding_levels": policy.get("finding_levels", {}),
            "non_claims": policy["non_claims"],
            "input_contract": "alert_package + LLM output + generic policy only; no annotations or ground truth",
        },
        "cases": safe_cases,
        "outputs": {cid: undefault(v) for cid, v in outputs.items()},
        "filters": {
            "tier": sorted({c["tier"] for c in safe_cases}),
            "split": sorted({c["split"] for c in safe_cases}),
            "dataset": sorted({c["dataset"] for c in safe_cases}),
        },
    }
    research_snapshot = {
        "record_schema": "safesoc.demo_research_snapshot.v1",
        "generated_utc": generated_utc,
        "research": {
            "evaluator": "validator_v1_1", "rubric_version": vv.VERSION,
            "checks": {"C1": "evidence-reference integrity", "C2": "verdict and severity calibration",
                       "C3": "counter-evidence acknowledgement", "C4": "action calibration"},
            "condition_policy": {c: {"verdict": p["verdict"], "severity": p["severity"],
                                     "actions": p["actions"]} for c, p in vv.CONDITION_POLICY.items()},
        },
        "condition_by_case": {c["case_id"]: c["condition"] for c in cases},
        "sweep": sweep,
        "dashboard": {"models": undefault(models), "routing": routing,
                      "stability": stability, "cost": cost, "deepening": deepening,
                      "external_replication": external_replication},
        "presets": presets,
        "filters": {
            "condition": sorted({c["condition"] for c in cases}),
        },
    }
    # Fail the build rather than put researcher intent in the startup/runtime payload.
    leaks = []
    for case in runtime_snapshot["cases"]:
        for key, value in case.items():
            if CASE_LEAK_PATTERN.search(json.dumps(value)):
                leaks.append(f"cases[{case['case_id']}].{key}")
    for preset in research_snapshot["presets"]:
        if ARTIFACT_LEAK_PATTERN.search(json.dumps(preset)):
            leaks.append(f"presets[{preset['key']}]")
    if leaks:
        raise SystemExit("refusing to write snapshot: researcher-intent material would be served:\n  "
                         + "\n  ".join(leaks))

    out = HERE / "snapshot.json"
    research_out = HERE / "research_snapshot.json"
    out.write_text(json.dumps(runtime_snapshot, indent=1) + "\n", encoding="utf-8")
    research_out.write_text(json.dumps(research_snapshot, indent=1) + "\n", encoding="utf-8")
    print(f"wrote {out.relative_to(ROOT)}  ({out.stat().st_size/1024:.0f} KB)")
    print(f"wrote {research_out.relative_to(ROOT)}  ({research_out.stat().st_size/1024:.0f} KB)")
    print(f"  cases={len(cases)}  evaluations={len(sweep)}  presets={len(presets)}")
    print(
        "  external replication="
        f"{external_replication['models']['gemini-2.5-flash']['a4_pass_n']}/16 Gemini · "
        f"{external_replication['models']['claude-sonnet-4-6']['a4_pass_n']}/16 Claude"
    )
    print(f"  runtime policy v{policy['policy_version']} · default profile {default_profile}")
    for p in presets:
        print(f"    · {p['key']:19s} {p['case_id']:9s} ({p['model']})")


if __name__ == "__main__":
    main()
