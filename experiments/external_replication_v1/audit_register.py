#!/usr/bin/env python3
"""Check the external-replication candidate register against its protocol."""

from __future__ import annotations

import csv
import json
import re
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
REGISTER = Path(__file__).with_name("CASE_REGISTER.csv")
ATTACK_ID = re.compile(r"T\d{4}(?:\.\d{3})?")

EXPECTED_DECISIONS = {
    "strong": ("malicious", "high|critical", "escalate|isolate"),
    "weak": ("suspicious", "low|medium", "monitor|investigate"),
    "missing": ("suspicious", "low|medium", "monitor|investigate"),
    "counter": ("benign", "informational|low", "close_benign|monitor"),
}
REQUIRED_RESPONSE_FAMILIES = {
    "endpoint_isolation",
    "credential_control",
    "network_blocking",
    "analyst_escalation",
}


def canonical_attack_ids() -> set[str]:
    ids: set[str] = set()
    for path in ROOT.glob("tier*/**/annotations/selection_metadata.json"):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            mapping = data.get("attack_category", {}).get(
                "candidate_attack_mapping", ""
            )
            ids.update(ATTACK_ID.findall(str(mapping)))
        except (OSError, json.JSONDecodeError):
            continue
    return ids


def require(condition: bool, message: str, failures: list[str]) -> None:
    if not condition:
        failures.append(message)


def main() -> int:
    with REGISTER.open(newline="", encoding="utf-8") as handle:
        rows = [row for row in csv.DictReader(handle) if row["status"] != "rejected"]

    failures: list[str] = []
    conditions = Counter(row["condition"] for row in rows)
    techniques = Counter(row["attack_id"] for row in rows)
    corpora = Counter(row["source_corpus"] for row in rows)
    depths = Counter(row["telemetry_depth"] for row in rows)
    clusters = Counter(row["capture_cluster"] for row in rows)
    verdicts = Counter(row["correct_verdict"] for row in rows)
    severities = Counter(row["acceptable_severity"] for row in rows)
    actions = Counter(row["acceptable_actions"] for row in rows)
    families = {row["operational_response_family"] for row in rows}

    require(len(rows) == 16, f"expected 16 active slots, found {len(rows)}", failures)
    require(
        conditions == Counter({"strong": 4, "weak": 4, "missing": 4, "counter": 4}),
        f"condition balance is {dict(conditions)}",
        failures,
    )
    require(len(techniques) >= 12, "fewer than 12 distinct ATT&CK IDs", failures)
    require(max(techniques.values(), default=0) <= 2, "an ATT&CK ID appears >2 times", failures)
    require(len(corpora) >= 3, "fewer than three source corpora", failures)
    require(depths["multi_source"] >= 4, "fewer than four multi-source slots", failures)
    require(depths["single_source"] > 0, "no single-source slot", failures)
    require(max(clusters.values(), default=0) <= 2, "a capture cluster contributes >2 slots", failures)
    require(
        REQUIRED_RESPONSE_FAMILIES <= families,
        "missing a required operational response family",
        failures,
    )

    for row in rows:
        expected = EXPECTED_DECISIONS[row["condition"]]
        actual = (
            row["correct_verdict"],
            row["acceptable_severity"],
            row["acceptable_actions"],
        )
        require(
            actual == expected,
            f"{row['slot_id']} violates rubric-v1.1 decision mapping",
            failures,
        )

    canonical = canonical_attack_ids()
    new_ids = set(techniques) - canonical
    require(len(new_ids) >= 8, f"only {len(new_ids)} ATT&CK IDs are new", failures)

    print(f"slots:              {len(rows)}")
    print(f"conditions:         {dict(sorted(conditions.items()))}")
    print(f"verdicts:           {dict(sorted(verdicts.items()))}")
    print(f"severity bands:     {dict(sorted(severities.items()))}")
    print(f"action bands:       {dict(sorted(actions.items()))}")
    print(f"source corpora:      {dict(sorted(corpora.items()))}")
    print(f"telemetry depth:    {dict(sorted(depths.items()))}")
    print(f"distinct ATT&CK:    {len(techniques)}")
    print(f"new ATT&CK IDs:     {len(new_ids)} ({', '.join(sorted(new_ids))})")
    print(f"response families:  {', '.join(sorted(families - {'none'}))}")

    if failures:
        for failure in failures:
            print(f"FAIL: {failure}")
        return 1
    print("PASS: candidate register satisfies the predeclared matrix")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
