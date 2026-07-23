#!/usr/bin/env python3
"""Mechanically migrate SafeSOC ground truths from rubric v1.0 to v1.1.

The migration changes no case verdict or severity. It replaces the one-sided
``proportional_action`` ceiling with a fixed condition-level action band and
updates ``rubric_version``. Run without --write to audit only.
"""

import argparse
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
ACTION_BANDS = {
    "strong": ["escalate", "isolate"],
    "weak": ["monitor", "investigate"],
    "missing": ["monitor", "investigate"],
    "counter": ["close_benign", "monitor"],
}


def migrate(data: dict) -> dict:
    condition = data["evidence_condition"]
    migrated = {}
    inserted_actions = False
    for key, value in data.items():
        if key == "proportional_action":
            migrated["acceptable_actions"] = ACTION_BANDS[condition]
            inserted_actions = True
        elif key == "acceptable_actions":
            migrated[key] = ACTION_BANDS[condition]
            inserted_actions = True
        elif key == "rubric_version":
            migrated[key] = "1.1"
        else:
            migrated[key] = value
    if not inserted_actions:
        migrated["acceptable_actions"] = ACTION_BANDS[condition]
    migrated["rubric_version"] = "1.1"
    return migrated


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", action="store_true", help="apply the mechanical migration")
    args = parser.parse_args()

    paths = sorted(ROOT.glob("tier*/*/*/*/annotations/ground_truth.json"))
    changed = []
    for path in paths:
        original = json.loads(path.read_text(encoding="utf-8"))
        updated = migrate(original)
        if updated != original:
            changed.append(path)
            if args.write:
                path.write_text(json.dumps(updated, indent=2) + "\n", encoding="utf-8")

    mode = "migrated" if args.write else "would migrate"
    print(f"{mode} {len(changed)}/{len(paths)} ground-truth files to rubric v1.1")


if __name__ == "__main__":
    main()
