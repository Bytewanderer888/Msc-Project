#!/usr/bin/env python3
"""Render the machine-readable trigger taxonomy for review and reporting."""

from __future__ import annotations

import csv

from trigger_analytic_taxonomy import ROOT, load_catalog


MARKDOWN = ROOT / "rubric/trigger_analytic_catalog_v1.0.md"
CSV_MAP = ROOT / "rubric/trigger_analytic_case_map_v1.0.csv"


def main() -> None:
    catalog = load_catalog()
    rows: list[dict[str, str]] = []
    lines = [
        "# Trigger analytic catalogue v1.0",
        "",
        "## Purpose",
        "",
        "This catalogue groups case-level trigger specifications by their primary",
        "observable detection mechanism. It does not replace any case predicate,",
        "scope, aggregation, or deterministic A0 selection rule.",
        "",
        "The classification is independent of ATT&CK technique and evidence",
        "condition: analytic family describes how the alert is generated; ATT&CK",
        "describes the security mechanism; evidence condition describes how strongly",
        "the retained package supports the proposition.",
        "",
        "## Coverage",
        "",
        "| Family | Name | Patterns | Cases |",
        "|---|---|---:|---:|",
    ]
    for family in catalog["families"]:
        case_count = sum(len(pattern["case_ids"]) for pattern in family["patterns"])
        lines.append(
            f"| `{family['family_id']}` | {family['name']} | "
            f"{len(family['patterns'])} | {case_count} |"
        )
        for pattern in family["patterns"]:
            for case_id in pattern["case_ids"]:
                rows.append(
                    {
                        "case_id": case_id,
                        "analytic_family_id": family["family_id"],
                        "analytic_family": family["name"],
                        "analytic_pattern_id": pattern["pattern_id"],
                        "analytic_pattern": pattern["name"],
                    }
                )

    lines.extend(["", "## Families and patterns", ""])
    for family in catalog["families"]:
        lines.extend(
            [
                f"### {family['family_id']} - {family['name']}",
                "",
                family["definition"],
                "",
            ]
        )
        for pattern in family["patterns"]:
            cases = ", ".join(f"`{case_id}`" for case_id in pattern["case_ids"])
            lines.extend(
                [
                    f"- **{pattern['pattern_id']} - {pattern['name']}:** "
                    f"{pattern['definition']}",
                    f"  Cases: {cases}",
                ]
            )
        lines.append("")

    MARKDOWN.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
    rows.sort(key=lambda row: row["case_id"])
    with CSV_MAP.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    print(
        f"wrote {MARKDOWN.relative_to(ROOT)} and {CSV_MAP.relative_to(ROOT)} "
        f"({len(rows)} cases)"
    )


if __name__ == "__main__":
    main()
