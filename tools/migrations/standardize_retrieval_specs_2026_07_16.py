#!/usr/bin/env python3
"""One-time formatting migration for the 31 Splunk retrieval specifications."""

from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def normalize(path: Path) -> None:
    case_dir = path.parent.parent
    rel_case = case_dir.relative_to(ROOT).as_posix()
    text = path.read_text(encoding="utf-8")

    text = re.sub(
        r"\A# ([A-Z]+-\d{3}) — Splunk runbook[^\n]*",
        r"# \1 — Splunk retrieval specification",
        text,
    )
    text = text.replace("dataset_v2/_splunk_ingest", "_splunk_ingest")
    text = text.replace("dataset_v2/tools/normalize.py", "tools/normalize.py")
    text = re.sub(r"^## Which files belong[^\n]*$", "## Source scope", text, flags=re.MULTILINE)
    text = re.sub(r"^## Log\s*$", "## Source scope", text, flags=re.MULTILINE)
    text = re.sub(r"^## Step 0 — Stage[^\n]*$", "## Step 0 — Stage and ingest", text, flags=re.MULTILINE)
    text = re.sub(r"^## Investigate[^\n]*$", "## Investigation", text, flags=re.MULTILINE)
    text = re.sub(r"^## Curation →[^\n]*$", "## Curation record", text, flags=re.MULTILINE)
    text = re.sub(r"^## Export → JSON[^\n]*$", "## Export", text, flags=re.MULTILINE)
    text = re.sub(r"^\*\*(Q\d+\s+—.*?)\*\*(.*)$", r"## \1\2", text, flags=re.MULTILINE)

    if "## Investigation" not in text:
        text = re.sub(r"^(## Q1\b)", "## Investigation\n\n\\1", text, count=1, flags=re.MULTILINE)
    if "## Curation record" not in text:
        marker = "## Export"
        record = (
            "## Curation record\n\n"
            "The selected record ids and researcher-only evidence roles are fixed in "
            "`build/case.json` and retained in `annotations/selection_metadata.json`.\n\n"
        )
        text = text.replace(marker, record + marker, 1)

    before_export, export_and_after = text.split("## Export", 1)
    export_body, normalize_and_after = export_and_after.split("## Normalize", 1)
    if "| dedup " not in export_body:
        export_body = export_body.replace("| sort ", "| dedup EventRecordID\n| sort ", 1)
    text = before_export + "## Export" + export_body + "## Normalize" + normalize_and_after

    text = re.sub(
        r"^## Normalize[^\n]*\n[\s\S]*\Z",
        (
            "## Normalize\n\n"
            "Run from the project root:\n\n"
            "```bash\n"
            f"python3 tools/normalize.py --case {rel_case} --from-log\n"
            f"python3 tools/normalize.py --case {rel_case} --verify-log\n"
            "```\n\n"
            "The first command rebuilds the package from the retained raw source. The second "
            "re-derives it and byte-compares it with `model_input/alert_package.json`.\n"
        ),
        text,
        flags=re.MULTILINE,
    )
    path.write_text(text.rstrip() + "\n", encoding="utf-8")


def main() -> None:
    paths = sorted(ROOT.glob("tier*/**/queries/retrieval_spec.md"))
    if len(paths) != 31:
        raise SystemExit(f"expected 31 Splunk retrieval specifications, found {len(paths)}")
    for path in paths:
        normalize(path)
    print("standardized 31 Splunk retrieval specifications")


if __name__ == "__main__":
    main()
