from __future__ import annotations

import json
from pathlib import Path

from tools.trigger_analytic_taxonomy import (
    classification_for,
    classification_index,
    load_catalog,
    validate_case_inventory,
    validate_spec_classification,
)


ROOT = Path(__file__).resolve().parents[2]


def discovered_case_ids() -> set[str]:
    paths = list(ROOT.glob("tier*/*/*/*/build/case.json"))
    paths.extend(
        (ROOT / "experiments/external_replication_v1/cases").glob(
            "*/*/build/case.json"
        )
    )
    return {json.loads(path.read_text())["case_id"] for path in paths}


def trigger_specs() -> list[Path]:
    paths = list(ROOT.glob("tier*/*/*/*/annotations/trigger_spec.json"))
    paths.extend(
        (ROOT / "experiments/external_replication_v1/cases").glob(
            "*/*/annotations/trigger_spec.json"
        )
    )
    return paths


def test_catalogue_covers_exact_discovered_inventory() -> None:
    case_ids = discovered_case_ids()
    validate_case_inventory(case_ids, require_exact=True)
    assert len(case_ids) == len(classification_index()) == 57


def test_catalogue_has_smaller_shared_structure() -> None:
    catalogue = load_catalog()
    pattern_count = sum(len(family["patterns"]) for family in catalogue["families"])
    assert len(catalogue["families"]) == 9
    assert pattern_count == 21
    assert pattern_count < len(classification_index())


def test_every_trigger_spec_references_its_catalogue_entry() -> None:
    specs = [json.loads(path.read_text()) for path in trigger_specs()]
    assert len(specs) == 57
    for spec in specs:
        validate_spec_classification(spec)
        assert classification_for(spec["case_id"])["analytic_family_id"].startswith("AF-")
