#!/usr/bin/env python3
"""Load and validate the shared SafeSOC trigger-analytic taxonomy."""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any, Iterable

import jsonschema


ROOT = Path(__file__).resolve().parent.parent
CATALOG_PATH = ROOT / "rubric/trigger_analytic_catalog_v1.0.json"
SCHEMA_PATH = ROOT / "tools/schema/trigger_analytic_catalog.schema.json"


class TriggerTaxonomyError(RuntimeError):
    pass


@lru_cache(maxsize=1)
def load_catalog() -> dict[str, Any]:
    catalog = json.loads(CATALOG_PATH.read_text(encoding="utf-8"))
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    errors = sorted(
        jsonschema.Draft7Validator(schema).iter_errors(catalog),
        key=lambda error: list(error.path),
    )
    if errors:
        detail = "; ".join(
            f"{'.'.join(str(part) for part in error.path) or '<root>'}: {error.message}"
            for error in errors
        )
        raise TriggerTaxonomyError(f"analytic catalogue schema failure: {detail}")

    family_ids: set[str] = set()
    pattern_ids: set[str] = set()
    case_ids: set[str] = set()
    for family in catalog["families"]:
        family_id = family["family_id"]
        if family_id in family_ids:
            raise TriggerTaxonomyError(f"duplicate family_id: {family_id}")
        family_ids.add(family_id)
        for pattern in family["patterns"]:
            pattern_id = pattern["pattern_id"]
            if pattern_id in pattern_ids:
                raise TriggerTaxonomyError(f"duplicate pattern_id: {pattern_id}")
            pattern_ids.add(pattern_id)
            overlap = case_ids & set(pattern["case_ids"])
            if overlap:
                raise TriggerTaxonomyError(
                    f"case IDs assigned to multiple patterns: {sorted(overlap)}"
                )
            case_ids.update(pattern["case_ids"])
    return catalog


@lru_cache(maxsize=1)
def classification_index() -> dict[str, dict[str, str]]:
    index: dict[str, dict[str, str]] = {}
    for family in load_catalog()["families"]:
        for pattern in family["patterns"]:
            for case_id in pattern["case_ids"]:
                index[case_id] = {
                    "analytic_family_id": family["family_id"],
                    "analytic_pattern_id": pattern["pattern_id"],
                }
    return index


def classification_for(case_id: str) -> dict[str, str]:
    try:
        return dict(classification_index()[case_id])
    except KeyError as exc:
        raise TriggerTaxonomyError(
            f"case is absent from trigger analytic catalogue: {case_id}"
        ) from exc


def validate_case_inventory(
    case_ids: Iterable[str], *, require_exact: bool = False
) -> None:
    actual = set(case_ids)
    catalogued = set(classification_index())
    missing = sorted(actual - catalogued)
    extra = sorted(catalogued - actual) if require_exact else []
    if missing or extra:
        raise TriggerTaxonomyError(
            f"taxonomy inventory mismatch: missing={missing}, extra={extra}"
        )


def validate_spec_classification(spec: dict[str, Any]) -> None:
    expected = classification_for(spec["case_id"])
    actual = {
        "analytic_family_id": spec.get("analytic_family_id"),
        "analytic_pattern_id": spec.get("analytic_pattern_id"),
    }
    if actual != expected:
        raise TriggerTaxonomyError(
            f"{spec['case_id']}: taxonomy mismatch: expected={expected}, actual={actual}"
        )
