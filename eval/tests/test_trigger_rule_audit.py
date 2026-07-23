from __future__ import annotations

from copy import deepcopy

import pytest

from tools.audit_trigger_rules import (
    TriggerAuditError,
    select_event,
    temporal_sessions,
    validate_non_circular,
)


def event(key: str, timestamp: str, process_id: str, image_loaded: str) -> dict:
    return {
        "record_key": key,
        "event_time_utc": timestamp,
        "event_code": 7,
        "event_type": "image_load",
        "computer": "host-01",
        "attributes": {
            "process_id": process_id,
            "image_loaded": image_loaded,
        },
    }


def valid_spec() -> dict:
    return {
        "schema_version": "1.0",
        "case_id": "ER-T01",
        "rule_id": "SAFESOC-TRG-ER-T01",
        "analytic_family_id": "AF-TEST",
        "analytic_pattern_id": "TEST-01",
        "title": "Short multi-module loading burst",
        "formalisation_timing": "prospective_pre_model",
        "rule_origin": {"type": "project_analytic", "reference": "test"},
        "scope": {
            "basis": "full_source",
            "complete_legal_scope": True,
            "description": "Every event in the declared source.",
        },
        "event_predicate": {"field": "event_code", "op": "eq", "value": 7},
        "aggregation": {
            "group_by": ["attributes.process_id"],
            "count_gte": 2,
            "session_gap_seconds_lte": 1,
            "distinct": {"field": "attributes.image_loaded", "count_gte": 2},
        },
        "selection": {
            "strategy": "earliest_in_highest_count_group",
            "justification": "Select the earliest event in the densest qualifying burst.",
        },
        "expected_a0": {"record_key": "second-a"},
        "rationale": "The rule represents a burst rather than one isolated load.",
    }


def test_temporal_sessions_split_on_declared_gap() -> None:
    events = [
        event("first", "2026-01-01T00:00:00Z", "10", "a.dll"),
        event("second-a", "2026-01-01T00:01:00Z", "10", "a.dll"),
        event("second-b", "2026-01-01T00:01:00.050Z", "10", "b.dll"),
    ]
    assert [[item["record_key"] for item in group] for group in temporal_sessions(events, 1)] == [
        ["first"],
        ["second-a", "second-b"],
    ]


def test_aggregate_selection_ignores_earlier_nonqualifying_singleton() -> None:
    events = [
        event("first", "2026-01-01T00:00:00Z", "10", "a.dll"),
        event("second-a", "2026-01-01T00:01:00Z", "10", "a.dll"),
        event("second-b", "2026-01-01T00:01:00.050Z", "10", "b.dll"),
    ]
    selected, group_count = select_event(events, valid_spec())
    assert selected["record_key"] == "second-a"
    assert group_count == 1


@pytest.mark.parametrize(
    "forbidden_field",
    [
        "record_key",
        "attributes.source_record_id",
        "attributes.block_index",
        "attributes.audit_serial",
        "event_time_utc",
        "raw_sha256",
    ],
)
def test_non_circular_validation_rejects_exact_locators(forbidden_field: str) -> None:
    spec = deepcopy(valid_spec())
    spec["event_predicate"] = {
        "field": forbidden_field,
        "op": "eq",
        "value": "one-record-only",
    }
    with pytest.raises(TriggerAuditError, match="prohibited post-hoc predicate field"):
        validate_non_circular(spec)
