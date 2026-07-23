import copy
import unittest

from tools.normalize import (
    _exclude_model_visible_attributes,
    _repair_mordor_text,
    _redact_model_visible_literals,
    _role_lookup_key,
    project,
)


def package():
    return {
        "main_alert": {
            "evidence_id": "A0",
            "attributes": {"command_line": "alert", "parent_command_line": "parent-a"},
        },
        "evidence_items": [
            {
                "evidence_id": "EV-001",
                "attributes": {"command_line": "event", "parent_command_line": "parent-b"},
            }
        ],
    }


class ModelVisibleExclusionTests(unittest.TestCase):
    def test_removes_only_configured_evidence_attribute(self):
        original = package()
        result = _exclude_model_visible_attributes(
            copy.deepcopy(original),
            {"model_visible_attribute_exclusions": {"EV-001": ["parent_command_line"]}},
        )
        self.assertNotIn("parent_command_line", result["evidence_items"][0]["attributes"])
        self.assertEqual(result["evidence_items"][0]["attributes"]["command_line"], "event")
        self.assertEqual(result["main_alert"], original["main_alert"])

    def test_unknown_evidence_id_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "unknown model-visible exclusion evidence id"):
            _exclude_model_visible_attributes(
                package(),
                {"model_visible_attribute_exclusions": {"EV-999": ["parent_command_line"]}},
            )

    def test_missing_attribute_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "model-visible exclusion field absent"):
            _exclude_model_visible_attributes(
                package(),
                {"model_visible_attribute_exclusions": {"EV-001": ["missing_field"]}},
            )


class ModelVisibleLiteralRedactionTests(unittest.TestCase):
    def test_replaces_literal_everywhere_without_changing_researcher_config(self):
        original = package()
        original["main_alert"]["attributes"]["command_line"] = "Evil Persistence"
        original["evidence_items"][0]["attributes"]["command_line"] = (
            "Consumer.Name=Evil Persistence"
        )
        cfg = {"model_visible_literal_redactions": {"Evil Persistence": "[redacted-name]"}}

        result = _redact_model_visible_literals(copy.deepcopy(original), cfg)

        self.assertEqual(
            result["main_alert"]["attributes"]["command_line"], "[redacted-name]"
        )
        self.assertEqual(
            result["evidence_items"][0]["attributes"]["command_line"],
            "Consumer.Name=[redacted-name]",
        )
        self.assertEqual(
            cfg["model_visible_literal_redactions"]["Evil Persistence"],
            "[redacted-name]",
        )

    def test_absent_literal_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "literal redaction source absent"):
            _redact_model_visible_literals(
                package(),
                {"model_visible_literal_redactions": {"absent": "[redacted]"}},
            )


class EventProjectionTests(unittest.TestCase):
    def test_sysmon_delete_value_is_projected_as_registry_change(self):
        event = """<Event><System><EventID>12</EventID><TimeCreated SystemTime='2020-01-01T00:00:00.000Z'/><EventRecordID>7</EventRecordID><Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>host</Computer></System><EventData><Data Name='ProcessGuid'>{guid}</Data><Data Name='ProcessId'>123</Data><Data Name='Image'>C:\\Windows\\reg.exe</Data><Data Name='TargetObject'>HKU\\...\\Run\\value</Data><Data Name='EventType'>DeleteValue</Data><Data Name='User'>corp\\user</Data></EventData></Event>"""

        event_type, attributes = project(event)

        self.assertEqual(event_type, "registry_object_change")
        self.assertEqual(attributes["registry_event"], "DeleteValue")
        self.assertEqual(attributes["target_object"], "HKU\\...\\Run\\value")


class MordorTextRepairTests(unittest.TestCase):
    def test_repairs_misdecoded_rtlo_marker(self):
        self.assertEqual(_repair_mordor_text("C:\\victim\\â€®cod.scr"), "C:\\victim\\\u202ecod.scr")

    def test_leaves_ordinary_text_unchanged(self):
        self.assertEqual(_repair_mordor_text("ordinary text"), "ordinary text")


class RoleLookupTests(unittest.TestCase):
    def test_preserves_sensor_qualified_multi_source_id(self):
        self.assertEqual(
            _role_lookup_key(
                "sysmon:7134", "Microsoft-Windows-Sysmon/Operational", True
            ),
            "sysmon:7134",
        )

    def test_qualifies_unprefixed_multi_source_id(self):
        self.assertEqual(
            _role_lookup_key("7134", "Microsoft-Windows-Sysmon/Operational", True),
            "sysmon:7134",
        )

    def test_leaves_single_source_id_unqualified(self):
        self.assertEqual(_role_lookup_key("7134", "Security", False), "7134")

if __name__ == "__main__":
    unittest.main()
