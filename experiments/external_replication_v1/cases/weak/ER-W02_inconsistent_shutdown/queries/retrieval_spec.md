# ER-W02 retrieval specification

Source: `data_sources/windows_apt_2025/combined.csv`.

1. Parse the source with Python's CSV parser; do not use physical line offsets because
   quoted event messages can contain embedded newlines.
2. Apply `annotations/trigger_spec.json` to the complete declared asset and source
   partition. Select `A0` only with its declared deterministic selection strategy.
3. Use `build/case.json` source identifiers only to verify the replayed `A0` and to
   reproduce the retained context; they are not trigger predicates.
4. Retain only the event facts listed in `model_input/alert_package.json` and apply
   the literal anonymisation/redaction rules in `build/case.json`.
5. Exclude every `_source.rule.*` field, Sysmon `RuleName`, copied event messages
   containing technique labels, Wazuh identity, and all decision labels.

The package preserves the native Windows event message and removes the duplicate detector description.

This source is a Wazuh alert-index export, not a complete raw event stream. This
case therefore makes no claim that an unobserved follow-on event is absent.
