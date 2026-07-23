# WMI-002 — Splunk retrieval specification

Category: WMI event-subscription persistence (installed; consumer execution not observed) · **Tier-1 single sensor (Sysmon)** · Split: dev.
Evidence condition: **strong** (consumer, filter, and binding are recorded as Created).
Calibration role: **preserve / up-rank**.

## Source scope
`.../attack_techniques/T1546.003/wmi_event_subscription/windows-sysmon.log` — host `win-host-14.attackrange.local`, Sysmon WMI events (EID 19/20/21); Q3 separately searches for matching EID 1 process creation.

## Step 0 — Stage and ingest
```
cp .../T1546.003/wmi_event_subscription/windows-sysmon.log  _splunk_ingest/wmi002_wmisub_sysmon.log
```
→ `sourcetype=XmlWinEventLog`, `index=attack_data`, source `wmi002_wmisub_sysmon.log`, `TZ=UTC`.

## Investigation
## Q1 — the alert (A0): a WMI consumer with an encoded payload (EID20)
```spl
index=attack_data source="wmi002_wmisub_sysmon.log" EventCode IN (19,20,21)
| table _time EventRecordID EventCode Name Type Destination Query
```
→ **A0 = 53920** — a `CommandLineEventConsumer` carrying a hidden `-encodedcommand` PowerShell
payload. The raw subscription name is `Evil Persistence`; the normaliser replaces this exact
answer-revealing literal with `[redacted-name]` in model-visible fields.

## Q2 — the rest of the subscription (context EVs): the `__EventFilter` (53919, trigger =
`notepad.exe` launch), the `FilterToConsumerBinding` (53921), a later **modification of the
filter to `not-notepad.exe`** (151610), and the immediately following modification of the same
binding (151644). The modifications do not delete the consumer, filter, or binding and therefore
do not negate the already recorded installation.

**Derivation (DER-001):** base64 (UTF-16LE) decode of the consumer's `-encodedcommand` → a compressed PowerShell script (IEX). Stored as a trustworthy pre-decoded field.

## Q3 — did the consumer ever execute? (downstream scope limit)
```spl
index=attack_data source="wmi002_wmisub_sysmon.log" EventCode=1
```
→ no matching process-create or consumer execution is observed in the available capture.
The execution outcome is absent from the evidence, so the case cannot support claims that the
payload fired or that broader compromise followed.

**Strong crux:** EID 19/20/21 with `Operation=Created` confirms registration of the filter, encoded
consumer, and their binding. That complete, offensively configured persistence installation is the
security-relevant result. Consumer firing is a later outcome: its absence limits downstream claims
but does not reduce the confirmed installation to an unverified attempt.

## Curation record

The selected record ids and researcher-only evidence roles are fixed in `build/case.json` and retained in `annotations/selection_metadata.json`.

## Export
```spl
index=attack_data source="wmi002_wmisub_sysmon.log"
  EventRecordID IN (53920, 53919, 53921, 151610, 151644)
| dedup EventRecordID
| sort _time | table _time EventRecordID _raw
```
Export (All Time) → **JSON** → `extracted/wmi002_events.json`.

## Normalize

Run from the project root:

```bash
python3 tools/normalize.py --case tier1/strong/dev/WMI-002_wmi_subscription_unfired --from-log
python3 tools/normalize.py --case tier1/strong/dev/WMI-002_wmi_subscription_unfired --verify-log
```

The first command rebuilds the package from the retained raw source. The second re-derives it and byte-compares it with `model_input/alert_package.json`.
