# UQP-001 — Splunk retrieval specification

Category: Unquoted-path service persistence (T1574.009) · **Tier-1 single sensor (Sysmon)** · Split: held-out.
Evidence condition: **strong** (the path interception succeeds and `C:\program.exe` runs from `services.exe` as SYSTEM).
Calibration role: **under-triage-prone** (up-rank).

## Source scope
`.../suspicious_behaviour/first_time_windows_service/windows-sysmon.log` — host `win-dc-533.attackrange.local`, **EID1-only**.

## Step 0 — Stage and ingest
```
cp .../first_time_windows_service/windows-sysmon.log  _splunk_ingest/uqp001_service_sysmon.log
```
→ `sourcetype=XmlWinEventLog`, `index=attack_data`, source `uqp001_service_sysmon.log`, `TZ=UTC`.

## Investigation

## Q1 — The alert: an unquoted service path is created
**A0 = 8401** — `sc create "Example Service" binpath="C:\Program Files\windows_service.exe"`.
The unquoted path permits Windows service path interception at `C:\program.exe`.

## Q2 — Was the interception path populated and started?
**EV-001 = 8385** records the command chain that copies the same executable to the intended Program Files
path and to `C:\program.exe`. **EV-002 = 8420** launches `sc start "Example Service"`.

## Q3 — Did the privileged execution outcome occur?
**EV-003 = 8433** shows `services.exe` launching the planted `C:\program.exe` as
`NT AUTHORITY\SYSTEM`, while the process command line names the intended Program Files path. This is
the decisive path-interception outcome, not merely a vulnerable configuration.

## Q4 — What limits the conclusion?
**EV-004 = 8701** is a later service-deletion command. It limits claims about persistence duration but
does not undo the observed SYSTEM execution. Example naming does not establish authorization or benign intent.

## Curation record

The selected record ids and researcher-only evidence roles are fixed in `build/case.json` and retained in `annotations/selection_metadata.json`.

## Export
```spl
index=attack_data source="uqp001_service_sysmon.log"
  EventRecordID IN (8401, 8385, 8433, 8420, 8701)
| dedup EventRecordID
| sort _time | table _time EventRecordID _raw
```
Export (All Time) → **JSON** → `extracted/uqp001_events.json`.

## Normalize

Run from the project root:

```bash
python3 tools/normalize.py --case tier1/strong/heldout/UQP-001_unquoted_path_service --from-log
python3 tools/normalize.py --case tier1/strong/heldout/UQP-001_unquoted_path_service --verify-log
```

The first command rebuilds the package from the retained raw source. The second re-derives it and byte-compares it with `model_input/alert_package.json`.
