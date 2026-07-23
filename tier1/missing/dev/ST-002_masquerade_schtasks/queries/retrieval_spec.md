# ST-002 — Splunk retrieval specification

Category: Scheduled Task persistence attempt (T1053.005) · **Tier-1, single sensor (Sysmon)** · Split: dev.
Evidence condition: **missing** · Calibration role: **over-triage-prone** (down-rank test).

## Source scope
**One log:** `.../T1053.005/schtasks/windows-sysmon.log` (Computer `win-dc-974`). Verified
single-source (the folder's security log is the same host but a different sensor; not used here).

## Step 0 — Stage and ingest
`cp .../schtasks/windows-sysmon.log _splunk_ingest/st002_masquerade_schtasks_sysmon.log`
→ `sourcetype=XmlWinEventLog`, `index=attack_data`, source `st002_masquerade_schtasks_sysmon.log`, `TZ=UTC`.

---

## Investigation

## Q1 — The alert (A0): a task whose action targets an ADS
```spl
index=attack_data source="st002_masquerade_schtasks_sysmon.log" EventCode=1
  Image="*schtasks.exe" CommandLine="*/create*" CommandLine="*.ini:*"
| table _time EventRecordID CommandLine ParentImage
```
**A0 = record 1624574** — `schtasks /Create /TN "SoundIentifier" /TR "wmic process call create
\"C:\Users\Public\Disk101.ini:59e9c935\"" /SC Once`.

## Q2 — The disguise
The task name **`SoundIentifier`** typosquats *SoundIdentifier* — designed to read as a benign
Windows component. This makes the command suspicious, but it does not establish whether task
registration succeeded.

## Q3 — The suspicious proposed action
The `/TR` action runs **`wmic process call create`** on `…\Public\Disk101.ini:59e9c935`. The
**colon** makes `:59e9c935` an **NTFS Alternate Data Stream** path. The command proposes execution
through wmic, but this EID 1 event does not confirm that the stream exists, that the task registered,
or that its action ran.

## Q4 — Other disguised tasks
```spl
index=attack_data source="st002_masquerade_schtasks_sysmon.log" EventCode=1
  Image="*schtasks.exe" CommandLine="*/create*"
| table _time EventRecordID CommandLine
```
→ **`"Disk Diag"`** (record 1624587) → `explorer.exe …\Public\Weber0.js` every 6 min — a second
benign-named task proposing a `.js` action from a Public path.

## Q5 — Sysmon-observable payload / task-action execution?
```spl
index=attack_data source="st002_masquerade_schtasks_sysmon.log" (EventCode=11 TargetFilename="*Disk101*")
  OR (EventCode=1 (Image="*wmic.exe" OR CommandLine="*Weber0*"))
```
→ none captured in the retained Sysmon host window. The package therefore contains suspicious
task-creation invocations but no payload file or ProcessCreate attributable to either proposed task
action. Security Event 4698 is not observable in this Sysmon-only case, so registration status is
left indeterminate and is not used as the missing confirmation. The missing confirmation is the
Sysmon-observable task-action execution.

## Q6 — Over-triage crux
The commands are sufficiently suspicious to investigate, but a model must not convert `/Create`
process creation into proof that either task or payload succeeded. The justified band is
**low-medium**, with **investigate** rather than isolate, so the case tests down-ranking of an
alarming but unconfirmed outcome.

---

## Curation record
| Record | Task | Surfaced by | Why it's in the case |
|-------:|------|-------------|----------------------|
| **1624574** | `SoundIentifier` → wmic on ADS path | Q1/Q3 | **A0** — suspicious task-creation invocation; registration unconfirmed |
| 1624587 | `Disk Diag` → `explorer …\Public\Weber0.js` | Q4 | second suspicious task-creation invocation |

**Absent after raw-scope audit:** payload-file evidence and Sysmon ProcessCreate attributable to either
proposed task action (Q5). Security 4698/task-registration telemetry is outside this single-sensor
scope and is not counted as absent evidence. The broader win-dc-974 intrusion is excluded to keep the
case host/window scoped.

## Export
```spl
index=attack_data source="st002_masquerade_schtasks_sysmon.log"
  EventRecordID IN (1624574, 1624587)
| dedup EventRecordID
| sort _time | table _time EventRecordID _raw
```
Export (All Time) → **JSON** → `extracted/st002_events.json`.

## Normalize

Run from the project root:

```bash
python3 tools/normalize.py --case tier1/missing/dev/ST-002_masquerade_schtasks --from-log
python3 tools/normalize.py --case tier1/missing/dev/ST-002_masquerade_schtasks --verify-log
```

The first command rebuilds the package from the retained raw source. The second re-derives it and byte-compares it with `model_input/alert_package.json`.
