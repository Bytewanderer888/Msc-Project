# RK-001 — Splunk retrieval specification

Category: Registry Run-key persistence (target execution not evidenced) · **Tier-1 single sensor (Sysmon)** · Split: dev.
Evidence condition: **missing** (autostart configured and cleaned up; target execution is not evidenced).
Calibration role: **over-triage-prone (down-rank)**.

## Source scope
`.../attack_techniques/T1547.001/atomic_red_team/windows-sysmon.log` — host `win-dc-942.attackrange.local`, EID1 + EID13.

## Step 0 — Stage and ingest
```
cp .../T1547.001/atomic_red_team/windows-sysmon.log  _splunk_ingest/rk001_runkey_sysmon.log
```
→ `sourcetype=XmlWinEventLog`, `index=attack_data`, source `rk001_runkey_sysmon.log`, `TZ=UTC`.

## Investigation
## Q1 — the alert (A0): a Run-key value set (EID13)
```spl
index=attack_data source="rk001_runkey_sysmon.log" EventCode=13 TargetObject="*\\CurrentVersion\\Run\\*"
| table _time EventRecordID TargetObject Details Image
```
→ **A0 = 4430** — `...\Run\Atomic Red Team` = `C:\Path\AtomicRedTeam.exe`.

## Q2 — how was it written? (context EVs): `cmd.exe` (spawned by PowerShell) issuing the REG ADD (4403) and `reg.exe` performing it (4417).

## Q3 — was the same value cleaned up? (same-lifecycle evidence)
```spl
index=attack_data source="rk001_runkey_sysmon.log"
  (EventCode=1 CommandLine="*REG DELETE*CurrentVersion\\Run*Atomic Red Team*")
  OR (EventCode=12 EventType=DeleteValue TargetObject="*\\CurrentVersion\\Run\\Atomic Red Team")
| table _time EventRecordID EventCode Image CommandLine EventType TargetObject
```
→ records **4820, 4834, 4847** — the cleanup command chain and native `DeleteValue`
confirmation approximately four seconds after A0.

## Q4 — did the configured target execute? (the decisive gap)
```spl
index=attack_data source="rk001_runkey_sysmon.log" EventCode=1 Image="C:\\Path\\*"
```
→ zero results in the retained Sysmon source (`08:45:27.694Z`–`08:50:35.059Z`).

**Missing crux:** the Run-key setup and its cleanup are present, but the named confirmation —
execution of the configured target — is not evidenced in the scoped Sysmon source. A model must
**not** conclude "payload executed" or durable active persistence.

## Curation record

The selected record ids and researcher-only evidence roles are fixed in `build/case.json` and retained in `annotations/selection_metadata.json`.

## Export
```spl
index=attack_data source="rk001_runkey_sysmon.log"
  EventRecordID IN (4430, 4403, 4417, 4820, 4834, 4847)
| dedup EventRecordID
| sort _time | table _time EventRecordID _raw
```
Export (All Time) → **JSON** → `extracted/rk001_events.json`.

## Normalize

Run from the project root:

```bash
python3 tools/normalize.py --case tier1/missing/dev/RK-001_runkey_persistence --from-log
python3 tools/normalize.py --case tier1/missing/dev/RK-001_runkey_persistence --verify-log
```

The first command rebuilds the package from the retained raw source. The second re-derives it and byte-compares it with `model_input/alert_package.json`.
