# ST-001 — Splunk retrieval specification

Category: Scheduled Task persistence (T1053.005) · **Tier-1, single sensor (Sysmon)** · Split: held-out.
Evidence condition: **missing** · Calibration role: **over-triage-prone** (down-rank).

## Source scope
**One log:** `.../T1053.005/atomic_red_team/windows-sysmon.log` (Computer `win-dc-893`).
Verified single-source (every other T1053.005 log is a different host).

## Step 0 — Stage and ingest
`cp .../atomic_red_team/windows-sysmon.log _splunk_ingest/st001_atomic_schtasks_sysmon.log`
→ `sourcetype=XmlWinEventLog`, `index=attack_data`, source `st001_atomic_schtasks_sysmon.log`, `TZ=UTC`.

---

## Investigation

## Q1 — The alert (A0): a task-creation command launched
```spl
index=attack_data source="st001_atomic_schtasks_sysmon.log" EventCode=1
  Image="*schtasks.exe" CommandLine="*/create*" (CommandLine="*onstart*" OR CommandLine="*onlogon*" OR CommandLine="*system*")
| table _time EventRecordID CommandLine ParentImage User
```
**A0 = record 4456** — `schtasks /create /tn "T1053_005_OnStartup" /sc onstart /ru system /tr "cmd.exe /c calc.exe"`.

## Q2 — Walk UP (who created it?)
Parent is `cmd.exe` (a scripted burst of task creations by `ATTACKRANGE\Administrator`).

## Q3 — The task-creation burst
```spl
index=attack_data source="st001_atomic_schtasks_sysmon.log" EventCode=1
  (Image="*schtasks.exe" CommandLine="*/create*")
  OR (Image="*powershell.exe" CommandLine="*Register-ScheduledTask*")
| table _time EventRecordID Image CommandLine
```
→ **5 creation invocations**: `OnStartup` (SYSTEM), `OnLogon`, `spawn` (once),
`Atomic task` (daily), and PowerShell `AtomicTask`. These process events prove that the
commands were launched; they do not independently prove every task registration succeeded.

## Q4 — What actions were requested?
Read the `/TR` and `New-ScheduledTaskAction` arguments: two requests name `cmd.exe /c calc.exe`,
one names `calc.exe`, and two name bare `cmd.exe`. These command lines describe proposed task
actions; they do not prove action execution or establish the content/intent of a payload.

## Q5 — Was the same burst cleaned up?
```spl
index=attack_data source="st001_atomic_schtasks_sysmon.log" EventCode=1
  (Image="*schtasks.exe" CommandLine="*/delete*")
  OR (Image="*powershell.exe" CommandLine="*Unregister-ScheduledTask*")
| table _time EventRecordID Image CommandLine
```
→ records **4770, 4786, 4816, 4846, 4859** target the same five task names seconds
later. These are cleanup invocations; Sysmon EID1 does not prove every deletion succeeded.

## Q6 — Did a configured task action fire? (the decisive gap)
```spl
index=attack_data source="st001_atomic_schtasks_sysmon.log"
  EventCode=1 ParentImage IN ("*taskeng.exe","*taskhost*.exe","*svchost.exe")
```
→ zero matching configured-action executions in the retained Sysmon source
(`12:33:51.629Z`–`12:39:38.361Z`). Security Event 4698 is not used because this case is
Sysmon-only.

## Q7 — Missing crux
Task-creation and matching cleanup commands are visible, but the named confirmation — a configured
task action firing — is not evidenced in the scoped Sysmon source. The correct read is a suspicious
persistence setup/attempt requiring investigation, not confirmed malware persistence or execution.

---

## Curation record
| Record | Task | Surfaced by | Why it's in the case |
|-------:|------|-------------|----------------------|
| **4456** | `OnStartup` /ru system → `cmd /c calc.exe` | Q1 | **A0** — SYSTEM startup persistence |
| 4439 | `OnLogon` → `cmd /c calc.exe` | Q3 | logon-trigger creation request |
| 4487 | `spawn` (once) → bare `cmd.exe` | Q3 | one-time creation request |
| 4518 | `Atomic task` (daily) → bare `cmd.exe` | Q3 | daily creation request |
| 4534 | `AtomicTask` → `calc.exe` | Q3 | PowerShell registration request |
| 4770, 4786, 4816, 4846, 4859 | matching cleanup invocations | Q5 | same-lifecycle mitigating context |

**Absent (the point):** no task-scheduler-attributed execution of a configured action (Q6).

## Export
```spl
index=attack_data source="st001_atomic_schtasks_sysmon.log"
  EventRecordID IN (4456, 4439, 4487, 4518, 4534, 4770, 4786, 4816, 4846, 4859)
| dedup EventRecordID
| sort _time | table _time EventRecordID _raw
```
Export (All Time) → **JSON** → `extracted/st001_events.json`.

## Normalize

Run from the project root:

```bash
python3 tools/normalize.py --case tier1/missing/heldout/ST-001_atomic_schtasks_persistence --from-log
python3 tools/normalize.py --case tier1/missing/heldout/ST-001_atomic_schtasks_persistence --verify-log
```

The first command rebuilds the package from the retained raw source. The second re-derives it and byte-compares it with `model_input/alert_package.json`.
