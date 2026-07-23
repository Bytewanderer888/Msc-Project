# ACCT-001 — Splunk retrieval specification

Category: Create Account — Local Account (T1136.001) · **Tier-1, single sensor (Sysmon)** · Split: dev.
Evidence condition: **missing** · Calibration role: **over-triage-prone** (down-rank).

## Source scope
**One log:** `.../T1136.001/atomic_red_team/windows-sysmon.log` (Computer `win-dc-7216619`). Single host, single sensor (Sysmon EID 1).

## Step 0 — Stage and ingest
`cp .../windows-sysmon.log _splunk_ingest/acct001_create_account_sysmon.log`
→ `sourcetype=XmlWinEventLog`, `index=attack_data`, source `acct001_create_account_sysmon.log`, `TZ=UTC`.

---

## Investigation

## Q1 — The alert (A0): an account-creation command is launched
```spl
index=attack_data source="acct001_create_account_sysmon.log" EventCode=1 CommandLine="*net user*/add*"
| table _time EventRecordID CommandLine
```
**A0 = 4218** — Sysmon records process creation for `net user /add "T1136.001_CMD" …`.
This is an account-creation command associated with persistence, but EID 1 does not report whether
the requested account operation succeeded.

## Q2 — More account activity
```spl
index=attack_data source="acct001_create_account_sysmon.log" EventCode=1
  (CommandLine="*net user*/add*" OR CommandLine="*New-LocalUser*" OR CommandLine="*net localgroup*")
| table _time EventRecordID CommandLine
```
→ process-creation events for a second account command via `New-LocalUser` (4259), and commands
requesting creation of `T1136.001_Admin` plus a local-group addition (4277).

## Q3 — The decisive check: look for cleanup and confirmed outcomes
```spl
index=attack_data source="acct001_create_account_sysmon.log" EventCode=1
  (CommandLine="*net user*/del*" OR CommandLine="*Remove-LocalUser*")
| table _time EventRecordID CommandLine
```
→ cleanup commands target all three account names seconds later: `net user /del` records
4542/4600 and `Remove-LocalUser` record 4582. Sysmon EID 1 proves that these commands were launched,
not that deletion succeeded. The available package contains no event confirming a surviving account
or subsequent account use; this single-sensor package also cannot establish that such activity never occurred.

## Q4 — Is later use visible to this sensor?
```spl
index=attack_data source="acct001_create_account_sysmon.log" EventCode=1
  User IN ("*\\T1136.001_CMD", "*\\T1136.001_PowerShell", "*\\T1136.001_Admin")
| table _time EventRecordID User Image CommandLine
```
→ zero results in the retained Sysmon source (`10:39:12.911642600Z`–`10:47:54.752898700Z`).
This checks a Sysmon-observable sign of later account use. It does not claim that Sysmon can prove
the underlying account creation/deletion state or replace Security logon telemetry.

## Q5 — Missing crux
Account-creation and group-add commands form an alarming persistence surface. Nearby cleanup commands
target all three names, while Sysmon-observable later use is absent from the scoped source. Correct
read: *"account-operation commands observed; persistent outcome not confirmed → Low–Medium,
investigate,"* not *"confirmed backdoor persistence."*

---

## Curation record
| Record | Event | Why in the case |
|-------:|-------|-----------------|
| **4218** | `net user /add "…_CMD"` | **A0** — account-creation command |
| 4259 | `New-LocalUser …` | second account-creation command |
| 4277 | `net user /add "…_Admin"` + `net localgroup` | creation and group-add commands |
| 4542 | `net user /del "…_CMD"` | cleanup command targeting the CMD account |
| 4582 | `Remove-LocalUser "…_PowerShell"` | cleanup command targeting the PowerShell account |
| 4600 | `net user /del "…_Admin"` | cleanup command targeting the Admin account |

**Absent from the package (the point):** operation-success evidence, a surviving account, or
subsequent account use. Absence from this Sysmon-only package is not proof that such activity never occurred.

## Export
```spl
index=attack_data source="acct001_create_account_sysmon.log" EventRecordID IN (4218,4259,4277,4542,4582,4600)
| dedup EventRecordID
| sort _time | table _time EventRecordID _raw
```

## Normalize

Run from the project root:

```bash
python3 tools/normalize.py --case tier1/missing/dev/ACCT-001_create_local_account --from-log
python3 tools/normalize.py --case tier1/missing/dev/ACCT-001_create_local_account --verify-log
```

The first command rebuilds the package from the retained raw source. The second re-derives it and byte-compares it with `model_input/alert_package.json`.
