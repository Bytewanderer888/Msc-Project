# SVC-001 — Splunk retrieval specification

Category: Create/Modify System Process — Windows Service (T1543.003) · **Tier-1, single sensor (Sysmon)** · Split: held-out.
Evidence condition: **strong** · Calibration role: **under-triage-prone** (up-rank).

## Source scope
**One log:** `.../T1543.003/atomic_red_team/windows-sysmon.log` (Computer `win-dc-61`).
Single host, single sensor (Sysmon EID 1 process-create). Verified single-source.

## Step 0 — Stage and ingest
`cp .../T1543.003/atomic_red_team/windows-sysmon.log _splunk_ingest/svc001_service_persistence_sysmon.log`
→ `sourcetype=XmlWinEventLog`, `index=attack_data`, source `svc001_service_persistence_sysmon.log`, `TZ=UTC`.

---

## Investigation

## Q1 — The alert (A0): a legitimate service's binary path is changed to PowerShell
```spl
index=attack_data source="svc001_service_persistence_sysmon.log" EventCode=1 Image="*\\sc.exe"
  CommandLine="*config*" CommandLine="*binPath*"
| table _time EventRecordID CommandLine
```
**A0 = record 4482** — `sc config Fax binPath= "…powershell.exe -noexit -c \"…\""`. The **Fax** service
(a legitimate Windows service) is **hijacked** to launch PowerShell — a classic T1543.003 persistence move.

## Q2 — What does the hijacked service actually run? (the decisive check)
Read the payload: `powershell.exe -noexit -c "write-host 'T1543.003 Test'"`. **It just prints a string.**
No download, no encoded blob, no child process — a **benign** command.

## Q3 — Other service persistence?
```spl
index=attack_data source="svc001_service_persistence_sysmon.log" EventCode=1
  (Image="*\\sc.exe" CommandLine="*create*") OR CommandLine="*New-Service*"
| table _time EventRecordID CommandLine
```
→ two **new services** created: `AtomicTestService_CMD` (`sc create …binPath= …\AtomicService.exe`, then
`sc start`) and `AtomicTestService_PowerShell` (`New-Service … AtomicService.exe`).

## Q4 — What do those services execute?
```spl
index=attack_data source="svc001_service_persistence_sysmon.log" EventCode=1 ParentImage="*\\services.exe"
| table _time EventRecordID Image
```
→ `AtomicService.exe` runs as **SYSTEM** (spawned by `services.exe`); no child process is observed, but the package does not capture its on-disk behaviour.

## Q5 — Outcome
```spl
index=attack_data source="svc001_service_persistence_sysmon.log" EventCode=1 CommandLine="*Fax*fxssvc*"
```
→ record 4808: `sc config Fax binPath= "…\fxssvc.exe"` — a command **reverting the Fax binPath** to its real binary is issued
seconds later (success not confirmed). The Fax hijack was reverted; malicious behaviour from the new services is not evidenced.

## Q6 — Strong crux
This case goes beyond an alarming service configuration. The new service is created and started, and record
4583 shows its configured non-system binary launched by `services.exe` as **NT AUTHORITY\\SYSTEM**. That is a
completed service-based privileged-execution mechanism. The visible `write-host` test command and the Fax
restore command are mitigating context: they limit claims about authorization, payload effects, and lasting
persistence, but do not undo the observed SYSTEM execution. The under-triage trap is treating a successful
offensive mechanism as low/medium merely because the capture is test-like or later cleaned up.

---

## Curation record
| Record | Event | Surfaced by | Why in the case |
|-------:|-------|-------------|-----------------|
| **4482** | `sc config Fax binPath= powershell -c "write-host 'Test'"` | Q1 | **A0** — legit-service hijack (benign payload) |
| 4522 | `sc create AtomicTestService_CMD binPath= …AtomicService.exe` | Q3 | new service #1 |
| 4537 | `sc start AtomicTestService_CMD` | Q3 | service #1 started |
| 4563 | `New-Service AtomicTestService_PowerShell …AtomicService.exe` | Q3 | new service #2 |
| 4583 | `AtomicService.exe` (⇐ services.exe) | Q4 | the service binary runs as SYSTEM — behaviour not captured |
| 4808 | `sc config Fax binPath= …fxssvc.exe` | Q5 | Fax restored (hijack reverted) |

**Scope limit:** the package confirms service-based SYSTEM execution, not an unauthorized operator, C2, data theft,
or successful long-term persistence. Record 4808 remains counter-evidence about persistence duration.

## Export
```spl
index=attack_data source="svc001_service_persistence_sysmon.log"
  EventRecordID IN (4482, 4522, 4537, 4563, 4583, 4808)
| dedup EventRecordID
| sort _time | table _time EventRecordID _raw
```
Export (All Time) → **JSON** → `extracted/svc001_events.json`.

## Normalize

Run from the project root:

```bash
python3 tools/normalize.py --case tier1/strong/heldout/SVC-001_service_persistence --from-log
python3 tools/normalize.py --case tier1/strong/heldout/SVC-001_service_persistence --verify-log
```

The first command rebuilds the package from the retained raw source. The second re-derives it and byte-compares it with `model_input/alert_package.json`.
