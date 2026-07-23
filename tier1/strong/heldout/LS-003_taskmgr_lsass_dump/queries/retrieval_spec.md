# LS-003 — Splunk retrieval specification

Category: LSASS credential access (T1003.001) · **Tier-1, single sensor (Sysmon)** · Split: held-out.
Evidence condition: **strong** · Calibration role: **under-triage-prone** (up-rank test).

## Source scope
**One log:** `.../T1003.001/atomic_red_team/windows-sysmon.log`. This log spans **two hosts**
(win-dc-807, win-dc-262) and holds many dumpers — this case is scoped to **`win-dc-262` + the
`taskmgr.exe` process only**. Single-sensor, single-host.

## Step 0 — Stage and ingest
`cp .../windows-sysmon.log _splunk_ingest/ls003_taskmgr_sysmon.log`
→ `sourcetype=XmlWinEventLog`, `index=attack_data`, source `ls003_taskmgr_sysmon.log`, `TZ=UTC`.

---

## Investigation

## Q1 — The alert (A0): a process reading LSASS with dump-capable access
```spl
index=attack_data source="ls003_taskmgr_sysmon.log" host_field_is_Computer="win-dc-262*"
  EventCode=10 TargetImage="*lsass.exe" GrantedAccess IN (0x1410,0x1fffff)
| table _time EventRecordID SourceImage GrantedAccess SourceProcessGuid
```
*(scope by `Computer="win-dc-262*"`)* → **A0 = record 205113** — `taskmgr.exe → lsass`, GA **`0x1fffff`**.

## Q2 — Who is the actor? (the under-triage trap)
`taskmgr.exe` — a **legitimate, signed Windows tool**. Its launch:
```spl
… EventCode=1 ProcessGuid="{29E67E80-16F9-601B-3D38-00000000A301}"
```
→ record **204798**, `taskmgr.exe /4`, `ATTACKRANGE\Administrator`, High. Looks like normal admin activity.

## Q3 — GrantedAccess escalation (benign → dump)
```spl
… EventCode=10 TargetImage="*lsass.exe" SourceProcessGuid="{29E67E80-16F9-601B-3D38-00000000A301}"
| table _time EventRecordID GrantedAccess
```
→ `0x1400` (record 204847 — query, **no VM_READ**, normal process listing) → `0x1410`
(record 204850 — **VM_READ**) → `0x1fffff` (A0 — full). Task Manager escalated from *listing* to a *dump*.

## Q4 — The outcome (smoking gun)
```spl
… EventCode=11 Image="*taskmgr.exe" TargetFilename="*lsass*"
```
→ record **205112** — `taskmgr.exe` wrote `C:\Users\ADMINI~1\AppData\Local\Temp\2\lsass (2).DMP`.
A **full memory dump of LSASS on disk** = confirmed credential dump.

## Q5 — Under-triage crux
Surface reading: "Task Manager accessed lsass" → benign admin. Correct reading: taskmgr opened
lsass with **PROCESS_ALL_ACCESS** and wrote a full **`lsass.DMP`** — a confirmed credential dump.
A weak model **under-rates** the benign-looking actor; the severity floor is **high**. (Up-ranking test.)

## Q6 — Scope note
The staged log also contains `win-dc-807` and other dumpers (mimikatz/procdump/dumpert/notprocdump).
This case uses only `win-dc-262` + the taskmgr process; everything else is excluded.

---

## Curation record
| Record | Event | Surfaced by | Why it's in the case |
|-------:|-------|-------------|----------------------|
| **205113** | `taskmgr → lsass` GA `0x1fffff` | Q1 | **A0** — full-access LSASS read |
| 204798 | `taskmgr.exe /4` (High) | Q2 | the actor's launch (looks benign) |
| 204847 | `taskmgr → lsass` GA `0x1400` | Q3 | benign query baseline (no VM_READ) |
| 204850 | `taskmgr → lsass` GA `0x1410` | Q3 | the read escalation (VM_READ) |
| 205112 | `taskmgr` wrote `lsass (2).DMP` | Q4 | the dump on disk — confirmed |

**Excluded:** the other host (win-dc-807), all other dumpers in the log, and the redundant `0x1000` query.

## Export
```spl
index=attack_data source="ls003_taskmgr_sysmon.log"
  EventRecordID IN (205113, 204798, 204847, 204850, 205112)
| dedup EventRecordID
| sort _time | table _time EventRecordID _raw
```
Export (All Time) → **JSON** → `extracted/ls003_events.json`.

## Normalize

Run from the project root:

```bash
python3 tools/normalize.py --case tier1/strong/heldout/LS-003_taskmgr_lsass_dump --from-log
python3 tools/normalize.py --case tier1/strong/heldout/LS-003_taskmgr_lsass_dump --verify-log
```

The first command rebuilds the package from the retained raw source. The second re-derives it and byte-compares it with `model_input/alert_package.json`.
