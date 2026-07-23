# LS-002 — Splunk retrieval specification

Category: LSASS credential access (T1003.001) · **Tier-1, single sensor (Sysmon)** · Split: dev.
Evidence condition: **weak** (suggestive LOLBin dump, but target identity + outcome unverified).
Calibration role: **over-triage-prone** (down-rank).

## Source scope
**One log:** `.../T1003.001/atomic_red_team/createdump_windows-sysmon.log` (Computer `win-host-622`).
Verified single-source (every other log in the folder is a different host). **EID1-only** capture.

## Step 0 — Stage and ingest
`cp .../createdump_windows-sysmon.log _splunk_ingest/ls002_createdump_sysmon.log`
→ `sourcetype=XmlWinEventLog`, `index=attack_data`, source `ls002_createdump_sysmon.log`, `TZ=UTC`.
Verify: `index=attack_data source="ls002_createdump_sysmon.log" | stats count values(Computer)`.

---

## Investigation

## Q1 — The alert (A0): a dump-capable LOLBin
```spl
index=attack_data source="ls002_createdump_sysmon.log" EventCode=1 Image="*createdump.exe"
| table _time EventRecordID CommandLine ParentImage User IntegrityLevel
```
**A0 = record 65364864** — `createdump.exe -u -f …\dotnet-lsass.dmp 632`, High integrity, parent `powershell.exe`.

## Q2 — Walk UP (how launched?)
Parent is `powershell.exe` / `pwsh.exe` — a scripted invocation.

## Q3 — Read the target
The command line has output **`dotnet-lsass.dmp`** and target **PID `632`**. The filename
*suggests* LSASS — but a filename is operator-chosen, and PID 632 is just a number so far.

## Q4 — VERIFY the target identity (the decisive check)
Is PID 632 actually LSASS? Look for corroboration:
```spl
index=attack_data source="ls002_createdump_sysmon.log"
  (EventCode=1 ProcessId=632) OR (EventCode=10 TargetImage="*lsass.exe")
```
→ **0 results.** No process_create identifies PID 632, and no EID10 access to `lsass.exe` by name.
**Target identity UNVERIFIED.**

## Q5 — Was a dump actually produced?
```spl
index=attack_data source="ls002_createdump_sysmon.log" EventCode=11 TargetFilename="*lsass*"
```
→ **0 results** — no `.dmp` file captured. **Outcome UNCONFIRMED.**

## Q6 — Repeated attempts
```spl
index=attack_data source="ls002_createdump_sysmon.log" EventCode=1 Image="*createdump.exe"
| stats count, values(CommandLine)
```
→ **5 runs** over ~20 min; **4 of them have no target PID at all** → mostly incomplete attempts.

**Weak crux:** suggestive (LOLBin + lsass-named output + a plausible PID) but unverified target
and unconfirmed outcome. A model must **not** conclude "LSASS was dumped."

---

## Curation record
| Record | Event | Surfaced by | Why it's in the case |
|-------:|-------|-------------|----------------------|
| **65364864** | `createdump … dotnet-lsass.dmp 632` | Q1 | **A0** — the only run with a target PID |
| 65365536 / 65397981 / 65399564 / 65436350 | `createdump … dotnet-lsass.dmp` (no PID) | Q6 | repeated attempts, no target |

**Absent (and that's the point):** no process_create for PID 632 (Q4), no `lsass.exe` access (Q4),
no `.dmp` file (Q5) — so the target identity and a successful dump are *both* uncorroborated.

## Export
```spl
index=attack_data source="ls002_createdump_sysmon.log"
  EventRecordID IN (65364864, 65365536, 65397981, 65399564, 65436350)
| dedup EventRecordID
| sort _time | table _time EventRecordID _raw
```
Export (All Time) → **JSON** → `extracted/ls002_events.json`.

## Normalize

Run from the project root:

```bash
python3 tools/normalize.py --case tier1/weak/dev/LS-002_createdump --from-log
python3 tools/normalize.py --case tier1/weak/dev/LS-002_createdump --verify-log
```

The first command rebuilds the package from the retained raw source. The second re-derives it and byte-compares it with `model_input/alert_package.json`.
