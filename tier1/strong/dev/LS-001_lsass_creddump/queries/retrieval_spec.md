# LS-001 — Splunk retrieval specification

Category: LSASS credential access (T1003.001) · **Tier-1, single sensor (Sysmon)** · Split: dev.
Evidence condition: **strong** · Calibration role: **preserve** (validator must NOT down-rank a genuine dump).

## Source scope
**One log:** `.../T1003.001/atomic_red_team/windows-sysmon_creddump.log` (Computer `win-dc-137`).
Verified single-source: every other log in the folder is a *different* host
(security=win-dc-811, procdump-security=win-host-117, createdump-sysmon=win-host-622,
main-sysmon=win-dc-262/807) — none fusible. This capture is **EID10 (process-access) only**.

## Step 0 — Stage and ingest
`cp .../windows-sysmon_creddump.log _splunk_ingest/ls001_creddump_sysmon.log`
→ `sourcetype=XmlWinEventLog`, `index=attack_data`, source `ls001_creddump_sysmon.log`, `TZ=UTC`.
Verify: `index=attack_data source="ls001_creddump_sysmon.log" | stats count values(Computer)`.

*(LSASS pivots on the access itself — GrantedAccess / CallTrace / direction — not a process tree.)*

---

## Investigation

## Q1 — The alert (A0): a named tool reading LSASS
```spl
index=attack_data source="ls001_creddump_sysmon.log" EventCode=10 TargetImage="*lsass.exe"
  (SourceImage="*mimikatz*" OR SourceImage="*xordump*" OR CallTrace="*comsvcs.dll*")
| table _time EventRecordID SourceImage GrantedAccess CallTrace
```
**A0 = record 40595850** — `mimikatz.exe → lsass`, GA `0x1010`.

## Q2 — Enumerate ALL LSASS accessors (who touched lsass?)
```spl
index=attack_data source="ls001_creddump_sysmon.log" EventCode=10 TargetImage="*lsass.exe"
| stats values(GrantedAccess) count by SourceImage
```
→ `mimikatz.exe`, `rundll32.exe`, `xordump.exe`, `wmiprvse.exe`, `svchost.exe`.

## Q3 — GrantedAccess triage (dump-capable vs benign)
`0x1010` / `0x1410` / `0x1fffff` include **PROCESS_VM_READ** → can read LSASS memory = **dump-capable**
(mimikatz, rundll32, xordump). `0x1400` lacks VM_READ → **benign query** (svchost).

## Q4 — CallTrace triage (dumping modules)
```spl
… EventCode=10 TargetImage="*lsass.exe" | table SourceImage GrantedAccess CallTrace
```
`rundll32.exe` → CallTrace includes **`comsvcs.dll`** (the MiniDump export) = the comsvcs dump.
`svchost.exe` → **`lsm.dll`** = legitimate Local Session Manager.

## Q5 — Direction confirmation
Every access is **SOURCE(tool) → TARGET(lsass)** — the correct credential-dumping direction.
(The reverse — `lsass` as *source* — would be a benign/normal pattern, i.e. the PS-001 trap.)

## Q6 — Scope / absence note
This capture has **no EID1/EID11** (no command line, no `.dmp` file). The dump-capable
memory-read access *is* the evidence. A richer full-telemetry dump exists on other hosts but
would break single-source.

---

## Curation record
| Record | Access | Surfaced by | Why it's in the case |
|-------:|--------|-------------|----------------------|
| **40595850** | `mimikatz.exe → lsass` GA `0x1010` | Q1 | **A0** — named tool reading LSASS |
| 40597812 | `rundll32.exe → lsass` GA `0x1410`, `comsvcs.dll` | Q4 | comsvcs MiniDump |
| 40604410 | `xordump.exe → lsass` GA `0x1fffff` | Q3 | full-access dump |
| 40591054 | `svchost.exe → lsass` GA `0x1400`, `lsm.dll` | Q3/Q4 | **benign** legitimate-accessor contrast |

**Excluded:** duplicate accesses, the borderline `wmiprvse`/`cimwin32` access, and repeated benign `svchost` accesses.

## Export
```spl
index=attack_data source="ls001_creddump_sysmon.log"
  EventRecordID IN (40595850, 40597812, 40604410, 40591054)
| dedup EventRecordID
| sort _time | table _time EventRecordID _raw
```
Export (All Time) → **JSON** → `extracted/ls001_events.json`.

## Normalize

Run from the project root:

```bash
python3 tools/normalize.py --case tier1/strong/dev/LS-001_lsass_creddump --from-log
python3 tools/normalize.py --case tier1/strong/dev/LS-001_lsass_creddump --verify-log
```

The first command rebuilds the package from the retained raw source. The second re-derives it and byte-compares it with `model_input/alert_package.json`.
