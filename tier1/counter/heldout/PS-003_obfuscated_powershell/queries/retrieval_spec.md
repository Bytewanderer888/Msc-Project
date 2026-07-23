# PS-003 — Splunk retrieval specification

Category: PowerShell (T1059.001) · **Tier-1, single sensor (Sysmon)** · Split: held-out.
Evidence condition: **counter** (obfuscation looks malicious, but deterministic deobfuscation
reveals a benign `Write-Host`; plus the lsass-direction trap).

## Source scope
**One log:** `.../T1059.001/obfuscated_powershell/windows-sysmon.log` (Computer `win-dc-397`).
Verified single-source: the folder holds only that Sysmon log + a `.yml` manifest.

## Step 0 — Stage and ingest
`cp .../obfuscated_powershell/windows-sysmon.log _splunk_ingest/ps003_obfuscated_sysmon.log`
→ *Add Data → Upload* → `sourcetype=XmlWinEventLog`, `index=attack_data`,
source `ps003_obfuscated_sysmon.log`, `TZ=UTC`. (`host`=your Splunk box; real host = `Computer`.)
Verify: `index=attack_data source="ps003_obfuscated_sysmon.log" | stats count values(Computer)`.

---

## Investigation

## Q1 — The alert (A0)
```spl
index=attack_data source="ps003_obfuscated_sysmon.log" EventCode=1
  Image="*powershell.exe" CommandLine="*replace*" CommandLine="*+'*"
| table _time EventRecordID ProcessGuid ParentProcessGuid CommandLine
```
**A0 = record 28476**, `ProcessGuid={E983936C-D099-6006-FD07-00000000A301}`, command
`('Wri'+'te-Host '+'aAgHello, '+'World!'+'aAg').RePlAcE('aAg',[char]39) | iex`.

## Q2 — Walk UP (how launched?)
```spl
index=attack_data source="ps003_obfuscated_sysmon.log" EventCode=1
  ProcessGuid="<A0.ParentProcessGuid>"
| table EventRecordID Image CommandLine ParentImage
```
→ record **28429** (`cmd.exe`), parent **`explorer.exe`** — an interactive launch.

## Q3 — Walk DOWN (children)
```spl
index=attack_data source="ps003_obfuscated_sysmon.log" EventCode=1
  ParentProcessGuid="{E983936C-D099-6006-FD07-00000000A301}"
| table EventRecordID Image CommandLine
```
→ **none.** The `| iex` runs in-process; no child spawned (no compiler, unlike PS-001).

## Q4 — Files written by A0
```spl
index=attack_data source="ps003_obfuscated_sysmon.log" EventCode=11
  ProcessGuid="{E983936C-D099-6006-FD07-00000000A301}"
| table _time EventRecordID TargetFilename
```
→ **28485** (`PSScriptPolicyTest…` — benign runtime artifact only).

## Q5 — Hypotheses: what does the obfuscated command do, and did it touch LSASS?
1. **Deobfuscate** (offline / `DER-001`): concat the single-quoted fragments →
   `Write-Host aAgHello, World!aAg`, then `.Replace('aAg',[char]39)` → **`Write-Host 'Hello, World!'`** — benign.
2. Direction check:
```spl
index=attack_data source="ps003_obfuscated_sysmon.log" EventCode=10
  SourceImage="*lsass.exe" TargetProcessGuid="{E983936C-D099-6006-FD07-00000000A301}"
```
→ records **28486, 28487** — **LSASS is the SOURCE** (reversed). The forward query
(`TargetImage=*lsass* SourceProcessGuid=A0`) returns **0**. Counter-evidence, both ways.

## Q6 — Absence: any outcome?
```spl
index=attack_data source="ps003_obfuscated_sysmon.log" EventCode=3
  ProcessGuid="{E983936C-D099-6006-FD07-00000000A301}"
```
→ **0** — no network. The deobfuscated `Write-Host` has no side effect.

---

## Curation record
| Record | Event | Surfaced by | Why it's in the case |
|-------:|-------|-------------|----------------------|
| **28476** | EID1 obfuscated powershell `\| iex` | Q1 | **A0** — triggering alert (deobfuscates via DER-001) |
| 28429 | EID1 `cmd.exe` (parent, via explorer) | Q2 | interactive launch context |
| 28485 | EID11 `PSScriptPolicyTest…` | Q4 | benign runtime artifact |
| 28486 | EID10 `lsass → powershell` | Q5 | **counter** — LSASS is the *source* |
| 28487 | EID10 `lsass → powershell` | Q5 | **counter** — LSASS is the *source* |

**Excluded:** heavy benign desktop noise (`Explorer.EXE → SearchUI/ShellExperienceHost/firefox`),
`csrss/conhost/svchost` handle-opens; Q3/Q6 empty (no child, no network — the *absences* confirm benign).

## Export
```spl
index=attack_data source="ps003_obfuscated_sysmon.log"
  EventRecordID IN (28476, 28429, 28485, 28486, 28487)
| dedup EventRecordID
| sort _time | table _time EventRecordID _raw
```
Export (All Time) → **JSON** → `extracted/ps003_events.json`.

## Normalize

Run from the project root:

```bash
python3 tools/normalize.py --case tier1/counter/heldout/PS-003_obfuscated_powershell --from-log
python3 tools/normalize.py --case tier1/counter/heldout/PS-003_obfuscated_powershell --verify-log
```

The first command rebuilds the package from the retained raw source. The second re-derives it and byte-compares it with `model_input/alert_package.json`.
