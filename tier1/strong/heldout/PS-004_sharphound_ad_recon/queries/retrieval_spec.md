# PS-004 — Splunk retrieval specification

Category: PowerShell (T1059.001) · **Tier-1, single sensor (Sysmon)** · Split: held-out.
Evidence condition: **strong** · Calibration role: **under-triage-prone** (up-rank test).

## Source scope
**One log used:** `.../T1059.001/sharphound/windows-sysmon.log` (Computer `win-dc-233`).
NB: the folder *also* has a same-host (`win-dc-233`) `windows-powershell.log` (4104) → a
**multi-source (Tier-2) variant is possible**; deferred (needs the classic-format parser).

## Step 0 — Stage and ingest
`cp .../sharphound/windows-sysmon.log _splunk_ingest/ps004_sharphound_sysmon.log`
→ `sourcetype=XmlWinEventLog`, `index=attack_data`, source `ps004_sharphound_sysmon.log`, `TZ=UTC`.
Verify: `index=attack_data source="ps004_sharphound_sysmon.log" | stats count values(Computer)`.

---

## Investigation

## Q1 — The alert (A0)
```spl
index=attack_data source="ps004_sharphound_sysmon.log" EventCode=1
  Image="*powershell.exe" CommandLine="*import-module*SharpHound*"
| table _time EventRecordID ProcessGuid ParentProcessGuid CommandLine
```
**A0 = record 648984** (`powershell.exe import-module c:\temp\SharpHound.ps1`),
`ProcessGuid={D419E45B-DE7E-60B8-674E-00000000C401}`, parent `cmd.exe`.

## Q2 — Walk UP (how launched?)
```spl
index=attack_data source="ps004_sharphound_sysmon.log" EventCode=1
  ProcessGuid="<A0.ParentProcessGuid>"
| table EventRecordID Image CommandLine ParentImage
```
→ `cmd.exe /c powershell.exe import-module …`, itself spawned by a launching `powershell.exe`
(scripted/interactive origin).

## Q3 — The collector (pivot on the tool + temp dir)
A0 imports `SharpHound.ps1` from `c:\temp`; the compiled collector is a **separate** process
(not a GUID child of A0), correlated by host + user + `c:\temp` + tool:
```spl
index=attack_data source="ps004_sharphound_sysmon.log" EventCode=1
  Image="*\\SharpHound.exe" CommandLine="*CollectionMethod all*"
| table _time EventRecordID ProcessGuid CommandLine User IntegrityLevel
```
→ record **649806** — `c:\temp\sharphound.exe --CollectionMethod all`, `ATTACKRANGE\Administrator`,
High, `ProcessGuid={D419E45B-DEF0-60B8-814E-00000000C401}`.

## Q4 — What did the collector produce?
```spl
index=attack_data source="ps004_sharphound_sysmon.log" EventCode=11
  ProcessGuid="{D419E45B-DEF0-60B8-814E-00000000C401}"
| table _time EventRecordID TargetFilename
```
→ records **649831/649842/649843/649844/649845/649846/649857** — per-object JSON for
**groups, gpos, users, OUs, domains, computers** + **`BloodHound.zip`**.

## Q5 — Hypothesis: what collection outcome is evidenced?
The attributed output set spans users, groups, computers, OUs, GPOs, and domains and includes a
BloodHound archive. This confirms substantial AD collection output on a domain controller. The package
does not contain an exit status, so it does not claim error-free completion.

## Q6 — The under-triage crux
Surface reading: "a tool wrote some JSON + a zip to `C:\Temp`." Correct reading: SharpHound executed
and produced a broad AD collection artifact set on a DC — a serious pre-attack signal. A weak model
**under-rates** this; the correct severity floor is elevated. (This is the up-ranking test.)

---

## Curation record
| Record | Event | Surfaced by | Why it's in the case |
|-------:|-------|-------------|----------------------|
| **648984** | EID1 `powershell import-module SharpHound.ps1` | Q1 | **A0** — triggering alert |
| 649806 | EID1 `sharphound.exe --CollectionMethod all` | Q3 | the collector executed |
| 649831/649842/649843/649844/649845/649846 | EID11 groups/gpos/users/ous/domains/computers `.json` | Q4 | broad AD collection artifacts |
| 649857 | EID11 `…_BloodHound.zip` | Q4 | packaged collection archive |

**Excluded:** the SharpHound GUID-named `.bin` cache, Splunk-forwarder `splunk-powershell.exe`
noise, repeated import-module invocations, and the second collector run (`-c all`).

## Export
```spl
index=attack_data source="ps004_sharphound_sysmon.log"
  EventRecordID IN (648984, 649806, 649831, 649842, 649843, 649844, 649845, 649846, 649857)
| dedup EventRecordID
| sort _time | table _time EventRecordID _raw
```
Export (All Time) → **JSON** → `extracted/ps004_events.json`.

## Normalize

Run from the project root:

```bash
python3 tools/normalize.py --case tier1/strong/heldout/PS-004_sharphound_ad_recon --from-log
python3 tools/normalize.py --case tier1/strong/heldout/PS-004_sharphound_ad_recon --verify-log
```

The first command rebuilds the package from the retained raw source. The second re-derives it and byte-compares it with `model_input/alert_package.json`.
