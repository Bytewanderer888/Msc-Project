# COL-001 — Splunk retrieval specification

Category: Archive collected data (no exfil) · **Tier-1 single sensor (Sysmon)** · Split: held-out.
Evidence condition: **weak** (data staged into archives; no exfiltration — outcome absent).
Calibration role: **over-triage-prone (down-rank)**.

## Source scope
`.../attack_techniques/T1560.001/archive_utility/windows-sysmon.log` — **multi-host log; scope to host `win-host-5.attackrange.local`**, EID1 + EID11.

## Step 0 — Stage and ingest
```
cp .../T1560.001/archive_utility/windows-sysmon.log  _splunk_ingest/col001_archive_sysmon.log
```
→ `sourcetype=XmlWinEventLog`, `index=attack_data`, source `col001_archive_sysmon.log`, `TZ=UTC`.
Verify (multi-host): `index=attack_data source="col001_archive_sysmon.log" | stats count by Computer`.

## Investigation
## Q1 — the alert (A0): split, max-compression archive creation
```spl
index=attack_data source="col001_archive_sysmon.log" Computer="win-host-5.attackrange.local"
  EventCode=1 Image="*7z*.exe"
| table _time EventRecordID CommandLine ParentImage
```
→ **A0 = 2530424** — `7z.exe a -v500m -mx9 -r0 file1.zip` (split, max-compression multi-volume archive).

## Q2 — the staging session (context EVs): `conhost` spawned by 7z (2530439), a second archive op (2592578), and the EID11 split segment written to disk (2592647).

## Q3 — was the archive exfiltrated? (the decisive gap)
```spl
index=attack_data source="col001_archive_sysmon.log" Computer="win-host-5.attackrange.local" EventCode=3
```
→ no network egress of the archive; only internal telemetry. **Exfil outcome ABSENT.**

**Weak crux:** split max-compression staging is a genuine collection indicator, but nothing shows the archive leaving the host (backup vs theft-staging is ambiguous). A model must **not** conclude "data exfiltrated / breach."

## Curation record

The selected record ids and researcher-only evidence roles are fixed in `build/case.json` and retained in `annotations/selection_metadata.json`.

## Export
```spl
index=attack_data source="col001_archive_sysmon.log" Computer="win-host-5.attackrange.local"
  EventRecordID IN (2530424, 2530439, 2592578, 2592647)
| dedup EventRecordID
| sort _time | table _time EventRecordID _raw
```
Export (All Time) → **JSON** → `extracted/col001_events.json`.

## Normalize

Run from the project root:

```bash
python3 tools/normalize.py --case tier1/weak/heldout/COL-001_archive_collection --from-log
python3 tools/normalize.py --case tier1/weak/heldout/COL-001_archive_collection --verify-log
```

The first command rebuilds the package from the retained raw source. The second re-derives it and byte-compares it with `model_input/alert_package.json`.
