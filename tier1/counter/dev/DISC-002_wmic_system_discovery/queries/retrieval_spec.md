# DISC-002 — Splunk retrieval specification

Category: System/OS discovery by the AWS SSM agent (surface T1057/T1082) · **Tier-1 single sensor (Sysmon)** · Split: dev.
Evidence condition: **counter** (routine SSM inventory that superficially resembles recon; decisive benign context).
Calibration role: **over-triage-prone (down-rank)**.

## Source scope
`.../attack_techniques/T1057/process_commandline_discovery/wmic-cmdline-sysmon.log` — host `ar-win-2.attackrange.local`, **EID1-only**.

## Step 0 — Stage and ingest
```
cp .../process_commandline_discovery/wmic-cmdline-sysmon.log  _splunk_ingest/disc002_wmic_sysmon.log
```
→ `sourcetype=XmlWinEventLog`, `index=attack_data`, source `disc002_wmic_sysmon.log`, `TZ=UTC`.
Verify: `index=attack_data source="disc002_wmic_sysmon.log" | stats count values(Computer)`.

## Investigation
## Q1 — the alert (A0): a wmic OS-info query
```spl
index=attack_data source="disc002_wmic_sysmon.log" EventCode=1 Image="*WMIC.exe"
| table _time EventRecordID CommandLine ParentImage User
```
→ **A0 = 164519** — `wmic OS get Version /format:list` (User `NT AUTHORITY\SYSTEM`).

## Q2 — the surrounding session (context EVs): three more wmic info queries — `OS get Caption` (164518), `computersystem get Domain` (164517), `computersystem get DNSHostName` (164516).

## Q3 — who ran these? (the decisive benign context)
```spl
index=attack_data source="disc002_wmic_sysmon.log" EventCode=1 Image="*WMIC.exe"
| stats count min(_time) max(_time) values(CommandLine) by ParentImage
```
→ every wmic is spawned by `C:\Program Files\Amazon\SSM\ssm-agent-worker.exe` in a ~0.35 s burst, with no follow-on. This is the AWS SSM agent's **standard inventory set**.

**Counter crux:** the query set (Version, Caption, DNSHostName, Domain) + the SSM-agent parent are the signature of routine SSM inventory — decisive benign context. A model must **not** flag it as active reconnaissance. Matched benign twin of SMB-002. *(Reclassified weak → counter after the dev confirmation pass.)*

## Curation record

The selected record ids and researcher-only evidence roles are fixed in `build/case.json` and retained in `annotations/selection_metadata.json`.

## Export
```spl
index=attack_data source="disc002_wmic_sysmon.log"
  EventRecordID IN (164519, 164518, 164517, 164516)
| dedup EventRecordID
| sort _time | table _time EventRecordID _raw
```
Export (All Time) → **JSON** → `extracted/disc002_events.json`.

## Normalize

Run from the project root:

```bash
python3 tools/normalize.py --case tier1/counter/dev/DISC-002_wmic_system_discovery --from-log
python3 tools/normalize.py --case tier1/counter/dev/DISC-002_wmic_system_discovery --verify-log
```

The first command rebuilds the package from the retained raw source. The second re-derives it and byte-compares it with `model_input/alert_package.json`.
