# DISC-003 — Splunk retrieval specification

Category: Local account/group discovery (no follow-on) · **Tier-1 single sensor (Sysmon)** · Split: held-out.
Evidence condition: **weak** (local account enumeration; no follow-on — intent ambiguous).
Calibration role: **over-triage-prone (down-rank)**.

## Source scope
`.../attack_techniques/T1087.001/AD_discovery/windows-sysmon.log` — **multi-host log; scope to host `win-host-987.attackrange.local`**, EID1-only.

## Step 0 — Stage and ingest
```
cp .../T1087.001/AD_discovery/windows-sysmon.log  _splunk_ingest/disc003_localacct_sysmon.log
```
→ `sourcetype=XmlWinEventLog`, `index=attack_data`, source `disc003_localacct_sysmon.log`, `TZ=UTC`.

## Investigation
## Q1 — the alert (A0): local account enumeration
```spl
index=attack_data source="disc003_localacct_sysmon.log" Computer="win-host-987.attackrange.local"
  EventCode=1 (CommandLine="*Get-LocalUser*" OR CommandLine="*Win32_UserAccount*")
| table _time EventRecordID CommandLine ParentImage
```
→ **A0 = 30727372** — `powershell Get-LocalUser`.

## Q2 — the recon burst (context EVs): a `cmd /c powershell Get-LocalUser` wrapper (30727364) and two `Get-WmiObject Win32_UserAccount` enumerations (30727454, 30727462).

## Q3 — any follow-on? (the decisive gap)
```spl
index=attack_data source="disc003_localacct_sysmon.log" Computer="win-host-987.attackrange.local"
  EventCode=1 NOT (CommandLine="*Get-LocalUser*" OR CommandLine="*Win32_UserAccount*")
```
→ no credential-access, lateral-movement, or payload execution follows. **Outcome ABSENT.**

**Weak crux:** account enumeration is a real recon indicator, but with no follow-on the intent is ambiguous (admin audit vs reconnaissance). A model must **not** over-read it as active recon. (Distinct from DISC-001 = AD/domain, DISC-002 = SSM/system inventory.)

## Curation record

The selected record ids and researcher-only evidence roles are fixed in `build/case.json` and retained in `annotations/selection_metadata.json`.

## Export
```spl
index=attack_data source="disc003_localacct_sysmon.log" Computer="win-host-987.attackrange.local"
  EventRecordID IN (30727372, 30727364, 30727454, 30727462)
| dedup EventRecordID
| sort _time | table _time EventRecordID _raw
```
Export (All Time) → **JSON** → `extracted/disc003_events.json`.

## Normalize

Run from the project root:

```bash
python3 tools/normalize.py --case tier1/weak/heldout/DISC-003_local_account_discovery --from-log
python3 tools/normalize.py --case tier1/weak/heldout/DISC-003_local_account_discovery --verify-log
```

The first command rebuilds the package from the retained raw source. The second re-derives it and byte-compares it with `model_input/alert_package.json`.
