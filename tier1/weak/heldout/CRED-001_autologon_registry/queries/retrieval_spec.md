# CRED-001 — Splunk retrieval specification

Category: Credentials in registry — AutoLogon set then reverted · **Tier-1 single sensor (Sysmon)** · Split: held-out.
Evidence condition: **weak** (plaintext creds written to Winlogon then deleted; no read/use — outcome absent).
Calibration role: **over-triage-prone (down-rank)**.

## Source scope
`.../attack_techniques/T1552.002/autoadminlogon/windows-sysmon.log` — **multi-host log; scope to host `win-dc-456.attackrange.local`**, EID1 + EID12/13.

## Step 0 — Stage and ingest
```
cp .../T1552.002/autoadminlogon/windows-sysmon.log  _splunk_ingest/cred001_autologon_sysmon.log
```
→ `sourcetype=XmlWinEventLog`, `index=attack_data`, source `cred001_autologon_sysmon.log`, `TZ=UTC`.

## Investigation
## Q1 — the alert (A0): AutoLogon username written to the registry
```spl
index=attack_data source="cred001_autologon_sysmon.log" Computer="win-dc-456.attackrange.local"
  EventCode=1 CommandLine="*Winlogon*DefaultUserName*"
| table _time EventRecordID CommandLine
```
→ **A0 = 48598** — `reg add ...\Winlogon /v DefaultUserName /d administrator`.

## Q2 — the credential + the revert (context EVs): `reg add ... /v DefaultPassword /d 12345` (48607), the two EID13 value sets — DefaultUserName (48606) and DefaultPassword (48615) — and the **EID12 delete of DefaultPassword** (48813): the credential is removed shortly after.

## Q3 — was the credential read / used? (the decisive gap)
```spl
index=attack_data source="cred001_autologon_sysmon.log" Computer="win-dc-456.attackrange.local"
  (EventCode=1 CommandLine="*DefaultPassword*") OR (EventCode=3)
```
→ no read/query, egress, or authentication follow-on is observed. EV-004 confirms deletion of
`DefaultPassword`; deletion of `DefaultUserName` is not evidenced.

**Weak crux:** plaintext AutoLogon values in the registry are a real T1552.002 indicator, but read or use is
not evidenced and the password value is later deleted. Intent remains ambiguous; a model must **not** conclude
"credentials stolen / used."

## Curation record

The selected record ids and researcher-only evidence roles are fixed in `build/case.json` and retained in `annotations/selection_metadata.json`.

## Export
```spl
index=attack_data source="cred001_autologon_sysmon.log" Computer="win-dc-456.attackrange.local"
  EventRecordID IN (48598, 48607, 48606, 48615, 48813)
| dedup EventRecordID
| sort _time | table _time EventRecordID _raw
```
Export (All Time) → **JSON** → `extracted/cred001_events.json`.

## Normalize

Run from the project root:

```bash
python3 tools/normalize.py --case tier1/weak/heldout/CRED-001_autologon_registry --from-log
python3 tools/normalize.py --case tier1/weak/heldout/CRED-001_autologon_registry --verify-log
```

The first command rebuilds the package from the retained raw source. The second re-derives it and byte-compares it with `model_input/alert_package.json`.
