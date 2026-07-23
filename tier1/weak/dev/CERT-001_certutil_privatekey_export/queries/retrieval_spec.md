# CERT-001 — Splunk retrieval specification

Category: Credential access via certificate private-key export (T1552.004) · **Tier-1 single sensor (Sysmon)** · Split: dev.
Evidence condition: **weak** (private-key export is a real indicator, but intent + outcome unverified).
Calibration role: **over-triage-prone** (down-rank).

## Source scope
`.../suspicious_behaviour/certutil_exe_certificate_extraction/windows-sysmon.log` — host `win-dc-782.attackrange.local`, **EID1-only**.

## Step 0 — Stage and ingest
```
cp .../certutil_exe_certificate_extraction/windows-sysmon.log  _splunk_ingest/cert001_certutil_sysmon.log
```
→ `sourcetype=XmlWinEventLog`, `index=attack_data`, source `cert001_certutil_sysmon.log`, `TZ=UTC`.
Verify: `index=attack_data source="cert001_certutil_sysmon.log" | stats count values(Computer)`.

## Investigation
## Q1 — the alert (A0): a private-key export
```spl
index=attack_data source="cert001_certutil_sysmon.log" EventCode=1 Image="*certutil.exe"
| table _time EventRecordID CommandLine ParentImage IntegrityLevel
```
→ **A0 = 14386** — `certutil.exe -privatekey -exportpfx "Computer" Computer.pfx` (High integrity, parent `cmd.exe`).

## Q2 — the surrounding session (context EVs): a 2nd private-key export `-privatekey -exportpfx "1234" test.pfx` (14673), store enumeration `-Store MY` (20445), a thumbprint export `-exportPFX My <thumb> C:\cert.pfx` (20623), and `-dcinfo` (14745).

## Q3 — was anything exfiltrated / used? (the decisive gap)
```spl
index=attack_data source="cert001_certutil_sysmon.log" (EventCode=3) OR (EventCode=11 TargetFilename="*.pfx")
```
→ no network egress of the PFX and no downstream use captured. **Outcome UNVERIFIED.**

**Weak crux:** exporting a certificate private key is a genuine T1552.004 indicator, but `certutil` is a signed MS tool and cert export/backup is a legitimate admin task — and nothing shows the keys leaving the host or being used. A model must **not** conclude "confirmed private-key theft."

## Curation record

The selected record ids and researcher-only evidence roles are fixed in `build/case.json` and retained in `annotations/selection_metadata.json`.

## Export
```spl
index=attack_data source="cert001_certutil_sysmon.log"
  EventRecordID IN (14386, 14673, 20445, 20623, 14745)
| dedup EventRecordID
| sort _time | table _time EventRecordID _raw
```
Export (All Time) → **JSON** → `extracted/cert001_events.json`.

## Normalize

Run from the project root:

```bash
python3 tools/normalize.py --case tier1/weak/dev/CERT-001_certutil_privatekey_export --from-log
python3 tools/normalize.py --case tier1/weak/dev/CERT-001_certutil_privatekey_export --verify-log
```

The first command rebuilds the package from the retained raw source. The second re-derives it and byte-compares it with `model_input/alert_package.json`.
