# ING-002 — Splunk retrieval specification

Category: Ingress tool transfer (staging visible; execution unconfirmed) · **Tier-1 single sensor (Sysmon)** · Split: held-out.
Evidence condition: **missing** (transfer commands and one file creation are visible; execution is not evidenced).
Calibration role: **over-triage-prone (down-rank)**.

## Source scope
`.../attack_techniques/T1105/atomic_red_team/windows-sysmon.log` — **multi-host log; scope to host `win-dc-792.attackrange.local`**, EID1 + EID11.

## Step 0 — Stage and ingest
```
cp .../T1105/atomic_red_team/windows-sysmon.log  _splunk_ingest/ing002_download_sysmon.log
```
→ `sourcetype=XmlWinEventLog`, `index=attack_data`, source `ing002_download_sysmon.log`, `TZ=UTC`.

## Investigation
## Q1 — the alert (A0): a bitsadmin download
```spl
index=attack_data source="ing002_download_sysmon.log" Computer="win-dc-792.attackrange.local"
  EventCode=1 Image="*bitsadmin.exe"
| table _time EventRecordID CommandLine ParentImage
```
→ **A0 = 5917230** — `bitsadmin /transfer ... <GitHub raw URL> %Temp%\Atomic-license.txt`.

## Q2 — the download + file-create (context EVs): a `certutil -urlcache` fetch of the same file (5917149), the EID11 file-create of `Atomic-license.txt` in `%Temp%` (5917171), and the `cmd.exe` wrapper (5917221).

## Q3 — was the downloaded file executed? (the decisive gap)
```spl
index=attack_data source="ing002_download_sysmon.log" Computer="win-dc-792.attackrange.local"
  EventCode=1 (Image="*Atomic-license*" OR ParentImage="*Atomic-license*")
```
→ zero matching ProcessCreate events. The filename is `LICENSE.txt`, but content and file type are not
verified; execution of the destination is not evidenced in the scoped source window.

**Missing crux:** bitsadmin and certutil transfer invocations are present, and EV-002 confirms
certutil created the destination object. The filename suggests `LICENSE.txt`, but the package has no
content, hash, or reputation evidence and does not independently confirm bitsadmin success. No process
execution of the destination is present in the scoped Sysmon source. A model must **not** conclude
"malware executed / host compromised" or call the object benign from its name alone.

## Curation record

The selected record ids and researcher-only evidence roles are fixed in `build/case.json` and retained in `annotations/selection_metadata.json`.

## Export
```spl
index=attack_data source="ing002_download_sysmon.log" Computer="win-dc-792.attackrange.local"
  EventRecordID IN (5917230, 5917149, 5917171, 5917221)
| dedup EventRecordID
| sort _time | table _time EventRecordID _raw
```
Export (All Time) → **JSON** → `extracted/ing002_events.json`.

## Normalize

Run from the project root:

```bash
python3 tools/normalize.py --case tier1/missing/heldout/ING-002_bitsadmin_download --from-log
python3 tools/normalize.py --case tier1/missing/heldout/ING-002_bitsadmin_download --verify-log
```

The first command rebuilds the package from the retained raw source. The second re-derives it and byte-compares it with `model_input/alert_package.json`.
