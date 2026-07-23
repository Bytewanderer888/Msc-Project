# ING-001 — Splunk retrieval specification

Category: Ingress Tool Transfer (T1105) · **Tier-1, single sensor (Sysmon)** · Split: dev.
Evidence condition: **missing** · Calibration role: **over-triage-prone** (down-rank).

## Source scope
**One log:** `.../T1105/atomic_red_team/windows-sysmon_curl.log` (Computer `win-dc-469`).
Single host, single sensor (Sysmon EID 1 process-create + EID 11 file-create). Verified single-source.

## Step 0 — Stage and ingest
`cp .../T1105/atomic_red_team/windows-sysmon_curl.log _splunk_ingest/ing001_curl_download_sysmon.log`
→ `sourcetype=XmlWinEventLog`, `index=attack_data`, source `ing001_curl_download_sysmon.log`, `TZ=UTC`.

---

## Investigation

## Q1 — The alert (A0): curl downloading a DLL from an external URL
```spl
index=attack_data source="ing001_curl_download_sysmon.log" EventCode=1 Image="*\\curl.exe"
| table _time EventRecordID CommandLine ParentImage
```
**A0 = record 34354060** — `curl.exe -k https://github.com/…/AllTheThingsx64.dll -o
c:\users\public\music\allthethingsx64.dll` (insecure fetch of a **DLL** to a **Public** path via cmd.exe).

## Q2 — Download pattern
```spl
index=attack_data source="ing001_curl_download_sysmon.log" EventCode=1 Image="*\\curl.exe"
| table _time EventRecordID CommandLine
```
→ **4 downloads** of the same `AllTheThingsx64.dll`, staged to `C:\Users\Public\Music\` (×2),
`C:\ProgramData\`, and `…\AppData\Local\Temp\` — classic **malware-staging locations**.

## Q3 — The files landed
```spl
index=attack_data source="ing001_curl_download_sysmon.log" EventCode=11 TargetFilename="*allthethings*"
| table _time EventRecordID TargetFilename
```
→ four `allthethingsx64.dll` file-creates (records 34354105, 34354151, 34354196, 34354241). The payload
**is on disk**.

## Q4 — The decisive check: did the DLL execute or load?
```spl
index=attack_data source="ing001_curl_download_sysmon.log"
  (EventCode=1 Image="*allthethings*") OR (EventCode=7 ImageLoaded="*allthethings*")
  OR (EventCode=1 (CommandLine="*rundll32*allthethings*" OR CommandLine="*regsvr32*allthethings*"))
```
→ **zero results in the retained source.** The source spans only
`16:32:41.994656500Z`–`16:32:42.454400000Z`, so the bounded conclusion is that execution or
loading is **not evidenced in this capture**, not that it could never occur later.

## Q5 — What is the file, actually?
No hash/reputation is available from these events, and the source URL is
`github.com/redcanaryco/atomic-red-team/…/T1218.010/bin/AllTheThingsx64.dll` — a **known red-team test
repository**. So the payload's malicious nature is **unconfirmed** (and there's a benign-source hint).

## Q6 — Missing crux
A DLL was fetched to staging paths (alarming), but execution is **not evidenced in the retained
source**, and its content/intent is
**unconfirmed**. The evidence needed to conclude a compromise (execution, malicious behaviour, a bad
reputation) is **absent**. The correct read is *"suspicious download → contain the file and investigate"*
(Medium), **not** *"confirmed malware infection"* (High/Critical). A model that concludes compromise from
staging alone is over-triaging — this case catches that.

---

## Curation record
| Record | Event | Surfaced by | Why in the case |
|-------:|-------|-------------|-----------------|
| **34354060** | `curl -o …\Public\Music\allthethingsx64.dll` | Q1 | **A0** — external DLL download |
| 34354107 | `curl --output …\Public\Music\…` | Q2 | second download |
| 34354153 | `curl -o c:\programdata\…` | Q2 | third download (ProgramData) |
| 34354198 | `curl -o …\Temp\2\…` | Q2 | fourth download (Temp) |
| 34354105, 34354151, 34354196, 34354241 | `allthethingsx64.dll` file-creates | Q3 | the payload on disk (4 locations) |

**Absent (the point):** any execution/load of the DLL (Q4) — no process, no `rundll32`/`regsvr32`, no image
load. The confirming malicious outcome is not present. (Payload content also unverifiable here.)

## Export
```spl
index=attack_data source="ing001_curl_download_sysmon.log"
  EventRecordID IN (34354060, 34354105, 34354107, 34354151, 34354153, 34354196, 34354198, 34354241)
| dedup EventRecordID
| sort _time | table _time EventRecordID _raw
```
Export (All Time) → **JSON** → `extracted/ing001_events.json`.

## Normalize

Run from the project root:

```bash
python3 tools/normalize.py --case tier1/missing/dev/ING-001_curl_dll_staging --from-log
python3 tools/normalize.py --case tier1/missing/dev/ING-001_curl_dll_staging --verify-log
```

The first command rebuilds the package from the retained raw source. The second re-derives it and byte-compares it with `model_input/alert_package.json`.
