# BF-001 — Splunk retrieval specification

Category: Brute Force (T1110 / T1110.001) · **Tier-1, single sensor (Sysmon)** · Split: dev.
Evidence condition: **weak** · Calibration role: **over-triage-prone** (down-rank).

## Source scope
**One log:** `.../T1110.001/rdp_brute_sysmon/sysmon.log` (Computer `ar-win-dc`).
Single host, single sensor — Sysmon **network** events (EID 3) only. Verified single-source.

## Step 0 — Stage and ingest
`cp .../rdp_brute_sysmon/sysmon.log _splunk_ingest/bf001_rdp_bruteforce_sysmon.log`
→ `sourcetype=XmlWinEventLog`, `index=attack_data`, source `bf001_rdp_bruteforce_sysmon.log`, `TZ=UTC`.

---

## Investigation

## Q1 — The alert (A0): an inbound RDP connection from an external IP
```spl
index=attack_data source="bf001_rdp_bruteforce_sysmon.log" EventCode=3 DestinationPort=3389
| table _time EventRecordID SourceIp SourcePort DestinationIp Initiated Image
```
**A0 = record 4816** — an inbound (`Initiated=false`) RDP/TCP-3389 connection to `ar-win-dc`
(10.0.1.14) from **23.93.242.200**, accepted by `svchost.exe` (TermService).

## Q2 — One-off, or a pattern?
```spl
index=attack_data source="bf001_rdp_bruteforce_sysmon.log" EventCode=3 DestinationPort=3389
| stats count min(_time) max(_time) dc(SourcePort) by SourceIp
```
→ **23 connections** from the **single IP 23.93.242.200** over ~5.5 min (19:33:06–19:38:40), each on
a **new source port** (52977→53140) = 23 distinct connection attempts. A classic RDP connection brute.

## Q3 — External source?
`23.93.242.200` is outside the `10.0.1.0/24` range — an external host repeatedly hitting RDP. Suspicious.

## Q4 — The decisive check: did any logon actually happen? (auth outcome)
```spl
index=attack_data source="bf001_rdp_bruteforce_sysmon.log" (EventCode=4624 OR EventCode=4625)
```
→ **nothing.** This capture is Sysmon **network** telemetry only; there is **no Security auth data**
(no 4625 failures, no 4624 success). **We cannot tell whether any authentication was even attempted,
let alone succeeded.**

## Q5 — Any post-compromise activity on the host?
```spl
index=attack_data source="bf001_rdp_bruteforce_sysmon.log" (EventCode=1 OR EventCode=11)
```
→ none — no process creation, no file writes. Nothing indicates a foothold was obtained.

## Q6 — Weak crux
Repeated inbound RDP connections from one external IP are a real **brute-force indicator** — but
network-connection metadata alone is **insufficient to confirm a compromise** (no auth success, no
follow-on activity). The correct read is *"suspicious repeated RDP connections from an external IP →
investigate / check auth logs,"* **not** *"confirmed RDP brute-force breach."* A model that escalates
to High on connection counts alone is over-triaging — this case catches that.

---

## Curation record
| Record(s) | Event | Surfaced by | Why in the case |
|-----------|-------|-------------|-----------------|
| **4816** | first inbound RDP connection from 23.93.242.200 | Q1 | **A0** — the triggering external-RDP alert |
| 4827,4828,4829,4830,4831,4840,4851,4853,4858–4869,4871,4885 | the remaining 22 inbound RDP connections (same IP) | Q2 | establish the 23-connection brute burst |

**Absent (the point):** any 4624/4625 auth event (Q4), any process/file activity (Q5) — the outcome
that would confirm compromise is not in view.

## Export
```spl
index=attack_data source="bf001_rdp_bruteforce_sysmon.log"
  EventRecordID IN (4816,4827,4828,4829,4830,4831,4840,4851,4853,4858,4859,4860,4861,4862,4863,4864,4865,4866,4867,4868,4869,4871,4885)
| dedup EventRecordID
| sort _time | table _time EventRecordID _raw
```
Export (All Time) → **JSON** → `extracted/bf001_events.json`.

## Normalize

Run from the project root:

```bash
python3 tools/normalize.py --case tier1/weak/dev/BF-001_rdp_bruteforce --from-log
python3 tools/normalize.py --case tier1/weak/dev/BF-001_rdp_bruteforce --verify-log
```

The first command rebuilds the package from the retained raw source. The second re-derives it and byte-compares it with `model_input/alert_package.json`.
