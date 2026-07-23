# PS-002 — Splunk retrieval specification

Category: PowerShell (T1059.001) · **Tier-1, single sensor (Sysmon)** · Split: dev.
Evidence condition: **weak** (visible download action + file on disk, but content/execution unconfirmed).

## Source scope
**One log:** `.../T1059.001/hidden_powershell/windows-sysmon.log` (Computer `win-dc-555`).
NB: this folder *also* contains the encoded-wrapper events (the PS-001 twin) — this case
deliberately uses the **visible hidden-window download cradle**, not those.

## Step 0 — Stage and ingest
`cp .../hidden_powershell/windows-sysmon.log _splunk_ingest/ps002_hidden_ps_sysmon.log`
→ *Add Data → Upload* → `sourcetype=XmlWinEventLog`, `index=attack_data`,
source becomes **`ps002_hidden_ps_sysmon.log`**. (`host` = your Splunk box; real host is the
`Computer` field = `win-dc-555`.) Set `TZ=UTC` on the sourcetype.
Verify: `index=attack_data source="ps002_hidden_ps_sysmon.log" | stats count values(Computer)`.

---

## Investigation

## Q1 — The alert (A0)
```spl
index=attack_data source="ps002_hidden_ps_sysmon.log" EventCode=1
  Image="*powershell.exe" CommandLine="*DownloadFile*" CommandLine="*hidden*"
| table _time EventRecordID ProcessGuid ParentProcessGuid CommandLine
```
**A0 = record 14032**, `ProcessGuid={E036F963-8F04-5FB7-0000-00105CD62200}`. Carry its
ProcessGuid and ParentProcessGuid forward.

## Q2 — Walk UP (how launched?)
```spl
index=attack_data source="ps002_hidden_ps_sysmon.log" EventCode=1
  ProcessGuid="<A0.ParentProcessGuid>"
| table EventRecordID Image CommandLine ParentImage
```
→ record **13586** (`cmd.exe`), whose parent is **`explorer.exe`** — an *interactive* launch.

## Q3 — Walk DOWN (children)
```spl
index=attack_data source="ps002_hidden_ps_sysmon.log" EventCode=1
  ParentProcessGuid="{E036F963-8F04-5FB7-0000-00105CD62200}"
| table EventRecordID Image CommandLine
```
→ **none.** `DownloadFile` saves to disk without spawning a child.

## Q4 — Files written by A0
```spl
index=attack_data source="ps002_hidden_ps_sysmon.log" EventCode=11
  ProcessGuid="{E036F963-8F04-5FB7-0000-00105CD62200}"
| table _time EventRecordID TargetFilename
```
→ **14041** (`PSScriptPolicyTest…` — benign) and **14046**
(`C:\Users\Administrator\Default_File_Path.ps1` — the **downloaded file landed**).

## Q5 — Hypothesis: did the download actually reach the network?
```spl
index=attack_data source="ps002_hidden_ps_sysmon.log" (EventCode=3 OR EventCode=22)
  ProcessGuid="{E036F963-8F04-5FB7-0000-00105CD62200}"
```
→ **0 results.** No EID3/EID22 captured — the destination is known *only* from the
command-line URL (`bit.ly/…`), not corroborated by a network sensor. (A key "weak" signal.)

## Q6 — Absence: was the downloaded file executed?
```spl
index=attack_data source="ps002_hidden_ps_sysmon.log" EventCode=1 CommandLine="*Default_File_Path*"
```
→ **0 results** — execution of the fetched `.ps1` is not evidenced in the scoped source. The supported
reading is a suspicious download with unverified content and no observed execution → weak.

---

## Curation record
| Record | Event | Surfaced by | Why it's in the case |
|-------:|-------|-------------|----------------------|
| **14032** | EID1 hidden-window `DownloadFile` cradle | Q1 | **A0** — triggering alert |
| 13586 | EID1 `cmd.exe` (parent, via explorer) | Q2 | interactive launch context |
| 14041 | EID11 `PSScriptPolicyTest…` | Q4 | benign runtime artifact |
| 14046 | EID11 `Default_File_Path.ps1` | Q4 | the download landed (action succeeded) |

**Excluded / absent:** the OS `csrss/conhost/svchost` handle-opens (noise); Q3/Q5/Q6 all
returned nothing (no child, no network, no execution) — those *absences are the evidence*.
The Atomic test ran ~7 cradle variants (09:37–09:53); scoped to this one clean execution.

## Export
```spl
index=attack_data source="ps002_hidden_ps_sysmon.log"
  EventRecordID IN (14032, 13586, 14041, 14046)
| dedup EventRecordID
| sort _time | table _time EventRecordID _raw
```
Export (All Time) → **JSON** → `extracted/ps002_events.json`.

## Normalize

Run from the project root:

```bash
python3 tools/normalize.py --case tier1/weak/dev/PS-002_hidden_powershell_cradle --from-log
python3 tools/normalize.py --case tier1/weak/dev/PS-002_hidden_powershell_cradle --verify-log
```

The first command rebuilds the package from the retained raw source. The second re-derives it and byte-compares it with `model_input/alert_package.json`.
