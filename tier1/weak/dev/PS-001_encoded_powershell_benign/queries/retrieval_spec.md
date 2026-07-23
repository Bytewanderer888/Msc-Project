# PS-001 — Splunk retrieval specification

Category: PowerShell (T1059.001) · **Tier-1, single sensor (Sysmon)** · Split: dev.
Evidence condition: **weak** (present encoded execution remains semantically ambiguous) **+ counter element** (LSASS-direction trap).

This is the **canonical format for all query files**: an ordered sequence of pivots
that models how an analyst / AI-SOC tool actually investigates — start from the alert,
extract its entities, then expand outward by *identity* (ProcessGuid), not by guesswork.
Each query consumes the output (the GUIDs) of the previous one.

## Source scope
**Exactly ONE log:** `.../T1059.001/powershell_execution_policy/windows-sysmon.log`
(the `Computer` field is `win-dc-235`). The folder's `windows-powershell.log`/
`windows-security.log` are different hosts → NOT part of this incident. Tier-1 single-sensor.

## Step 0 — Stage and ingest
The dataset file is `windows-sysmon.log` — a name shared by hundreds of folders. Do NOT
upload it under that name (on Upload, Splunk sets `source` = the uploaded filename, so
every `windows-sysmon.log` collides into one `source`). Give this case's log a unique name:

1. **Copy + rename** into the staging folder (once):
   ```bash
   cp ".../T1059.001/powershell_execution_policy/windows-sysmon.log" \
      "_splunk_ingest/ps001_execpolicy_sysmon.log"
   ```
2. **Ingest** → *Add Data → Upload* → `ps001_execpolicy_sysmon.log`,
   `sourcetype=XmlWinEventLog`, `index=attack_data`. Splunk then sets
   **`source="ps001_execpolicy_sysmon.log"`** (the filename) — that is what every query
   below uses. *(Optional: set a Source override to drop the `.log`.)*

> ⚠️ **`host` is your Splunk machine (e.g. `lalaladeAir`), NOT `win-dc-235`.** On upload
> Splunk stamps its own hostname; the real host is the **`Computer`** field inside the
> events. Scope with `source=` (or `Computer=`) — never `host=win-dc-235`.

**Verify:**
```spl
index=attack_data source="ps001_execpolicy_sysmon.log" | stats count values(Computer)
```
→ ~7,921 events, `Computer=win-dc-235.attackrange.local`, `_time` in UTC. If events exist
here but the field-based queries below return nothing, your Sysmon fields aren't extracted
→ install the "Splunk Add-on for Sysmon", then re-run.

---

## Investigation

## Q1 — The alert (A0): extract its entities
```spl
index=attack_data source="ps001_execpolicy_sysmon.log" EventCode=1
  Image="*powershell.exe" CommandLine="*EncodedCommand*"
| table _time EventRecordID ProcessGuid ParentProcessGuid CommandLine
```
Two nested encoded PowerShells. **A0 = the executing (inner) one — record 93.**
Carry forward:
- `A0.ProcessGuid       = {2935EF20-8ECF-5FD0-0000-001039791000}`
- `A0.ParentProcessGuid = {2935EF20-8ECE-5FD0-0000-00106A6D1000}`

## Q2 — Walk UP the ancestry (how was A0 launched?)
Pivot on `A0.ParentProcessGuid`, then repeat on each parent's parent:
```spl
index=attack_data source="ps001_execpolicy_sysmon.log" EventCode=1
  ProcessGuid="{2935EF20-8ECE-5FD0-0000-00106A6D1000}"
| table EventRecordID Image CommandLine ProcessGuid ParentProcessGuid
```
→ record **73** (outer powershell); its parent = `{...00109F6C1000}`. Repeat once more →
record **60** (`cmd.exe /C PowerShell ...`), whose parent is `WinrsHost.exe` (a **remote
WinRS session** — the origin). Stop there. **Lineage so far:** WinRS → cmd(60) → ps(73) → **A0(93)**.

## Q3 — Walk DOWN to children (what did A0 do?)
Pivot on `A0.ProcessGuid`:
```spl
index=attack_data source="ps001_execpolicy_sysmon.log" EventCode=1
  ParentProcessGuid="{2935EF20-8ECF-5FD0-0000-001039791000}"
| table _time EventRecordID Image CommandLine ProcessGuid
```
→ **110** (`chcp.com`) and **128** (`csc.exe` — inline C# compilation). Lineage GUIDs now:
`L = { …00109F6C1000, …00106A6D1000, …001039791000 }` (+ csc).

## Q4 — Behavioural evidence for the lineage (files)
```spl
index=attack_data source="ps001_execpolicy_sysmon.log" EventCode=11
  ProcessGuid IN ("{2935EF20-8ECF-5FD0-0000-001039791000}",
                  "{2935EF20-8ECE-5FD0-0000-00106A6D1000}")
| table _time EventRecordID Image TargetFilename
```
→ **87, 107** (`PSScriptPolicyTest*` — benign runtime checks), **126, 127**
(`40sjawwp.dll` / `.cmdline` — compiler inputs). (csc's output `40sjawwp.dll` = record **154**.)

## Q5 — Hypothesis check: "is this credential dumping?" (the key finding)
An encoded PowerShell on a DC → test the LSASS hypothesis **in both directions**.
First, did the PowerShell access LSASS?
```spl
index=attack_data source="ps001_execpolicy_sysmon.log" EventCode=10
  TargetImage="*lsass.exe"
  SourceProcessGuid IN ("{2935EF20-8ECF-5FD0-0000-001039791000}","{2935EF20-8ECE-5FD0-0000-00106A6D1000}")
```
→ **0 results.** Now the reverse — did LSASS access the PowerShell?
```spl
index=attack_data source="ps001_execpolicy_sysmon.log" EventCode=10
  SourceImage="*lsass.exe"
  TargetProcessGuid IN ("{2935EF20-8ECF-5FD0-0000-001039791000}","{2935EF20-8ECE-5FD0-0000-00106A6D1000}")
```
→ records **88, 89, 108, 109**. **LSASS is the SOURCE.** This is the counter-evidence: a
"PowerShell dumped LSASS" conclusion is **contradicted** (direction reversed).

## Q6 — Absence checks (what is NOT there)
```spl
index=attack_data source="ps001_execpolicy_sysmon.log" EventCode=3
  ProcessGuid IN ("{2935EF20-8ECF-5FD0-0000-001039791000}","{2935EF20-8ECE-5FD0-0000-00106A6D1000}")
```
→ **0 results** — no network connection is visible for this lineage. The condition is still
**weak**, not missing: encoded execution, descendants, and compiler artifacts are present, but
their security meaning remains ambiguous because the command supplied to the decoded STDIN
wrapper is unavailable. The zero-result query bounds what may be asserted; it is not treated as
a decisive benign fact.

---

## Curation record
The 14 records are **not a magic list** — each is an output of a specific pivot above, and
every excluded event is accounted for. This table is the audit trail behind the export query.

| Record | Event (Sysmon) | Surfaced by | Why it is in the case |
|-------:|----------------|-------------|-----------------------|
| **93** | EID1 `powershell -EncodedCommand` | **Q1** | **A0** — the triggering alert |
| 60  | EID1 `cmd /C PowerShell` | Q2 (ancestry) | launch chain: remote WinRS → cmd |
| 73  | EID1 outer `powershell -enc` | Q2 (ancestry) | A0's parent (nested encoding) |
| 110 | EID1 `chcp.com` | Q3 (descendants) | A0 child — wrapper sets code page |
| 128 | EID1 `csc.exe` | Q3 (descendants) | A0 child — inline C# compilation |
| 87  | EID11 `PSScriptPolicyTest…` | Q4 (files) | benign runtime-policy artifact |
| 107 | EID11 `PSScriptPolicyTest…` | Q4 (files) | benign runtime-policy artifact |
| 126 | EID11 `40sjawwp.dll` | Q4 (files) | compiler input/output |
| 127 | EID11 `40sjawwp.cmdline` | Q4 (files) | compiler input |
| 154 | EID11 `40sjawwp.dll` (by csc) | Q4 (files) | compiler output |
| 88  | EID10 `lsass → ps(73)` | Q5 (hypothesis) | **counter** — LSASS is the *source* |
| 89  | EID10 `lsass → ps(73)` | Q5 (hypothesis) | **counter** — LSASS is the *source* |
| 108 | EID10 `lsass → ps(93)` | Q5 (hypothesis) | **counter** — LSASS is the *source* |
| 109 | EID10 `lsass → ps(93)` | Q5 (hypothesis) | **counter** — LSASS is the *source* |

**Deliberately excluded** (also part of the audit trail):
- ~24 EID10 handle-opens by `csrss.exe` / `conhost.exe` / `svchost.exe` on the lineage
  processes — benign OS plumbing (standard access masks), not security-relevant.
- `WinrsHost.exe` — kept only as the *parent context* inside record 60, not a separate EV.
- **Q6** network (EID3) returned **0** — nothing to include; the absence is itself recorded evidence.

Because the source log is fixed (SHA-256 in `source/provenance.json`), these EventRecordIDs are
stable and reproducible. This table is the human-readable form of the `evidence_id_map` /
`event_groups` in `annotations/selection_metadata.json`.

## Export
You've identified the records in Q1–Q6; now pull the curated 14 in one deterministic query
and keep the raw XML so the normalizer can parse any field:
```spl
index=attack_data source="ps001_execpolicy_sysmon.log"
  EventRecordID IN (93, 60, 73, 87, 88, 89, 107, 108, 109, 110, 126, 127, 128, 154)
| dedup EventRecordID
| sort _time
| table _time EventRecordID _raw
```
Run it (time range **All Time**) → click **Export** (icon under the search bar) →
**Format: JSON** → save as `extracted/ps001_events.json`. That 14-record JSON is your
reproducibility artifact and the normalizer's input.
*(If your extraction names the field `RecordNumber` instead of `EventRecordID`, use that.)*

## Normalize

Run from the project root:

```bash
python3 tools/normalize.py --case tier1/weak/dev/PS-001_encoded_powershell_benign --from-log
python3 tools/normalize.py --case tier1/weak/dev/PS-001_encoded_powershell_benign --verify-log
```

The first command rebuilds the package from the retained raw source. The second re-derives it and byte-compares it with `model_input/alert_package.json`.
