# INJ-001 — Splunk retrieval specification

Category: Process injection (T1055) · **Tier-1, single sensor (Sysmon)** · Split: dev.
Evidence condition: **strong** · Calibration role: **preserve**.

## Source scope
**One log:** `.../T1055/sliver/notepad_windows-sysmon.log` (Computer `win-dc-84`). The folder's
other logs are the same host but separate/sparse captures; this case uses the notepad Sysmon capture.

## Step 0 — Stage and ingest
`cp .../sliver/notepad_windows-sysmon.log _splunk_ingest/inj001_sliver_notepad_sysmon.log`
→ `sourcetype=XmlWinEventLog`, `index=attack_data`, source `inj001_sliver_notepad_sysmon.log`, `TZ=UTC`.

---

## Investigation

## Q1 — The alert (A0): a remote thread into unbacked memory
```spl
index=attack_data source="inj001_sliver_notepad_sysmon.log" EventCode=8
  StartModule="-"
| table _time EventRecordID SourceImage TargetImage StartAddress StartModule StartFunction
```
**A0 = record 15275583** — `ILL_UNBLINKING.exe → notepad.exe`, `StartModule='-'` (unbacked).
Carry `SourceProcessGuid={0F9A6540-3D66-63F5-5C09-…}` and the target notepad's guid.

## Q2 — The injector
`ILL_UNBLINKING.exe` — a **non-system, randomly-named binary** (a Sliver C2 codename), not a
signed Windows tool. It is the SOURCE of the remote thread.

## Q3 — The target (sacrificial process)
```spl
index=attack_data source="inj001_sliver_notepad_sysmon.log" EventCode=1
  Image="*notepad.exe"
| table _time EventRecordID CommandLine ParentImage
```
→ `notepad.exe` spawned by **`ILL_UNBLINKING.exe`** with an **empty command line** (`notepad.exe ""`)
— i.e. spawned *to be injected*, not opened by a user (parent isn't `explorer.exe`).

## Q4 — Injection semantics
- **Direction:** SOURCE (`ILL_UNBLINKING`) → TARGET (`notepad`) — the injector wrote into the target.
- **`StartModule='-'`**: the remote thread starts in **unbacked/private memory** (no backing DLL)
  = **shellcode**. A legitimate remote thread would name a backing module.

## Q5 — Repeated?
```spl
index=attack_data source="inj001_sliver_notepad_sysmon.log" EventCode=8 SourceImage="*ILL_UNBLINKING*"
| stats count values(TargetImage)
```
→ **3 rounds** of spawn-notepad → inject (22:02, 22:03, 22:05) — sustained C2 activity, not a one-off.

## Q6 — Follow-on note
No EID3 network from the injected notepad is captured here; the injection itself is already confirmed
by the unbacked remote thread + sacrificial spawn, so severity does not depend on catching the beacon.

---

## Curation record
| Record | Event | Surfaced by | Why it's in the case |
|-------:|-------|-------------|----------------------|
| **15275583** | EID8 `ILL_UNBLINKING → notepad`, `StartModule='-'` | Q1 | **A0** — shellcode injection |
| 15275575 / 15275927 / 15277465 | EID1 `notepad ""` ← `ILL_UNBLINKING` | Q3 | sacrificial targets (empty-cmdline spawns) |
| 15275935 / 15277473 | EID8 `ILL_UNBLINKING → notepad`, `'-'` | Q5 | injection rounds 2 & 3 |

**Excluded:** 27 EID10 process-access handle-opens (injection plumbing noise).

## Export
```spl
index=attack_data source="inj001_sliver_notepad_sysmon.log"
  EventRecordID IN (15275583, 15275575, 15275927, 15275935, 15277465, 15277473)
| dedup EventRecordID
| sort _time | table _time EventRecordID _raw
```
Export (All Time) → **JSON** → `extracted/inj001_events.json`.

## Normalize

Run from the project root:

```bash
python3 tools/normalize.py --case tier1/strong/dev/INJ-001_sliver_notepad_injection --from-log
python3 tools/normalize.py --case tier1/strong/dev/INJ-001_sliver_notepad_injection --verify-log
```

The first command rebuilds the package from the retained raw source. The second re-derives it and byte-compares it with `model_input/alert_package.json`.
