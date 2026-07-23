# LOGON-001 — Splunk retrieval specification

Category: Logon-script persistence (selected post-delete reconfiguration; no subsequent firing observed) · **Tier-1 single sensor (Sysmon)** · Split: held-out.
Evidence condition: **missing** (autostart setup visible; activation of the selected final lifecycle is not evidenced).
Calibration role: **over-triage-prone (down-rank)**.

## Source scope
`.../attack_techniques/T1037.001/logonscript_reg/sysmon.log` — **multi-host log; scope to host `win-dc-429.attackrange.local`**, EID13 + EID1.

## Step 0 — Stage and ingest
```
cp .../T1037.001/logonscript_reg/sysmon.log  _splunk_ingest/logon001_logonscript_sysmon.log
```
→ `sourcetype=XmlWinEventLog`, `index=attack_data`, source `logon001_logonscript_sysmon.log`, `TZ=UTC`.

## Investigation
## Q1 — the alert (A0): UserInitMprLogonScript set (EID13)
```spl
index=attack_data source="logon001_logonscript_sysmon.log" Computer="win-dc-429.attackrange.local"
  EventCode=13 TargetObject="*UserInitMprLogonScript*"
| table _time EventRecordID TargetObject Details Image
```
→ **A0 = 1057604** — `...\Environment\UserInitMprLogonScript` = `C:\Windows\System32\calc.exe` (a benign system binary).

## Q2 — how was it written? (context EV): `reg.exe` performing the REG ADD (1057596).

## Q3 — did the selected final configuration trigger after A0? (the decisive gap)
```spl
index=attack_data source="logon001_logonscript_sysmon.log" Computer="win-dc-429.attackrange.local"
  EventCode=1 earliest="09/27/2021:09:27:14" (Image="*\\calc.exe" OR ParentImage="*\\userinit.exe")
| table _time EventRecordID Image ParentImage CommandLine LogonId
```
→ zero matching ProcessCreate events through source end at **09:29:06.117Z**. The target path looks like
`calc.exe`, but the package does not verify the file's identity or benignity. The bounded finding is that
activation of the selected final configuration is **not evidenced**.

## Q4 — raw-scope lifecycle audit (prevents curated omission)
```spl
index=attack_data source="logon001_logonscript_sysmon.log" Computer="win-dc-429.attackrange.local"
  (TargetObject="*UserInitMprLogonScript*" OR ParentImage="*\\userinit.exe")
| table _time EventRecordID EventCode EventType Image ParentImage TargetObject Details CommandLine
| sort _time
```

The raw source contains an earlier lifecycle: record **1051834** sets the value at 09:18:30.392Z,
and record **1055590** shows `userinit.exe -> calc.exe` at 09:21:45.820Z. That earlier value is deleted
by **1057290** at 09:25:44.328Z. A second set is deleted by **1057583** at 09:27:09.913Z, which forms
the lifecycle boundary immediately before selected A0 **1057604** at 09:27:14.881Z. No firing follows
the selected A0 before source end. Therefore the case does not claim that the capture never fired; it
tests the final post-delete reconfiguration whose activation remains unobserved.

**Missing crux:** the selected logon-script persistence setup is present, but its post-A0 activation is
not evidenced in the remaining raw window. A model must not conclude "active malicious persistence /
payload runs", and the annotator must not claim that the mechanism never fired elsewhere in the capture.

## Curation record

The selected record ids and researcher-only evidence roles are fixed in `build/case.json` and retained in `annotations/selection_metadata.json`.

## Export
```spl
index=attack_data source="logon001_logonscript_sysmon.log" Computer="win-dc-429.attackrange.local"
  EventRecordID IN (1057604, 1057596)
| dedup EventRecordID
| sort _time | table _time EventRecordID _raw
```
Export (All Time) → **JSON** → `extracted/logon001_events.json`.

## Normalize

Run from the project root:

```bash
python3 tools/normalize.py --case tier1/missing/heldout/LOGON-001_logon_script --from-log
python3 tools/normalize.py --case tier1/missing/heldout/LOGON-001_logon_script --verify-log
```

The first command rebuilds the package from the retained raw source. The second re-derives it and byte-compares it with `model_input/alert_package.json`.
