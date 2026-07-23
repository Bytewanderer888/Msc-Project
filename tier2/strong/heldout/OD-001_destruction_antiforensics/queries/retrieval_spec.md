# OD-001 — Splunk retrieval specification

Category: Olympic Destroyer — destructive wiper + anti-forensics (T1490 Inhibit System Recovery +
T1070.001 Clear Windows Event Logs) · **Tier-2, MULTI-sensor (Sysmon + Security)** · Split: held-out.
Evidence condition: **strong** · Calibration role: **preserve** (confirmed destructive attack — hold Critical).

## Source scope
- `.../malware/olympic_destroyer/sysmon.log` (XML)
- `.../malware/olympic_destroyer/security.log` (**stanza** key=value format — engine converts on load)

Both are scoped to Computer **`win-dc-tcontreras-attack-range-173`**. This is genuine fusion: Sysmon retains
the command invocations, while Security Event 1102 independently confirms the Security-log clear and names
the account. The package does not infer unrecorded command result statuses.

## Step 0 — Stage and ingest
```
cp .../olympic_destroyer/sysmon.log   _splunk_ingest/olympic_sysmon.log
cp .../olympic_destroyer/security.log _splunk_ingest/olympic_security.log
```
Ingest each → `index=attack_data`, sources `olympic_sysmon.log` / `olympic_security.log`, `TZ=UTC`.
(The Security log is stanza format; Splunk auto-extracts `EventCode`/`ComputerName`/`RecordNumber`.)

---

## Investigation

## Q1 — The alert (A0, Sysmon): shadow-copy deletion command launched
```spl
index=attack_data source="olympic_sysmon.log" Computer="win-dc-tcontreras-attack-range-173*" EventCode=1
  Image="*vssadmin.exe" CommandLine="*delete shadows*"
| table _time EventRecordID CommandLine
```
**A0 = sysmon:290147** — `vssadmin delete shadows /all /quiet` is launched. Sysmon ProcessCreate
does not independently record whether shadow-copy deletion succeeded.

## Q2 — The destructive + anti-forensic burst (Sysmon)
```spl
index=attack_data source="olympic_sysmon.log" Computer="win-dc-tcontreras-attack-range-173*" EventCode=1
  (Image="*bcdedit.exe" OR Image="*wevtutil.exe" OR Image="*wbadmin.exe")
| table _time EventRecordID CommandLine
```
→ `bcdedit /set {default} bootstatuspolicy ignoreallfailures` (290231), `bcdedit … recoveryenabled no`
(290240), **`wevtutil cl System`** (290266), and **`wevtutil cl Security`** (290300) are launched.
This is a destructive and anti-forensic command pattern; only the Security-log clear has independent
result telemetry in this package.

## Q3 — The Security view (fusion keystone): the log-clear result
```spl
index=attack_data source="olympic_security.log" ComputerName="win-dc-tcontreras-attack-range-173*" EventCode=1102
| table _time RecordNumber
```
→ **security:324614** — EventID **1102 "The audit log was cleared"**, by **`ATTACKRANGE\Administrator`**, at
the same instant as `wevtutil cl Security`. It records the audit-log clear itself.

## Q4 — Why fusion is required here
Sysmon records the destructive and anti-forensic commands but does not provide their exit status. Security
1102 confirms one outcome — the Security log was cleared — and names the `Administrator` account. Fusing the
same-host, same-window sensors therefore adds genuine complementary corroboration without claiming that every
requested VSS, BCD, or System-log operation succeeded.

## Q5 — Strong / preserve crux
A high-integrity destructive and anti-forensic command sequence is present, and Security 1102 confirms the
Security-log clear by `Administrator`. This supports a **destructive attack with confirmed anti-forensics** at
Critical severity. The bounded conclusion does not assert successful shadow deletion, BCD modification, or
System-log clearing without result telemetry.

---

## Curation record
| Key | Sensor | Event | Why in the case |
|-----|--------|-------|-----------------|
| **sysmon:290147** | Sysmon | `vssadmin delete shadows /all /quiet` | **A0** — deletion command invocation; result not recorded |
| sysmon:290231 | Sysmon | `bcdedit … bootstatuspolicy ignoreallfailures` | recovery-change command; result not recorded |
| sysmon:290240 | Sysmon | `bcdedit … recoveryenabled no` | recovery-change command; result not recorded |
| sysmon:290266 | Sysmon | `wevtutil cl System` | System-log clear command; result not recorded |
| sysmon:290300 | Sysmon | `wevtutil cl Security` | Security-log clear command |
| security:324614 | Security | **1102** "audit log cleared" by `ATTACKRANGE\Administrator` | confirms the Security-log clear and names the account |

## Export
```spl
index=attack_data
  (source="olympic_sysmon.log" Computer="win-dc-tcontreras-attack-range-173*" EventRecordID IN (290147,290231,290240,290266,290300))
  OR (source="olympic_security.log" ComputerName="win-dc-tcontreras-attack-range-173*" EventCode=1102)
| eval EventRecordID=coalesce(EventRecordID, RecordNumber)
| dedup source EventRecordID
| sort 0 _time
| table _time source EventRecordID _raw
```
Export (All Time) → **JSON** → `extracted/od001_events.json`. (Engine tags each event's sensor from its
provider and converts the stanza Security event to XML.)

## Normalize

Run from the project root:

```bash
python3 tools/normalize.py --case tier2/strong/heldout/OD-001_destruction_antiforensics --from-log
python3 tools/normalize.py --case tier2/strong/heldout/OD-001_destruction_antiforensics --verify-log
```

The first command rebuilds the package from the retained raw source. The second re-derives it and byte-compares it with `model_input/alert_package.json`.
