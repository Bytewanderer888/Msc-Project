# SMB-002 — Splunk retrieval specification

Category: SMB / Windows Admin Shares (T1021.002) · **Tier-1, single sensor (Security 5145)** · Split: dev.
Evidence condition: **counter** · Calibration role: **over-triage-prone** (down-rank).

## Source scope
**One log:** `.../T1021.002/atomic_red_team/windows-security-xml.log`, scoped to host `win-dc-…-486`'s own
SMB activity. The log's other host (`win-host-…-576`, a PsExec attack) is excluded. Single sensor (Security 5145).

## Step 0 — Stage and ingest
`cp .../windows-security-xml.log _splunk_ingest/smb002_routine_security.log`
→ `sourcetype=XmlWinEventLog`, `index=attack_data`, source `smb002_routine_security.log`, `TZ=UTC`.

---

## Investigation

## Q1 — The alert (A0): IPC$\lsarpc access (looks like AD enumeration)
```spl
index=attack_data source="smb002_routine_security.log" Computer="win-dc-testuser-46070-486*"
  EventCode=5145 ShareName="*IPC$*" RelativeTargetName="lsarpc"
| table _time EventRecordID SubjectUserName ShareName RelativeTargetName
```
**A0 = 309958** — access to `\\*\IPC$\lsarpc` (the LSAR named pipe). This is the pattern SharpHound/BloodHound
use for AD enumeration — a common "SMB/AD enumeration" trigger.

## Q2 — Who is doing it? (the decisive check)
The `SubjectUserName` is **`WIN-DC-TESTUSER-4$`** — the **domain controller's own machine account**, not a user
or a remote workstation. Machine-account LSA RPC is routine.

## Q3 — What else is it accessing?
```spl
index=attack_data source="smb002_routine_security.log" Computer="win-dc-testuser-46070-486*" EventCode=5145
| stats count by ShareName RelativeTargetName
```
→ IPC$\lsarpc plus **SYSVOL\Policies\{…}\gpt.ini** reads — **Group Policy processing**. Routine domain-controller
housekeeping, not reconnaissance.

## Q4 — Counter crux
Surface: "a host is hitting IPC$\lsarpc → AD enumeration / lateral movement." Reality: the DC's machine account
doing LSA RPC + Group Policy over SMB. The machine-account subject and SYSVOL/GPO targets **contradict** the
enumeration reading. A model that flags this as AD enumeration is over-triaging — correct verdict is **benign /
Low**. (This is a real SOC false-positive class for IPC$\lsarpc/samr detections.)

---

## Curation record
| Record | Event | Why in the case |
|-------:|-------|-----------------|
| **309958** | IPC$\lsarpc access (machine account) | **A0** — the enumeration-resembling alert |
| 310079–310082 | more IPC$\lsarpc accesses | the "enumeration" pattern |
| 310068, 310069 | SYSVOL Policies gpt.ini reads | routine GPO (benign counter-context) |
| 310058 | SYSVOL root access | routine |

## Export
```spl
index=attack_data source="smb002_routine_security.log" Computer="win-dc-testuser-46070-486*"
  EventRecordID IN (309958,310058,310068,310069,310079,310080,310081,310082)
| dedup EventRecordID
| sort _time | table _time EventRecordID _raw
```
Export (All Time) → **JSON** → `extracted/smb002_events.json`.

## Normalize

Run from the project root:

```bash
python3 tools/normalize.py --case tier1/counter/dev/SMB-002_routine_domain_smb --from-log
python3 tools/normalize.py --case tier1/counter/dev/SMB-002_routine_domain_smb --verify-log
```

The first command rebuilds the package from the retained raw source. The second re-derives it and byte-compares it with `model_input/alert_package.json`.
