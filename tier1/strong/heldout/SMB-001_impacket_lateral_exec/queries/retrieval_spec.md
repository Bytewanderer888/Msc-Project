# SMB-001 — Splunk retrieval specification

Category: Impacket-style WMI and service execution (T1021.002-style surface) · **Tier-1, single sensor (Sysmon)** · Split: held-out.
Evidence condition: **strong** · Calibration role: **preserve** (hold High — do not downgrade on the benign `calc` payload).

## Source scope
**One log:** `.../T1021.002/atomic_red_team/wmiexec_windows-sysmon.log` (Computer `ar-win-2`).
This capture is the **superset**: it holds two Impacket-style execution patterns from one observed host.
The sibling `smbexec_windows-sysmon.log` is a strict 3-event **subset** (records 117785/786/788) of it.
Single host, single sensor (Sysmon EID 1 process-create + EID 13 registry).

## Step 0 — Stage and ingest
`cp .../atomic_red_team/wmiexec_windows-sysmon.log _splunk_ingest/smb001_impacket_lateral_sysmon.log`
→ `sourcetype=XmlWinEventLog`, `index=attack_data`, source `smb001_impacket_lateral_sysmon.log`, `TZ=UTC`.

---

## Investigation

## Q1 — The alert (A0): a WMI provider spawning a shell that writes to ADMIN$
```spl
index=attack_data source="smb001_impacket_lateral_sysmon.log" EventCode=1
  ParentImage="*WmiPrvSE.exe" CommandLine="*ADMIN$*"
| table _time EventRecordID CommandLine User
```
**A0 = record 117769** — `cmd.exe /Q /c calc.exe 1> \\127.0.0.1\ADMIN$\__1682093952… 2>&1`, spawned by
`WmiPrvSE.exe` as `ATTACKRANGE\Administrator`. **WmiPrvSE spawning cmd + stdout redirected to an admin
share = the Impacket `wmiexec` signature.**

## Q2 — The wmiexec-style command pattern
```spl
index=attack_data source="smb001_impacket_lateral_sysmon.log" EventCode=1 ParentImage="*WmiPrvSE.exe"
| table _time EventRecordID CommandLine
```
→ a run of `cmd /Q /c … 1> \\127.0.0.1\ADMIN$\__<ts> 2>&1` — one sequence at 16:19
(117767, then A0 117769) and another at 16:20 (117779). This is the characteristic wmiexec-style
WMI command pattern. Because the share path is loopback, the package does not identify a separate source host.

## Q3 — The payload executed
A0 runs `calc.exe` → child process **117770** (`calc.exe ⇐ cmd.exe`). The demo payload executes inside
the observed WMI command chain; its benign function does not neutralise the execution mechanism.

## Q4 — A second execution pattern: the smbexec-style service
```spl
index=attack_data source="smb001_impacket_lateral_sysmon.log"
  (EventCode=13 TargetObject="*\\Services\\*ImagePath") OR (EventCode=1 ParentImage="*services.exe")
```
→ **117785**: a service **`BTOBTO`** (Impacket smbexec's default name) registered with
ImagePath `%COMSPEC% /Q /c echo … ^> \\127.0.0.1\C$\__output` — **117786**: `services.exe` runs it as
`NT AUTHORITY\SYSTEM` (writes `C:\Windows\rIIBPrqF.bat`) — **117788**: the bat executes. This confirms
service-based SYSTEM execution with output redirected to the loopback C$ share.

## Q5 — Actor and scope
One **90-second window** (16:19:13–16:20:56) on `ar-win-2`: `ATTACKRANGE\Administrator` in the WMI chain,
followed by SYSTEM service execution. No distinct remote source host is present. **Excluded:** 117807
(a later `cmd`/ADMIN$ spawned by `explorer.exe` as a
*different* user, `reed_potts` — a separate interactive session), and redundant wmiexec `cd`-probes 117768/117780.

## Q6 — Strong crux (preserve)
Two independent Impacket-style mechanisms — **wmiexec** (WmiPrvSE→cmd→ADMIN$) and **smbexec**
(BTOBTO SYSTEM service→C$) — establish command and SYSTEM-level code execution on the observed host.
The loopback paths do not prove cross-host lateral movement. Correct verdict = **High**. The calibration
test: the WMI payload is `calc.exe` (benign-looking) — a well-calibrated model must **not** downgrade on the
payload; the delivery mechanism alone confirms compromise. (This case catches a model that under-weights
confirmed tooling because the demo command looks harmless.)

---

## Curation record
| Record | Event | Surfaced by | Why it's in the case |
|-------:|-------|-------------|----------------------|
| **117769** | `WmiPrvSE→cmd /Q /c calc.exe 1> ADMIN$` | Q1 | **A0** — wmiexec-style WMI command |
| 117767 | `WmiPrvSE→cmd /Q /c cd \ 1> ADMIN$` | Q2 | wmiexec-style command sequence |
| 117770 | `calc.exe ⇐ cmd.exe` | Q3 | the payload executes |
| 117779 | `WmiPrvSE→cmd /Q /c cd \ 1> ADMIN$` | Q2 | second wmiexec-style command sequence |
| 117785 | reg: `Services\BTOBTO\ImagePath = %COMSPEC% echo…C$\__output` | Q4 | smbexec service created |
| 117786 | `services.exe→cmd` (writes `rIIBPrqF.bat`, →C$\__output) | Q4 | smbexec service runs (SYSTEM) |
| 117788 | `cmd→cmd /Q /c rIIBPrqF.bat` | Q4 | smbexec payload bat executes |

**Excluded:** 117768, 117780 (redundant `cd`-probes); 117807 (separate `explorer.exe`/`reed_potts` session).

## Export
```spl
index=attack_data source="smb001_impacket_lateral_sysmon.log"
  EventRecordID IN (117769, 117767, 117770, 117779, 117785, 117786, 117788)
| dedup EventRecordID
| sort _time | table _time EventRecordID _raw
```
Export (All Time) → **JSON** → `extracted/smb001_events.json`.

## Normalize

Run from the project root:

```bash
python3 tools/normalize.py --case tier1/strong/heldout/SMB-001_impacket_lateral_exec --from-log
python3 tools/normalize.py --case tier1/strong/heldout/SMB-001_impacket_lateral_exec --verify-log
```

The first command rebuilds the package from the retained raw source. The second re-derives it and byte-compares it with `model_input/alert_package.json`.
