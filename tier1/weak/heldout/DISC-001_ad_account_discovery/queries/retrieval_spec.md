# DISC-001 — Splunk retrieval specification

Category: Account Discovery (T1087 / T1087.002 domain) · **Tier-1, single sensor (Sysmon)** · Split: held-out.
Evidence condition: **weak** · Calibration role: **over-triage-prone** (down-rank).

## Source scope
**One log:** `.../T1087.002/AD_discovery/windows-sysmon.log`, scoped to host `win-dc-391`'s first
account-discovery burst. The log's other host (`win-host-944`) and the repeat burst are excluded.
Single sensor (Sysmon EID 1 process-create). Verified single-source.

## Step 0 — Stage and ingest
`cp .../T1087.002/AD_discovery/windows-sysmon.log _splunk_ingest/disc001_ad_discovery_sysmon.log`
→ `sourcetype=XmlWinEventLog`, `index=attack_data`, source `disc001_ad_discovery_sysmon.log`, `TZ=UTC`.

---

## Investigation

## Q1 — The alert (A0): a domain account-discovery command
```spl
index=attack_data source="disc001_ad_discovery_sysmon.log" EventCode=1 Computer="win-dc-391*"
  Image="*\\net.exe" CommandLine="*user /domain*"
| table _time EventRecordID CommandLine ParentImage
```
**A0 = record 48627** — `net user /domain` (enumerate domain users), spawned by `cmd.exe` on the DC.

## Q2 — Isolated, or a recon burst?
```spl
index=attack_data source="disc001_ad_discovery_sysmon.log" EventCode=1 Computer="win-dc-391*"
| search CommandLine="*user*domain*" OR CommandLine="*dsquery*" OR CommandLine="*ds_user*" OR CommandLine="*Get-ADUser*"
| table _time EventRecordID Image CommandLine
```
→ a **4-second burst of five different user-enumeration methods** (09:32:05–09:32:09): `net user/users
/domain`, `dsquery user`, `wmic … ds_user`, `powershell get-wmiobject ds_user`, `Get-ADUser -Filter *`.

## Q3 — What is being enumerated?
Every method targets **domain user accounts** (`ds_user`, `/domain`, `Get-ADUser`). This is broad
**domain account discovery** (T1087.002) — mapping who exists in the directory.

## Q4 — The decisive check: any follow-on?
```spl
index=attack_data source="disc001_ad_discovery_sysmon.log" Computer="win-dc-391*"
  (EventCode=10) OR (EventCode=3) OR (EventCode=1 CommandLine="*mimikatz*" OR CommandLine="*runas*" OR CommandLine="*psexec*")
```
→ zero matching follow-on events in the scoped source. Credential access, lateral movement, and exploitation
are not evidenced after the enumeration; the bounded package contains discovery activity only.

## Q5 — Actor context
All launched by `cmd.exe` (scripted) on the DC — consistent with an attacker's recon script, **but also**
with a pentest, an inventory/monitoring tool, or an admin script. The source is **ambiguous**.

## Q6 — Weak crux
Rapid multi-method user enumeration is a genuine **reconnaissance indicator** — but discovery alone is
**insufficient to confirm a breach**: it has no malicious *outcome* (no creds, no movement) and no
unambiguous malicious *actor*. The correct read is *"suspicious AD enumeration → investigate for
follow-on"* (Medium), **not** *"confirmed attacker operating in the directory"* (High/Critical). A model
that escalates discovery-only activity to a confirmed compromise is over-triaging — this case catches that.

---

## Curation record
| Record | Method | Surfaced by | Why in the case |
|-------:|--------|-------------|-----------------|
| **48627** | `net user /domain` | Q1 | **A0** — the triggering account-discovery command |
| 48659 | `net users /domain` | Q2 | second `net` enumeration variant |
| 48675 | `dsquery user` | Q2 | AD directory user query |
| 48691 | `wmic … PATH ds_user GET ds_samaccountname` | Q2 | WMI/LDAP user enumeration |
| 48727 | `powershell get-wmiobject -class ds_user` | Q2 | WMI `ds_user` enumeration |
| 48785 | `powershell Get-ADUser -Filter *` | Q2 | AD-module user enumeration |

**Excluded:** the `net1.exe` delegated children and `cmd.exe /c` wrappers (redundant), the duplicate/partial
`net user /do` invocations, the repeat burst at 09:33, and the other host (`win-host-944`).
**Absent (the point):** any credential-access, lateral-movement, or exploitation follow-on (Q4).

## Export
```spl
index=attack_data source="disc001_ad_discovery_sysmon.log" Computer="win-dc-391*"
  EventRecordID IN (48627, 48659, 48675, 48691, 48727, 48785)
| dedup EventRecordID
| sort _time | table _time EventRecordID _raw
```
Export (All Time) → **JSON** → `extracted/disc001_events.json`.

## Normalize

Run from the project root:

```bash
python3 tools/normalize.py --case tier1/weak/heldout/DISC-001_ad_account_discovery --from-log
python3 tools/normalize.py --case tier1/weak/heldout/DISC-001_ad_account_discovery --verify-log
```

The first command rebuilds the package from the retained raw source. The second re-derives it and byte-compares it with `model_input/alert_package.json`.
