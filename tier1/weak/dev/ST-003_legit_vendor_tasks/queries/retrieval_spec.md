# ST-003 — Splunk retrieval specification

Category: Scheduled Task (T1053.005) · **Tier-1, single sensor (Security 4698)** · Split: dev.
Evidence condition: **weak** · Calibration role: **over-triage-prone** (down-rank).

## Source scope
**One log:** `.../T1053.005/atomic_red_team/4698_windows-security.log`, scoped to host
`win-host-…-569`'s **vendor-named task definitions**. The log's other host (`win-dc-84`) and its
attack tasks (`\atomic`, `\test`) are excluded. Single-sensor (Security 4698 task-created).

## Step 0 — Stage and ingest
`cp .../4698_windows-security.log _splunk_ingest/st003_legit_tasks_security.log`
→ `sourcetype=XmlWinEventLog`, `index=attack_data`, source `st003_legit_tasks_security.log`, `TZ=UTC`.

---

## Investigation

## Q1 — The alert (A0): a task definition configured to run a script as SYSTEM
```spl
index=attack_data source="st003_legit_tasks_security.log" EventCode=4698
  _raw="*NT AUTHORITY\\SYSTEM*" _raw="*.bat*"
| table _time EventRecordID _raw
```
**A0 = record 353006** — creation of task definition `\npcapwatchdog`, configured to invoke
`C:\Program Files\Npcap\CheckStatus.bat` as `NT AUTHORITY\SYSTEM` at boot. Event 4698 proves
task creation, not execution of the task action.

## Q2 — The alarming surface
A boot-triggered task definition whose action is a `.bat` file and whose run-as account is **SYSTEM**
resembles a persistence mechanism. This is a real indicator, but it does not by itself establish
malicious intent or successful execution.

## Q3 — Mitigating context
Read the task's **Command path**: `C:\Program Files\Npcap\CheckStatus.bat`. A vendor-named
`Program Files` path is consistent with installed software and weakens an immediate malicious
interpretation. It is not decisive benign evidence because A0 has no Author and this Security log
contains no signature, hash, or software-inventory confirmation.

## Q4 — Context: what else is scheduled on this host?
```spl
index=attack_data source="st003_legit_tasks_security.log" EventCode=4698 Computer="win-host*569*"
| table _time EventRecordID _raw
```
→ `aurora-agent-*-update` definitions (author **Nextron Systems**, action under
`C:\Program Files\Aurora-Agent`) and a `Mozilla\Firefox Default Browser Agent` definition
(author **Mozilla**). These nearby events provide vendor-attributed context; they do not prove A0
benign or show that any task executed.

## Q5 — Check the limits of the available evidence
The three context definitions carry matching vendor Authors and reference vendor-named paths.
A0 references an Npcap path but has no Author. The package has no signature, hash reputation,
installed-software inventory, task-run event, child process, or outcome that would decisively
confirm either malicious persistence or benign maintenance.

## Q6 — Weak-evidence crux
Surface: "boot-triggered SYSTEM `.bat` → confirmed persistence, High." Mitigating context:
vendor-named paths and three nearby vendor-authored task definitions. Neither side is decisive.
The supported triage decision is **suspicious / Low–Medium / investigate**, not confirmed malicious
and not confirmed benign.

---

## Curation record
| Record | Task | Surfaced by | Why it's in the case |
|-------:|------|-------------|----------------------|
| **353006** | `npcapwatchdog` → `Program Files\Npcap\CheckStatus.bat` (SYSTEM) | Q1 | **A0** — boot-triggered SYSTEM script action; provenance not decisively verified |
| 349689 | `aurora-agent-signature-update` (Nextron, SYSTEM) | Q4 | mitigating vendor-authored context |
| 349690 | `aurora-agent-program-update` (Nextron, SYSTEM) | Q4 | mitigating vendor-authored context |
| 341746 | `Mozilla\Firefox Default Browser Agent` (Administrator) | Q4 | mitigating vendor-authored context |

**Excluded:** the other host (win-dc-84) and its attack tasks (`\atomic`, `\test`, `\CreateExplorerShellUnelevated`).

## Export
```spl
index=attack_data source="st003_legit_tasks_security.log"
  EventRecordID IN (353006, 349689, 349690, 341746)
| dedup EventRecordID
| sort _time | table _time EventRecordID _raw
```
Export (All Time) → **JSON** → `extracted/st003_events.json`.

## Normalize

Run from the project root:

```bash
python3 tools/normalize.py --case tier1/weak/dev/ST-003_legit_vendor_tasks --from-log
python3 tools/normalize.py --case tier1/weak/dev/ST-003_legit_vendor_tasks --verify-log
```

The first command rebuilds the package from the retained raw source. The second re-derives it and byte-compares it with `model_input/alert_package.json`.
