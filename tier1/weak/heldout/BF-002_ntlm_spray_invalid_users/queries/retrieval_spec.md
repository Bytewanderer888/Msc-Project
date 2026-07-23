# BF-002 — Splunk retrieval specification

Category: Brute Force (T1110 / T1110.003 password spray) · **Tier-1, single sensor (Security)** · Split: held-out.
Evidence condition: **weak** · Calibration role: **over-triage-prone** (down-rank).

## Source scope
**One log:** `.../T1110.003/purplesharp_invalid_users_ntlm_xml/windows-security.log`, scoped to host
`win-host-…-447`'s **failed-logon (4625)** records. Single sensor (Security auth). PurpleSharp-simulated
(noted honestly — the evidence *pattern*, not the simulation, is what the case tests).

## Step 0 — Stage and ingest
`cp .../purplesharp_invalid_users_ntlm_xml/windows-security.log _splunk_ingest/bf002_ntlm_spray_security.log`
→ `sourcetype=XmlWinEventLog`, `index=attack_data`, source `bf002_ntlm_spray_security.log`, `TZ=UTC`.

---

## Investigation

## Q1 — The alert (A0): a failed logon
```spl
index=attack_data source="bf002_ntlm_spray_security.log" EventCode=4625
| table _time EventRecordID TargetUserName SubStatus LogonType AuthenticationPackageName
```
**A0 = record 335396** — a failed NTLM logon (EventID 4625) for a non-existent user
(`SubStatus=0xc0000064` = *user name does not exist*), `AuthenticationPackage=NTLM`, on `win-host-447`.

## Q2 — How many, how fast?
```spl
index=attack_data source="bf002_ntlm_spray_security.log" EventCode=4625
| stats count min(_time) max(_time) dc(TargetUserName)
```
→ **50 failed logons in ~1 second** (19:03:49–19:03:50), **50 distinct target usernames**. The volume +
rate = an **automated** attempt, not human error.

## Q3 — Which accounts, and did they exist?
Every attempt targets a **different, random username** and every one returns `SubStatus=0xc0000064`
(*no such user*). This is **username spraying / enumeration with a bad list** — not one real account was hit.

## Q4 — The decisive check: any success?
```spl
index=attack_data source="bf002_ntlm_spray_security.log" EventCode=4624
```
→ zero 4624 events in the scoped source. A successful logon and credential compromise are not evidenced;
the absence of 4624 is not an assertion about activity outside the retained sensor and window.

## Q5 — Source / context
`IpAddress='-'`, `WorkstationName` = the host itself, `LogonType=2` — the burst was generated locally
(a PurpleSharp simulation artifact; a real remote spray would be LogonType 3 from a source IP). Either
way, the auth-layer evidence is: many failures, **zero successes.**

## Q6 — Weak crux
A burst of 50 failed logons is a genuine **brute-force / spray indicator** — but the evidence is
**insufficient to confirm any compromise or impact**: no success, and not one valid account was even
found (all `0xc0000064`). The correct read is *"failed spray attempt against non-existent users →
low impact, monitor,"* **not** *"confirmed credential-access breach."* A model that escalates to High on
the raw failure count (ignoring that all failed against non-existent users, with no success) is
over-triaging — this case catches that.

---

## Curation record
| Record(s) | Event | Surfaced by | Why in the case |
|-----------|-------|-------------|-----------------|
| **335396** | first failed NTLM logon (non-existent user) | Q1 | **A0** — the triggering failed-logon alert |
| 335397–335445 | the remaining 49 failed logons (distinct non-existent users) | Q2 | establish the 50-in-1-sec automated spray |

**Absent (the point):** any 4624 success (Q4) — the outcome that would confirm compromise. All 50 fail
with `0xc0000064` (no such user), so impact is low.

## Export
```spl
index=attack_data source="bf002_ntlm_spray_security.log" EventCode=4625 Computer="win-host*447*"
| dedup EventRecordID
| sort _time | table _time EventRecordID _raw
```
Export (All Time) → **JSON** → `extracted/bf002_events.json`. (All 50 failed logons — the volume is the signal.)

## Normalize

Run from the project root:

```bash
python3 tools/normalize.py --case tier1/weak/heldout/BF-002_ntlm_spray_invalid_users --from-log
python3 tools/normalize.py --case tier1/weak/heldout/BF-002_ntlm_spray_invalid_users --verify-log
```

The first command rebuilds the package from the retained raw source. The second re-derives it and byte-compares it with `model_input/alert_package.json`.
