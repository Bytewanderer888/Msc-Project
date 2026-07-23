# Differentiation audit against the frozen 41-case benchmark

Audit date: 2026-07-22. Status: all 16 frozen packages completed event-level
differentiation and pre-freeze checks before any model call.

## Comparison dimensions

A candidate is not considered differentiated merely because its source file or
ATT&CK ID differs. It is compared against the frozen benchmark on:

1. security mechanism and ATT&CK mapping;
2. evidence proposition and missing/decisive boundary;
3. source corpus and capture cluster;
4. platform and sensor combination;
5. calibration trap presented to the model;
6. operational response family.

## Replacements made after comparison

Six initial candidates were too close to existing cases and were replaced:

| Removed candidate | Nearest frozen cases | Reason for removal | Replacement |
|---|---|---|---|
| LSASS dump | LS-001, LS-003 | same credential source and decisive dump outcome | runtime manipulation of a control application with observed impact (`T1565.003`) |
| LSASS read without dump | LS-002 | same target and invocation-versus-outcome boundary | script-host TCP activity with unknown session semantics (`T1095`) |
| Windows scheduled task without firing | ST-001, ST-002 | same platform, precursor, and missing confirmation | Linux crontab edit without commit or firing (`T1053.003`) |
| transferred object without execution | ING-001, ING-002 | same staging-versus-execution boundary | failed Linux file-removal outcome (`T1070.004`) |
| account creation without use | ACCT-001 | same account-persistence proposition | failed Linux backup-removal outcome (`T1490`) |
| AInception LSASS case retained in early matrix | LS family | source independence alone did not justify repetition | removed with the LSASS dump candidate above |

## Retained overlaps that are intentional

Some mappings overlap at a family level but test a different evidence problem:

- `T1021.006`: ER-S04 and ER-C02 intentionally contrast a successful remote
  execution pivot with loopback-only WinRM traffic. The pair tests whether the
  model responds to destination and outcome context.
- `T1105`: the frozen benchmark uses unconfirmed object staging. ER-C04 is a
  Linux package-manager benign analogue with official repositories and an APT
  user agent; its condition and explanatory burden are different.

## Added coverage

The revised replication matrix adds mechanisms absent from the original set,
including:

- webshell command handling (`T1505.003`);
- Unix `sudo` privilege escalation (`T1548.003`);
- cyber-physical runtime data manipulation (`T1565.003`);
- WinRM/PowerShell remoting (`T1021.006`);
- non-application-layer script-host traffic (`T1095`);
- network service scanning (`T1046`);
- Linux systemd preparation before service activation (`T1543.002`);
- Linux crontab editing before commit or firing (`T1053.003`);
- failed file deletion with an explicit `unlinkat` result (`T1070.004`);
- failed backup removal and recovery-impairment boundary (`T1490`);
- signed Windows servicing DLL context (`T1574.002`);
- PrintNightmare-like spooler false-positive context (`T1210`).

It also adds Linux audit/Apache telemetry, heterogeneous IDS output, network
flows, and cyber-physical outcome telemetry rather than only changing Windows
command names.

## Decision

The revised matrix is sufficiently differentiated for external replication.
All 16 cases pass package schema, leakage, evidence-ID, decision-band, source
hash, and selected-record provenance checks. The four CAM-LDS `missing` cases
come from four independent scenario/run clusters and use defender-visible
telemetry only. The complete set was frozen only after this review; no model was
called before the freeze.
