# Source suitability and leakage audit

Status date: 2026-07-22. This is a candidate-stage audit; it is not a case
freeze record.

## Windows-APT Dataset 2025

### Strengths

- broad Windows ATT&CK candidate pool across 36 emulated scenarios;
- Sysmon and Windows event channels support host-scoped evidence review;
- many naturally occurring detector false positives and precursor-only events.

### Limitations and controls

- The combined CSV has no authoritative event-to-scenario ground-truth column.
- The CSV was exported from Wazuh alert indices rather than a complete raw-event
  archive. Absence of an outcome in this file therefore cannot establish a
  `missing` condition, because a non-alerting outcome may have been omitted
  upstream.
- Wazuh rule descriptions, severity, and MITRE mappings are detector output, not
  SafeSOC ground truth.
- Detector fields can label normal Windows behavior with offensive techniques.
- Every candidate therefore requires semantic review. This corpus is restricted
  to positive-event `weak` and `counter` candidates; no `missing` case may be
  admitted from `combined.csv`.

Fields under `_source.rule.*`, upstream scenario names, and framework tokens are
excluded from model-visible packages.

## CAM-LDS

### Strengths

- complete host-scoped raw logs are retained for each simulation run;
- step-level time windows can be checked against audit, authentication, service,
  file, and network telemetry rather than only a detector output stream;
- attacker execution metadata and output support candidate discovery and QA,
  while the package itself can remain label-free;
- multiple scenario variants provide independent capture/run units.

### Limitations and controls

- the corpus focuses on attack manifestations and does not provide a broad
  normal-user background distribution;
- step labels and AttackMate commands reveal the intended technique and are
  researcher-side discovery aids only;
- a `missing` case is accepted only when the precursor is visible, the named
  outcome is observable by a declared sensor, and the complete step/run scope
  contains no such outcome;
- four missing slots must use independent scenario/run clusters; repeated step
  extractions or technique views of the same raw event do not count separately.

### Accepted missing-evidence boundaries

| Case | Defender-visible precursor | Named confirmation not present in scope |
|---|---|---|
| ER-M01 | service editor artifact plus root `daemon-reload` | service enable/start, active-unit result, or payload process before the alert-time boundary |
| ER-M02 | syslog `BEGIN EDIT` plus audit `crontab -e` | crontab `REPLACE`/`END EDIT` or a newly installed cron child |
| ER-M03 | `rm` execution | successful `unlinkat`; the correlated result is `success=no`, `ENOENT` |
| ER-M04 | recursive backup-removal command | successful target deletion; the wildcard remains literal and the correlated result is `ENOENT` |

ER-M01 is explicitly a point-in-time triage case, not a retrospective claim
that the service never ran. Its window ends at the source-defined daemon-reload
step; later scenario steps are disclosed by the GT boundary and are not hidden
events that were already available at alert time.

Rejected CAM candidates include successful transfers, successful service
restart/activation, and `userdel`/`shell` failures visible only in the attacker
console. The last group is excluded because attacker output is not SOC
telemetry and would leak information unavailable to the deployed analyst.

Source of record: CAM-LDS, DOI `10.5281/zenodo.18861762`.

## AIT Alert Data Set

### Strengths

- eight separately varied enterprise testbeds;
- 2,655,821 alerts from Wazuh, Suricata, and AMiner;
- normal-user false positives and independent attack-phase timing;
- raw observations are often retained in `full_log`, HTTP, flow, and AMiner
  `RawLogData` fields.

### Limitations and controls

- The corpus contains alerts derived from AIT-LDSv2, not the complete 130.6 GB
  raw-log collection.
- Multiple products can represent the same underlying log line; that does not
  constitute multi-source fusion.
- Attack phase names and detector prose directly leak the answer.
- An absence in AIT-ADS is not proof of absence in AIT-LDSv2, so AIT-ADS is not
  used for a `missing` case unless the relevant raw scope is independently
  obtainable and audited.

Model packages exclude Wazuh `rule`, Suricata `alert.signature/category`, AMiner
analysis-component names, scenario names, and phase labels. Neutral HTTP, flow,
authentication, process, path, status, and timestamp facts may remain.

## AInception SL100

### Strengths

- endpoint, network, Linux, and drone telemetry from one multi-stage capture;
- explicit action windows and observable outcomes;
- useful genuine fusion candidates for remote execution and impact.

### Limitations and controls

- all attack steps belong to one continuous chain;
- labelled Windows JSON loses some field semantics present in the raw text;
- supplied timeline metadata contains timestamp inconsistencies and a duplicate
  key, which must be resolved against raw event times.

The set uses at most two SL100 cases, records their shared cluster, reads raw
events where possible, and excludes attack-step/timeline labels from packages.

## Rejected source: SILRAD 1.0

SILRAD was inspected but not retained. Its distributed CSVs contain numerical
FastText-style features rather than semantically auditable raw security events
and do not preserve the provenance needed to construct SafeSOC evidence
packages. It is unsuitable for this replication study despite its small size.
