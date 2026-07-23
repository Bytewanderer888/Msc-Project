# Trigger analytic catalogue v1.0

## Purpose

This catalogue groups case-level trigger specifications by their primary
observable detection mechanism. It does not replace any case predicate,
scope, aggregation, or deterministic A0 selection rule.

The classification is independent of ATT&CK technique and evidence
condition: analytic family describes how the alert is generated; ATT&CK
describes the security mechanism; evidence condition describes how strongly
the retained package supports the proposition.

## Coverage

| Family | Name | Patterns | Cases |
|---|---|---:|---:|
| `AF-PROC` | Process and command execution | 4 | 27 |
| `AF-REG` | Registry and policy modification | 2 | 5 |
| `AF-PERS` | Persistence object creation | 3 | 8 |
| `AF-ACCESS` | Cross-process and sensitive-process access | 3 | 4 |
| `AF-AUTH` | Authentication and session anomaly | 2 | 2 |
| `AF-NET` | Network and remote-resource activity | 2 | 4 |
| `AF-MOD` | Module loading | 1 | 2 |
| `AF-WEB` | Web and HTTP request activity | 2 | 3 |
| `AF-STATE` | System and monitoring state | 2 | 2 |

## Families and patterns

### AF-PROC - Process and command execution

Rules triggered primarily by process creation, parent-child relationships, executable identity, or command-line features.

- **PROC-01 - Command-line behaviour match:** A process or audited command matches security-relevant program, option, target, or redirection features.
  Cases: `ACCT-001`, `CERT-001`, `COL-001`, `DISC-001`, `DISC-002`, `DISC-004`, `ER-M01`, `ER-M03`, `ER-M04`, `ER-S02`, `FW-001`, `ING-001`, `ING-002`, `LS-002`, `OD-001`, `RDL-001`, `SMB-001`
- **PROC-02 - Script-interpreter behaviour:** A script interpreter is identified through encoded, hidden, obfuscated, discovery, download, or module-loading command features.
  Cases: `DISC-003`, `PS-001`, `PS-002`, `PS-003`, `PS-004`
- **PROC-03 - Execution-chain relationship:** The alert depends on a parent-child or staged execution relationship rather than one isolated command token.
  Cases: `AMQ-001`, `ER-S04`, `UAC-001`
- **PROC-04 - Executable name or path anomaly:** The executable name, extension, Unicode presentation, or launch path is the primary observable alert surface.
  Cases: `RTLO-001`, `RUN-001`

### AF-REG - Registry and policy modification

Rules triggered by registry writes that change persistence, logon, credential, or security-control configuration.

- **REG-01 - Registry persistence value:** A registry value associated with logon or autorun behaviour is created or modified.
  Cases: `CRED-001`, `LGN-002`, `LOGON-001`, `RK-001`
- **REG-02 - Security-control registry change:** A registry value controlling security telemetry or defensive service behaviour is modified.
  Cases: `EVL-001`

### AF-PERS - Persistence object creation

Rules triggered by creation or modification of scheduled jobs, services, or WMI persistence objects.

- **PERS-01 - Scheduled-job definition:** A cron or Windows scheduled-task definition is created, edited, or configured for later execution.
  Cases: `ER-M02`, `ST-001`, `ST-002`, `ST-003`
- **PERS-02 - Service configuration:** A service definition or binary path is created or changed in a persistence-relevant way.
  Cases: `SVC-001`, `UQP-001`
- **PERS-03 - WMI subscription object:** A WMI command-line consumer or subscription object contains a persistence-relevant command payload.
  Cases: `WMI-001`, `WMI-002`

### AF-ACCESS - Cross-process and sensitive-process access

Rules triggered by process-handle access, remote thread creation, or runtime attachment to another process.

- **ACCESS-01 - Sensitive-process handle access:** A process opens a high-access handle to a sensitive credential-bearing process.
  Cases: `LS-001`, `LS-003`
- **ACCESS-02 - Cross-process thread injection:** A remote thread is created in another process with an anomalous or unbacked start address.
  Cases: `INJ-001`
- **ACCESS-03 - Runtime instrumentation attachment:** A privileged instrumentation process attaches to another running process through an operating-system tracing primitive.
  Cases: `ER-S03`

### AF-AUTH - Authentication and session anomaly

Aggregate rules triggered by repeated connection or authentication events within a declared time window.

- **AUTH-01 - Inbound connection burst:** Repeated inbound connections from one source to an authentication service exceed a declared threshold.
  Cases: `BF-001`
- **AUTH-02 - Failed-authentication spray:** Rapid failures across multiple target identities satisfy count, time-window, and distinct-user thresholds.
  Cases: `BF-002`

### AF-NET - Network and remote-resource activity

Rules triggered by endpoint network connections or access to remote management and shared resources.

- **NET-01 - Endpoint network connection:** A process-level network event matches protocol, direction, endpoint, or management-port features.
  Cases: `ER-C02`, `ER-W01`
- **NET-02 - Remote resource access:** A file-share, named-pipe, or policy-resource access event matches a security-relevant remote object pattern.
  Cases: `GPO-001`, `SMB-002`

### AF-MOD - Module loading

Rules triggered by one or more library image-load events involving a security-relevant host process or path.

- **MOD-01 - Process module-load pattern:** A host process loads one or more libraries from a path or burst pattern that forms the alert surface.
  Cases: `ER-C01`, `ER-C03`

### AF-WEB - Web and HTTP request activity

Rules triggered by HTTP request paths, user agents, parameters, response status, or web-endpoint command features.

- **WEB-01 - HTTP request pattern:** An HTTP request matches repository, scanner, method, path, user-agent, or response-status features.
  Cases: `ER-C04`, `ER-W04`
- **WEB-02 - Web endpoint command parameter:** A request to an uploaded server-side endpoint carries an encoded or command-bearing parameter.
  Cases: `ER-S01`

### AF-STATE - System and monitoring state

Rules triggered by explicit operating-system state or monitoring-health notifications rather than process semantics.

- **STATE-01 - Host state anomaly:** A native operating-system event reports an anomalous shutdown or availability state.
  Cases: `ER-W02`
- **STATE-02 - Monitoring health change:** A monitoring service reports loss of endpoint connectivity or visibility.
  Cases: `ER-W03`
