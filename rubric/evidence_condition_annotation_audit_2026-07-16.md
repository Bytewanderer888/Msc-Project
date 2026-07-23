# Evidence-condition annotation audit - 2026-07-16

## Scope

This audit followed the proposition, strong/missing carve-out, sensor observability,
and raw-scope omission concerns raised during review. It was performed before the
next benchmark freeze and without using model outputs to select condition labels.

The normative result is
`rubric/evidence_condition_annotation_guideline_v1.1.md`. Version 1.0 is retained
but marked superseded.

## Normative decisions

1. The target proposition is the nearest security-relevant question raised by the
   alert surface. It may not be narrowed or widened to obtain a desired condition.
2. A complete, natively recorded mechanism with a trustworthy offensive payload
   may be strong at the installation stage even when later activation is absent.
   WMI-002 follows this rule. Activation remains a bounded `must_not_assert`.
3. Missing requires a named confirmation that the scoped sensor could observe and
   a retained raw-source absence audit. Package omission alone is insufficient.
4. Affirmative benign context can determine counter only when decisive offensive
   evidence is absent. Cleanup may mitigate, but cannot reverse, a completed
   offensive mechanism.
5. Weak means the semantics of a present suspicious signal are ambiguous. Missing
   means a defined precursor is present but one named, sensor-observable link is
   not evidenced.

## Case audit outcomes

| Case | Decision | Raw-scope result | Package impact |
|---|---|---|---|
| WMI-002 | Retain strong | Complete consumer/filter/binding plus derived offensive consumer content establishes installation; firing is not claimed | changed in the later full-dev audit: added the binding modification immediately following the filter update |
| PS-001 | Reclassify missing -> weak | Encoded execution, children, and compiler artifacts are present; unavailable STDIN makes their meaning ambiguous rather than defining a clean missing link | unchanged |
| ACCT-001 | Retain missing | No scoped Sysmon ProcessCreate is attributed to the requested account names; Sysmon is not used to claim SAM state or Security-log authentication | unchanged |
| ING-001 | Retain missing, bound the claim | No execution/load is present in the retained approximately 0.46-second source; no claim is made beyond that short window | unchanged |
| LGN-002 | Retain missing | No post-write userinit.exe/art.bat ProcessCreate in the retained Sysmon window; the case does not claim that no logon occurred | unchanged |
| RK-001 | Retain missing, rebuild lifecycle | Same-value cleanup records 4820, 4834, and native DeleteValue 4847 were present and are now included; configured-target execution remains absent | changed |
| ST-002 | Retain missing | No Sysmon-observable configured action/payload firing; Security 4698 was removed as an impossible Sysmon-only confirmation | unchanged |
| EVL-001 | Retain missing | No post-write reboot/shutdown transition in scoped Sysmon; service state and log loss remain unknown in both directions | unchanged |
| ING-002 | Retain missing | File creation is confirmed only for certutil; object content and execution are not evidenced in scoped Sysmon | unchanged |
| LOGON-001 | Retain missing for final lifecycle | Earlier firing belongs to an earlier set/delete lifecycle; zero firing after the final A0 within the retained source | unchanged |
| ST-001 | Retain missing, rebuild lifecycle | Fifth creation invocation and five matching cleanup invocations were omitted and are now included; no task-scheduler-attributed action firing is present | changed |

Every case that remains under `tier1/missing/` now contains
`metadata.case_scope.absence_audit` in `build/case.json`.

## Package hashes

Unchanged packages:

- PS-001: `fdde848e1b8494472432a7417dd161864168410393f332908dcf9896f6529f33`
- ACCT-001: `9d10ed248922cac2a3cccb0b3f94a27c55b535044f80bb7317d55dc19bc95d22`
- ING-001: `47e1ccef825ac30e28edde85aa1a9b6290e4b50ea600a951c37dd965cde661bb`
- LGN-002: `b91f37cdcc7b47fc5b4ae7463a99ddab31dac976d57671d46cf223bf2c2075e7`
- ST-002: `a3c0da41e11c43fe916c213eedeab8c3b12ce81a2a5745d7b1ca98366338c8b4`
- EVL-001: `4cd884f501bc8a1f4248237b4adf6c436d998aa7f694f6389ce881eda30d6f03`
- ING-002: `9e9d98ec2a4d5a8097ae1758dd60c1d9c2a063f16eb569889ee9f559a765df8a`
- LOGON-001: `dbaa913305319a35358f0aa18b395b4ebfd24feb62ffc5048a31863e8a48fd09`

Changed packages:

| Case | Old SHA-256 | New SHA-256 |
|---|---|---|
| RK-001 | `73a8f2b1925490873a6884f032a46257cf0150032f99989fbbce5869101e3255` | `86db7908ebde2283bf07b3c7f527146af3a1b376e1f8ca7c0175e086dd094f92` |
| ST-001 | `c9e16432c573186a8212de2afdbc3bbdb3a3f45e2525e44f634d1512668ebd54` | `1b5bae0f2a393f1c21c1545af5eeeb46a09c4b85c99b695fc897cf6461ee89b7` |
| WMI-002 | `3f3457eef6231904b8c4182cf5ed68d496f72beaaf00f2a296ce5105088ce1f4` | `9b84d8512153ee9fc3e51e749348e625e16dc8cce3e73d9d43cb9c21496dac50` |

All listed packages were regenerated from the retained export and verified
against the retained raw source with `tools/normalize.py --verify-log`.
Byte-identical package rebuilds caused filesystem modification times to advance;
`eval/artifact_continuity.json` records those SHA-256 continuity claims so the run
inventory does not misclassify unchanged model inputs as unresolved drift.

## Output invalidation and rerun boundary

Old RK-001 and ST-001 outputs were moved, not deleted, to:

`archive/invalidated_outputs/2026-07-16/rk_st_lifecycle_completion/`

The subsequent full-development-set raw audit also invalidated outputs for WMI-002,
UAC-001, AMQ-001, FW-001, and RTLO-001. Those outputs are retained at:

`archive/invalidated_outputs/2026-07-16/dev_selection_completeness/`

Only calls for those changed model inputs are invalidated. PS-001 changed folder and
condition label only; its model-visible package is byte-identical, so it does not
require a new model call. Its offline condition-stratified metrics must be regenerated
after current outputs are complete.
