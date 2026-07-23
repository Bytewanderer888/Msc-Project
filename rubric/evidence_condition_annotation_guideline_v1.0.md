# Evidence-Condition Definition and Annotation Guideline - v1.0

> **Superseded on 2026-07-16 by
> `evidence_condition_annotation_guideline_v1.1.md`.** v1.0 is retained as the
> documentation-audit baseline. Do not use it for new annotation or runtime-policy
> development; its proposition-selection, WMI installation, missing-case QA, and
> strong/counter decision-tree wording are incomplete.

**Status:** benchmark annotation protocol, recorded 2026-07-15 after the final
41-case evidence audit and before development of the ground-truth-free runtime
validator. This document formalises the condition boundaries already applied to
the frozen benchmark. It does not change any package, ground-truth label, model
output, or reported result.

**Normative relationship:** this guideline defines how a human annotator assigns
the four evidence conditions. `evidence_sufficiency_rubric_v1.1.md` defines how
the resulting verdict, severity, evidence, and action fields are scored by the
offline evaluator. The per-case `ground_truth.json` is the case-specific answer
key produced by applying both documents.

## 1. Purpose and scope

SafeSOC evaluates whether an LLM's SOC triage decision is proportionate to the
evidence visible at triage time. Cases are therefore grouped by **evidence
condition**, not by ATT&CK technique or attack family.

The four conditions are:

```text
strong | weak | missing | counter
```

They describe the state of support for a defined security proposition in one
canonical `alert_package.json`. They do not estimate how common an attack is,
prove an operator's real-world intent, or claim complete ATT&CK coverage.

This protocol applies identically to:

- development and held-out cases;
- attack_data and OTRF cases after normalisation;
- Tier-1 single-sensor and Tier-2 genuine-fusion packages.

## 2. Unit of annotation and evidence boundary

The annotation unit is **one frozen, model-visible alert package**, including:

- one main alert, `A0`;
- zero or more contextual evidence items, `EV-xxx`;
- zero or more deterministic derivations, `DER-xxx`;
- the package's stated host, sensor, and time-window scope.

The annotator must judge the same evidence that the model receives. ATT&CK IDs,
folder names, curation notes, source-corpus narratives, test-framework identity,
and later incident knowledge must not determine the condition when those facts
are absent from the package.

Raw logs, `build/case.json`, provenance, and retrieval records may be used to:

1. verify that selected events are authentic and reproducible;
2. confirm sensor coverage, host scope, and the observation window;
3. check that no selected event was mistranscribed or omitted accidentally.

They must not be used to justify a verdict with facts hidden from the model. If a
fact is necessary to determine the condition, it must either be represented in
the canonical package or the case must be weakened, excluded, or rebuilt before
freeze.

## 3. Start with a security proposition

Before assigning a condition, state the specific proposition being tested. The
proposition must be narrower than a general claim such as "this host was
attacked". Examples include:

- a service-based privileged execution mechanism completed;
- a credential-dumping outcome is evidenced;
- a persistence mechanism was configured but did not visibly fire;
- an alarming SMB pattern is routine Group Policy processing.

The condition answers:

> How strongly does the package support this proposition, and what decision is
> proportionate to that support?

This step prevents a command name or ATT&CK mapping from becoming the answer by
itself.

## 4. Fixed condition definitions

### 4.1 Strong

**Definition:** the package directly evidences the target security-relevant
outcome, successful execution state, or a decisive offensive mechanism. The
evidence goes beyond a command being issued or a configuration being attempted.

Operational requirements:

1. At least one visible event or trustworthy derivation directly supports the
   target proposition.
2. The decisive observation is attributable to the scoped host, process,
   account, and time window with adequate correlation.
3. A plausible benign-looking surface, authorised simulation context, or later
   cleanup does not negate the observed mechanism itself.
4. The conclusion is behavioural: `malicious` means that the offensive mechanism
   or security-relevant outcome is decisively evidenced. It does not prove that
   the real-world operator lacked authorisation.

Typical decisive evidence includes:

- the planted or configured program is actually launched by the target service
  or persistence mechanism;
- native telemetry records creation of the complete mechanism state, rather
  than only a command requesting it;
- a collection or dumping operation produces the expected result artifacts;
- multiple genuinely correlated sensors confirm the same compromise outcome.

Insufficient by itself:

- a process-create event showing only that `sc`, `schtasks`, `reg`, `certutil`,
  or another utility was invoked;
- a suspicious filename, path, command flag, or ATT&CK mapping;
- a command that requests an operation without success or result telemetry;
- researcher knowledge that the capture came from an attack simulation.

Fixed policy:

```text
verdict:  malicious
severity: high | critical
actions:  escalate | isolate
```

### 4.2 Weak

**Definition:** the package contains a genuine suspicious indicator, behaviour,
or attempt, but the visible evidence is ambiguous or insufficient to establish
the target malicious outcome. The uncertainty comes primarily from what the
present evidence can mean, rather than from one clearly defined missing link in
an otherwise explicit execution chain.

Operational characteristics:

1. There is positive suspicious evidence; the case is not labelled weak merely
   because information is generally sparse.
2. The behaviour is dual-use, low-context, target-unverified, or compatible with
   both benign and malicious explanations.
3. No decisive benign context supports closing the alert.
4. No decisive outcome supports a strong label.

Examples of weak evidence patterns include:

- a dual-use administration or discovery command without corroborating attack
  activity;
- repeated failed authentication attempts without a successful authentication;
- invocation of a dumping or transfer utility when the target, result, content,
  or follow-on use is not established;
- a suspicious registry or configuration change whose security impact remains
  ambiguous on the visible evidence.

Fixed policy:

```text
verdict:  suspicious
severity: low | medium
actions:  monitor | investigate
```

### 4.3 Missing

**Definition:** the package contains a recognisable setup, precursor, or attempted
step for a security-relevant outcome, but a specific expected confirmation is not
evidenced within an adequate sensor and time-window scope.

The label means:

> The confirming outcome is missing from the available package.

It does **not** mean:

> The outcome certainly did not happen in the real world.

Operational requirements:

1. The precursor or setup is directly visible.
2. The expected confirming event or artifact can be named before reading the
   model output.
3. The available sensor would reasonably be capable of observing that
   confirmation, or the package explicitly preserves the relevant scoped search.
4. The observation window is adequate for the bounded claim.
5. The annotation uses "not evidenced in the package/window", not an unbounded
   claim such as "never happened".

Examples include:

- a task-creation command with no task-registration or task-fired evidence;
- a WMI, service, account, or run-key setup with no visible target execution or
  subsequent use;
- a transfer or staging action with no execution of the transferred object;
- a persistence trigger configured without the event that would activate it.

If the expected outcome would not have been observable with the available
sensor, the case must not use absence as decisive evidence. It should normally be
classified as weak or excluded as indeterminate.

Fixed policy:

```text
verdict:  suspicious
severity: low | medium
actions:  monitor | investigate
```

### 4.4 Counter

**Definition:** the package contains affirmative, case-relevant benign or
contradicting evidence strong enough to defeat the alarming interpretation and
support a benign disposition.

Counter is not the residual class for cases that lack proof of attack.

Operational requirements:

1. The benign explanation is grounded in visible evidence IDs.
2. The context explains the same activity that made the alert look malicious.
3. The explanation is sufficiently specific and decisive to support benign,
   rather than merely lowering confidence.
4. No remaining visible outcome independently establishes a strong offensive
   mechanism.

Examples of decisive counter-context include:

- a narrow machine-account access pattern to default Group Policy artifacts
  consistent with routine GPO processing;
- a management agent directly parenting a short, coherent inventory burst;
- trustworthy asset, signer, baseline, or provenance evidence that explains the
  alerted activity, when that context is present in the package.

Insufficient by itself:

- no follow-on attack activity;
- a familiar vendor-like filename or installation path without trustworthy
  provenance;
- later cleanup after a malicious mechanism already executed;
- the fact that the source capture was an authorised test;
- a general statement that the activity "could be legitimate".

Fixed policy:

```text
verdict:  benign
severity: informational | low
actions:  close_benign | monitor
```

## 5. The weak-missing-counter boundary

These three conditions may all lack confirmed compromise, but for different
reasons:

| Condition | What is present? | Why is the outcome not malicious/high? |
|---|---|---|
| Weak | A real but ambiguous suspicious signal | The positive evidence does not uniquely support the malicious interpretation |
| Missing | A defined precursor or setup | A named confirmation step is not evidenced in an adequate package/window |
| Counter | Affirmative benign or contradicting context | The visible context positively explains or defeats the alarming interpretation |

Short test:

```text
Weak:    "This is suspicious, but the observed behaviour is ambiguous."
Missing: "The setup is visible, but the expected result is not evidenced."
Counter: "The visible context affirmatively explains why this is benign."
```

Absence alone can distinguish missing from strong, but it cannot establish
counter. Counter requires positive benign evidence.

## 6. Annotation decision procedure

Apply the following procedure without reading any model output for the case being
annotated.

### Step 1 - Freeze the annotation unit

Record the canonical package path and SHA-256. Confirm that the package is schema
valid and reproducible from retained source material.

### Step 2 - State scope and proposition

Record:

- host and user scope;
- sensor or genuine-fusion scope;
- time-window boundary;
- the precise security proposition being evaluated.

### Step 3 - Build an evidence ledger

For every relevant `A0`, `EV-xxx`, and `DER-xxx`, record:

| Field | Meaning |
|---|---|
| Observation | What the event directly records |
| Role | supporting, counter, or contextual |
| Permitted inference | What the observation can support |
| Prohibited inference | What it does not prove |

Use observation language such as "the process was launched", "the file was
created", or "the value was deleted". Do not silently rewrite these as "the
operation succeeded", "the payload was malicious", or "the account was used".

### Step 4 - Test the target outcome

Ask:

1. Is the target proposition directly evidenced?
2. Is the observation a result/state event, or merely a command requesting it?
3. Is the target object or process actually identified?
4. Are cross-event relationships genuinely correlated by host, process, user,
   and time?
5. Does cleanup limit persistence duration without negating completed execution?

If the proposition is decisively evidenced, continue to the benign-context test
and then assign strong unless the same event is affirmatively explained as
routine or benign.

### Step 5 - Test benign and contradicting context

Ask whether visible counter-context explains the alerted activity itself. A
generic alternative explanation is not enough. Distinguish:

- **decisive counter-context**, which can determine a counter condition;
- **mitigating context**, which must be acknowledged but does not change an
  already confirmed strong outcome;
- **weak context**, which only lowers confidence and cannot justify benign.

### Step 6 - Test a missing confirmation

If no decisive outcome is visible, identify whether the case contains an explicit
precursor and a named expected confirmation. Confirm sensor and time-window
adequacy before assigning missing.

### Step 7 - Assign one condition

Use this decision tree:

```text
Is the target security proposition directly and decisively evidenced?
  Yes -> Does visible context prove that the same activity is routine/benign?
           Yes -> COUNTER
           No  -> STRONG
  No  -> Is there decisive visible benign context for the alarming activity?
           Yes -> COUNTER
           No  -> Is a defined precursor present and a named confirmation absent
                  within an adequate observable scope?
                    Yes -> MISSING
                    No  -> Is there a genuine but ambiguous suspicious signal?
                             Yes -> WEAK
                             No  -> EXCLUDE / INDETERMINATE
```

The `EXCLUDE / INDETERMINATE` outcome is preferable to forcing an unstable case
into the quantitative benchmark.

### Step 8 - Apply the fixed policy fields

Do not tune verdict, severity, or action bands per case:

| Condition | `correct_verdict` | `acceptable_severity` | `acceptable_actions` |
|---|---|---|---|
| strong | malicious | high, critical | escalate, isolate |
| weak | suspicious | low, medium | monitor, investigate |
| missing | suspicious | low, medium | monitor, investigate |
| counter | benign | informational, low | close_benign, monitor |

Assign `calibration_role` separately:

- `preserve` for overt strong cases where the correct high decision should be
  retained;
- `up_rank` for subtle strong cases whose surface invites under-triage;
- `down_rank` for weak, missing, and counter cases that probe over-triage.

The role describes the intended calibration stress; it does not override the
evidence condition.

### Step 9 - Complete the grounding fields

Populate:

- `supporting_evidence`: IDs that warrant the correct verdict;
- `counter_evidence`: IDs containing decisive or mitigating context that the
  model should acknowledge;
- `must_not_assert`: concrete conclusions not supported by the package;
- `the_trap`: the specific over-triage or under-triage failure being tested;
- `rationale`: a bounded evidence-to-decision explanation.

`counter_evidence` may appear in any condition. For example, cleanup can mitigate
a strong case without converting it to counter. The **counter condition** is used
only when benign context determines the overall verdict.

`must_not_assert` is a manual semantic-audit aid under rubric v1.1. It must not be
described as fully enforced by deterministic C1.

### Step 10 - Review and freeze

Perform a second pass that checks:

1. every cited GT evidence ID exists in the package;
2. the rationale uses only model-visible facts;
3. every absence statement is scoped to the package/window;
4. command invocation is not stated as successful outcome without evidence;
5. the fixed condition-to-policy mapping is exact;
6. folder, `case.json`, GT, metadata, and manifest condition labels agree.

Record `annotated_by`, `rubric_version`, and review status. AI assistance may be
used to locate inconsistencies, but it is not an independent human annotator. If
only one human annotator is available, disclose that limitation and retain the
evidence ledger and rationale for auditability.

## 7. Boundary rules

The following rules apply across all techniques and both corpora.

1. **Invocation is not success.** A process-create event proves that a command was
   launched, not that the requested account, task, service, transfer, or policy
   operation completed.
2. **A suggestive name is not identity.** A filename such as `lsass.dmp`, a PID,
   path, extension, or test-like label does not identify content or target without
   corroboration.
3. **Native state events can be decisive.** A sensor event that directly records
   creation, execution, access, or deletion may establish that state even when no
   command exit code is available.
4. **Absence is bounded.** Write "not evidenced in the available package" rather
   than "did not happen" or "never occurred".
5. **Sensor adequacy is required for missing.** Do not treat an unobservable event
   as absent evidence.
6. **Cleanup does not erase history.** Deletion or restoration may limit duration
   or impact, but it does not negate a completed execution already recorded.
7. **Authorisation is not behaviour.** A lab or red-team origin does not make an
   observed offensive mechanism benign; it limits claims about real-world intent.
8. **Technique is metadata.** ATT&CK mapping supports description and sampling,
   not condition assignment.
9. **No fabricated fusion.** Events from different hosts, users, days, or
   uncorrelated captures must not be combined to create a stronger chain.
10. **Counter requires affirmative support.** Familiar paths, common tools, and
    lack of follow-on activity are not decisive benign evidence on their own.
11. **Severity follows support, not alarm wording.** Rule names, command flags,
    and security-tool vocabulary do not justify high severity without the
    condition-level evidence threshold.
12. **Case curation must remain neutral.** The package may be scoped to a realistic
    alert-centred window, but must not hide directly correlated evidence merely to
    manufacture weak or missing conditions.

## 8. Annotation record template

The human annotation worksheet should contain at least:

```text
Case ID:
Package SHA-256:
Corpus / tier / split:
Host, sensor, and time-window scope:
Security proposition:

Evidence ledger:
  ID | direct observation | role | permitted inference | prohibited inference

Outcome test:
Benign/counter-context test:
Missing-confirmation test and sensor adequacy:
Boundary or disagreement notes:

Final condition:
Calibration role:
Correct verdict:
Acceptable severity band:
Acceptable action band:
Supporting evidence IDs:
Counter-evidence IDs:
Must-not-assert statements:
Rationale:
Annotator and review status:
```

The committed `ground_truth.json` stores the machine-readable subset. The case
build metadata and retrieval record retain the scope and provenance details.

## 9. Quality assurance and adjudication

Recommended quality controls are:

1. annotate without viewing the model output being scored;
2. use a two-pass review separated from the initial annotation;
3. independently review all boundary cases and a sample from every condition;
4. record disagreements and the evidence rule used to resolve them;
5. report condition counts and disclose small or imbalanced strata;
6. expose case-level results rather than relying only on aggregate accuracy.

This benchmark uses a single primary human annotator under a time constraint.
The mitigation is a fixed condition-level policy, schema validation, retained raw
provenance, explicit per-case evidence IDs and rationale, repeated consistency
audits, and full disclosure of the single-annotator limitation. AI-assisted review
does not replace independent domain-expert adjudication.

## 10. Freeze and change control

After benchmark freeze:

- a wording clarification that does not change any model-visible input or policy
  field requires an annotation audit note;
- a GT condition, verdict, severity, action, or evidence-ID change requires a
  versioned annotation correction and offline re-scoring of affected outputs;
- a model-visible package change requires a new package hash, invalidation of the
  old model output, and a replacement model call for that case;
- a condition-level rule change requires a new guideline/rubric version and
  re-evaluation of every affected case;
- no label may be changed because a held-out model output appears surprising.

All superseded outputs remain archived with their invalidation reason and API
usage record.

## 11. Relationship to the runtime validator

This guideline is a **human annotation standard**, not deployable ground truth.
The future runtime validator may operationalise reusable parts of it, such as:

- command invocation versus observed result;
- presence of a named execution or outcome event;
- sensor and correlation adequacy;
- acknowledgement of visible counter-context;
- decision and action bands justified by the inferred evidence state.

The runtime validator must read only the alert package, the LLM output, and a
reusable evidence policy. It must not read `ground_truth.json`, the folder's
condition, case-specific expected bands, or researcher-only metadata. Its output
should be `supported`, `unsupported`, or `indeterminate`, with a reason and a
preserve/down-rank/up-rank/human-review recommendation.

During evaluation, the frozen human GT may be used **after** runtime prediction to
measure agreement, false positives, false negatives, and analyst deferral. In
this relationship:

```text
guideline + human evidence review -> benchmark ground truth
runtime policy + visible evidence  -> deployable validation prediction
offline comparison                 -> runtime-validator evaluation
```

The runtime policy may approximate the annotation standard, but it must never be
presented as access to the answer key or as proof of absolute incident truth.
