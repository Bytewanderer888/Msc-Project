# Alert-anchor selection policy v1.0

## Purpose

SafeSOC evaluates post-alert triage, not detector recall. Each case therefore
needs a reproducible alert anchor (`A0`) before contextual evidence is added.
This policy prevents `A0` from being chosen because it produces a desired
evidence condition or model result.

## Rule-first requirement

Every case must contain `annotations/trigger_spec.json`. The specification
defines a behavioural analytic over the complete legal source scope. It must be
possible to execute the rule without reading:

- the evidence-condition label or ground truth;
- any model output or evaluator result;
- the selected EventRecordID, source line, byte range, or exact timestamp.

Those exact identifiers may appear only under `expected_a0`, where they act as
an assertion checked after rule execution.

## Permitted rule inputs

A trigger rule may use observable fields that a detector could use at alert
time, including event code, provider, channel, host scope, process image,
command-line features, registry or file paths, network endpoints, access masks,
signature state, and native success/failure status. A source-defined capture
step may bound scope when that boundary exists independently of the benchmark
label.

Exact host or endpoint values are permitted only when they represent a declared
asset/IOC scope. They must not be introduced solely to isolate the already
selected row. Exact timestamps are never behavioural predicates.

## Complete-scope replay

The audit executes the event predicate over the complete source available to
the case after only its declared host/sensor scope is applied. Context-event
selection is separate and cannot influence whether an event matches the trigger
rule.

If a rule matches multiple events, the specification must use a deterministic
selection strategy. Permitted strategies are:

- `earliest_match`;
- `latest_match`;
- `earliest_in_highest_count_group` for aggregate detections.

For an aggregate detection, `A0` is the declared representative event from the
matched group, not a claim that a single row independently satisfied the whole
analytic.

## Failure conditions

A case fails the trigger audit when:

- the behavioural rule does not match the retained `A0`;
- the selected event changes under the declared deterministic strategy;
- the rule depends on a prohibited exact selector or answer label;
- the full legal source scope cannot be replayed;
- the rule is so case-specific that it merely restates one record rather than a
  plausible detection behaviour.

A failed case must be revised, re-anchored, or quarantined before a new model
run. Passing this audit does not establish detector accuracy; it establishes
that the benchmark's triage entry point is reproducible and non-circular.

## Shared analytic taxonomy

Every trigger specification references one `analytic_family_id` and one
`analytic_pattern_id` from `trigger_analytic_catalog_v1.0.json`. The family is
the primary observable mechanism that causes the rule to fire; the pattern is
the reusable detection skeleton instantiated by the case-specific fields and
parameters.

This taxonomy does not replace the case rule. A family label alone cannot
select `A0`, and it must not be inferred from evidence condition, ground truth,
or model output. It provides a cross-case index showing which executable rules
share a detection mechanism while preserving the complete case-level replay.

## Protocol timing

For the original 41-case benchmark, executable trigger specifications are a
retrospective formalisation of the previously documented Q1/main-alert rules.
They may verify reproducibility but cannot be described as prospective
pre-registration. For `external_replication_v1`, trigger specifications and
audit results must be frozen before the first provider call.
