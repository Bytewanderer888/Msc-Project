# External replication selection protocol v1.0

## 1. Target matrix

Stop at 16 accepted cases, with exactly four cases in each evidence condition.
The following requirements apply to the set as a whole:

- at least 12 distinct ATT&CK technique IDs;
- at least 8 technique IDs absent from the frozen 41-case benchmark;
- no technique ID used by more than two replication cases;
- at least three independent upstream corpora;
- at least four genuine multi-source cases;
- both single-source and multi-source cases represented;
- no more than two cases from one continuous capture/attack chain;
- endpoint isolation, credential control, network blocking, and analyst
  escalation each represented as an operational response family.

These are diversity constraints, not quota overrides. A case is rejected if it
does not honestly instantiate its condition even when its rejection leaves a
matrix cell unfilled.

## 2. Independence unit

The independence unit is the capture/scenario/run, not the event row. Cases
from the same continuous chain share a `capture_cluster` and are analysed as a
cluster in any uncertainty statement. Repeated detector alerts for one event do
not increase the case count or sensor-depth count.

## 3. Genuine multi-source rule

A case is `multi_source` only when two or more distinct sensors/log sources
observe the same host/action and compatible time window. Two IDS products
reprocessing one raw line, two copies of the same event, or logs from different
hosts/days are not genuine fusion.

## 4. Condition gates

Before condition annotation, every case must pass the alert-anchor policy in
`rubric/alert_anchor_selection_policy_v1.0.md`. The authoritative
`annotations/trigger_spec.json` must:

- express a behavioural analytic using only fields observable at alert time;
- execute over the complete declared source, step, sensor, or asset scope;
- avoid exact timestamps, record IDs, source lines, byte offsets, labels, GT,
  and model output as trigger predicates;
- resolve multiple matches with a declared deterministic strategy;
- reproduce the retained `A0` under `tools/audit_trigger_rules.py`.

Each specification must also reference its shared analytic family and pattern
from `rubric/trigger_analytic_catalog_v1.0.json`. This is a detection-mechanism
index only; it does not replace the executable case predicate or influence the
evidence-condition annotation.

Exact source locators remain in `expected_a0`, `build/case.json`, and provenance
only as post-rule integrity assertions. Passing this gate establishes a
reproducible, non-circular triage entry point; it does not claim detector recall
or population-level detection accuracy.

### Strong

The package must decisively establish the security proposition or a completed
offensive mechanism. A suspicious command, alert signature, detector label, or
precursor without its required outcome is insufficient.

### Weak

A real security-relevant signal is present, but its meaning or intent remains
ambiguous. The ambiguity concerns what the observed signal means, not an omitted
named outcome.

### Missing

A named precursor-to-outcome chain is incomplete. The missing confirmation must
be observable by at least one declared sensor, and a raw-scope audit must show
that it is absent from the full host/time/sensor window, not merely omitted from
the package.

A point-in-time alert window is allowed only when it ends at a source-defined
alert or collection-step boundary and represents the evidence available to an
analyst at that moment. It must not omit an event that had already occurred.
Later events in a longer attack sequence remain outside the bounded proposition
and must be disclosed in `must_not_assert`; they cannot be used to claim that an
outcome "never" happened.

### Counter

The suspicious surface remains visible, but affirmative context supports a
routine or benign explanation. Absence of follow-on alone never qualifies as
counter-evidence.

## 5. Leakage gate

The model-visible package must exclude:

- condition, verdict, severity, action band, calibration role, and ground truth;
- scenario/attack-step labels and attack timelines;
- ATT&CK IDs, tactic/technique names, Atomic/Caldera/test-framework names;
- detector rule names, rule severity, IDS classifications, and prose signatures
  that directly state the answer;
- source filenames or IDs that encode the case label.

Neutral event facts and deterministic derivations may remain. Redactions must be
typed where their type matters, such as `[redacted-password]`; generic framework
names may use `[x]` under the frozen placeholder convention.

## 6. Ground-truth gate

Each accepted case must include:

- one constrained security proposition;
- supporting and counter-evidence IDs;
- `must_not_assert` boundaries;
- fixed rubric-v1.1 verdict, severity, and canonical action bands;
- an operational response family and deployment rationale;
- source path/member, record locator, timestamp window, and hashes;
- an annotator checklist confirming package/GT consistency.

Ground truth is completed before any model call. Detector labels can help locate
events but cannot substitute for semantic review.

## 7. Analysis rule

The replication set is reported separately from the frozen benchmark. Primary
metrics are joint pass, C1-C4 failure counts, condition-level calibration, and
direction of error. Because cases can share a capture cluster, case-level
percentages are accompanied by exact counts and a cluster-aware sensitivity
summary; no population prevalence claim is made.
