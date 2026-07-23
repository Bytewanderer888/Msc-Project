# Evaluation deepening (v1)

## Purpose

This is an offline extension of the frozen SafeSOC A2/A4 results. It adds
measurement depth without changing the 41 canonical packages, ground truth,
saved model outputs, prompts, or provider settings.

It is a secondary analysis added after completion of the primary model runs;
it is not presented as a preregistered experiment. The original C2 headline
endpoint is unchanged, while the additional distances, intervals, stability
breakdown, and taxonomy are reported as secondary or descriptive analyses.

The extension contains four bounded analyses:

1. Ordinal distance from the admissible verdict, severity, and action bands.
2. Wilson/bootstrap intervals and a paired held-out Gemini-vs-Claude comparison.
3. Field-level stability across the three saved A2 rounds.
4. A synthetic conformance suite that checks deterministic C1-C4 isolation and
   invariance properties.

Condition-level summaries and macro condition averages are descriptive only;
the latter give the small counter stratum the same weight as larger strata.

Held-out round 1 is the primary model comparison. Rounds 2 and 3 are used only
to characterise stability and are not treated as independent samples.

## Run

```bash
python3 experiments/evaluation_deepening_v1/run_analysis.py
python3 -m unittest discover -s eval/tests -p 'test_*.py'
```

The analysis makes zero API calls. It reads the existing reports under
`eval/reports/` and writes:

- `RESULTS.json`: machine-readable aggregate and case-level instability data.
- `RESULTS.md`: thesis-ready summary tables and interpretation guardrails.
- `case_metrics.csv`: one row per saved A2 case-output (246 rows).
- `CONFORMANCE_MATRIX.md`: expected and observed C1-C4 mutation vectors.

## Scope limits

- C2 joint correctness remains the headline endpoint.
- Ordinal distances are reported separately by field; there is no composite score.
- Confidence is exploratory and does not change C1-C4.
- The conformance suite tests deterministic implementation behaviour. It does
  not turn C1 or C3 into broad semantic natural-language verifiers.
