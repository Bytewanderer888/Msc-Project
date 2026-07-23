# Gemini thinking-budget sensitivity (v1)

## Purpose

This is a separate robustness sensitivity over the 16 already-constructed matched-pair
packages. It asks whether a non-zero reasoning budget changes Gemini 2.5 Flash's
evidence sensitivity. It does not modify or re-run the 41 canonical benchmark cases.

The control outputs are the completed thinking-off results in `outcome_pairs_v1` and
`context_pairs_v1`. The treatment keeps the same model, A2 prompt, temperature, output
schema, packages, and 2,048-token output cap, changing only:

```text
thinkingBudget: 0 -> 1024
```

A fixed budget is used instead of provider-default dynamic thinking so the intervention
is reproducible and cannot consume the entire output allowance unpredictably. Existing
visible responses use far fewer than the remaining tokens.

## Endpoints

- Primary: number of matched pairs whose two versions both enter their predeclared bands.
- Secondary: intended directional movement and changed decision tuples.
- Exploratory: thought-token use, visible response tokens, confidence, and latency.

The study is interpreted as a configuration sensitivity, not as a new primary benchmark
arm and not as evidence about every reasoning budget or model.

## Run

```bash
export GEMINI_API_KEY="..."

# Dry run: lists all missing treatment outputs.
python3 experiments/thinking_sensitivity_v1/run_sensitivity.py

# Recommended first request; it is retained as part of the final 16 outputs.
python3 experiments/thinking_sensitivity_v1/run_sensitivity.py --only QE-284 --execute

# Continue with every remaining package; existing output is skipped.
python3 experiments/thinking_sensitivity_v1/run_sensitivity.py --execute

# Offline scoring after all 16 outputs exist.
python3 experiments/thinking_sensitivity_v1/score_sensitivity.py
```

All treatment outputs and append-only usage provenance are isolated under `outputs/` in
this directory. A failed or quota-interrupted run can be resumed without repeating a
saved case.
