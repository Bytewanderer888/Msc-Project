# Development model-input freeze

`dev_model_input_freeze_v1.json` is the pre-rerun integrity baseline for the 21
development packages. It freezes what can affect a model call:

- every canonical `alert_package.json` byte hash;
- the effective A1 and A2 system prompts (text after the `---` delimiter);
- the Gemini request template and request configuration; and
- the input/output schemas and runner implementation for review.

Create the baseline only after package, prompt, and request review:

```bash
python3 tools/freeze_model_inputs.py --write
python3 tools/freeze_model_inputs.py
```

Run the check immediately before every quota-limited replacement call. A clean
check means that GT, rubric, validator, A3/A4, retrieval-document, or report edits
must not be used as a reason to rerun the model. A canonical package, effective
prompt, requested model, or request-configuration change requires explicit review.

This input freeze is intentionally separate from `MANIFEST.json`. The project-wide
manifest is refreshed only after all intended outputs and reports are complete.
