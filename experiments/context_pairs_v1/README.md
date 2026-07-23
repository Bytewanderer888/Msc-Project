# Context-reveal pairs (v1)

This controlled within-scenario experiment tests whether an LLM correctly lowers its
triage decision when decisive benign context is revealed while the alarming observations
remain present.

Each pair contains two independently submitted, neutrally identified packages:

- **weak**: the suspicious surface is visible, but the benign explanation is withheld;
- **counter**: the suspicious surface is unchanged and source-backed benign context is
  revealed.

The experiment is separate from `outcome_pairs_v1`. Outcome pairs manipulate malicious
confirmation (base to Strong); context pairs manipulate benign explanation (Weak to
Counter). Together they form the controlled paired evidence-sensitivity study.

## Design

- CC1 / DISC-002: reveal Amazon SSM parent-process provenance.
- CC2 / RDL-001: reveal WebClient, `davclnt.dll`, and OneDrive WebDAV provenance.
- CC3 / SMB-002: reveal machine-account provenance and same-session Group Policy reads.
- CC4 / PS-003: reveal the reconstructed benign `Hello, World!` PowerShell payload.

The expected response is a non-reversed reduction in verdict, severity, and action, with
both versions entering their predeclared target bands. Expected labels are analyst-side
only and are never included in model input.

## Run configuration

- Model: `gemini-2.5-flash`
- Prompt: frozen A2 evidence-aware prompt
- Temperature: 0
- Thinking: off
- Maximum output tokens: 2,048
- Independent request per package

Exact prompt and API-time script hashes are recorded in `RUN_CONFIG.json`. The scripts
under `provenance/` are portable publication copies: only machine-specific repository
and temporary-directory paths were replaced, and the corresponding published-copy
hashes are recorded separately.

## Results

All 4 pairs and 8 model outputs are complete.

- Full endpoint met: **0/4 pairs**.
- Correct downward decision movement: **1/4 pairs**.
- Benign intervention acknowledged in the Counter rationale: **4/4 pairs**.
- No triage response despite the new context: **2/4 pairs**.
- Reversed or mixed response: **1/4 pair**.

Pair-level reading:

- CC1: both versions were closed as benign; the Weak version was prematurely closed.
- CC2: both versions remained suspicious/medium/investigate; benign context was noticed
  but did not change triage.
- CC3: severity increased from low to medium after benign context was revealed.
- CC4: triage moved from suspicious/high to benign/informational/close; the direction was
  correct, although the Weak severity exceeded its target band.

Combined with the 4 completed outcome pairs, the controlled study contains **8 matched
pairs and 16 model outputs**. The intervention was used in the rationale in 8/8 pairs,
but triage moved in the intended direction in only 4/8, and both versions entered their
target bands in only 1/8. The model therefore notices changed evidence more reliably than
it converts that evidence into a calibrated decision.

## Files

- `manifest.private.json`: pair definitions, source hashes, interventions, and target bands.
- `packages/QC-*.json`: 8 model-visible packages with neutral identifiers.
- `outputs/<provider>__<model>/`: saved outputs and retained usage records.
- `run_pairs.py`: skip-existing API runner; dry-run unless `--execute` is supplied.
- `score_pairs.py`: offline integrity audit and pair scoring.
- `RESULTS.json`: deterministic machine-readable score report.
- `provenance/`: unchanged scripts used to construct and run the temporary experiment.

## Commands

```bash
python3 experiments/context_pairs_v1/score_pairs.py
python3 experiments/context_pairs_v1/run_pairs.py  # dry-run; currently 0 missing
```
