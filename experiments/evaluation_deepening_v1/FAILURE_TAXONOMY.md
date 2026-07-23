# Lightweight failure taxonomy

## Purpose and scope

This qualitative coding layer explains *how* representative calibration errors
arise. It does not replace C1-C4, does not add a new quantitative endpoint, and
does not claim population frequencies. Categories can overlap. The examples
below come from frozen outputs or the completed paired evidence study.

| Failure mode | Operational meaning | Representative observation | Why the validator flags it |
|---|---|---|---|
| Precursor-as-outcome collapse | A setup or attempt is treated as proof that the intended security outcome occurred. | `LOGON-001`: Gemini calls registry configuration a successful persistence attempt although no logon-triggered execution is evidenced. | Missing evidence supports suspicious investigation, not malicious/high escalation. |
| Signal-to-attribution inflation | A real anomalous signal is promoted to confirmed attacker intent without the confirmation needed for that attribution. | `BF-002`: rapid failed logons against nonexistent usernames are described accurately, but both models still move to malicious/high without successful authentication or follow-on activity. | The signal is real but remains weak; severity exceeds the admissible band. |
| Counter-evidence inversion or neglect | Decisive benign context is ignored, underweighted, or interpreted in the wrong direction. | `PS-003`: Gemini cites the benign decoded command and LSASS-to-PowerShell access but interprets the reversed access direction as credential dumping. | The designated counter-evidence should move the result toward benign/low. |
| Decisive-outcome underweighting | The model notices the decisive outcome but does not move the decision into the strong band. | `UQP-001`: Gemini cites execution by `SYSTEM` through the service mechanism but remains suspicious/medium/investigate. | The observed mechanism execution supports malicious/high and escalation. |
| Asymmetric evidence updating | Added decisive evidence is cited, but decision calibration changes inconsistently; absence of that evidence is not treated symmetrically. | In the outcome-pair study, added outcome evidence was cited in 4/4 strong versions, but both versions entered their predeclared bands in only 1/4 pairs. | The within-scenario contrast shows evidence recognition without reliable sufficiency-sensitive updating. |

## Coding rule

Assign a category only when the saved rationale and package support the stated
mechanism. Record C2/C4 failures separately from the qualitative code. Because
this project uses one primary annotator, the taxonomy is reported as an
interpretive case analysis rather than an inter-rater frequency claim.

## Thesis-safe conclusion

The dominant errors are not random formatting failures. They are reasoning
failures at the boundary between an observed precursor, a decisive outcome, and
an alternative benign explanation. The paired study strengthens this reading:
the model can cite newly added evidence while still failing to recalibrate the
decision consistently.
