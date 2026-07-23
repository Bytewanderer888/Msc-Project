# Category Selection Rationale

*Why these ATT&CK techniques, and not the other ~200 in `attack_data`.* Written for the
methodology chapter / viva defence.

## 1. Sampling stance — purposive, not representative

This dataset is a **controlled diagnostic benchmark** for an evidence-sufficiency validator,
**not** a population sample of ATT&CK. Representative/random sampling would be the wrong tool
(it suits population-prevalence estimation, which this study does not claim). The method is
**stratified purposive sampling** (Patton, *Qualitative Research & Evaluation Methods*, 2015 —
combining *maximum-variation* and *criterion* sampling):

- **Strata = the validator's decision dimensions**, not attack families:
  - **Primary:** evidence condition ∈ {strong, weak, missing, counter}
  - **Secondary:** calibration role ∈ {down-rank (over-triage-prone), preserve, up-rank
    (under-triage-prone)}, and **ATT&CK tactic** (for kill-chain breadth).
- A technique is selected **because it naturally instantiates a stratum the design needs**,
  with realistic (not fabricated) evidence.

The objective is to **fill the design matrix (condition × role × split)** with natural cases —
not to "cover ATT&CK."

## 2. Inclusion criteria (the "why these")

1. **Natural instantiation** — the technique naturally produces the target evidence condition,
   so cases are realistic rather than contrived (discovery → weak; LOLBins → counter;
   injection → strong).
2. **Triage relevance** — it fires real SOC alerts / maps to public detection content
   (Sigma, EDR). A *triage* validator must be tested on things that get triaged.
3. **Tactic spread** — collectively span the kill chain (Execution → Credential Access →
   Persistence → Privilege Escalation / Defense Evasion → Lateral Movement → Discovery), so the
   claim is "generalises across the attack lifecycle," not one phase.
4. **Clean telemetry in the corpus** — host-scoped single-sensor captures (honest Tier-1) or
   genuine multi-sensor fusion (Tier-2). An openly-stated data-availability constraint.
5. **Mechanistic distinctness** — each technique stresses a *different* evidence pattern
   (no near-duplicates), so breadth is real.

**Stopping rule (saturation of the design matrix):** stop adding techniques once every evidence
condition has **≥2 cases in dev and ≥2 in held-out**. Breadth is bounded by the matrix, not by
the size of ATT&CK.

## 3. Selected techniques

| Technique | Tactic | Naturally supplies | Why it is included |
|---|---|---|---|
| T1059.001 PowerShell | Execution | missing / weak / counter / strong | ubiquitous alert; obfuscation spans all conditions |
| T1003.001 LSASS | Credential Access | strong (preserve + under-triage), weak | high-severity TP archetype; tool-dependent subtlety |
| T1055 Process Injection | Defense Evasion / Priv-Esc | strong (preserve) | canonical overt TP (unbacked shellcode) |
| T1053.005 Scheduled Task | Persistence | missing / counter / under-triage | benign-vs-malicious task tension |
| T1021.002 SMB / Admin Shares | Lateral Movement | strong (preserve) | confirmed remote-exec archetype |
| T1110 Brute Force | Credential Access | weak → strong gradient | fixes weak-in-both-splits; ambiguity is intrinsic |
| T1218 System Binary Proxy (LOLBins) | Defense Evasion | counter + strong | benign system binaries that look malicious |
| T1087 Account Discovery | Discovery | weak + counter | recon: suspicious-but-common |
| T1547 Registry Run Keys | Persistence | counter + strong + missing | legit autoruns vs malicious persistence |
| T1543.003 Windows Service | Persistence / Priv-Esc | strong (subtle) | service creation plus confirmed SYSTEM execution; cleanup tests under-triage |
| T1574.009 Unquoted Path | Execution / Priv-Esc | strong (subtle) | distinguishes a vulnerable path from a path interception that actually executes |

Each row earns its place under criterion 1 (supplies a needed condition) and is distinct under
criterion 5; together they satisfy criterion 3 (six ATT&CK tactics).

## 4. Scope boundary & categorical exclusions

**In scope:** host-based Windows endpoint techniques that (i) commonly trigger SOC triage,
(ii) collectively instantiate all four evidence conditions naturally, and (iii) span multiple
ATT&CK tactics.

**Deliberately excluded (a delimitation, not a coverage claim):**
- techniques with **no clean host-scoped telemetry** in the corpus;
- techniques that **do not produce a triage alert**;
- techniques **redundant** with an included evidence pattern;
- **out-of-domain** families (cloud, network-only, macOS/Linux).

## 5. Reproducible selection protocol

1. Define strata: 4 evidence conditions × 3 calibration roles × 2 splits, plus desiderata
   (tactic spread, SOC relevance).
2. Candidate pool = `attack_data` techniques with usable, host-scoped Windows telemetry.
3. Apply inclusion criteria 1–5; for each stratum, select the technique(s) that most naturally
   and cleanly instantiate it (single-source for Tier-1; genuine fusion for Tier-2).
4. Add cases until every condition has ≥2 in dev and ≥2 in held-out (saturation).
5. Record case-level event exclusions in each case's build metadata and state the
   corpus-wide categorical exclusions below. This project does not claim that every
   unselected ATT&CK folder underwent a formal candidate-by-candidate screen.

## 6. Threats to validity (state these, don't hide them)

- **Not statistically representative.** Purposive sampling supports claims about the validator's
  behaviour across the *sampled decision space*, not about population prevalence of techniques.
- **Corpus-bound.** `attack_data` is Windows-endpoint-biased; findings may not transfer to
  cloud/network/*nix telemetry.
- **Small-N by design.** This is a diagnostic benchmark; the effective unit of analysis is
  **case × model × validator-check**, reported with descriptive (not inferential) statistics.
- **Adjudication.** Ground truth is single-annotator (timeline constraint); mitigated by a
  frozen rubric and fully documented per-case reasoning.
- **Selection log.** The study retains inclusion rationales and categorical exclusions,
  but not an exhaustive row for every unselected corpus folder. Claims are therefore
  bounded to the sampled decision space rather than a complete ATT&CK candidate screen.
