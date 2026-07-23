# Validator v1.1 conformance matrix

| Scenario | Purpose | Expected C1/C2/C3/C4 | Observed | Result |
|---|---|---|---|---:|
| BASE | Unmodified in-band control | P/P/P/P | P/P/P/P | PASS |
| INV-EVIDENCE-ORDER | Reordering evidence items must not alter any check | P/P/P/P | P/P/P/P | PASS |
| INV-CONFIDENCE | Confidence is exploratory and must not alter C1-C4 | P/P/P/P | P/P/P/P | PASS |
| INV-VALID-IRRELEVANT-ID | Adding a valid irrelevant ID must not matter when a relevant key ID remains | P/P/P/P | P/P/P/P | PASS |
| INV-ID-PRESERVING-PROSE | A fixed synonym rewrite that preserves citations must not alter checks | P/P/P/P | P/P/P/P | PASS |
| C1-INVALID-ID | A fabricated evidence identifier must fail C1 only | F/P/P/P | F/P/P/P | PASS |
| C1-UNSUPPORTED-DECODE | A decoded-value claim without a derivation must fail C1 only | F/P/P/P | F/P/P/P | PASS |
| C2-VERDICT-OVER | Changing only the weak-case verdict to malicious must fail C2 only | P/F/P/P | P/F/P/P | PASS |
| C2-SEVERITY-OVER | Changing only weak-case severity to high must fail C2 only | P/F/P/P | P/F/P/P | PASS |
| C2-SEVERITY-UNDER | Changing only strong-case severity to low must fail C2 only | P/F/P/P | P/F/P/P | PASS |
| C3-COUNTER-CITATION-REMOVED | Removing the designated counter citation must fail C3 only | P/P/F/P | P/P/F/P | PASS |
| C4-ACTION-OVER | Changing only weak-case action to isolate must fail C4 only | P/P/P/F | P/P/P/F | PASS |
| C4-ACTION-UNDER | Changing only strong-case action to monitor must fail C4 only | P/P/P/F | P/P/P/F | PASS |
| C2-C4-COMBINED-OVER | Overstating verdict, severity and action must fail C2 and C4 only | P/F/P/F | P/F/P/F | PASS |

Scope note: the suite checks deterministic check isolation and metamorphic invariance. It deliberately does not claim that C1 can detect every unsupported free-text assertion or that C3 understands the meaning of counter-evidence prose.
