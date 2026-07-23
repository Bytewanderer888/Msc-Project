# Development-set raw-source audit - 2026-07-16

## Scope and method

All 21 development cases were checked against their retained raw source, not only
against the delivered `alert_package.json`. For each case the review checked the
alert proposition, same-host/sensor/time boundary, causal lineage, selected and
excluded events, ground-truth claims, evidence-id mapping, and condition-level
verdict/severity/action policy. Model outputs were not used to choose or revise a
condition label.

Each `build/case.json` now records a researcher-only `metadata.security_proposition`.
This makes the proposition-selection rule in the v1.1 annotation guideline
case-auditable and prevents an annotator from silently narrowing or widening the
question to obtain a preferred condition. The field is copied only to
`selection_metadata.json`; it is not included in `alert_package.json`.

The audit keeps the development distribution unchanged:

| Condition | Cases |
|---|---:|
| Strong | 6 |
| Weak | 7 |
| Missing | 5 |
| Counter | 3 |
| Total | 21 |

## Case outcomes

| Case | Condition | Audit outcome | Model input |
|---|---|---|---|
| INJ-001 | strong | Retained; bounded the claim to observed unbacked remote-thread injection, not a named shellcode family | unchanged |
| LS-001 | strong | Retained; EID10 supports offensive LSASS access but not dump-file creation or recovered credentials | unchanged |
| RTLO-001 | strong | Retained; repaired the misdecoded U+202E marker and removed an unsupported delivery claim | changed |
| UAC-001 | strong | Retained; added the high-integrity PowerShell child and later registry-key cleanup | changed |
| WMI-002 | strong | Retained; added the binding modification immediately following the filter modification | changed |
| AMQ-001 | strong | Retained; added Security and Sysmon events linking the payload to its child shell; stopped treating port 4444 alone as proof of a reverse shell; describes fusion as complementary corroboration rather than claiming both sensors are individually insufficient | changed |
| BF-001 | weak | Retained; GT now references all 23 package events, including EV-022 | unchanged |
| CERT-001 | weak | Retained; raw review found no matching PFX file creation/use or confirmed egress in the case scope | unchanged |
| FW-001 | weak | Retained; added same-rule deletion and matching registry deletion about five seconds later | changed |
| LS-002 | weak | Retained; createdump invocation is present, but target identity and successful dump creation remain unconfirmed | unchanged |
| PS-001 | weak | Retained; present encoded execution is semantically ambiguous, not a clean precursor-only missing case | unchanged |
| PS-002 | weak | Retained; absence is now limited to A0's ProcessGuid and downloaded path; a later different variant is explicitly excluded | unchanged |
| ST-003 | weak | Retained; vendor paths/authors are suggestive but no package-visible signature verification exists | unchanged |
| ACCT-001 | missing | Retained; account-management commands are observed, while surviving account state/use is not established | unchanged |
| ING-001 | missing | Retained; setup is observed but execution/load is absent within the short retained source window | unchanged |
| LGN-002 | missing | Retained; no post-write userinit/art.bat ProcessCreate exists in the sensor-observable retained window | unchanged |
| RK-001 | missing | Retained; complete set/delete lifecycle is present and configured-target execution remains absent | unchanged in this audit |
| ST-002 | missing | Retained; no Sysmon-observable task action firing exists; Security 4698 is not used as a Sysmon-only requirement | unchanged |
| DISC-002 | counter | Retained for the exact SSM-parent inventory lineage; separate cmd-parent WMI events do not make the host globally benign | unchanged |
| RDL-001 | counter | Retained; System32 WebDAV path, WebClient parent, DavSetCookie, and Microsoft destination are decisive without claiming signature verification | unchanged |
| SMB-002 | counter | Retained; machine-account SYSVOL/LSARPC activity is routine domain-controller context; later repetitions are redundant | unchanged |

## Changed package boundary

Only five of the 21 model-visible packages changed in this audit:

| Case | Old SHA-256 | New SHA-256 |
|---|---|---|
| WMI-002 | `3f3457eef6231904b8c4182cf5ed68d496f72beaaf00f2a296ce5105088ce1f4` | `9b84d8512153ee9fc3e51e749348e625e16dc8cce3e73d9d43cb9c21496dac50` |
| UAC-001 | `9e032d9d4e08ff144632e81df14a576de1705e0097daeca57aeeb2b6971a4453` | `90473111ce73afdcc17e05ac3a024b623490a6f8e7452b001c93ba9d371e1ba6` |
| AMQ-001 | `06b89956f3a31f5fc3460a11474333c53bc09e738da07ef2e92c734acf0925b7` | `aa5cebd43ef584bb539d5704439e209b0e09c9f93e812c5f9eed344e52aff5b0` |
| FW-001 | `5cd433ee0f12a5aa2bff74dc6e1dda30fd099200b5a22b59d3797cffc6324453` | `9c7e10d9e4116ad57d8a27030194248ff502afe24cea540849df65e480341566` |
| RTLO-001 | `05bbcffecc245c95112e5f0eb9139b1cc5544c213c2cebba665495d874b38ad2` | `1a1abb88fc82f6b483e8e8971f32214a051a8923640fa362a4237b7090b3addc` |

The other 16 package hashes remained unchanged. GT-only wording and evidence-id
corrections do not require new model calls, but their offline scores must be
regenerated from valid outputs.

## Output invalidation

Forty-seven historical outputs for the five changed packages were invalidated
by this audit. After their replacements passed the final run-matrix and
continuity checks, the invalidated copies were omitted from the public release.
The authoritative retained outputs are under `eval/outputs/`; their completeness
is recorded in `eval/reports/run_matrix_current.json`.

## Verification record

- `tools/audit_split_ground_truth.py --split dev`: 21/21 passed, including fixed-proposition presence and preservation.
- Unit tests: 23/23 passed.
- `tools/verify_all_packages.py`: 41/41 byte-identical raw-source rebuilds passed.
- `tools/check_cases.py`: 41/41 case structures present; no plaintext or base64-decoded answer/environment leakage.
- `MANIFEST.json` was deliberately not refreshed because the five replacement output sets are not complete.

Machine-readable records:

- `eval/reports/dev_ground_truth_audit_2026-07-16.json`
- `eval/reports/package_rebuild_verification.json`
