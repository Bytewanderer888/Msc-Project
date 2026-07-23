# AInception SL100 staging

This directory stages the public AInception SL100 corpus for candidate
selection in SafeSOC's external replication study.

- DOI: `10.5281/zenodo.17659656`
- License: CC BY 4.0
- Local retrieval date: 2026-07-22

The capture contains two normal drone missions followed by a six-step attack
chain, with endpoint, network, Linux, and drone telemetry. The ZIP is a local
staging cache and is not committed. The accompanying dataset PDF and
`SOURCE_MANIFEST.json` are retained.

## SafeSOC use constraints

SL100 is one continuous attack chain, not six independent corpora. SafeSOC caps
its contribution at two cases and records a shared `capture_cluster`. A case is
called multi-source only when the selected sensors observe the same host/action
and time window; merely placing unrelated logs in one package is prohibited.

Case extraction uses raw records from the archive. Pre-labelled files, attack
step names, timeline annotations, and framework identifiers are ground-truth
inputs only and are removed from model-visible packages. Known timestamp and
duplicate-key inconsistencies in the supplied timeline must be resolved against
raw event timestamps and documented at case level.
