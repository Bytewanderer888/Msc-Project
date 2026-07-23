# Selected OTRF Raw Sources

This directory preserves only the six OTRF Security-Datasets ZIP files used by the ten
OTRF-derived SafeSOC cases. Files retain their original repository-relative paths under
`datasets/` so each `build/case.json:mordor_log` can be resolved against this directory.

`MANIFEST.json` records source paths, SHA-256 hashes, sizes, and consuming case IDs. The
snapshot is 57,464,829 bytes (about 54.8 MiB); it avoids depending on a mutable Downloads
folder or bundling the entire upstream collection.

For the compound APT29 files, `day1/` and `day2/` are the upstream evaluation-scenario
names, not SafeSOC split or experiment-round labels. See
`datasets/compound/apt29/README.md` for the case mapping.
