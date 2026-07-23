# Splunk attack_data sources

SafeSOC uses 33 raw log files from the public Splunk `attack_data` repository for
31 cases. `_splunk_ingest/` is a local staging cache containing copies of those
public files under the filenames expected by the case configurations. It is not
an original part of the SafeSOC benchmark, so the portable project retains a
retrieval-and-hash manifest rather than another copy of the upstream corpus.

## Upstream and licence

- Repository: `https://github.com/splunk/attack_data`
- Licence: Apache License 2.0
- Local licence copy: `data_sources/licenses/Splunk_attack_data_LICENSE.txt`
- Upstream distribution note: cloning some raw files may require Git LFS

SafeSOC itself does not use Git LFS: the local `_splunk_ingest/` cache is
gitignored and contains ordinary source files, not LFS pointers.

The SafeSOC repository retains curated event exports, neutral model packages,
case configuration, retrieval specifications, and provenance. It does not claim
authorship of the upstream raw captures.

## Recreate the optional cache

Retrieve the `upstream_repo_path` values listed in
`data_sources/attack_data_staged_manifest.json`. If the upstream repository is
cloned with Git, its large files may require Git LFS. Each case's
`queries/retrieval_spec.md` records the corresponding staging command and Splunk
query.

```bash
git lfs install --skip-smudge
git clone https://github.com/splunk/attack_data.git attack_data-master
cd attack_data-master
git lfs pull --include="<upstream_repo_path from the manifest>"
```

Set `SAFESOC_DATA` to the parent directory containing `attack_data-master/`, or place
hash-identical copies under the local `_splunk_ingest/` cache using each
`staged_filename` from the manifest.

```bash
cd /path/to/SafeSOC
mkdir -p _splunk_ingest
python3 tools/build_attack_data_manifest.py
python3 tools/verify_all_packages.py
```

`tools/normalize.py --verify-log` first resolves the upstream source path. If it
is unavailable, it accepts a staged file only when its SHA-256 matches the
case-level provenance. Normal model runs, A3/A4 evaluation, runtime validation,
and package rebuilding from `extracted/*.json` do not require this cache. The
cache is needed only for `--from-log`, `--verify-log`, and raw-source
completeness or absence audits.
