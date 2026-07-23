#!/usr/bin/env python3
"""
check_cases.py — SafeSOC structural audit + manifest integrity check.

Three jobs, one command:

  1. STRUCTURE — every case directory has its full expected file set, corpus-aware:
       attack_data cases:  build/case.json · model_input/alert_package.json ·
                           annotations/selection_metadata.json · source/provenance.json ·
                           queries/retrieval_spec.md · extracted/*.json
                           annotations/ground_truth.json
       OTRF cases:         same MINUS queries/ + extracted/ (built direct from the OTRF JSON —
                           their absence is by design, not a defect).
     Ground truth is required on both splits after benchmark annotation freeze. OTRF cases
     must not retain Splunk-only queries/ or extracted/ artifacts.

  2. MANIFEST — verify every research asset against MANIFEST.json (sha256 + size), so
     "nothing changed since the freeze" is checkable, not asserted.
       MISSING  = in the manifest, gone from disk
       MODIFIED = on disk, hash differs          -> exit 1
       NEW      = on disk, not yet in the manifest (e.g. a fresh model run) -> exit 0 + hint

  3. LEAKAGE — no answer/environment token reaches a model-visible package, in plaintext OR inside any
     base64 blob (decoded UTF-16LE and UTF-8, every field): technique ids, framework names (Atomic/…), or
     un-anonymised host/domain (attackrange/dmevals). Any hit -> exit 1.

Usage (from anywhere):
    python3 tools/check_cases.py            # audit structure + verify against MANIFEST.json
    python3 tools/check_cases.py --write    # audit structure + (re)write MANIFEST.json as the new baseline

Covered: tier1/ tier2/ (dataset) · rubric/ tools/schema/ (spec) · eval/ tools/ code+prompt (harness) ·
eval/outputs/ (model outputs) · experiments/ (controlled variants) · README/SELECTION_RATIONALE (docs).
Excluded: optional raw-source staging caches, invalidated historical runs, Git internals, __pycache__,
.pytest_cache, .DS_Store, MANIFEST.json itself, and regenerable presentation artifacts. The excluded
raw-source paths and hashes remain pinned in their source manifests.
"""
import argparse, base64, datetime, glob, hashlib, json, os, re, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))   # tools/ -> project root
MANIFEST = os.path.join(ROOT, "MANIFEST.json")

EXCLUDE_DIRS = {"__pycache__", ".pytest_cache", ".git", "_splunk_ingest"}
EXCLUDE_NAMES = {".DS_Store", "MANIFEST.json"}
EXCLUDE_TOP = {"safesoc_briefing.html", "SafeSOC_Progress_Report.docx"}   # regenerated deliverables
EXCLUDE_RELS = {
    "data_sources/windows_apt_2025/combined.csv",
    "data_sources/ainception_sl100/SL100.zip",
    "data_sources/ait_ads/ait_ads.zip",
    "data_sources/cam_lds/manifestations_raw.zip",
}

# Answer / environment tokens that must never reach a model-visible package — in plaintext OR hidden inside
# a base64 -EncodedCommand (decoded UTF-16LE). Automates the manual leak audit: Atomic harness in an encoded
# parent command, technique ids, framework names, un-anonymised host/domain from a stale build.
LEAK_RX = re.compile(r"(atomic|at0micstrong|redcanary|purplesharp|allthethings|invoke-atomic|red[ _-]?team"
                     r"|T\d{4}(?:\.\d{3})?|attack[-_ ]?range|dmevals|scranton|mordor"
                     # un-anonymised corpus host prefixes — incl. NetBIOS machine-account forms
                     # (e.g. WIN-HOST-MHAAG-$) that the DNS-name host-anon map used to miss (2026-07-14)
                     r"|win-host-|win-dc-|ec2amaz|ar-win-)", re.I)


# ---------------- structure audit ----------------

def audit_structure():
    """Return (problems, counts). problems = [(case_path, [missing...])]."""
    problems, cases = [], []
    counts = {"by_split_cond": {}, "corpus": {"attack_data": 0, "OTRF": 0},
              "heldout_gt_present": 0, "heldout_total": 0}
    for tier in ("tier1", "tier2"):
        tdir = os.path.join(ROOT, tier)
        if not os.path.isdir(tdir):
            continue
        for cond in sorted(os.listdir(tdir)):
            for split in ("dev", "heldout"):
                sp = os.path.join(tdir, cond, split)
                if not os.path.isdir(sp):
                    continue
                for case in sorted(os.listdir(sp)):
                    d = os.path.join(sp, case)
                    if os.path.isdir(d):
                        cases.append((tier, cond, split, case, d))

    def has(d, *p):
        return os.path.exists(os.path.join(d, *p))

    for tier, cond, split, case, d in cases:
        cj = has(d, "build", "case.json")
        otrf = False
        if cj:
            try:
                otrf = "mordor_log" in json.load(open(os.path.join(d, "build", "case.json")))
            except Exception:
                otrf = None
        counts["corpus"]["OTRF" if otrf else "attack_data"] += 1
        counts["by_split_cond"][f"{split}/{cond}"] = counts["by_split_cond"].get(f"{split}/{cond}", 0) + 1
        exp = {"build/case.json": cj,
               "model_input/alert_package.json": has(d, "model_input", "alert_package.json"),
               "annotations/selection_metadata.json": has(d, "annotations", "selection_metadata.json"),
               "source/provenance.json": has(d, "source", "provenance.json")}
        gt = has(d, "annotations", "ground_truth.json")
        exp["annotations/ground_truth.json"] = gt
        if split == "heldout":
            counts["heldout_total"] += 1
            if gt:
                counts["heldout_gt_present"] += 1
        unexpected = []
        if cj and otrf is False:                      # Splunk-authoritative case
            exp["queries/retrieval_spec.md"] = has(d, "queries", "retrieval_spec.md")
            exp["extracted/*.json"] = bool(glob.glob(os.path.join(d, "extracted", "*.json")))
        elif cj and otrf is True:
            if has(d, "queries"):
                unexpected.append("UNEXPECTED queries/ (OTRF cases build directly from retained JSON)")
            if has(d, "extracted"):
                unexpected.append("UNEXPECTED extracted/ (OTRF cases build directly from retained JSON)")
        issues = [f"MISSING {key}" for key, present in exp.items() if not present] + unexpected
        if issues:
            problems.append((os.path.relpath(d, ROOT), issues))
    counts["total_cases"] = len(cases)
    return problems, counts


# ---------------- manifest ----------------

def category(rel):
    if rel.startswith("archive/"):
        return "archive"
    if rel.startswith("experiments/"):
        return "experiments"
    if rel.startswith(("tier1/", "tier2/")):
        return "dataset"
    if rel.startswith("rubric/") or rel.startswith("tools/schema/"):
        return "spec"
    if rel.startswith("eval/outputs/"):
        return "outputs"
    if rel.startswith(("eval/", "tools/")):
        return "harness"
    return "docs"


def walk_files():
    out = []
    for dirpath, dirnames, filenames in os.walk(ROOT):
        dirnames[:] = [x for x in dirnames if x not in EXCLUDE_DIRS]
        for fn in sorted(filenames):
            if fn in EXCLUDE_NAMES or fn.endswith(".pyc") or fn.startswith((".~", "~$")):
                continue
            rel = os.path.relpath(os.path.join(dirpath, fn), ROOT).replace(os.sep, "/")
            if rel in EXCLUDE_TOP or rel in EXCLUDE_RELS or rel.startswith("archive/invalidated_outputs/"):
                continue
            out.append(rel)
    return sorted(out)


def sha256(path, chunk=8 * 1024 * 1024):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for blk in iter(lambda: f.read(chunk), b""):
            h.update(blk)
    return h.hexdigest()


def write_manifest(counts):
    files = {}
    for rel in walk_files():
        p = os.path.join(ROOT, rel)
        files[rel] = {"sha256": sha256(p), "bytes": os.path.getsize(p), "category": category(rel)}
    man = {"project": "SafeSOC",
           "generated_utc": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
           "rubric_version": "1.1",
           "structure": {"total_cases": counts["total_cases"], "corpus": counts["corpus"],
                         "by_split_cond": counts["by_split_cond"],
                         "heldout_gt_present": counts["heldout_gt_present"]},
           "files": files}
    with open(MANIFEST, "w") as f:
        json.dump(man, f, indent=1, sort_keys=True)
    return man


def verify_manifest():
    """Return (man, missing, modified, new) or (None, ...) if no manifest exists."""
    if not os.path.exists(MANIFEST):
        return None, [], [], []
    man = json.load(open(MANIFEST))
    disk = walk_files()
    disk_set, man_files = set(disk), man["files"]
    missing = sorted(set(man_files) - disk_set)
    new = sorted(disk_set - set(man_files))
    modified = []
    for rel in sorted(disk_set & set(man_files)):
        p = os.path.join(ROOT, rel)
        ent = man_files[rel]
        if os.path.getsize(p) != ent["bytes"] or sha256(p) != ent["sha256"]:
            modified.append(rel)
    return man, missing, modified, new


# ---------------- leakage ----------------

def _strings(o):
    if isinstance(o, str):
        yield o
    elif isinstance(o, list):
        for x in o:
            yield from _strings(x)
    elif isinstance(o, dict):
        for v in o.values():
            yield from _strings(v)


def leak_scan():
    """Every model-visible package, scanned for answer/environment tokens in plaintext AND inside base64
    blobs (decoded both UTF-16LE, the -EncodedCommand form, and UTF-8). Every string field is checked, not
    just those after a -enc prefix. Returns [(case_id, plaintext_hits, decoded_hits)]."""
    hits = []
    for f in sorted(glob.glob(os.path.join(ROOT, "tier*", "*", "*", "*", "model_input", "alert_package.json"))):
        pkg = json.load(open(f))
        cid = pkg.get("case_id", os.path.relpath(f, ROOT))
        plain = sorted({m.group(0) for m in LEAK_RX.finditer(open(f, encoding="utf-8").read())}, key=str.lower)
        dec = set()
        for s in _strings(pkg):
            for b in re.findall(r"[A-Za-z0-9+/]{24,}={0,2}", s):
                raw = None
                for pad in ("", "=", "=="):
                    try:
                        raw = base64.b64decode(b + pad)
                        break
                    except Exception:
                        continue
                if raw is None:
                    continue
                for enc in ("utf-16le", "utf-8"):   # -EncodedCommand is UTF-16LE; UTF-8 catches other blobs
                    dec |= {m.group(0) for m in LEAK_RX.finditer(raw.decode(enc, "ignore"))}
        if plain or dec:
            hits.append((cid, plain, sorted(dec, key=str.lower)))
    return hits


# ---------------- main ----------------

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--write", action="store_true", help="(re)write MANIFEST.json as the new baseline")
    a = ap.parse_args()

    problems, counts = audit_structure()
    dev_n = sum(v for k, v in counts["by_split_cond"].items() if k.startswith("dev/"))
    held_n = sum(v for k, v in counts["by_split_cond"].items() if k.startswith("heldout/"))
    print("=== SafeSOC integrity check ===")
    print(f"structure : {counts['total_cases']} cases (dev {dev_n} / held-out {held_n}) · "
          f"attack_data {counts['corpus']['attack_data']} / OTRF {counts['corpus']['OTRF']} · "
          f"held-out ground truths present: {counts['heldout_gt_present']}/{counts['heldout_total']}")
    if problems:
        print(f"  ✗ {len(problems)} case(s) with missing files:")
        for path, miss in problems:
            print(f"    {path}")
            for issue in miss:
                print(f"        {issue}")
    else:
        print("  ✓ every case has its full expected file set")

    leaks = leak_scan()
    if leaks:
        print(f"  ✗ ANSWER/ENV LEAKAGE in {len(leaks)} package(s) — the model can see the answer:")
        for cid, ph, dh in leaks:
            print(f"      {cid}: plaintext={ph or '-'}  base64-decoded={dh or '-'}")
    else:
        print("  ✓ no answer/environment leakage (plaintext or base64-decoded)")

    if a.write:
        man = write_manifest(counts)
        bycat = {}
        for e in man["files"].values():
            bycat[e["category"]] = bycat.get(e["category"], 0) + 1
        print(f"manifest  : WROTE {os.path.basename(MANIFEST)} · {len(man['files'])} files · "
              + " · ".join(f"{k} {v}" for k, v in sorted(bycat.items())))
        print("  this is now the integrity baseline; re-run without --write to verify against it")
        sys.exit(1 if (problems or leaks) else 0)

    man, missing, modified, new = verify_manifest()
    if man is None:
        print("manifest  : MANIFEST.json not found — create the baseline with:  python3 tools/check_cases.py --write")
        sys.exit(1 if problems else 0)
    bycat = {}
    for e in man["files"].values():
        bycat[e["category"]] = bycat.get(e["category"], 0) + 1
    print(f"manifest  : {os.path.basename(MANIFEST)} · generated {man['generated_utc']} · "
          f"rubric v{man['rubric_version']} · {len(man['files'])} files "
          f"({' · '.join(f'{k} {v}' for k, v in sorted(bycat.items()))})")
    for label, items in (("MISSING", missing), ("MODIFIED", modified)):
        if items:
            print(f"  ✗ {label} ({len(items)}):")
            for r in items:
                print(f"      {r}")
    if new:
        print(f"  · NEW, not in manifest ({len(new)}) — expected after a fresh model run / annotation; "
              f"refresh with --write:")
        for r in new:
            print(f"      {r}")
    if not (missing or modified or new):
        print("  ✓ all files match the manifest — nothing changed since the baseline")
    sys.exit(1 if (problems or leaks or missing or modified) else 0)


if __name__ == "__main__":
    main()
