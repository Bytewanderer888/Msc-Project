#!/usr/bin/env python3
"""
run_model.py — run the SafeSOC SOC-triage prompt over the dataset on any of several LLMs,
so the same ground-truth-backed offline evaluator can score outputs across models, not just one.

Providers:
  gemini     — Google Gemini via REST (requests). Newer keys use the x-goog-api-key HEADER.
               Thinking defaults to OFF (thinkingConfig.thinkingBudget=0): reproducible, the whole token
               budget goes to the JSON answer, and the mode matches the no-thinking Claude config.
  anthropic  — Anthropic Claude via REST (requests). No SDK — one transport for both providers.
               Two modes:
                 real-time : one POST /v1/messages per case (default).
                 --batch   : POST /v1/messages/batches — ALL cases in one async batch at 50% price.
                             Best for the offline eval (independent requests, latency irrelevant).

Cost notes (Anthropic):
  * --batch        -> 50% off. The main lever. ~$0.25 for a full dev run on Sonnet 4.6, ~$0.08 on Haiku 4.5.
  * model choice   -> Haiku 4.5 ($1/$5) is 3x cheaper than Sonnet 4.6 ($3/$15); set ANTHROPIC_MODEL.
  * NO prompt cache: the model only sees the ~600-token system prompt + the per-case package. The rubric
                     and output schema are NOT sent to the model (rubric -> validator; schema -> client-side
                     jsonschema), and ~600 tokens is below Sonnet 4.6's 2048-token cache minimum, so there is
                     no static block worth caching. (If a big shared prompt is ever added, cache it then.)
  * --skip-existing-> never re-spends on a case that already has an output (resume after errors/partial runs).

Quota-aware batching for the Gemini free tier (e.g. 20 requests/day vs 21 dev cases):
  python3 eval/run_model.py --provider gemini --model gemini-2.5-flash --split dev --skip-existing --limit 15
  # another day, same line finishes the rest; the validator names whatever is still missing.

Setup:
    pip install requests jsonschema
    export GEMINI_API_KEY="..."      ;  export GEMINI_MODEL="gemini-2.5-flash"
    export ANTHROPIC_API_KEY="..."   ;  export ANTHROPIC_MODEL="claude-sonnet-4-6"   # or claude-haiku-4-5

Run (from the SafeSOC/ project root):
    python3 eval/run_model.py --provider gemini    --split dev
    python3 eval/run_model.py --provider anthropic --split dev --batch --skip-existing
    python3 eval/validator_v1_1.py --model <model_tag> --split dev

Writes one schema-validated reply per case to  eval/outputs/<model_tag>/<split>/<CASE_ID>.json.

For an isolated input-sensitivity experiment, pass both --package-dir and --experiment-tag. The
custom packages are read from that directory and outputs receive a separate __EXP_<tag> suffix,
so canonical packages and outputs cannot be overwritten accidentally.
"""
import os, re, json, time, argparse, sys, hashlib, platform, uuid, subprocess
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
# Prompt arms (ablation ladder): "evidence" = A2, the evidence-aware prompt (primary config);
# "basic" = A1, its minimal pair WITHOUT the analyst-discipline block. Same output contract.
PROMPTS = {"evidence": "gemini_triage_prompt.md", "basic": "triage_prompt_basic.md"}
ARM_SUFFIX = {"evidence": "__A2_evidence_prompt", "basic": "__A1_basic_prompt"}  # per-arm output-dir tag

def load_prompt(arm):
    return HERE.joinpath(PROMPTS[arm]).read_text(encoding="utf-8").split("---", 1)[1].strip()

OUT_SCHEMA = json.loads(HERE.joinpath("llm_output.schema.json").read_text())

# Anthropic models that REMOVED sampling params (sending temperature -> HTTP 400).
ANTHROPIC_NO_TEMP = ("opus-4-7", "opus-4-8", "sonnet-5", "fable-5")
GEN_MAX_TOKENS = 2048                 # default output-token ceiling (the triage JSON is ~300 tokens)
RETRY_STATUS = (429, 500, 502, 503, 529)


class ModelNotFound(RuntimeError):
    """A 404 model-name error — identical for every case, so the run stops instead of retrying each."""
ANTHROPIC_API = "https://api.anthropic.com/v1"


def utc_now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sha256_text(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def display_path(path):
    path = Path(path).resolve()
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)


def enforce_gemini_dev_freeze(split, package_dir, model, temperature, max_tokens, thinking, force=False):
    """Fail before an API call if a canonical Gemini dev run drifts from the frozen request."""
    if split != "dev" or package_dir is not None:
        return
    expected = {
        "model": "gemini-2.5-flash",
        "temperature": 0.0,
        "max_tokens": GEN_MAX_TOKENS,
        "thinking": "off",
    }
    actual = {
        "model": model,
        "temperature": temperature,
        "max_tokens": max_tokens,
        "thinking": thinking,
    }
    problems = [
        f"{key}: expected {expected[key]!r}, got {actual[key]!r}"
        for key in expected
        if actual[key] != expected[key]
    ]
    check = subprocess.run(
        [sys.executable, str(ROOT / "tools/freeze_model_inputs.py")],
        cwd=ROOT,
        text=True,
        capture_output=True,
    )
    if check.returncode != 0:
        problems.append((check.stdout + check.stderr).strip() or "dev model-input freeze check failed")
    if not problems:
        print("  freeze gate: PASS (canonical Gemini dev inputs/config unchanged)")
        return
    detail = "\n  - ".join(problems)
    if force:
        print(f"  WARNING: bypassing Gemini dev freeze gate:\n  - {detail}", file=sys.stderr)
        return
    sys.exit(
        "refusing canonical Gemini dev call: the frozen model-input contract changed:\n"
        f"  - {detail}\n"
        "Review the drift first. Use --force only for a deliberate, documented replacement experiment."
    )


def packages(split, package_dir=None):
    # cases live at tier*/<evidence>/<split>/<case>/model_input/alert_package.json
    if package_dir is not None:
        for pk in sorted(Path(package_dir).glob("*.json")):
            yield pk.stem, pk
        return
    for pk in sorted(ROOT.glob(f"tier*/*/{split}/*/model_input/alert_package.json")):
        yield pk.parents[1].name, pk           # (case_dir_name, path)


def load_external_freeze(path, package_dir):
    """Validate a frozen external case set without weakening canonical ID guards."""
    manifest_path = Path(path).expanduser()
    if not manifest_path.is_absolute():
        manifest_path = ROOT / manifest_path
    manifest_path = manifest_path.resolve()
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        sys.exit(f"cannot read external freeze manifest {manifest_path}: {exc}")
    if manifest.get("status") != "frozen_pre_model":
        sys.exit("external freeze manifest is not in frozen_pre_model status")
    rows = manifest.get("cases") or []
    if manifest.get("case_count") != len(rows) or not rows:
        sys.exit("external freeze manifest has an invalid case count")

    expected = {}
    for row in rows:
        case_id = row.get("case_id")
        frozen_path = (ROOT / row.get("frozen_input_path", "")).resolve()
        if not case_id or frozen_path.parent != package_dir:
            sys.exit(f"external freeze path mismatch for case {case_id!r}")
        if not frozen_path.is_file() or sha256_file(frozen_path) != row.get("package_sha256"):
            sys.exit(f"external frozen input is absent or changed: {case_id}")
        expected[case_id] = row["package_sha256"]
    if len(expected) != len(rows):
        sys.exit("external freeze manifest contains duplicate case ids")
    return manifest_path, manifest, expected


def output_model_tag(model, prompt, round_number=None, experiment_tag=None):
    tag = re.sub(r"[^A-Za-z0-9._-]", "-", model) + ARM_SUFFIX.get(prompt, f"__{prompt}")
    if round_number and round_number > 1:
        tag += f"_round{round_number}"
    if experiment_tag:
        tag += f"__EXP_{experiment_tag}"
    return tag


def extract_json(text):
    text = text.strip()
    text = re.sub(r"^```(?:json)?", "", text).strip()
    text = re.sub(r"```$", "", text).strip()
    s, e = text.find("{"), text.rfind("}")
    return json.loads(text[s:e + 1] if (s != -1 and e > s) else text)


def _req(method, url, headers, timeout, payload=None, tries=6):
    """HTTP request with exponential backoff on 429 / 5xx (honours a numeric Retry-After header)."""
    import requests
    r = None
    for i in range(tries):
        r = requests.request(method, url, headers=headers, json=payload, timeout=timeout)
        if r.status_code in RETRY_STATUS and i < tries - 1:
            ra = (r.headers.get("retry-after") or "").strip()
            wait = float(ra) if ra.replace(".", "", 1).isdigit() else min(2.0 * (2 ** i), 60.0)
            print(f"    [{r.status_code}] backing off {wait:.0f}s ({i + 1}/{tries})", file=sys.stderr)
            time.sleep(wait)
            continue
        return r
    return r


def _anthropic_params(system, pkg, model, temperature, max_tokens):
    p = {"model": model, "max_tokens": max_tokens, "system": system,
         "messages": [{"role": "user", "content": "Alert package:\n```json\n" + pkg + "\n```"}]}
    if not any(t in model for t in ANTHROPIC_NO_TEMP):
        p["temperature"] = temperature         # temp accepted on e.g. sonnet-4-6 / haiku-4-5
    return p


# ---- real-time callers: (system, alert_package_text) -> raw reply text ----

def _gemini_models(api_key, ver="v1beta"):
    """Model names this key may use with generateContent (for a helpful 404 message). [] on any failure."""
    try:
        r = _req("GET", f"https://generativelanguage.googleapis.com/{ver}/models",
                 {"x-goog-api-key": api_key, "Content-Type": "application/json"}, 30)
        r.raise_for_status()
        return sorted(m["name"].replace("models/", "") for m in r.json().get("models", [])
                      if "generateContent" in m.get("supportedGenerationMethods", []))
    except Exception:
        return []


def call_gemini(system, pkg, model, api_key, temperature, max_tokens, thinking, timeout=300):
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
    prompt = system + "\n\n---\n\nAlert package:\n```json\n" + pkg + "\n```"
    gen = {"temperature": temperature, "responseMimeType": "application/json", "maxOutputTokens": max_tokens}
    if thinking == "off":                 # thinkingBudget=0: whole budget to the JSON answer (no truncation)
        gen["thinkingConfig"] = {"thinkingBudget": 0}
    elif thinking == "dynamic":           # model decides depth (may truncate the JSON — raise --max-tokens)
        gen["thinkingConfig"] = {"thinkingBudget": -1}
    # thinking == "omit": send no thinkingConfig at all (model default)
    r = _req("POST", url, {"x-goog-api-key": api_key, "Content-Type": "application/json"}, timeout,
             {"contents": [{"parts": [{"text": prompt}]}], "generationConfig": gen})
    if r.status_code == 404:
        try:
            detail = (r.json().get("error", {}).get("message") or "").strip()[:400]
        except Exception:
            detail = r.text[:400]
        avail = _gemini_models(api_key)
        hint = ("\n  models this key CAN use (generateContent):\n    " + "\n    ".join(avail)) if avail \
               else "\n  (could not list models — check GEMINI_API_KEY and that the Generative Language API is enabled)"
        raise ModelNotFound(f"Gemini model '{model}' not found (HTTP 404).\n  API said: {detail or '(no body)'}\n"
                            f"  Set --model NAME or export GEMINI_MODEL to a working one.{hint}")
    r.raise_for_status()
    d = r.json()
    um = d.get("usageMetadata", {})
    usage = {"input_tokens": um.get("promptTokenCount", 0),
             "output_tokens": um.get("candidatesTokenCount", 0) + um.get("thoughtsTokenCount", 0)}
    try:
        candidate = d["candidates"][0]
        meta = {
            "provider_response_id": d.get("responseId"),
            "provider_model_version": d.get("modelVersion"),
            "finish_reason": candidate.get("finishReason"),
        }
        return candidate["content"]["parts"][0]["text"], usage, meta
    except (KeyError, IndexError):
        raise RuntimeError("Gemini returned no usable candidate. Raw: " + json.dumps(d)[:600])


def call_anthropic(system, pkg, model, api_key, temperature, max_tokens, timeout=300):
    r = _req("POST", f"{ANTHROPIC_API}/messages",
             {"x-api-key": api_key, "anthropic-version": "2023-06-01", "content-type": "application/json"},
             timeout, _anthropic_params(system, pkg, model, temperature, max_tokens))
    if not r.ok:                                # surface the API error body (bad model, temp on a no-temp model, ...)
        raise RuntimeError(f"Anthropic HTTP {r.status_code}: {r.text[:400]}")
    d = r.json()
    text = "".join(b.get("text", "") for b in d.get("content", []) if b.get("type") == "text")
    if not text:                                # e.g. stop_reason == "refusal" returns HTTP 200 with no text
        raise RuntimeError(f"Anthropic returned no text (stop_reason={d.get('stop_reason')}). Raw: {json.dumps(d)[:400]}")
    u = d.get("usage", {})
    usage = {"input_tokens": u.get("input_tokens", 0), "output_tokens": u.get("output_tokens", 0)}
    meta = {
        "provider_response_id": d.get("id"),
        "provider_model_version": d.get("model"),
        "finish_reason": d.get("stop_reason"),
    }
    return text, usage, meta


def parse_and_write(text, outpath, tag):
    """Shared success path: extract JSON, schema-validate, write, and pretty-print one line."""
    import jsonschema
    out = extract_json(text)
    jsonschema.validate(out, OUT_SCHEMA)
    outpath.write_text(json.dumps(out, indent=2))
    print(f"  {tag:9s} -> {out['verdict']:10s}/{out['severity']:13s} act={out['recommended_action']}")


def usage_log(outdir, split):
    """Append-only per-call usage log (JSONL) — one record per API result, written OUTSIDE the <split>/ dir so
    the validator's *.json glob never sees it. Appending per result (not bulk at the end) keeps the accounting
    for already-completed cases even if the run is interrupted mid-way — which the Gemini free tier does often.
    cost.py dedups by case (last line wins), so re-runs are handled."""
    return outdir.parent / f"usage_{split}.jsonl"


def run_event_log(outdir, split):
    """Append-only experiment provenance, separate from the model-output JSON directory."""
    return outdir.parent / f"run_events_{split}.jsonl"


def append_usage(path, case, u, model, billing_mode, completed_utc=None, invocation_id=None):
    """Append one usage record the instant a result is parsed. billing_mode ('realtime' | 'batch') is recorded
    at the source of truth, so cost.py prices each call by how it was ACTUALLY billed — never a guessed flag."""
    rec = {"case": case, "input_tokens": u.get("input_tokens", 0), "output_tokens": u.get("output_tokens", 0),
           "model": model, "billing_mode": billing_mode}
    if completed_utc:
        rec["completed_utc"] = completed_utc
    if invocation_id:
        rec["invocation_id"] = invocation_id
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(rec) + "\n")


def append_run_event(path, context, case, package_info, status, *, outpath=None, usage=None,
                     provider_meta=None, elapsed_seconds=None, error=None):
    """Persist enough API-time provenance to bind one output to its exact experimental inputs."""
    rec = dict(context)
    rec.update({
        "completed_utc": utc_now(),
        "case": case,
        "status": status,
        "package_path": package_info["path"],
        "package_sha256": package_info["sha256"],
    })
    if outpath is not None:
        rec["output_path"] = display_path(outpath)
        if Path(outpath).exists():
            rec["output_sha256"] = sha256_file(outpath)
    if usage:
        rec["input_tokens"] = usage.get("input_tokens", 0)
        rec["output_tokens"] = usage.get("output_tokens", 0)
    if provider_meta:
        rec.update({k: v for k, v in provider_meta.items() if v is not None})
    if elapsed_seconds is not None:
        rec["elapsed_seconds"] = round(elapsed_seconds, 3)
    if error:
        rec["error"] = error
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(rec, sort_keys=True) + "\n")


def run_anthropic_batch(work, system, model, api_key, temperature, max_tokens, poll_s=10, max_min=30):
    """Submit every case as ONE Message Batch (50% price, async). work = [(tag, outpath, pkg), ...]."""
    hdr = {"x-api-key": api_key, "anthropic-version": "2023-06-01", "content-type": "application/json"}
    reqs = [{"custom_id": tag, "params": _anthropic_params(system, pkg, model, temperature, max_tokens)}
            for tag, _op, pkg in work]
    outmap = {tag: op for tag, op, _pkg in work}
    r = _req("POST", f"{ANTHROPIC_API}/messages/batches", hdr, 300, {"requests": reqs})
    if not r.ok:
        raise RuntimeError(f"batch create HTTP {r.status_code}: {r.text[:500]}")
    bid = r.json()["id"]
    print(f"  batch {bid}: submitted {len(reqs)} requests at 50% price; polling every {poll_s}s ...")
    b = None
    for _ in range(int(max_min * 60 / poll_s)):
        time.sleep(poll_s)
        b = _req("GET", f"{ANTHROPIC_API}/messages/batches/{bid}", hdr, 60).json()
        print(f"    {b.get('processing_status')}  {b.get('request_counts', {})}", file=sys.stderr)
        if b.get("processing_status") == "ended":
            break
    else:
        raise RuntimeError(f"batch {bid} still processing after ~{max_min} min; fetch its results_url later")
    rr = _req("GET", b["results_url"], hdr, 300)
    rr.raise_for_status()
    ok, errs, usage = 0, [], {}
    for line in rr.text.splitlines():
        if not line.strip():
            continue
        res = json.loads(line)
        cid, rtype = res["custom_id"], res["result"]["type"]
        if rtype != "succeeded":
            errs.append((cid, rtype, res["result"].get("error")))
            continue
        msg = res["result"]["message"]
        text = "".join(x.get("text", "") for x in msg.get("content", []) if x.get("type") == "text")
        try:
            parse_and_write(text, outmap[cid], cid)
            u = msg.get("usage", {})
            usage[cid] = {
                "input_tokens": u.get("input_tokens", 0),
                "output_tokens": u.get("output_tokens", 0),
                "provider_response_id": msg.get("id"),
                "provider_model_version": msg.get("model"),
                "finish_reason": msg.get("stop_reason"),
                "batch_id": bid,
            }
            ok += 1
        except Exception as e:
            errs.append((cid, "parse", str(e)))
    for cid, kind, detail in errs:
        print(f"  ERROR {cid}: {kind}: {str(detail)[:160]}", file=sys.stderr)
    return ok, len(reqs), usage


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--provider", required=True, choices=["gemini", "anthropic"])
    ap.add_argument("--split", default="dev", choices=["dev", "heldout"])
    ap.add_argument("--model", default=None, help="model id (else the provider env default)")
    ap.add_argument("--temperature", type=float, default=0.0)
    ap.add_argument("--max-tokens", type=int, default=None, help=f"output-token ceiling (default {GEN_MAX_TOKENS})")
    ap.add_argument("--limit", type=int, default=None, help="process at most N cases this run (daily-quota control)")
    ap.add_argument("--skip-existing", action="store_true",
                    help="skip cases that already have an output file (resume without re-spending)")
    ap.add_argument("--only", default=None,
                    help="comma-separated case_ids to run, e.g. --only WMI-002,ACCT-001 — a targeted re-run "
                         "that processes ONLY these and skips everything else (independent of --skip-existing)")
    ap.add_argument("--round", type=int, default=None,
                    help="repeat-run index for stability checks: round >= 2 writes to <model>_round<N>/ so "
                         "earlier rounds are kept side-by-side (round 1 = the plain <model>/ dir)")
    ap.add_argument("--batch", action="store_true",
                    help="Anthropic only: submit all cases via the Batch API (50%% cheaper, async)")
    ap.add_argument("--sleep", type=float, default=None,
                    help="seconds between real-time requests (default: 6 for gemini free tier, 0.5 for anthropic)")
    ap.add_argument("--gemini-thinking", choices=["off", "dynamic", "omit"], default="off",
                    help="Gemini thinkingConfig: off=thinkingBudget 0 (default), dynamic=-1, omit=no field")
    ap.add_argument("--prompt", choices=sorted(PROMPTS), default="evidence",
                    help="prompt arm: evidence = A2 evidence-aware (default) · basic = A1 minimal pair "
                         "(no analyst-discipline block); non-default arms write to <model>_<arm>/")
    ap.add_argument("--package-dir", default=None,
                    help="experiment-only directory containing <CASE_ID>.json package variants; must be "
                         "paired with --experiment-tag so canonical outputs cannot be overwritten")
    ap.add_argument("--experiment-tag", default=None,
                    help="experiment label appended to the output model tag as __EXP_<tag>; must be paired "
                         "with --package-dir")
    ap.add_argument("--external-freeze-manifest", default=None,
                    help="frozen external case-set manifest; permits new case IDs only when every package "
                         "matches the manifest and the frozen run contract")
    ap.add_argument("--force", action="store_true",
                    help="override a freeze or held-out guard (deliberate, documented exception only)")
    a = ap.parse_args()
    system = load_prompt(a.prompt)

    if bool(a.package_dir) != bool(a.experiment_tag):
        sys.exit("--package-dir and --experiment-tag must be supplied together. This prevents an "
                 "experimental package from overwriting canonical outputs.")
    if a.external_freeze_manifest and not a.package_dir:
        sys.exit("--external-freeze-manifest requires --package-dir and --experiment-tag")

    package_dir = None
    experiment_tag = None
    external_freeze = None
    external_case_hashes = None
    if a.package_dir:
        package_dir = Path(a.package_dir).expanduser()
        if not package_dir.is_absolute():
            package_dir = ROOT / package_dir
        package_dir = package_dir.resolve()
        if not package_dir.is_dir():
            sys.exit(f"--package-dir does not exist or is not a directory: {package_dir}")
        experiment_tag = re.sub(r"[^A-Za-z0-9._-]", "-", a.experiment_tag).strip("-._")
        if not experiment_tag:
            sys.exit("--experiment-tag must contain at least one letter or number")
        if a.external_freeze_manifest:
            _, external_freeze, external_case_hashes = load_external_freeze(
                a.external_freeze_manifest, package_dir
            )
        if a.split == "heldout" and not external_freeze and not a.force:
            sys.exit("refusing: custom package experiments are dev-only by default. Use --force only for "
                     "a deliberate, documented held-out experiment.")

    if a.batch and a.provider != "anthropic":
        sys.exit("--batch is Anthropic-only (Gemini has no equivalent here); drop --batch for gemini.")

    # Freeze protocol: the ablation ladder (any non-evidence prompt arm) is DEV-ONLY. Held-out is the single
    # frozen configuration, run once — an ablation arm on it means extra passes over the sealed set, exactly
    # what pre-registration forbids. Refuse, with an explicit escape hatch for a documented exception.
    if a.split == "heldout" and a.prompt != "evidence" and not a.force:
        sys.exit(f"refusing: --prompt {a.prompt} is an ablation arm, and the ablation ladder is dev-only.\n"
                 f"  held-out runs only the frozen evidence arm, once (see the freeze record / README).\n"
                 f"  if this is a deliberate, documented exception, re-run with --force.")

    max_tokens = a.max_tokens or GEN_MAX_TOKENS
    if a.provider == "gemini":
        model = a.model or os.environ.get("GEMINI_MODEL", "gemini-2.5-flash")
        api_key, env = os.environ.get("GEMINI_API_KEY", ""), "GEMINI_API_KEY"
        caller = lambda s, p: call_gemini(s, p, model, api_key, a.temperature, max_tokens, a.gemini_thinking)
    else:
        model = a.model or os.environ.get("ANTHROPIC_MODEL", "claude-sonnet-4-6")
        api_key, env = os.environ.get("ANTHROPIC_API_KEY", ""), "ANTHROPIC_API_KEY"
        caller = lambda s, p: call_anthropic(s, p, model, api_key, a.temperature, max_tokens)
        if a.model is None and "ANTHROPIC_MODEL" not in os.environ:
            print("  note: defaulting to claude-sonnet-4-6. Cheapest = ANTHROPIC_MODEL=claude-haiku-4-5; "
                  "add --batch for 50% off.", file=sys.stderr)
    if external_freeze:
        contract = external_freeze.get("run_contract") or {}
        actual = {
            "split_label": a.split,
            "prompt_arm": a.prompt,
            "temperature": a.temperature,
            "max_output_tokens": max_tokens,
            "rounds_per_model": a.round or 1,
        }
        expected = {key: contract.get(key) for key in actual}
        drift = [f"{key}: expected {expected[key]!r}, got {actual[key]!r}"
                 for key in actual if actual[key] != expected[key]]
        if model not in contract.get("models", []):
            drift.append(f"model {model!r} is not in frozen model list {contract.get('models', [])}")
        if a.provider == "gemini" and a.gemini_thinking != contract.get("gemini_thinking"):
            drift.append(
                f"gemini_thinking: expected {contract.get('gemini_thinking')!r}, "
                f"got {a.gemini_thinking!r}"
            )
        if drift:
            sys.exit("external frozen run contract changed:\n  - " + "\n  - ".join(drift))
    if a.provider == "gemini":
        enforce_gemini_dev_freeze(
            a.split, package_dir, model, a.temperature, max_tokens, a.gemini_thinking, a.force
        )
    if not api_key:
        sys.exit(f'{env} not set.  export {env}="your-key"')

    sleep = a.sleep if a.sleep is not None else (6.0 if a.provider == "gemini" else 0.5)
    model_tag = output_model_tag(model, a.prompt, a.round, experiment_tag)
    outdir = HERE / "outputs" / model_tag / a.split
    outdir.mkdir(parents=True, exist_ok=True)

    # build the work list (respect --only + --skip-existing + --limit) up front so batch and real-time share it
    package_rows = list(packages(a.split, package_dir))
    if package_dir:
        custom_ids = {cid.split("_")[0] for cid, _ in package_rows}
        if external_case_hashes is not None:
            if custom_ids != set(external_case_hashes):
                sys.exit(
                    "external package directory does not exactly match the freeze manifest: "
                    f"missing={sorted(set(external_case_hashes) - custom_ids)}, "
                    f"extra={sorted(custom_ids - set(external_case_hashes))}"
                )
        else:
            canonical_ids = {cid.split("_")[0] for cid, _ in packages(a.split)}
            unknown_custom = custom_ids - canonical_ids
            if unknown_custom:
                sys.exit(f"custom packages are not members of split '{a.split}': {sorted(unknown_custom)}")
        if not package_rows:
            sys.exit(f"--package-dir contains no JSON packages: {package_dir}")
        for cid, pkgpath in package_rows:
            tag = cid.split("_")[0]
            try:
                package_case_id = json.loads(pkgpath.read_text(encoding="utf-8")).get("case_id")
            except (OSError, json.JSONDecodeError) as e:
                sys.exit(f"invalid custom package {pkgpath}: {e}")
            if package_case_id != tag:
                sys.exit(f"custom package filename/id mismatch: {pkgpath.name} contains case_id={package_case_id!r}")
            if external_case_hashes is not None and sha256_file(pkgpath) != external_case_hashes[tag]:
                sys.exit(f"custom package changed after external freeze: {tag}")
    only = {c.strip() for c in a.only.split(",") if c.strip()} if a.only else None
    if only:
        avail = {cid.split("_")[0] for cid, _ in package_rows}
        unknown = only - avail
        if unknown:
            sys.exit(f"--only lists case ids not in split '{a.split}': {sorted(unknown)}")
    work, skipped, package_info = [], 0, {}
    for cid, pkgpath in package_rows:
        tag = cid.split("_")[0]
        if only and tag not in only:
            continue                                   # targeted re-run: ignore everything not named in --only
        outpath = outdir / f"{tag}.json"
        if a.skip_existing and outpath.exists():
            skipped += 1
            continue
        if a.limit is not None and len(work) >= a.limit:
            break
        package_text = pkgpath.read_text(encoding="utf-8")
        package_info[tag] = {
            "path": display_path(pkgpath),
            "sha256": sha256_text(package_text),
        }
        work.append((tag, outpath, package_text))

    mode = "batch" if a.batch else "real-time"
    print(f"=== {a.provider} / {model}  on {a.split}  [{mode} · prompt={a.prompt}]  ->  "
          f"eval/outputs/{model_tag}/{a.split}/  ({len(work)} to run, {skipped} skipped) ===")
    if package_dir:
        try:
            package_label = package_dir.relative_to(ROOT)
        except ValueError:
            package_label = package_dir
        print(f"    experimental packages: {package_label}  [tag={experiment_tag}]")
    if not work:
        print("nothing to run (all cases already have outputs). done.")
        return

    billing = "batch" if a.batch else "realtime"
    invocation_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:8]
    prompt_path = HERE / PROMPTS[a.prompt]
    context = {
        "record_schema": "safesoc.run_event.v1",
        "invocation_id": invocation_id,
        "started_utc": utc_now(),
        "provider": a.provider,
        "requested_model": model,
        "model_tag": model_tag,
        "split": a.split,
        "round": a.round or 1,
        "prompt_arm": a.prompt,
        "prompt_path": display_path(prompt_path),
        "prompt_file_sha256": sha256_file(prompt_path),
        "system_prompt_sha256": sha256_text(system),
        "output_schema_path": display_path(HERE / "llm_output.schema.json"),
        "output_schema_sha256": sha256_file(HERE / "llm_output.schema.json"),
        "runner_sha256": sha256_file(Path(__file__)),
        "temperature_requested": a.temperature,
        "temperature_sent": (
            None if a.provider == "anthropic" and any(t in model for t in ANTHROPIC_NO_TEMP)
            else a.temperature
        ),
        "max_output_tokens": max_tokens,
        "top_p_sent": None,
        "seed_sent": None,
        "gemini_thinking": a.gemini_thinking if a.provider == "gemini" else None,
        "billing_mode": billing,
        "anthropic_api_version": "2023-06-01" if a.provider == "anthropic" else None,
        "gemini_api_version": "v1beta" if a.provider == "gemini" else None,
        "request_timeout_seconds": 300,
        "max_request_attempts": 6,
        "retry_http_statuses": list(RETRY_STATUS),
        "schema_enforcement": "client-side jsonschema after provider JSON generation",
        "package_source": display_path(package_dir) if package_dir else "canonical",
        "experiment_tag": experiment_tag,
        "python_version": platform.python_version(),
        "platform": platform.platform(),
        "command_args": sys.argv[1:],
    }
    ulog = usage_log(outdir, a.split)
    elog = run_event_log(outdir, a.split)
    tin = tout = 0
    if a.batch:
        batch_started = time.monotonic()
        try:
            ok, n, usage = run_anthropic_batch(work, system, model, api_key, a.temperature, max_tokens)
        except Exception as e:
            elapsed = time.monotonic() - batch_started
            for case, outpath, _pkg in work:
                append_run_event(
                    elog, context, case, package_info[case], "error", outpath=outpath,
                    elapsed_seconds=elapsed, error=f"{type(e).__name__}: {str(e)[:500]}",
                )
            raise
        for case, u in usage.items():                 # a batch completes atomically -> record its results together
            completed = utc_now()
            append_usage(ulog, case, u, model, "batch", completed, invocation_id)
            provider_meta = {
                key: u.get(key)
                for key in ("provider_response_id", "provider_model_version", "finish_reason", "batch_id")
            }
            append_run_event(
                elog, context, case, package_info[case], "success",
                outpath=outdir / f"{case}.json", usage=u, provider_meta=provider_meta,
                elapsed_seconds=time.monotonic() - batch_started,
            )
            tin += u.get("input_tokens", 0); tout += u.get("output_tokens", 0)
    else:
        n = ok = 0
        for i, (tag, outpath, pkg) in enumerate(work):
            if i:
                time.sleep(sleep)              # pace requests so the free-tier RPM limit isn't tripped
            n += 1
            call_started = time.monotonic()
            try:
                text, u, provider_meta = caller(system, pkg)
                parse_and_write(text, outpath, tag)
                completed = utc_now()
                append_usage(ulog, tag, u, model, "realtime", completed, invocation_id)
                append_run_event(
                    elog, context, tag, package_info[tag], "success", outpath=outpath, usage=u,
                    provider_meta=provider_meta, elapsed_seconds=time.monotonic() - call_started,
                )
                tin += u.get("input_tokens", 0); tout += u.get("output_tokens", 0)
                ok += 1
            except ModelNotFound as e:
                append_run_event(
                    elog, context, tag, package_info[tag], "error", outpath=outpath,
                    elapsed_seconds=time.monotonic() - call_started,
                    error=f"{type(e).__name__}: {str(e)[:500]}",
                )
                n -= 1                                # this case wasn't really attempted against a valid model
                sys.exit(f"\nFATAL (stopping — same for every case):\n{e}")
            except Exception as e:
                append_run_event(
                    elog, context, tag, package_info[tag], "error", outpath=outpath,
                    elapsed_seconds=time.monotonic() - call_started,
                    error=f"{type(e).__name__}: {str(e)[:500]}",
                )
                print(f"  ERROR {tag}: {type(e).__name__}: {str(e)[:160]}", file=sys.stderr)

    print(f"\n{ok}/{n} triaged this run"
          + (f" ({skipped} skipped, already had output)" if skipped else "")
          + f" -> eval/outputs/{model_tag}/{a.split}/")
    if ok:
        print(f"usage       :  +{tin:,} in / +{tout:,} out tokens ({billing} billing)  ->  {ulog.relative_to(HERE.parent)}")
        print(f"provenance  :  invocation {invocation_id} -> {elog.relative_to(HERE.parent)}")
    print(f"score with  :  python3 eval/validator_v1_1.py --model {model_tag} --split {a.split}")
    print(f"cost with   :  python3 eval/cost.py      --model {model_tag} --split {a.split}")


if __name__ == "__main__":
    main()
