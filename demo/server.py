#!/usr/bin/env python3
"""Local service for the SafeSOC validation workbench.

Serves the static workbench and exposes a small API. The two validation paths are kept
strictly separate, in code as well as in the interface:

  POST /api/validate   -> runtime_validator.validate_runtime_case
                          Loads ONLY the neutral alert package, the saved LLM output, and the
                          frozen generic policy. It never opens annotations/ground_truth.json.
                          This is the deployable path.

  GET  /api/research   -> validator_v1_1.validate_case
                          Adds the frozen ground truth and runs the A4 oracle. Offline research
                          evaluation only; never part of the runtime path.

Model outputs are replayed from disk — no provider is called, so demonstrations are
deterministic, free, and identical to the thesis results.

    python3 demo/server.py            # then open http://localhost:8765
"""
from __future__ import annotations

import argparse
import json
import sys
import traceback
from functools import lru_cache
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT / "eval"))
import runtime_validator as rv   # noqa: E402
import validator_v1_1 as vv      # noqa: E402

STATIC = {"/": "index.html", "/index.html": "index.html",
          "/app.js": "app.js", "/styles.css": "styles.css",
          "/assets/safesoc-logo.png": "assets/safesoc-logo.png",
          "/assets/evidence-band-mark.svg": "assets/evidence-band-mark.svg"}
MIME = {".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8",
        ".css": "text/css; charset=utf-8", ".json": "application/json; charset=utf-8",
        ".png": "image/png", ".svg": "image/svg+xml"}
DEMO_POLICY = ROOT / "eval" / "runtime_policy_v1.2.json"


class ApiError(Exception):
    def __init__(self, message, status=400):
        super().__init__(message)
        self.status = status


def jload(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


@lru_cache(maxsize=1)
def snapshot() -> dict:
    path = HERE / "snapshot.json"
    if not path.exists():
        raise ApiError("snapshot.json missing — run: python3 demo/build_snapshot.py", 500)
    return jload(path)


@lru_cache(maxsize=1)
def research_snapshot() -> dict:
    path = HERE / "research_snapshot.json"
    if not path.exists():
        raise ApiError("research_snapshot.json missing — run: python3 demo/build_snapshot.py", 500)
    return jload(path)


@lru_cache(maxsize=1)
def runtime_context():
    return (rv.load_policy(DEMO_POLICY), jload(rv.PACKAGE_SCHEMA), jload(rv.OUTPUT_SCHEMA))


@lru_cache(maxsize=1)
def package_index() -> dict[str, Path]:
    """Resolve packages server-side without exposing condition-bearing repository paths."""
    index = {}
    for case in snapshot()["cases"]:
        case_id = case["case_id"]
        matches = list(ROOT.glob(f"tier*/*/*/{case_id}_*/model_input/alert_package.json"))
        if len(matches) != 1:
            raise ApiError(f"expected one package for {case_id}, found {len(matches)}", 500)
        index[case_id] = matches[0]
    return index


def package_path(case_id: str) -> Path:
    case_record(case_id)
    return package_index()[case_id]


def case_dir_path(case_id: str) -> Path:
    return package_path(case_id).parents[1]


def case_record(case_id: str) -> dict:
    rec = next((c for c in snapshot()["cases"] if c["case_id"] == case_id), None)
    if not rec:
        raise ApiError(f"unknown case: {case_id}", 404)
    return rec


def as_round(raw) -> int:
    """Parse a round number without turning a typo into a 500."""
    value = raw[0] if isinstance(raw, list) else raw
    try:
        return int(value)
    except (TypeError, ValueError):
        raise ApiError(f"round must be an integer, got {value!r}", 400)


def output_path(case_id: str, model: str, arm: str, round_: int) -> Path:
    try:
        rel = snapshot()["outputs"][case_id][model][arm][str(round_)]
    except KeyError:
        raise ApiError(f"no saved output for {case_id} / {model} / {arm} / round {round_}", 404)
    return ROOT / rel


def api_case(params) -> dict:
    """Package + which model arms/rounds have a saved output. No ground truth."""
    case_id = params.get("case_id", [""])[0]
    rec = case_record(case_id)
    package = jload(package_path(case_id))
    return {"case": rec, "package": package,
            "available": snapshot()["outputs"].get(case_id, {})}


def api_output(params) -> dict:
    case_id = params.get("case_id", [""])[0]
    model = params.get("model", [""])[0]
    arm = params.get("arm", ["A2_evidence_prompt"])[0]
    round_ = as_round(params.get("round", ["1"]))
    path = output_path(case_id, model, arm, round_)
    return {"case_id": case_id, "model": model, "arm": arm, "round": round_,
            "output": jload(path), "output_rel": str(path.relative_to(ROOT))}


def api_validate(body: dict) -> dict:
    """The deployable path. Reads package + output + policy. Never ground truth."""
    case_id, model = body.get("case_id"), body.get("model")
    arm = body.get("arm", "A2_evidence_prompt")
    round_ = as_round(body.get("round", 1))
    case_record(case_id)
    pkg_path = package_path(case_id)
    out_path = output_path(case_id, model, arm, round_)
    policy, package_schema, output_schema = runtime_context()

    result = rv.validate_runtime_case(
        jload(pkg_path), jload(out_path), policy, package_schema, output_schema,
        expected_case_id=case_id,
    )
    return {
        "validator": "SafeSOC policy-based runtime validator",
        "validator_version": rv.VERSION,
        "policy_version": policy["policy_version"],
        "policy_path": rv.relative(DEMO_POLICY),
        "policy_sha256": rv.sha256(DEMO_POLICY),
        "default_profile": policy["default_profile"],
        "token_calls": 0,
        "input_contract": "alert_package + LLM output + generic policy only; "
                          "no annotations or ground truth were read",
        "inputs_read": [f"benchmark/{case_id}/alert_package.json", rv.relative(out_path),
                        rv.relative(DEMO_POLICY),
                        rv.relative(rv.PACKAGE_SCHEMA), rv.relative(rv.OUTPUT_SCHEMA)],
        "package_sha256": rv.sha256(pkg_path),
        "output_sha256": rv.sha256(out_path),
        "case": result,
        "non_claims": policy["non_claims"],
    }


def api_research(params) -> dict:
    """Offline research evaluation. This is the ONLY endpoint that opens ground truth."""
    case_id = params.get("case_id", [""])[0]
    model = params.get("model", [""])[0]
    arm = params.get("arm", ["A2_evidence_prompt"])[0]
    round_ = as_round(params.get("round", ["1"]))
    case_record(case_id)
    package = jload(package_path(case_id))
    output = jload(output_path(case_id, model, arm, round_))
    gt_path = case_dir_path(case_id) / "annotations" / "ground_truth.json"
    if not gt_path.exists():
        raise ApiError(f"no ground truth for {case_id}", 404)
    gt = jload(gt_path)

    checks = vv.validate_case(package, output, gt)
    failed = [c for c in vv.ALL_CHECKS if vv.check_failed(checks, c)]
    c2 = checks["C2_decision_calibration"]
    return {
        "evaluator": "validator_v1_1 (offline A4 oracle)",
        "rubric_version": vv.VERSION,
        "scope": "offline research evaluation only; not part of the deployable runtime path",
        "case_id": case_id,
        "evidence_condition": gt["evidence_condition"],
        "calibration_role": gt.get("calibration_role"),
        "expected": {"verdict": gt["correct_verdict"], "severity": gt["acceptable_severity"],
                     "actions": gt["acceptable_actions"]},
        "grounding": gt.get("grounding", {}),
        "rationale": gt.get("rationale", ""),
        "checks": checks,
        "failed_checks": failed,
        "a4_ok": not failed,
        "directions": {"verdict": c2["verdict_direction"], "severity": c2["severity_direction"],
                       "action": checks["C4_action_calibration"]["direction"]},
        "must_not_assert": gt.get("grounding", {}).get("must_not_assert", []),
    }


ROUTES = {"/api/snapshot": lambda p: snapshot(),
          "/api/research-snapshot": lambda p: research_snapshot(), "/api/case": api_case,
          "/api/output": api_output, "/api/research": api_research}


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        if "--verbose" in sys.argv:
            super().log_message(fmt, *args)

    def _send(self, payload: bytes, ctype: str, status=200):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(payload)

    def _json(self, obj, status=200):
        self._send(json.dumps(obj).encode("utf-8"), MIME[".json"], status)

    def do_GET(self):
        parsed = urlparse(self.path)
        try:
            if parsed.path in ROUTES:
                self._json(ROUTES[parsed.path](parse_qs(parsed.query)))
                return
            name = STATIC.get(parsed.path)
            if not name:
                self._json({"error": "not found"}, 404); return
            path = HERE / name
            self._send(path.read_bytes(), MIME[path.suffix])
        except ApiError as exc:
            self._json({"error": str(exc)}, exc.status)
        except Exception as exc:                      # pragma: no cover - surfaced in the UI
            traceback.print_exc()
            self._json({"error": f"{type(exc).__name__}: {exc}"}, 500)

    def do_POST(self):
        parsed = urlparse(self.path)
        try:
            if parsed.path != "/api/validate":
                self._json({"error": "not found"}, 404); return
            length = int(self.headers.get("Content-Length", 0) or 0)
            raw = self.rfile.read(length) or b"{}"
            try:
                body = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise ApiError(f"request body is not valid JSON: {exc}", 400)
            if not isinstance(body, dict):
                raise ApiError("request body must be a JSON object", 400)
            self._json(api_validate(body))
        except ApiError as exc:
            self._json({"error": str(exc)}, exc.status)
        except Exception as exc:                      # pragma: no cover
            traceback.print_exc()
            self._json({"error": f"{type(exc).__name__}: {exc}"}, 500)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()
    if not (HERE / "snapshot.json").exists():
        raise SystemExit("snapshot.json missing — run: python3 demo/build_snapshot.py")
    snap = snapshot()
    print(f"SafeSOC validation workbench  ·  http://{args.host}:{args.port}")
    print(f"  {len(snap['cases'])} frozen cases · runtime policy v{snap['runtime']['policy_version']}"
          f" · default profile {snap['runtime']['default_profile']}")
    print("  model outputs are replayed from disk — no provider is called")
    ThreadingHTTPServer((args.host, args.port), Handler).serve_forever()


if __name__ == "__main__":
    main()
