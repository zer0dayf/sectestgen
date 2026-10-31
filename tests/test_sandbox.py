import io
import json
import shutil
import subprocess
import tarfile
from pathlib import Path

import pytest

from sectestgen.adapters.classifier import DefaultClassifier, apply_runtime_evidence
from sectestgen.core.models import (
    Classification,
    Confidence,
    Finding,
    Pipeline,
    ReachabilityEvidence,
    RuntimeEvidence,
    SourceLocation,
)
from sectestgen.sandbox import harness
from sectestgen.sandbox.executor import (
    DockerSandboxExecutor,
    SandboxError,
    dockerfile,
    image_tag,
    python_version,
)

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
VULN = FIXTURES / "vulnerable_fastapi"
APP = VULN / "app.py"


def _route(method, path, sources, start=1, end=500, file=APP):
    return {"method": method, "path": path, "function": "f", "file_path": str(file),
            "start_line": start, "end_line": end, "sources": sources}


def _finding(route, sink, source, line=10, cls=Classification.REACHABLE, file=APP):
    label = f"{route['method']} {route['path']}"
    return Finding(
        id=f"{label}:{sink}:{line}",
        pipeline=Pipeline.STATIC,
        tool="semgrep",
        sink=sink,
        classification=cls,
        location=SourceLocation(file_path=str(file), line=line),
        user_input_source=f"{label} :: {source}",
        raw={"route": label, "entry_point": True},
        reachability=ReachabilityEvidence(reachable=True),
    )


# --- classifier ---------------------------------------------------------------


def test_observed_runtime_evidence_confirms():
    finding = Finding(id="x", pipeline=Pipeline.STATIC, tool="t", reachability=ReachabilityEvidence(reachable=True))
    finding.runtime = RuntimeEvidence(observed=True)

    DefaultClassifier().classify(finding)

    assert finding.classification is Classification.CONFIRMED
    assert finding.confidence is Confidence.HIGH


def test_not_observed_keeps_classification_and_lowers_confidence():
    finding = Finding(id="x", pipeline=Pipeline.STATIC, tool="t", reachability=ReachabilityEvidence(reachable=True))
    finding.runtime = RuntimeEvidence(observed=False)

    DefaultClassifier().classify(finding)

    assert finding.classification is Classification.REACHABLE
    assert finding.confidence is Confidence.LOW


def test_not_validated_changes_nothing():
    finding = Finding(id="x", pipeline=Pipeline.STATIC, tool="t", classification=Classification.REACHABLE,
                      confidence=Confidence.MEDIUM, runtime=RuntimeEvidence(observed=None))

    apply_runtime_evidence(finding)

    assert finding.classification is Classification.REACHABLE
    assert finding.confidence is Confidence.MEDIUM


# --- planning -----------------------------------------------------------------


def test_plan_deduplicates_cases_and_explains_unsupported_findings():
    route = _route("GET", "/ping/{host:path}", [{"name": "host", "kind": "path", "field": None}])
    a = _finding(route, "command_execution", "path:host")
    b = _finding(route, "command_execution", "path:host", line=11)
    java = _finding(route, "sql_injection", "path:host", file=VULN / "A.java")
    unknown_sink = _finding(route, "xss", "path:host")

    executor = DockerSandboxExecutor([route])
    plan = executor._plan([a, b, java, unknown_sink], VULN)

    assert len(plan.cases) == 1
    assert plan.finding_case[a.id] == plan.finding_case[b.id]
    case = plan.cases[0]
    assert case["module_file"] == "vulnerable_fastapi/app.py"
    assert case["target"] == {"kind": "path", "name": "host", "field": None}
    assert "Python/FastAPI targets only" in java.runtime.observed_behavior
    assert "no runtime validator" in unknown_sink.runtime.observed_behavior


def test_finding_outside_a_route_is_not_planned():
    finding = _finding(_route("GET", "/x", []), "sql_injection", "query:q")
    finding.raw["route"] = None

    plan = DockerSandboxExecutor([]).execute_many([finding], VULN)

    assert finding.runtime.observed is None
    assert "not inside a discovered FastAPI route" in finding.runtime.observed_behavior
    assert plan == [finding]


# --- request building (container-side harness) --------------------------------


def test_build_request_injects_only_the_target_source():
    case = {
        "method": "POST",
        "path": "/items/{item_id}/{rest:path}",
        "sources": [
            {"name": "item_id", "kind": "path", "field": None},
            {"name": "rest", "kind": "path", "field": None},
            {"name": "q", "kind": "query", "field": None},
            {"name": "x_token", "kind": "header", "field": None},
            {"name": "session", "kind": "cookie", "field": None},
            {"name": "payload", "kind": "body", "field": "expression"},
            {"name": "payload", "kind": "body", "field": "note"},
        ],
        "target": {"kind": "body", "name": "payload", "field": "expression"},
    }

    request = harness.build_request(case, "PAYLOAD")

    assert request["url"] == "/items/1/1"
    assert request["params"] == {"q": "1"}
    assert request["headers"] == {"x-token": "1"}
    assert request["cookies"] == {"session": "1"}
    assert request["json"] == {"expression": "PAYLOAD", "note": "1"}


def test_build_request_path_converter_keeps_slashes():
    case = {"method": "GET", "path": "/ping/{host:path}",
            "sources": [{"name": "host", "kind": "path", "field": None}],
            "target": {"kind": "path", "name": "host", "field": None}}

    assert harness.build_request(case, "a/b c")["url"] == "/ping/a/b%20c"


def test_single_plain_body_parameter_is_not_embedded():
    case = {"method": "POST", "path": "/p", "sources": [{"name": "document", "kind": "body", "field": None}],
            "target": {"kind": "body", "name": "document", "field": None}}

    assert harness.build_request(case, "doc")["json"] == "doc"


def test_sql_marker_never_appears_literally_in_payload():
    variants = harness._sqli_variants({"nonce": "abc123"}, Path("."))

    assert variants
    assert all("SECTESTGENabc123" not in value for _, value, _ in variants)


# --- harness against the fixture on the host (no Docker) ----------------------


_FIXTURE_CASES = [
    ("GET", "/files", "path_traversal", {"name": "filename", "kind": "query", "field": None}, True),
    ("GET", "/files-safe", "path_traversal", {"name": "filename", "kind": "query", "field": None}, False),
    ("POST", "/calc", "dynamic_evaluation", {"name": "payload", "kind": "body", "field": "expression"}, True),
    ("POST", "/calc-safe", "dynamic_evaluation", {"name": "payload", "kind": "body", "field": "expression"}, False),
    ("GET", "/profile", "unsafe_deserialization", {"name": "session_data", "kind": "cookie", "field": None}, True),
    ("GET", "/profile-safe", "unsafe_deserialization",
     {"name": "session_data", "kind": "cookie", "field": None}, False),
    ("GET", "/users/search", "sql_injection", {"name": "name", "kind": "query", "field": None}, True),
    ("GET", "/users/search-safe", "sql_injection", {"name": "name", "kind": "query", "field": None}, False),
]


def _cases(rows):
    return [
        {"id": f"case-{i}", "nonce": f"n{i:04d}", "sink_type": sink, "module_file": "vulnerable_fastapi/app.py",
         "method": method, "path": path, "sources": [source], "target": source}
        for i, (method, path, sink, source, _) in enumerate(rows)
    ]


def test_harness_confirms_vulnerable_and_not_safe_endpoints_on_host():
    results = harness.run_plan({"cases": _cases(_FIXTURE_CASES)}, FIXTURES, case_timeout=60)

    observed = {r["id"]: r["observed"] for r in results}
    for i, (*_, expected) in enumerate(_FIXTURE_CASES):
        assert observed[f"case-{i}"] is expected, _FIXTURE_CASES[i][1]


def test_harness_reports_unloadable_app(tmp_path):
    (tmp_path / "broken").mkdir()
    (tmp_path / "broken" / "app.py").write_text("import does_not_exist_xyz\n", encoding="utf-8")
    case = {"id": "c", "nonce": "n", "sink_type": "sql_injection", "module_file": "broken/app.py",
            "method": "GET", "path": "/", "sources": [], "target": {"kind": "query", "name": "q", "field": None}}

    [result] = harness.run_plan({"cases": [case]}, tmp_path, case_timeout=30)

    assert result["observed"] is None
    assert "could not load app" in result["error"]


# --- container command (fake Docker) ------------------------------------------


class _FakeDocker:
    def __init__(self, results: list[dict] | None = None, image_present: bool = True, run_error=None):
        self.calls: list[list[str]] = []
        self.archive_names: list[str] = []
        self.results = results or []
        self.image_present = image_present
        self.run_error = run_error

    def __call__(self, cmd, **kwargs):
        self.calls.append(cmd)
        verb = cmd[1]
        if verb == "image":
            return subprocess.CompletedProcess(cmd, 0 if self.image_present else 1, b"", b"")
        if verb == "run":
            if self.run_error is not None:
                raise self.run_error
            with tarfile.open(fileobj=io.BytesIO(kwargs["input"])) as tar:
                self.archive_names = tar.getnames()
            out = "".join(f"{harness.RESULT_PREFIX}{json.dumps(r)}\n" for r in self.results)
            return subprocess.CompletedProcess(cmd, 0, out.encode(), b"")
        return subprocess.CompletedProcess(cmd, 0, b"", b"")


def _use_fake(monkeypatch, fake):
    monkeypatch.setattr("sectestgen.sandbox.executor.subprocess.run", fake)
    monkeypatch.setattr("sectestgen.sandbox.executor.shutil.which", lambda name: "/usr/bin/docker")


def _calc_finding():
    route = _route("POST", "/calc", [{"name": "payload", "kind": "body", "field": "expression"}])
    return route, _finding(route, "dynamic_evaluation", "body:payload.expression")


def test_container_is_isolated_and_results_become_evidence(monkeypatch):
    route, finding = _calc_finding()
    fake = _FakeDocker(results=[{
        "id": "case-1", "observed": True, "expected": "marker", "error": None,
        "attempts": [{"variant": "expression", "status": 200, "observed": True,
                      "request": {"method": "POST", "url": "/calc"}}],
    }])
    _use_fake(monkeypatch, fake)

    DockerSandboxExecutor([route], image="img").execute_many([finding], VULN)

    run = next(c for c in fake.calls if c[1] == "run")
    for flag, value in [("--network", "none"), ("--cap-drop", "ALL"), ("--user", "65534:65534"),
                        ("--security-opt", "no-new-privileges"), ("--pids-limit", "128"), ("--memory", "512m")]:
        assert run[run.index(flag) + 1] == value
    assert "--read-only" in run
    assert fake.calls[-1][1:3] == ["rm", "--force"]
    assert ".sectestgen/harness.py" in fake.archive_names
    assert "vulnerable_fastapi/app.py" in fake.archive_names
    assert not any("__pycache__" in n for n in fake.archive_names)
    assert finding.runtime.observed is True
    assert finding.runtime.request == {"method": "POST", "url": "/calc"}
    assert "expression" in finding.runtime.observed_behavior


def test_missing_image_marks_findings_not_validated(monkeypatch):
    route, finding = _calc_finding()
    _use_fake(monkeypatch, _FakeDocker(image_present=False))

    executor = DockerSandboxExecutor([route], image="missing:tag")
    executor.execute_many([finding], VULN)

    assert finding.runtime.observed is None
    assert "sectestgen sandbox build" in finding.runtime.observed_behavior
    assert "not found" in executor.last_error


def test_timeout_removes_container(monkeypatch):
    route, finding = _calc_finding()
    fake = _FakeDocker(run_error=subprocess.TimeoutExpired(cmd="docker run", timeout=1))
    _use_fake(monkeypatch, fake)

    DockerSandboxExecutor([route], image="img").execute_many([finding], VULN)

    name = next(c for c in fake.calls if c[1] == "run")
    name = name[name.index("--name") + 1]
    assert fake.calls[-1][1:] == ["rm", "--force", name]
    assert finding.runtime.observed is None
    assert "timed out" in finding.runtime.observed_behavior


def test_no_docker_binary(monkeypatch):
    route, finding = _calc_finding()
    monkeypatch.setattr("sectestgen.sandbox.executor.shutil.which", lambda name: None)

    DockerSandboxExecutor([route]).execute_many([finding], VULN)

    assert finding.runtime.observed is None
    assert "needs Docker" in finding.runtime.observed_behavior


# --- image naming -------------------------------------------------------------


def test_image_tag_depends_on_python_version_and_requirements(tmp_path):
    assert image_tag(tmp_path) == "sectestgen-sandbox:py3.11-base"
    (tmp_path / "requirements.txt").write_text("fastapi==0.110.3\n", encoding="utf-8")
    (tmp_path / ".python-version").write_text("3.9.19\n", encoding="utf-8")

    tag = image_tag(tmp_path)

    assert tag.startswith("sectestgen-sandbox:py3.9-req-")
    assert python_version(tmp_path) == "3.9"


def test_unsupported_python_version_is_rejected(tmp_path):
    (tmp_path / ".python-version").write_text("2.7\n", encoding="utf-8")

    with pytest.raises(SandboxError):
        python_version(tmp_path)


def test_dockerfile_installs_target_pins_before_harness_packages():
    text = dockerfile(True, "3.9")

    assert text.startswith("FROM python:3.9.19-slim")
    assert text.index("install_requirements.py") < text.index("fastapi==")


# --- real Docker (skipped without the daemon and image) -----------------------


def _docker_ready(target: Path) -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        tag = image_tag(target)
        return subprocess.run(["docker", "image", "inspect", tag], capture_output=True, timeout=30).returncode == 0
    except (OSError, subprocess.SubprocessError, SandboxError):
        return False


@pytest.mark.skipif(not _docker_ready(VULN), reason="needs Docker and `sectestgen sandbox build fixtures/vulnerable_fastapi`")
def test_docker_sandbox_confirms_every_vulnerable_fixture_endpoint_and_no_safe_one():
    rows = [
        *_FIXTURE_CASES,
        ("GET", "/ping/{host:path}", "command_execution", {"name": "host", "kind": "path", "field": None}, True),
        ("GET", "/ping-safe/{host:path}", "command_execution", {"name": "host", "kind": "path", "field": None}, False),
    ]
    routes, findings, expected = [], [], {}
    for method, path, sink, source, vulnerable in rows:
        route = _route(method, path, [source])
        route["file_path"] = str(APP.resolve())
        routes.append(route)
        spec = f"{source['kind']}:{source['name']}" + (f".{source['field']}" if source["field"] else "")
        finding = _finding(route, sink, spec, file=APP.resolve())
        findings.append(finding)
        expected[finding.id] = vulnerable

    DockerSandboxExecutor(routes).execute_many(findings, VULN)

    for finding in findings:
        assert finding.runtime.observed is expected[finding.id], (finding.id, finding.runtime.logs)
