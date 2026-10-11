import json
import shutil
import subprocess
from pathlib import Path

import pytest

from sectestgen.adapters.semgrep_adapter import SemgrepAdapter, SemgrepNotFoundError
from sectestgen.adapters.spring_adapter import SpringFrameworkAdapter

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
FASTAPI = FIXTURES / "vulnerable_fastapi"
SPRING = FIXTURES / "vulnerable_spring"
ALL_SINKS = {
    "command_execution",
    "dynamic_evaluation",
    "unsafe_deserialization",
    "path_traversal",
    "sql_injection",
}


def _semgrep_runnable() -> bool:
    local = shutil.which("semgrep")
    if local is not None:
        try:
            subprocess.run([local, "--version"], capture_output=True, timeout=60)
            return True
        except (OSError, subprocess.SubprocessError):
            pass
    docker = shutil.which("docker")
    if docker is None:
        return False
    try:
        return subprocess.run([docker, "info"], capture_output=True, timeout=60).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


needs_semgrep = pytest.mark.skipif(
    not _semgrep_runnable(), reason="neither a runnable semgrep nor a running docker daemon"
)


@pytest.fixture(scope="module")
def fastapi_findings():
    return list(SemgrepAdapter().run(FASTAPI))


@pytest.fixture(scope="module")
def spring_findings():
    return list(SemgrepAdapter().run(SPRING))


@needs_semgrep
def test_finds_all_five_sink_categories_in_fixture(fastapi_findings):
    assert {f.sink for f in fastapi_findings} == ALL_SINKS


@needs_semgrep
def test_finding_carries_location_and_rule_id(fastapi_findings):
    eval_finding = next(
        f for f in fastapi_findings if f.sink == "dynamic_evaluation" and f.location.line == 126
    )

    assert eval_finding.tool == "semgrep"
    assert eval_finding.rule_id == "sectestgen-dynamic-evaluation"
    assert eval_finding.location.file_path.endswith("app.py")
    assert Path(eval_finding.location.file_path).is_file()


@needs_semgrep
def test_java_rules_flag_only_vulnerable_spring_endpoints(spring_findings):
    truth = json.loads((SPRING / "ground_truth.json").read_text(encoding="utf-8"))
    vulnerable = {e["path"]: e["sink_type"] for e in truth if e["vulnerable"]}
    routes = list(SpringFrameworkAdapter().discover_routes(SPRING))

    flagged: dict[str, str] = {}
    for finding in spring_findings:
        route = next(
            r
            for r in routes
            if r["file_path"] == str(Path(finding.location.file_path).resolve())
            and r["start_line"] <= finding.location.line <= r["end_line"]
        )
        flagged[route["path"]] = finding.sink
        assert finding.rule_id.startswith("sectestgen-java-")

    assert flagged == vulnerable


def test_docker_runner_is_offline_read_only_and_maps_paths(monkeypatch, tmp_path):
    rules = tmp_path / "rules.yml"
    rules.write_text("rules: []\n", encoding="utf-8")
    target = tmp_path / "project"
    target.mkdir()
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        payload = {"results": [{"check_id": "rules0.sectestgen-x", "path": "/src/pkg/A.java",
                                "start": {"line": 3}, "end": {"line": 3}, "extra": {}}]}
        return subprocess.CompletedProcess(cmd, 1, stdout=json.dumps(payload), stderr="")

    monkeypatch.setattr("sectestgen.adapters.semgrep_adapter.subprocess.run", fake_run)
    monkeypatch.setattr(
        "sectestgen.adapters.semgrep_adapter.shutil.which",
        lambda name: "/usr/bin/docker" if name == "docker" else None,
    )

    adapter = SemgrepAdapter(config_paths=[rules])
    findings = list(adapter.run(target))

    cmd = calls[0]
    assert adapter.used_runner == "docker"
    assert cmd[cmd.index("--network") + 1] == "none"
    assert f"{target.resolve()}:/src:ro" in cmd
    assert f"{tmp_path.resolve()}:/rules0:ro" in cmd
    assert findings[0].location.file_path == str(target.resolve() / "pkg" / "A.java")
    assert findings[0].rule_id == "sectestgen-x"


def test_docker_runner_rejects_registry_configs(monkeypatch, tmp_path):
    monkeypatch.setattr(
        "sectestgen.adapters.semgrep_adapter.shutil.which",
        lambda name: "/usr/bin/docker" if name == "docker" else None,
    )
    with pytest.raises(RuntimeError, match="local rule files"):
        list(SemgrepAdapter(config_paths=["p/python"]).run(tmp_path))


def test_falls_back_to_docker_when_local_binary_is_blocked(monkeypatch, tmp_path):
    rules = tmp_path / "rules.yml"
    rules.write_text("rules: []\n", encoding="utf-8")

    def fake_run(cmd, **kwargs):
        if cmd[0] == "/usr/bin/semgrep":
            raise OSError(4551, "blocked by Application Control policy")
        return subprocess.CompletedProcess(cmd, 0, stdout='{"results": []}', stderr="")

    monkeypatch.setattr("sectestgen.adapters.semgrep_adapter.subprocess.run", fake_run)
    monkeypatch.setattr("sectestgen.adapters.semgrep_adapter.shutil.which", lambda name: f"/usr/bin/{name}")

    adapter = SemgrepAdapter(config_paths=[rules])
    assert list(adapter.run(tmp_path)) == []
    assert adapter.used_runner == "docker"


def test_no_semgrep_and_no_docker_raises(monkeypatch, tmp_path):
    monkeypatch.setattr("sectestgen.adapters.semgrep_adapter.shutil.which", lambda name: None)

    with pytest.raises(SemgrepNotFoundError):
        list(SemgrepAdapter().run(tmp_path))
