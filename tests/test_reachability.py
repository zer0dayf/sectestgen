from pathlib import Path

from sectestgen.adapters.fastapi_adapter import FastAPIFrameworkAdapter
from sectestgen.adapters.reachability import BoundedReachabilityEngine
from sectestgen.core.models import Finding, Pipeline, SourceLocation

SAMPLE_APP = '''
from fastapi import FastAPI, Query

app = FastAPI()


@app.get("/reachable/{host}")
def reachable_route(host: str) -> dict:
    output = os.popen(f"ping {host}").read()
    return {"output": output}


@app.get("/not-reachable")
def not_reachable_route(name: str = Query(...)) -> dict:
    output = os.popen("ping 127.0.0.1").read()
    return {"output": output}


@app.get("/ambiguous")
def ambiguous_route(name: str = Query(...)) -> dict:
    other = some_unknown_helper()
    output = os.popen(other).read()
    return {"output": output}


def not_a_route(host):
    return os.popen(host).read()
'''


def _write_sample(tmp_path: Path) -> Path:
    target = tmp_path / "app.py"
    target.write_text(SAMPLE_APP, encoding="utf-8")
    return target


def _make_finding(file_path: Path, line: int) -> Finding:
    return Finding(
        id="test",
        pipeline=Pipeline.STATIC,
        tool="test",
        location=SourceLocation(file_path=str(file_path), line=line),
    )


def test_reachable_when_source_flows_into_sink(tmp_path):
    app_file = _write_sample(tmp_path)
    routes = list(FastAPIFrameworkAdapter().discover_routes(tmp_path))
    engine = BoundedReachabilityEngine(routes)

    finding = _make_finding(app_file, 9)  # os.popen(f"ping {host}") line
    engine.analyze(finding, tmp_path)

    assert finding.reachability.reachable is True
    assert finding.raw["entry_point"] is True


def test_not_observed_when_sink_args_are_fully_literal(tmp_path):
    app_file = _write_sample(tmp_path)
    routes = list(FastAPIFrameworkAdapter().discover_routes(tmp_path))
    engine = BoundedReachabilityEngine(routes)

    finding = _make_finding(app_file, 15)  # os.popen("ping 127.0.0.1") line
    engine.analyze(finding, tmp_path)

    assert finding.reachability.reachable is False
    assert finding.raw["entry_point"] is True


def test_inconclusive_when_taint_forwarded_through_unknown_call(tmp_path):
    app_file = _write_sample(tmp_path)
    routes = list(FastAPIFrameworkAdapter().discover_routes(tmp_path))
    engine = BoundedReachabilityEngine(routes)

    finding = _make_finding(app_file, 22)  # os.popen(forwarded) line
    engine.analyze(finding, tmp_path)

    assert finding.reachability.reachable is None
    assert finding.raw["entry_point"] is True


def test_inconclusive_when_sink_outside_any_route(tmp_path):
    app_file = _write_sample(tmp_path)
    routes = list(FastAPIFrameworkAdapter().discover_routes(tmp_path))
    engine = BoundedReachabilityEngine(routes)

    finding = _make_finding(app_file, 27)  # not_a_route()'s os.popen(host) line
    engine.analyze(finding, tmp_path)

    assert finding.reachability.reachable is None
    assert finding.raw["entry_point"] is False
