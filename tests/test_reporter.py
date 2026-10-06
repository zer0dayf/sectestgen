import json

from sectestgen.adapters.reporter import HTMLReporter, JSONReporter
from sectestgen.core.models import Classification, Finding, Pipeline, Severity


def _finding() -> Finding:
    finding = Finding(
        id="f1",
        pipeline=Pipeline.STATIC,
        tool="semgrep",
        rule_id="sectestgen-dynamic-evaluation",
        severity=Severity.HIGH,
    )
    finding.classification = Classification.REACHABLE
    return finding


def test_json_reporter_round_trips_findings(tmp_path):
    output = JSONReporter().generate([_finding()], tmp_path / "report1.json")

    payload = json.loads(output.read_text(encoding="utf-8"))
    assert len(payload) == 1
    assert payload[0]["id"] == "f1"
    assert payload[0]["classification"] == "REACHABLE"


def test_html_reporter_writes_valid_looking_page(tmp_path):
    output = HTMLReporter().generate([_finding()], tmp_path / "report1.html")

    content = output.read_text(encoding="utf-8")
    assert "<html" in content
    assert "sectestgen-dynamic-evaluation" in content
    assert "REACHABLE" in content


def test_html_reporter_handles_empty_findings(tmp_path):
    output = HTMLReporter().generate([], tmp_path / "report1.html")

    content = output.read_text(encoding="utf-8")
    assert "No findings." in content
