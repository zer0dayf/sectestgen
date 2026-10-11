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


def test_html_reporter_renders_sca_columns(tmp_path):
    finding = Finding(
        id="s1",
        pipeline=Pipeline.SCA,
        tool="grype",
        rule_id="GHSA-xxxx",
        cve="CVE-2020-14343",
        package_name="PyYAML",
        package_version="5.3.1",
        purl="pkg:pypi/pyyaml@5.3.1",
        fixed_version="5.4",
        raw={"usage": {"status": "referenced_in_entry_point", "direct": True}},
    )
    output = HTMLReporter(Pipeline.SCA).generate([finding], tmp_path / "report2.html")

    content = output.read_text(encoding="utf-8")
    assert "Report 2" in content
    assert "CVE-2020-14343 (GHSA-xxxx)" in content
    assert "PyYAML@5.3.1" in content
    assert "referenced_in_entry_point" in content
