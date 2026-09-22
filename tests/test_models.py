from sectestgen.core.models import Classification, Finding, Pipeline, Severity


def test_finding_defaults_to_inconclusive():
    finding = Finding(id="f1", pipeline=Pipeline.STATIC, tool="semgrep")
    assert finding.classification is Classification.INCONCLUSIVE


def test_finding_to_dict_serializes_enums_and_dates():
    finding = Finding(id="f1", pipeline=Pipeline.STATIC, tool="semgrep", severity=Severity.HIGH)
    data = finding.to_dict()

    assert data["pipeline"] == "static"
    assert data["severity"] == "HIGH"
    assert isinstance(data["created_at"], str)
