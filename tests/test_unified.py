from sectestgen.core.models import (
    Classification,
    Confidence,
    Finding,
    Pipeline,
    ReachabilityEvidence,
    RuntimeEvidence,
    Severity,
    SourceLocation,
)
from sectestgen.unified import build_issues


def _static(rule, file, line, sink, cls, sev=Severity.HIGH):
    return Finding(
        id=f"s:{rule}:{line}",
        pipeline=Pipeline.STATIC,
        tool="semgrep",
        rule_id=rule,
        severity=sev,
        classification=cls,
        sink=sink,
        location=SourceLocation(file_path=file, line=line),
    )


def _sca(cve, package, cls, sites=None, sink=None):
    usage = {"status": "referenced_in_entry_point"}
    if sites is not None:
        usage["symbols"] = {"sites": sites}
    return Finding(
        id=f"sca:{cve}",
        pipeline=Pipeline.SCA,
        tool="grype",
        cve=cve,
        package_name=package,
        purl=f"pkg:pypi/{package}@1",
        severity=Severity.CRITICAL,
        classification=cls,
        sink=sink,
        raw={"usage": usage},
    )


def test_two_static_tools_on_same_line_and_sink_merge(tmp_path):
    f = str(tmp_path / "app.py")
    bandit = _static("B301", f, 42, "unsafe_deserialization", Classification.REACHABLE)
    bandit.tool = "bandit"
    semgrep = _static("sectestgen-pickle", f, 42, "unsafe_deserialization", Classification.REACHABLE)

    issues = build_issues([bandit, semgrep], [])

    assert len(issues) == 1
    assert sorted(issues[0].to_dict()["tools"]) == ["bandit", "semgrep"]


def test_sca_finding_joins_static_issue_on_the_same_line(tmp_path):
    f = str(tmp_path / "app.py")
    static = _static("B506", f, 28, "unsafe_deserialization", Classification.REACHABLE)
    sca = _sca("CVE-2020-14343", "pyyaml", Classification.REACHABLE,
               sites=[{"file_path": f, "line": 28, "entry_point": "POST /config/parse"}],
               sink="unsafe_deserialization")

    issues = build_issues([static], [sca])

    assert len(issues) == 1
    issue = issues[0]
    assert {m.pipeline for m in issue.members} == {Pipeline.STATIC, Pipeline.SCA}
    assert issue.advisories == ["CVE-2020-14343"]


def test_sca_without_matching_static_line_stays_separate(tmp_path):
    f = str(tmp_path / "app.py")
    static = _static("B506", f, 28, "unsafe_deserialization", Classification.REACHABLE)
    sca = _sca("CVE-2019-10906", "jinja2", Classification.NOT_OBSERVED, sites=[])

    issues = build_issues([static], [sca])

    assert len(issues) == 2


def test_issue_takes_strongest_classification_and_highest_severity(tmp_path):
    f = str(tmp_path / "app.py")
    low = _static("r1", f, 10, "sql_injection", Classification.POTENTIALLY_REACHABLE, sev=Severity.MEDIUM)
    low.confidence = Confidence.LOW
    high = _static("r2", f, 10, "sql_injection", Classification.CONFIRMED, sev=Severity.CRITICAL)
    high.confidence = Confidence.HIGH

    issue = build_issues([low, high], [])[0]

    assert issue.classification is Classification.CONFIRMED
    assert issue.confidence is Confidence.HIGH
    assert issue.severity is Severity.CRITICAL


def test_issues_sorted_most_severe_first(tmp_path):
    f = str(tmp_path / "app.py")
    not_observed = _sca("CVE-1", "a", Classification.NOT_OBSERVED, sites=[])
    confirmed = _static("r", f, 5, "sql_injection", Classification.CONFIRMED)
    confirmed.runtime = RuntimeEvidence(observed=True)

    issues = build_issues([confirmed], [not_observed])

    assert issues[0].classification is Classification.CONFIRMED
    assert issues[0].to_dict()["runtime_observed"] is True


def test_finding_without_location_is_its_own_issue():
    a = Finding(id="a", pipeline=Pipeline.STATIC, tool="bandit", rule_id="B403",
                classification=Classification.INCONCLUSIVE, reachability=ReachabilityEvidence())
    b = Finding(id="b", pipeline=Pipeline.STATIC, tool="bandit", rule_id="B404",
                classification=Classification.INCONCLUSIVE, reachability=ReachabilityEvidence())

    assert len(build_issues([a, b], [])) == 2
