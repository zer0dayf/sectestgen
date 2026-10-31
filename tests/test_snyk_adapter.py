import json
from pathlib import Path

import pytest

from sectestgen.adapters.snyk_adapter import SnykAdapter, build_purl, snyk_symbols
from sectestgen.core.models import Severity
from sectestgen.pipeline import run_sca_pipeline

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
PY = FIXTURES / "sca_python"
JAVA = FIXTURES / "sca_java"


def test_reads_python_report():
    findings = {f.cve: f for f in SnykAdapter(PY / "snyk.json").run(PY / "sbom.cdx.json")}

    assert set(findings) == {"CVE-2020-14343", "CVE-2019-10906", "CVE-2018-18074", "CVE-2019-11324"}
    pyyaml = findings["CVE-2020-14343"]
    assert pyyaml.tool == "snyk"
    assert pyyaml.rule_id == "SNYK-PYTHON-PYYAML-590151"
    assert pyyaml.purl == "pkg:pypi/pyyaml@5.3.1"
    assert pyyaml.severity is Severity.CRITICAL
    assert pyyaml.fixed_version == "5.4"
    assert pyyaml.raw["vulnerable_symbols"] == {"symbols": ["yaml.full_load"], "sources": ["snyk"]}
    assert findings["CVE-2019-11324"].raw["direct"] is False


def test_maven_package_name_becomes_purl_and_internal_function_symbol():
    log4j = next(f for f in SnykAdapter(JAVA / "snyk.json").run(JAVA / "sbom.cdx.json") if f.cve == "CVE-2021-44228")

    assert log4j.purl == "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"
    assert log4j.package_name == "log4j-core"
    assert log4j.raw["vulnerable_symbols"]["symbols"] == ["org.apache.logging.log4j.core.lookup.JndiLookup.lookup"]


def test_one_finding_per_vulnerability_with_all_paths(tmp_path):
    vuln = {"id": "SNYK-1", "packageName": "urllib3", "version": "1.23", "severity": "high"}
    report = {
        "packageManager": "pip",
        "vulnerabilities": [
            {**vuln, "from": ["p@0", "requests@2", "urllib3@1.23"]},
            {**vuln, "from": ["p@0", "urllib3@1.23"]},
        ],
    }
    path = tmp_path / "snyk.json"
    path.write_text(json.dumps([report]), encoding="utf-8")

    findings = list(SnykAdapter(path).run(tmp_path))

    assert len(findings) == 1
    assert len(findings[0].raw["paths"]) == 2
    assert findings[0].raw["direct"] is True
    assert findings[0].cve is None


def test_error_report_is_raised(tmp_path):
    path = tmp_path / "snyk.json"
    path.write_text(json.dumps({"ok": False, "error": "Authentication failed"}), encoding="utf-8")

    with pytest.raises(ValueError, match="Authentication failed"):
        list(SnykAdapter(path).run(tmp_path))


def test_build_purl():
    assert build_purl("pip", "Py_YAML", "1") == "pkg:pypi/py-yaml@1"
    assert build_purl("gradle", "com.acme:lib", "2") == "pkg:maven/com.acme/lib@2"
    assert build_purl("npm", "@scope/pkg", "3") == "pkg:npm/%40scope/pkg@3"
    assert build_purl("maven", "no-group", "1") is None
    assert build_purl("cocoapods", "x", "1") is None


def test_snyk_symbols_from_source_path_and_class():
    vuln = {
        "functions": [
            {"functionId": {"filePath": "src/main/java/com/acme/Util.java", "functionName": "run"}},
            {"functionId": {"className": "Parser", "filePath": "acme/parse.py", "functionName": "go"}},
            {"functionId": {"filePath": "x.py"}},
        ]
    }
    assert snyk_symbols(vuln, "pkg:maven/com.acme/lib@1") == ["com.acme.Util.run", "acme.parse.Parser.go"]


def test_pipeline_deduplicates_three_providers_and_keeps_snyk_symbols(tmp_path):
    result = run_sca_pipeline(
        JAVA / "sbom.cdx.json", JAVA, tmp_path, grype_report=JAVA / "grype.json", snyk_report=JAVA / "snyk.json"
    )

    assert result.errors == []
    by_cve = {f.cve: f for f in result.findings}
    assert len(result.findings) == 3
    log4j = by_cve["CVE-2021-44228"]
    assert set(log4j.raw["also_reported_by"]) == {"grype", "snyk"}
    known = log4j.raw["usage"]["symbols"]
    assert "org.apache.logging.log4j.core.lookup.JndiLookup.lookup" in known["known"]
    assert known["sources"] == ["snyk", "curated"]
    assert log4j.classification.value == "REACHABLE"
    assert "vulnerable symbols" in (tmp_path / "report2.html").read_text(encoding="utf-8")


def test_python_pipeline_with_only_snyk_matches_ground_truth():
    result = run_sca_pipeline(PY / "sbom.cdx.json", PY, adapters=[SnykAdapter(PY / "snyk.json")])
    truth = {e["cve"]: e for e in json.loads((PY / "ground_truth.json").read_text(encoding="utf-8"))}

    for finding in result.findings:
        assert finding.classification.value == truth[finding.cve]["expected_classification"], finding.cve
        assert finding.confidence.value == truth[finding.cve]["expected_confidence"], finding.cve


def test_bad_symbols_file_is_reported_not_raised(tmp_path):
    bad = tmp_path / "symbols.json"
    bad.write_text("{}", encoding="utf-8")

    result = run_sca_pipeline(PY / "sbom.cdx.json", PY, grype_report=PY / "grype.json", symbols_file=bad)

    assert any(e.startswith("symbols:") for e in result.errors)
    assert len(result.findings) == 4
