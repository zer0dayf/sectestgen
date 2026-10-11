from pathlib import Path

import pytest

from sectestgen.adapters.grype_adapter import GrypeAdapter, GrypeNotFoundError
from sectestgen.core.models import Severity

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
PY = FIXTURES / "sca_python"


def test_reads_pre_generated_report():
    findings = {f.cve: f for f in GrypeAdapter(report=PY / "grype.json").run(PY / "sbom.cdx.json")}

    assert set(findings) == {"CVE-2020-14343", "CVE-2019-10906", "CVE-2018-18074", "CVE-2019-11324"}
    requests = findings["CVE-2018-18074"]
    assert requests.purl == "pkg:pypi/requests@2.19.1"
    assert requests.severity is Severity.HIGH
    assert requests.fixed_version == "2.20.0"


def test_ghsa_id_is_kept_as_rule_and_cve_taken_from_related():
    findings = {f.cve: f for f in GrypeAdapter(report=PY / "grype.json").run(PY / "sbom.cdx.json")}

    pyyaml = findings["CVE-2020-14343"]
    assert pyyaml.rule_id == "GHSA-8q59-q68h-6hv4"
    assert pyyaml.severity is Severity.CRITICAL


def test_missing_binary_without_report_raises(tmp_path):
    adapter = GrypeAdapter(binary="definitely-not-grype-xyz")
    with pytest.raises(GrypeNotFoundError):
        list(adapter.run(tmp_path / "sbom.json"))
