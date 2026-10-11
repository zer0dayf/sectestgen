import json
from pathlib import Path

import pytest

from sectestgen.adapters.cyclonedx import CycloneDXAdapter, load_sbom, normalize_purl
from sectestgen.core.models import Pipeline, Severity

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
PY_SBOM = FIXTURES / "sca_python" / "sbom.cdx.json"
JAVA_SBOM = FIXTURES / "sca_java" / "sbom.cdx.json"


def test_load_sbom_indexes_components_by_purl():
    sbom = load_sbom(PY_SBOM)

    pyyaml = sbom.find("pkg:pypi/PyYAML@5.3.1")
    assert pyyaml is not None
    assert pyyaml.name == "PyYAML"
    assert pyyaml.ecosystem == "pypi"


def test_load_sbom_splits_direct_and_transitive():
    sbom = load_sbom(PY_SBOM)

    assert sbom.find("pkg:pypi/requests@2.19.1").direct is True
    urllib3 = sbom.find("pkg:pypi/urllib3@1.23")
    assert urllib3.direct is False
    assert urllib3.parents == ["pkg:pypi/requests@2.19.1"]


def test_load_sbom_without_dependency_graph_leaves_direct_unknown(tmp_path):
    doc = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "components": [{"name": "x", "version": "1", "purl": "pkg:pypi/x@1"}],
    }
    path = tmp_path / "bom.json"
    path.write_text(json.dumps(doc), encoding="utf-8")

    assert load_sbom(path).find("pkg:pypi/x@1").direct is None


def test_load_sbom_rejects_non_cyclonedx(tmp_path):
    path = tmp_path / "spdx.json"
    path.write_text(json.dumps({"spdxVersion": "SPDX-2.3"}), encoding="utf-8")

    with pytest.raises(ValueError):
        load_sbom(path)


def test_normalize_purl_drops_qualifiers_and_case_for_pypi():
    assert normalize_purl("pkg:pypi/PyYAML@5.3.1?extra=x#sub") == "pkg:pypi/pyyaml@5.3.1"
    assert normalize_purl("pkg:maven/org.A/b@1?type=jar") == "pkg:maven/org.A/b@1"


def test_cyclonedx_adapter_normalizes_embedded_vulnerabilities():
    findings = {f.cve: f for f in CycloneDXAdapter().run(JAVA_SBOM)}

    assert set(findings) == {"CVE-2021-44228", "CVE-2022-42889", "CVE-2019-12384"}
    log4shell = findings["CVE-2021-44228"]
    assert log4shell.pipeline is Pipeline.SCA
    assert log4shell.purl == "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"
    assert log4shell.severity is Severity.CRITICAL
    assert log4shell.fixed_version == "2.15.0"
    assert log4shell.raw["cvss_score"] == 10.0


def test_cyclonedx_adapter_yields_nothing_without_vulnerabilities():
    assert list(CycloneDXAdapter().run(PY_SBOM)) == []
