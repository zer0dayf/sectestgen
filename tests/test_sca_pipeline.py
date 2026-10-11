import json
from pathlib import Path

from sectestgen.adapters.cyclonedx import CycloneDXAdapter
from sectestgen.adapters.grype_adapter import GrypeAdapter
from sectestgen.core.models import Finding, Pipeline
from sectestgen.pipeline import deduplicate_sca, run_sca_pipeline

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
PY = FIXTURES / "sca_python"
JAVA = FIXTURES / "sca_java"


def test_java_pipeline_deduplicates_cyclonedx_and_grype(tmp_path):
    result = run_sca_pipeline(JAVA / "sbom.cdx.json", JAVA, tmp_path, grype_report=JAVA / "grype.json")

    assert result.errors == []
    by_cve = {f.cve: f for f in result.findings}
    assert set(by_cve) == {"CVE-2021-44228", "CVE-2022-42889", "CVE-2019-12384"}
    assert by_cve["CVE-2021-44228"].raw["also_reported_by"] == ["grype"]
    assert "also_reported_by" not in by_cve["CVE-2019-12384"].raw


def test_python_pipeline_writes_report2(tmp_path):
    result = run_sca_pipeline(PY / "sbom.cdx.json", PY, tmp_path, grype_report=PY / "grype.json")

    payload = json.loads((tmp_path / "report2.json").read_text(encoding="utf-8"))
    assert len(payload) == 4
    assert all(item["pipeline"] == "sca" for item in payload)
    html = (tmp_path / "report2.html").read_text(encoding="utf-8")
    assert "Report 2" in html
    assert "CVE-2020-14343" in html
    assert result.counts_by_classification() == {"POTENTIALLY_REACHABLE": 1, "NOT_OBSERVED": 3}


def test_bad_sbom_is_reported_not_raised(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{}", encoding="utf-8")

    result = run_sca_pipeline(bad, tmp_path, tmp_path / "out")

    assert result.findings == []
    assert result.errors and result.errors[0].startswith("SBOM:")


def test_failing_provider_does_not_sink_the_run(tmp_path):
    adapters = [GrypeAdapter(binary="definitely-not-grype-xyz"), CycloneDXAdapter()]

    result = run_sca_pipeline(JAVA / "sbom.cdx.json", JAVA, adapters=adapters)

    assert len(result.findings) == 3
    assert any("GrypeAdapter" in e for e in result.errors)


def test_deduplicate_keeps_distinct_advisories_on_same_package():
    def f(tool, cve):
        return Finding(id=f"{tool}{cve}", pipeline=Pipeline.SCA, tool=tool, purl="pkg:pypi/x@1", cve=cve)

    kept = deduplicate_sca([f("grype", "CVE-1"), f("cyclonedx", "CVE-1"), f("grype", "CVE-2")])

    assert [k.cve for k in kept] == ["CVE-1", "CVE-2"]
    assert kept[0].raw["also_reported_by"] == ["cyclonedx"]
