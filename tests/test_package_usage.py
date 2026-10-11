import json
from pathlib import Path

import pytest

from sectestgen.adapters.classifier import SCAClassifier
from sectestgen.adapters.cyclonedx import CycloneDXAdapter, load_sbom
from sectestgen.adapters.fastapi_adapter import FastAPIFrameworkAdapter
from sectestgen.adapters.grype_adapter import GrypeAdapter
from sectestgen.adapters.package_usage import (
    ImportUsageReachabilityEngine,
    import_names_for,
    parse_purl,
)
from sectestgen.core.models import Classification, Confidence, Finding, Pipeline

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
PY = FIXTURES / "sca_python"
JAVA = FIXTURES / "sca_java"

# ground_truth.json describes usage in benchmark terms; the engine's status
# folds direct/transitive into `direct` and entry-point-or-not into status.
_STATUS_FOR_USAGE = {
    "direct_not_imported": "not_imported",
    "transitive_not_imported": "not_imported",
    "referenced_outside_entry_point": "referenced",
}


def _analyze(fixture: Path, findings: list[Finding]) -> dict[str, Finding]:
    sbom = load_sbom(fixture / "sbom.cdx.json")
    routes = list(FastAPIFrameworkAdapter().discover_routes(fixture))
    engine = ImportUsageReachabilityEngine(sbom, routes)
    classifier = SCAClassifier()
    return {f.cve: classifier.classify(engine.analyze(f, fixture)) for f in findings}


@pytest.mark.parametrize(
    "fixture, findings",
    [
        (PY, lambda: list(GrypeAdapter(report=PY / "grype.json").run(PY / "sbom.cdx.json"))),
        (JAVA, lambda: list(CycloneDXAdapter().run(JAVA / "sbom.cdx.json"))),
    ],
    ids=["python", "java"],
)
def test_matches_ground_truth(fixture, findings):
    results = _analyze(fixture, findings())
    truth = json.loads((fixture / "ground_truth.json").read_text(encoding="utf-8"))

    for entry in truth:
        finding = results[entry["cve"]]
        assert finding.raw["usage"]["status"] == _STATUS_FOR_USAGE.get(entry["usage"], entry["usage"])
        assert finding.classification.value == entry["expected_classification"], entry["cve"]
        assert finding.confidence.value == entry["expected_confidence"], entry["cve"]


def test_python_reference_inside_route_is_recorded_as_evidence():
    findings = list(GrypeAdapter(report=PY / "grype.json").run(PY / "sbom.cdx.json"))
    pyyaml = _analyze(PY, findings)["CVE-2020-14343"]

    assert pyyaml.raw["usage"]["status"] == "referenced_in_entry_point"
    assert any("app.py" in p and "POST /config/parse" in p for p in pyyaml.reachability.path)
    assert pyyaml.reachability.reachable is None


def test_transitive_not_imported_names_parent():
    findings = list(GrypeAdapter(report=PY / "grype.json").run(PY / "sbom.cdx.json"))
    urllib3 = _analyze(PY, findings)["CVE-2019-11324"]

    assert urllib3.raw["usage"]["direct"] is False
    assert "pkg:pypi/requests@2.19.1" in urllib3.reachability.notes


def test_java_controller_reference_is_entry_point_and_helper_is_not():
    results = _analyze(JAVA, list(CycloneDXAdapter().run(JAVA / "sbom.cdx.json")))

    assert results["CVE-2021-44228"].raw["usage"]["status"] == "referenced_in_entry_point"
    assert any("GreetingController.java" in p for p in results["CVE-2021-44228"].reachability.path)
    assert results["CVE-2022-42889"].raw["usage"]["status"] == "referenced"
    assert results["CVE-2019-12384"].raw["usage"]["status"] == "not_imported"


def test_java_comments_are_not_counted_as_references(tmp_path):
    (tmp_path / "A.java").write_text(
        "import org.yaml.snakeyaml.Yaml;\n// new Yaml()\n/* Yaml\n Yaml */\nclass A {}\n",
        encoding="utf-8",
    )
    finding = Finding(id="x", pipeline=Pipeline.SCA, tool="t", purl="pkg:maven/org.yaml/snakeyaml@1.26")

    ImportUsageReachabilityEngine().analyze(finding, tmp_path)

    assert finding.raw["usage"]["status"] == "imported_only"


def test_python_from_import_alias_counts_as_reference(tmp_path):
    (tmp_path / "m.py").write_text("from yaml import load as L\nL('x')\n", encoding="utf-8")
    finding = Finding(id="x", pipeline=Pipeline.SCA, tool="t", purl="pkg:pypi/pyyaml@5.3.1")

    ImportUsageReachabilityEngine().analyze(finding, tmp_path)

    assert finding.raw["usage"]["status"] == "referenced"


def test_unsupported_ecosystem_is_inconclusive(tmp_path):
    finding = Finding(id="x", pipeline=Pipeline.SCA, tool="t", purl="pkg:npm/lodash@4.17.15")

    SCAClassifier().classify(ImportUsageReachabilityEngine().analyze(finding, tmp_path))

    assert finding.raw["usage"]["status"] == "unsupported"
    assert finding.classification is Classification.INCONCLUSIVE


def test_no_sources_is_inconclusive_not_safe(tmp_path):
    finding = Finding(id="x", pipeline=Pipeline.SCA, tool="t", purl="pkg:pypi/requests@2.19.1")

    SCAClassifier().classify(ImportUsageReachabilityEngine().analyze(finding, tmp_path))

    assert finding.raw["usage"]["status"] == "no_sources"
    assert finding.classification is Classification.INCONCLUSIVE


def test_heuristic_mapping_caps_confidence_at_low(tmp_path):
    (tmp_path / "Ctl.java").write_text(
        "import org.acme.lib.Thing;\n@RestController\nclass Ctl { Thing t; }\n", encoding="utf-8"
    )
    finding = Finding(id="x", pipeline=Pipeline.SCA, tool="t", purl="pkg:maven/org.acme/lib@1.0")

    SCAClassifier().classify(ImportUsageReachabilityEngine().analyze(finding, tmp_path))

    assert finding.raw["usage"]["mapping"] == "heuristic"
    assert finding.classification is Classification.POTENTIALLY_REACHABLE
    assert finding.confidence is Confidence.LOW


def test_import_names_and_purl_parsing():
    assert import_names_for("pkg:pypi/PyYAML@5.3.1") == (["yaml"], "table")
    assert import_names_for("pkg:pypi/some_lib@1") == (["some_lib"], "name-convention")
    assert import_names_for("pkg:maven/org.apache.commons/commons-text@1.9") == (
        ["org.apache.commons.text"],
        "table",
    )
    ref = parse_purl("pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1?type=jar")
    assert (ref.ecosystem, ref.namespace, ref.name) == ("maven", "org.apache.logging.log4j", "log4j-core")
