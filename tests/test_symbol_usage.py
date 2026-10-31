import json

import pytest

from sectestgen.adapters.classifier import SCAClassifier
from sectestgen.adapters.package_usage import ImportUsageReachabilityEngine
from sectestgen.adapters.vulnerable_symbols import VulnerableSymbolDB
from sectestgen.core.models import Classification, Confidence, Finding, Pipeline

LOG4J = "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"
LOGGER_INFO = "org.apache.logging.log4j.Logger.info"


def _finding(purl: str, symbols: list[str]) -> Finding:
    return Finding(
        id="x",
        pipeline=Pipeline.SCA,
        tool="t",
        purl=purl,
        raw={"vulnerable_symbols": {"symbols": symbols, "sources": ["test"]}},
    )


def _run(finding: Finding, target, symbols: VulnerableSymbolDB | None = None) -> Finding:
    return SCAClassifier().classify(ImportUsageReachabilityEngine(symbols=symbols).analyze(finding, target))


def test_python_symbol_resolves_through_import_aliases(tmp_path):
    (tmp_path / "m.py").write_text(
        "import yaml as y\nfrom yaml import full_load as fl\ny.safe_load('a')\nfl('b')\n", encoding="utf-8"
    )
    finding = _run(_finding("pkg:pypi/pyyaml@5.3.1", ["yaml.full_load"]), tmp_path)

    assert finding.raw["usage"]["symbol_status"] == "symbol_referenced"
    assert finding.raw["usage"]["symbols"]["references"] == ["m.py:4 uses yaml.full_load"]
    assert finding.classification is Classification.POTENTIALLY_REACHABLE
    assert finding.confidence is Confidence.MEDIUM


def test_python_safe_api_is_not_the_vulnerable_symbol(tmp_path):
    (tmp_path / "m.py").write_text("import yaml\nyaml.safe_load('a')\n", encoding="utf-8")
    finding = _run(_finding("pkg:pypi/pyyaml@5.3.1", ["yaml.load", "yaml.full_load"]), tmp_path)

    assert finding.raw["usage"]["status"] == "referenced"
    assert finding.raw["usage"]["symbol_status"] == "symbol_not_referenced"
    assert finding.classification is Classification.POTENTIALLY_REACHABLE
    assert finding.confidence is Confidence.LOW
    assert "may still reach them" in finding.reachability.notes


def test_python_method_symbol_matches_its_class_with_a_label(tmp_path):
    (tmp_path / "m.py").write_text(
        "from jinja2.sandbox import SandboxedEnvironment\nenv = SandboxedEnvironment()\n", encoding="utf-8"
    )
    finding = _run(_finding("pkg:pypi/jinja2@2.10", ["jinja2.sandbox.SandboxedEnvironment.call"]), tmp_path)

    assert finding.raw["usage"]["symbols"]["references"] == [
        "m.py:2 uses class jinja2.sandbox.SandboxedEnvironment "
        "(call to jinja2.sandbox.SandboxedEnvironment.call not resolvable)"
    ]


def test_python_symbol_inside_route_is_reachable(tmp_path):
    (tmp_path / "app.py").write_text(
        "import yaml\nfrom fastapi import FastAPI\napp = FastAPI()\n\n"
        "@app.post('/p')\ndef p(doc: str):\n    return yaml.full_load(doc)\n",
        encoding="utf-8",
    )
    from sectestgen.adapters.fastapi_adapter import FastAPIFrameworkAdapter

    routes = list(FastAPIFrameworkAdapter().discover_routes(tmp_path))
    finding = _finding("pkg:pypi/pyyaml@5.3.1", ["yaml.full_load"])
    SCAClassifier().classify(ImportUsageReachabilityEngine(routes=routes).analyze(finding, tmp_path))

    assert finding.raw["usage"]["symbols"]["in_entry_point"] == ["app.py:7 uses yaml.full_load (in POST /p)"]
    assert finding.reachability.reachable is True
    assert finding.classification is Classification.REACHABLE
    assert finding.confidence is Confidence.MEDIUM


def test_java_symbol_resolves_through_declared_variable_type(tmp_path):
    (tmp_path / "Svc.java").write_text(
        "import org.apache.logging.log4j.Logger;\n"
        "class Svc {\n"
        "  private final Logger log;\n"
        "  void run(String s) { log.info(s); }\n"
        "}\n",
        encoding="utf-8",
    )
    finding = _run(_finding(LOG4J, [LOGGER_INFO]), tmp_path)

    assert finding.raw["usage"]["symbols"]["references"] == [f"Svc.java:4 uses {LOGGER_INFO}"]
    assert finding.raw["usage"]["symbol_status"] == "symbol_referenced"
    assert finding.reachability.reachable is None


def test_java_static_import_and_wildcard_import_resolve(tmp_path):
    (tmp_path / "A.java").write_text(
        "import org.apache.commons.text.*;\n"
        "import static org.apache.commons.text.lookup.StringLookupFactory.dnsStringLookup;\n"
        "@RestController\n"
        "class A {\n"
        "  Object a = StringSubstitutor.createInterpolator();\n"
        "  Object b = dnsStringLookup();\n"
        "}\n",
        encoding="utf-8",
    )
    finding = _run(
        _finding(
            "pkg:maven/org.apache.commons/commons-text@1.9",
            [
                "org.apache.commons.text.StringSubstitutor.createInterpolator",
                "org.apache.commons.text.lookup.StringLookupFactory.dnsStringLookup",
            ],
        ),
        tmp_path,
    )

    refs = finding.raw["usage"]["symbols"]["in_entry_point"]
    assert any("A.java:5" in r and "createInterpolator" in r for r in refs)
    assert any("A.java:6" in r and "dnsStringLookup" in r for r in refs)
    assert finding.classification is Classification.REACHABLE
    assert finding.reachability.reachable is True


def test_java_commented_out_symbol_call_is_ignored(tmp_path):
    (tmp_path / "A.java").write_text(
        "import org.apache.logging.log4j.Logger;\nclass A { Logger log; // log.info(x);\n}\n",
        encoding="utf-8",
    )
    finding = _run(_finding(LOG4J, [LOGGER_INFO]), tmp_path)

    assert finding.raw["usage"]["symbol_status"] == "symbol_not_referenced"


def test_not_imported_package_skips_symbol_analysis(tmp_path):
    (tmp_path / "m.py").write_text("import os\n", encoding="utf-8")
    finding = _run(_finding("pkg:pypi/pyyaml@5.3.1", ["yaml.load"]), tmp_path)

    assert finding.raw["usage"]["status"] == "not_imported"
    assert "symbol_status" not in finding.raw["usage"]
    assert finding.classification is Classification.NOT_OBSERVED


def test_curated_db_matches_on_advisory_and_package():
    db = VulnerableSymbolDB()
    log4j = Finding(id="a", pipeline=Pipeline.SCA, tool="t", purl=LOG4J, cve="CVE-2021-44228")
    other_package = Finding(id="b", pipeline=Pipeline.SCA, tool="t", purl="pkg:pypi/x@1", cve="CVE-2021-44228")
    unknown = Finding(id="c", pipeline=Pipeline.SCA, tool="t", purl=LOG4J, cve="CVE-0000-0000")

    symbols, sources = db.lookup(log4j)
    assert LOGGER_INFO in symbols and sources == ["curated"]
    assert db.lookup(other_package) == ([], [])
    assert db.lookup(unknown) == ([], [])


def test_provider_symbols_are_merged_with_curated_ones():
    finding = _finding(LOG4J, ["org.apache.logging.log4j.core.lookup.JndiLookup.lookup"])
    finding.cve = "CVE-2021-44228"

    symbols, sources = VulnerableSymbolDB().symbols_for(finding)

    assert symbols[0] == "org.apache.logging.log4j.core.lookup.JndiLookup.lookup"
    assert LOGGER_INFO in symbols
    assert sources == ["test", "curated"]


def test_user_symbols_file_is_loaded(tmp_path):
    path = tmp_path / "symbols.json"
    path.write_text(
        json.dumps([{"advisory": "GHSA-xxxx", "purl": "pkg:pypi/Some_Lib@9", "symbols": ["some_lib.danger"]}]),
        encoding="utf-8",
    )
    db = VulnerableSymbolDB.with_file(path)
    finding = Finding(id="x", pipeline=Pipeline.SCA, tool="t", purl="pkg:pypi/some-lib@1.0", rule_id="GHSA-xxxx")

    assert db.lookup(finding) == (["some_lib.danger"], ["file:symbols.json"])


@pytest.mark.parametrize("content", ['{"not": "a list"}', '[{"advisory": "CVE-1", "symbols": []}]'])
def test_bad_symbols_file_is_rejected(tmp_path, content):
    path = tmp_path / "symbols.json"
    path.write_text(content, encoding="utf-8")

    with pytest.raises(ValueError):
        VulnerableSymbolDB.with_file(path)
