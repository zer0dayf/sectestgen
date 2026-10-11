"""Pipeline orchestration.

- Static (WP1): Semgrep/Bandit -> FastAPI/Spring source/sink correlation
  -> bounded Python/Java reachability -> classification -> Report 1.
- SCA (WP2): CycloneDX SBOM (+ embedded vulnerabilities) / Grype ->
  de-duplication on purl + CVE -> Python/Java import-usage evidence ->
  classification -> Report 2.

Kept separate from `cli.py` so the pipelines are testable without going
through argparse.
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass, field
from pathlib import Path

from sectestgen.adapters.bandit_adapter import BanditAdapter
from sectestgen.adapters.classifier import DefaultClassifier, SCAClassifier
from sectestgen.adapters.cyclonedx import CycloneDXAdapter, load_sbom, normalize_purl
from sectestgen.adapters.fastapi_adapter import FastAPIFrameworkAdapter
from sectestgen.adapters.grype_adapter import GrypeAdapter
from sectestgen.adapters.java_reachability import JavaReachabilityEngine
from sectestgen.adapters.package_usage import ImportUsageReachabilityEngine
from sectestgen.adapters.reachability import BoundedReachabilityEngine
from sectestgen.adapters.reporter import HTMLReporter, JSONReporter
from sectestgen.adapters.semgrep_adapter import DEFAULT_RULES_PATHS, SemgrepAdapter
from sectestgen.adapters.spring_adapter import SpringFrameworkAdapter
from sectestgen.core.adapters import SCAAdapter, StaticAnalyzerAdapter
from sectestgen.core.models import Finding, Pipeline


@dataclass
class PipelineResult:
    findings: list[Finding]
    routes: list[dict]
    report_json: Path | None = None
    report_html: Path | None = None
    errors: list[str] = field(default_factory=list)

    def counts_by_classification(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for finding in self.findings:
            counts[finding.classification.value] = counts.get(finding.classification.value, 0) + 1
        return counts


def run_static_pipeline(
    target: Path,
    output_dir: Path | None = None,
    analyzers: list[StaticAnalyzerAdapter] | None = None,
    extra_rules: list[Path] | None = None,
) -> PipelineResult:
    """`extra_rules`: additional Semgrep rule files/directories run alongside
    the project's own packs (ignored when `analyzers` is given)."""
    target = Path(target).resolve()
    if analyzers is None:
        rules = [*DEFAULT_RULES_PATHS, *(extra_rules or [])]
        analyzers = [SemgrepAdapter(config_paths=rules), BanditAdapter()]

    routes = [
        *FastAPIFrameworkAdapter().discover_routes(target),
        *SpringFrameworkAdapter().discover_routes(target),
    ]

    findings: list[Finding] = []
    errors: list[str] = []
    for analyzer in analyzers:
        try:
            findings.extend(analyzer.run(target))
        except Exception as exc:  # noqa: BLE001 - one analyzer failing shouldn't sink the run
            errors.append(f"{type(analyzer).__name__}: {exc}")

    python_engine = BoundedReachabilityEngine(routes)
    java_engine = JavaReachabilityEngine(routes)
    classifier = DefaultClassifier()
    for finding in findings:
        is_java = finding.location is not None and finding.location.file_path.endswith(".java")
        (java_engine if is_java else python_engine).analyze(finding, target)
        classifier.classify(finding)

    result = PipelineResult(findings=findings, routes=routes, errors=errors)

    if output_dir is not None:
        output_dir = Path(output_dir)
        result.report_json = JSONReporter().generate(findings, output_dir / "report1.json")
        result.report_html = HTMLReporter().generate(findings, output_dir / "report1.html")

    return result


def run_sca_pipeline(
    sbom: Path,
    source: Path,
    output_dir: Path | None = None,
    grype_report: Path | None = None,
    adapters: list[SCAAdapter] | None = None,
) -> PipelineResult:
    """`source` is the project the SBOM describes; it's only read, never run."""
    sbom = Path(sbom).resolve()
    source = Path(source).resolve()
    if adapters is None:
        adapters = [CycloneDXAdapter()]
        if grype_report is not None or shutil.which("grype"):
            adapters.append(GrypeAdapter(report=grype_report))

    errors: list[str] = []
    try:
        sbom_index = load_sbom(sbom)
    except (OSError, ValueError) as exc:
        sbom_index = None
        errors.append(f"SBOM: {exc}")

    findings: list[Finding] = []
    if sbom_index is not None:
        for adapter in adapters:
            try:
                findings.extend(adapter.run(sbom))
            except Exception as exc:  # noqa: BLE001 - one provider failing shouldn't sink the run
                errors.append(f"{type(adapter).__name__}: {exc}")
    findings = deduplicate_sca(findings)

    routes = list(FastAPIFrameworkAdapter().discover_routes(source)) if source.exists() else []
    usage_engine = ImportUsageReachabilityEngine(sbom_index, routes)
    classifier = SCAClassifier()
    for finding in findings:
        usage_engine.analyze(finding, source)
        classifier.classify(finding)

    result = PipelineResult(findings=findings, routes=routes, errors=errors)

    if output_dir is not None:
        output_dir = Path(output_dir)
        result.report_json = JSONReporter().generate(findings, output_dir / "report2.json")
        result.report_html = HTMLReporter(Pipeline.SCA).generate(findings, output_dir / "report2.html")

    return result


def deduplicate_sca(findings: list[Finding]) -> list[Finding]:
    """One finding per (package, advisory). The first provider's finding is
    kept; later providers are recorded in raw["also_reported_by"] so the
    provenance isn't lost. Advisories are matched on CVE when both sides
    have one, else on the provider's own id."""
    kept: dict[tuple[str, str], Finding] = {}
    for finding in findings:
        key = (normalize_purl(finding.purl or finding.package_name or ""), finding.cve or finding.rule_id or "")
        existing = kept.get(key)
        if existing is None:
            kept[key] = finding
            continue
        also = existing.raw.setdefault("also_reported_by", [])
        if finding.tool != existing.tool and finding.tool not in also:
            also.append(finding.tool)
        existing.fixed_version = existing.fixed_version or finding.fixed_version
    return list(kept.values())
