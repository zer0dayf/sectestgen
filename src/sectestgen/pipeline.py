"""Static pipeline orchestration (WP1): Semgrep/Bandit -> FastAPI source/sink
correlation -> bounded reachability -> classification -> Report 1.

Kept separate from `cli.py` so the pipeline is testable without going
through argparse.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from sectestgen.adapters.bandit_adapter import BanditAdapter
from sectestgen.adapters.classifier import DefaultClassifier
from sectestgen.adapters.fastapi_adapter import FastAPIFrameworkAdapter
from sectestgen.adapters.reachability import BoundedReachabilityEngine
from sectestgen.adapters.reporter import HTMLReporter, JSONReporter
from sectestgen.adapters.semgrep_adapter import SemgrepAdapter
from sectestgen.core.adapters import StaticAnalyzerAdapter
from sectestgen.core.models import Finding


@dataclass
class StaticPipelineResult:
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
) -> StaticPipelineResult:
    target = Path(target).resolve()
    analyzers = analyzers if analyzers is not None else [SemgrepAdapter(), BanditAdapter()]

    routes = list(FastAPIFrameworkAdapter().discover_routes(target))

    findings: list[Finding] = []
    errors: list[str] = []
    for analyzer in analyzers:
        try:
            findings.extend(analyzer.run(target))
        except Exception as exc:  # noqa: BLE001 - one analyzer failing shouldn't sink the run
            errors.append(f"{type(analyzer).__name__}: {exc}")

    reachability_engine = BoundedReachabilityEngine(routes)
    classifier = DefaultClassifier()
    for finding in findings:
        reachability_engine.analyze(finding, target)
        classifier.classify(finding)

    result = StaticPipelineResult(findings=findings, routes=routes, errors=errors)

    if output_dir is not None:
        output_dir = Path(output_dir)
        result.report_json = JSONReporter().generate(findings, output_dir / "report1.json")
        result.report_html = HTMLReporter().generate(findings, output_dir / "report1.html")

    return result
