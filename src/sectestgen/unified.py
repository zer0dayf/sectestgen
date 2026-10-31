"""Report 3: merge and de-duplicate static (Report 1) and SCA (Report 2) findings.

Findings are grouped into issues:

1. Static findings on the same file + line + sink type are one issue
   (e.g. Semgrep and Bandit flagging the same `pickle.loads`); findings
   without a sink type group on file + line + rule instead.
2. An SCA finding joins the static issue whose file + line is one of the
   call sites of its vulnerable symbol (e.g. CVE-2020-14343 joins the
   static `yaml.load` deserialization finding on the same line).
3. Remaining SCA findings group on package (purl) + advisory, as Report 2
   already does across providers.

An issue takes the strongest classification of its members (CONFIRMED >
REACHABLE > POTENTIALLY_REACHABLE > INCONCLUSIVE > NOT_OBSERVED), the
highest confidence among members with that classification, and the highest
severity. Members keep their own evidence; nothing is re-classified here.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from sectestgen.adapters.cyclonedx import normalize_purl
from sectestgen.core.models import Classification, Confidence, Finding, Pipeline, Severity

CLASSIFICATION_RANK = {
    Classification.CONFIRMED: 4,
    Classification.REACHABLE: 3,
    Classification.POTENTIALLY_REACHABLE: 2,
    Classification.INCONCLUSIVE: 1,
    Classification.NOT_OBSERVED: 0,
}
_CONFIDENCE_RANK = {Confidence.LOW: 0, Confidence.MEDIUM: 1, Confidence.HIGH: 2}
_SEVERITY_RANK = {Severity.INFO: 0, Severity.LOW: 1, Severity.MEDIUM: 2, Severity.HIGH: 3, Severity.CRITICAL: 4}


@dataclass
class Issue:
    id: str
    members: list[Finding] = field(default_factory=list)

    @property
    def classification(self) -> Classification:
        return max((m.classification for m in self.members), key=CLASSIFICATION_RANK.__getitem__)

    @property
    def confidence(self) -> Confidence:
        top = self.classification
        return max((m.confidence for m in self.members if m.classification is top), key=_CONFIDENCE_RANK.__getitem__)

    @property
    def severity(self) -> Severity:
        return max((m.severity for m in self.members), key=_SEVERITY_RANK.__getitem__)

    @property
    def location(self) -> str | None:
        for member in self.members:
            if member.location is not None and member.location.file_path:
                return f"{member.location.file_path}:{member.location.line}"
        return None

    @property
    def advisories(self) -> list[str]:
        values = [m.cve or m.rule_id for m in self.members if m.pipeline is Pipeline.SCA]
        return sorted({v for v in values if v})

    @property
    def title(self) -> str:
        static = [m for m in self.members if m.pipeline is Pipeline.STATIC]
        sca = [m for m in self.members if m.pipeline is Pipeline.SCA]
        parts = []
        if static:
            sink = next((m.sink for m in static if m.sink), None)
            parts.append(sink.replace("_", " ") if sink else static[0].rule_id or static[0].title)
        if sca:
            package = sca[0].package_name or sca[0].purl
            parts.append(f"{', '.join(self.advisories)} in {package}")
        return " / ".join(parts)

    def to_dict(self) -> dict[str, Any]:
        route = next((m.raw.get("route") for m in self.members if m.raw.get("route")), None)
        runtime = next((m.runtime for m in self.members if m.runtime and m.runtime.observed is not None), None)
        return {
            "id": self.id,
            "title": self.title,
            "classification": self.classification.value,
            "confidence": self.confidence.value,
            "severity": self.severity.value,
            "location": self.location,
            "route": route,
            "advisories": self.advisories,
            "pipelines": sorted({m.pipeline.value for m in self.members}),
            "tools": sorted({t for m in self.members for t in [m.tool, *m.raw.get("also_reported_by", [])]}),
            "runtime_observed": runtime.observed if runtime else None,
            "members": [m.to_dict() for m in self.members],
        }


def _site(file_path: str, line: int | None) -> tuple[str, int | None]:
    return (str(Path(file_path).resolve()), line)


def build_issues(static: Iterable[Finding], sca: Iterable[Finding]) -> list[Issue]:
    issues: list[Issue] = []
    by_static_key: dict[tuple, Issue] = {}
    by_site: dict[tuple[str, int | None], list[Issue]] = {}

    for finding in static:
        location = finding.location
        if location is None or not location.file_path:
            key = ("nolocation", finding.id)
        else:
            key = (*_site(location.file_path, location.line), finding.sink or f"rule:{finding.rule_id}")
        issue = by_static_key.get(key)
        if issue is None:
            issue = by_static_key[key] = Issue(id=f"issue-{len(issues) + 1}")
            issues.append(issue)
            if location is not None and location.file_path:
                by_site.setdefault(_site(location.file_path, location.line), []).append(issue)
        issue.members.append(finding)

    by_sca_key: dict[tuple, Issue] = {}
    for finding in sca:
        sites = ((finding.raw.get("usage") or {}).get("symbols") or {}).get("sites") or []
        matches = [i for s in sites for i in by_site.get(_site(s["file_path"], s["line"]), [])]
        # Prefer the static issue with the same sink type, else the first one on that line.
        target = next((i for i in matches if any(m.sink and m.sink == finding.sink for m in i.members)), None)
        target = target or (matches[0] if matches else None)
        if target is None:
            key = (normalize_purl(finding.purl or finding.package_name or ""), finding.cve or finding.rule_id or "")
            target = by_sca_key.get(key)
            if target is None:
                target = by_sca_key[key] = Issue(id=f"issue-{len(issues) + 1}")
                issues.append(target)
        target.members.append(finding)

    issues.sort(key=lambda i: (-CLASSIFICATION_RANK[i.classification], -_SEVERITY_RANK[i.severity], i.id))
    return issues
