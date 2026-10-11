"""CycloneDX SBOM reading + the CycloneDX `vulnerabilities` SCAAdapter.

CycloneDX is the canonical SBOM format (see proposal). `load_sbom` turns a
CycloneDX JSON document into a purl-keyed component index plus the
direct/transitive split from its `dependencies` graph; every SCA adapter
and the usage engine share that index.

`CycloneDXAdapter` normalizes a BOM's embedded `vulnerabilities` section,
which is the shape Dependency-Track exports (BOM/VEX download), so a
Dependency-Track result can be consumed offline as a file without talking
to a Dependency-Track server.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from sectestgen.core.adapters import SCAAdapter
from sectestgen.core.models import Finding, Pipeline, Severity

_SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "moderate": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
    "none": Severity.INFO,
    "unknown": Severity.INFO,
}


@dataclass
class Component:
    name: str
    version: str | None
    purl: str | None
    group: str | None = None
    bom_ref: str | None = None
    direct: bool | None = None  # None = the SBOM has no dependency graph
    parents: list[str] = field(default_factory=list)  # purls depending on this one

    @property
    def ecosystem(self) -> str | None:
        return purl_type(self.purl)


@dataclass
class SBOM:
    path: Path
    components: dict[str, Component]  # keyed by normalized purl
    raw: dict

    def find(self, purl: str | None) -> Component | None:
        if not purl:
            return None
        return self.components.get(normalize_purl(purl))


def normalize_purl(purl: str) -> str:
    """Drop qualifiers/subpath and lowercase pypi names so purls from
    different tools compare equal (`pkg:pypi/PyYAML@5.3.1?x=y` ->
    `pkg:pypi/pyyaml@5.3.1`)."""
    base = purl.split("#", 1)[0].split("?", 1)[0]
    if base.startswith("pkg:pypi/"):
        base = base.lower().replace("_", "-")
    return base


def purl_type(purl: str | None) -> str | None:
    if not purl or not purl.startswith("pkg:"):
        return None
    return purl[4:].split("/", 1)[0].lower()


def severity_from_text(value: str | None) -> Severity:
    return _SEVERITY_MAP.get((value or "").strip().lower(), Severity.INFO)


def load_sbom(path: Path) -> SBOM:
    path = Path(path)
    raw = json.loads(path.read_text(encoding="utf-8-sig"))
    if raw.get("bomFormat") != "CycloneDX":
        raise ValueError(f"{path} is not a CycloneDX JSON document")

    components: dict[str, Component] = {}
    by_ref: dict[str, Component] = {}
    for item in _walk_components(raw.get("components", [])):
        purl = item.get("purl")
        component = Component(
            name=item.get("name", ""),
            version=item.get("version"),
            purl=purl,
            group=item.get("group"),
            bom_ref=item.get("bom-ref"),
        )
        if purl:
            components[normalize_purl(purl)] = component
        if component.bom_ref:
            by_ref[component.bom_ref] = component

    root_ref = (raw.get("metadata", {}).get("component") or {}).get("bom-ref")
    graph = {d.get("ref"): d.get("dependsOn", []) for d in raw.get("dependencies", [])}
    if graph:
        direct_refs = set(graph.get(root_ref, []))
        for component in by_ref.values():
            component.direct = component.bom_ref in direct_refs
        for parent_ref, children in graph.items():
            parent = by_ref.get(parent_ref)
            for child_ref in children:
                child = by_ref.get(child_ref)
                if child is not None and parent is not None and parent.purl:
                    child.parents.append(parent.purl)

    return SBOM(path=path, components=components, raw=raw)


def _walk_components(items: list[dict]) -> Iterable[dict]:
    for item in items:
        yield item
        yield from _walk_components(item.get("components", []))


class CycloneDXAdapter(SCAAdapter):
    """Findings from a CycloneDX BOM's embedded `vulnerabilities` section."""

    def run(self, sbom: Path) -> Iterable[Finding]:
        document = load_sbom(sbom)
        by_ref = {c.bom_ref: c for c in document.components.values() if c.bom_ref}

        for vuln in document.raw.get("vulnerabilities", []):
            for affected in vuln.get("affects", []):
                component = by_ref.get(affected.get("ref"))
                if component is None:
                    continue
                yield self._to_finding(vuln, affected, component)

    def _to_finding(self, vuln: dict, affected: dict, component: Component) -> Finding:
        vuln_id = vuln.get("id", "unknown")
        ratings = vuln.get("ratings", [])
        top_rating = max(ratings, key=lambda r: r.get("score") or 0, default={})
        fixed = next(
            (v.get("version") for v in affected.get("versions", []) if v.get("status") == "unaffected"),
            None,
        )
        cve = vuln_id if vuln_id.startswith("CVE-") else _first_cve(
            [ref.get("id", "") for ref in vuln.get("references", [])]
        )

        return Finding(
            id=f"cyclonedx:{vuln_id}:{component.purl}",
            pipeline=Pipeline.SCA,
            tool="cyclonedx",
            title=f"{vuln_id} in {component.name}@{component.version}",
            description=vuln.get("description", ""),
            severity=severity_from_text(top_rating.get("severity")),
            rule_id=vuln_id,
            package_name=component.name,
            package_version=component.version,
            purl=component.purl,
            cve=cve,
            fixed_version=fixed,
            raw={"vulnerability": vuln, "cvss_score": top_rating.get("score")},
        )


def _first_cve(ids: list[str]) -> str | None:
    return next((i for i in ids if i.startswith("CVE-")), None)
