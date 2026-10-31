"""Snyk SCAAdapter.

Reads a pre-generated `snyk test --json` report (a single project object,
or the list `--all-projects` writes). Snyk is never run from here: the CLI
needs an account and uploads the dependency graph to Snyk's service, which
the pipeline must not do on its own. Run it yourself and pass the report.

Snyk repeats a vulnerability once per dependency path (`from`), so entries
are collapsed on (Snyk id, package) with the paths kept as evidence. Snyk
reports no purl; one is built from `packageManager` + `packageName` so the
findings de-duplicate against CycloneDX/Grype. Snyk's vulnerable-function
metadata (`functions`/`functions_new`), when present, is kept as
`raw["vulnerable_symbols"]` for the usage engine.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable
from urllib.parse import quote

from sectestgen.adapters.cyclonedx import severity_from_text
from sectestgen.core.adapters import SCAAdapter
from sectestgen.core.models import Finding, Pipeline

_PURL_TYPES = {
    "pip": "pypi",
    "pipenv": "pypi",
    "poetry": "pypi",
    "maven": "maven",
    "gradle": "maven",
    "sbt": "maven",
    "npm": "npm",
    "yarn": "npm",
    "pnpm": "npm",
}


class SnykAdapter(SCAAdapter):
    def __init__(self, report: Path) -> None:
        self.report = Path(report)

    def run(self, sbom: Path) -> Iterable[Finding]:
        payload = json.loads(self.report.read_text(encoding="utf-8-sig"))
        projects = payload if isinstance(payload, list) else [payload]

        kept: dict[tuple[str, str], Finding] = {}
        for project in projects:
            if not project.get("vulnerabilities") and project.get("error"):
                raise ValueError(f"Snyk report contains an error: {project['error']}")
            manager = project.get("packageManager")
            for vuln in project.get("vulnerabilities", []):
                finding = self._to_finding(vuln, vuln.get("packageManager") or manager)
                key = (finding.rule_id or "", finding.purl or finding.package_name or "")
                existing = kept.get(key)
                if existing is None:
                    kept[key] = finding
                else:
                    existing.raw["paths"].extend(p for p in finding.raw["paths"] if p not in existing.raw["paths"])
                    existing.raw["direct"] = existing.raw["direct"] or finding.raw["direct"]
        return list(kept.values())

    def _to_finding(self, vuln: dict, manager: str | None) -> Finding:
        vuln_id = vuln.get("id", "unknown")
        name = vuln.get("packageName") or vuln.get("moduleName") or ""
        version = vuln.get("version")
        purl = build_purl(manager, name, version)
        cves = (vuln.get("identifiers") or {}).get("CVE") or []
        fixed_in = vuln.get("fixedIn") or []
        path = vuln.get("from") or []

        raw: dict = {
            "vulnerability": vuln,
            "cvss_score": vuln.get("cvssScore"),
            "paths": [path] if path else [],
            # from[0] is the project itself, so a two-element path is a direct dependency.
            "direct": len(path) == 2 if path else None,
        }
        symbols = snyk_symbols(vuln, purl)
        if symbols:
            raw["vulnerable_symbols"] = {"symbols": symbols, "sources": ["snyk"]}

        return Finding(
            id=f"snyk:{vuln_id}:{purl or name}",
            pipeline=Pipeline.SCA,
            tool="snyk",
            title=f"{cves[0] if cves else vuln_id} in {name}@{version}",
            description=vuln.get("description") or vuln.get("title", ""),
            severity=severity_from_text(vuln.get("severity")),
            rule_id=vuln_id,
            package_name=name.split(":")[-1] if _PURL_TYPES.get(manager or "") == "maven" else name,
            package_version=version,
            purl=purl,
            cve=cves[0] if cves else None,
            fixed_version=fixed_in[0] if fixed_in else None,
            raw=raw,
        )


def build_purl(manager: str | None, name: str, version: str | None) -> str | None:
    purl_type = _PURL_TYPES.get((manager or "").lower())
    if purl_type is None or not name:
        return None
    suffix = f"@{version}" if version else ""
    if purl_type == "pypi":
        return f"pkg:pypi/{name.lower().replace('_', '-')}{suffix}"
    if purl_type == "maven":
        group, _, artifact = name.rpartition(":")
        if not group:
            return None
        return f"pkg:maven/{group}/{artifact}{suffix}"
    if name.startswith("@") and "/" in name:
        scope, _, package = name.partition("/")
        return f"pkg:npm/{quote(scope)}/{package}{suffix}"
    return f"pkg:npm/{name}{suffix}"


def snyk_symbols(vuln: dict, purl: str | None) -> list[str]:
    """Vulnerable functions from Snyk metadata as dotted symbols:
    `pkg.module.func` (Python, from the file path) or
    `com.acme.Class.method` (Java, from the class file path)."""
    symbols: list[str] = []
    for entry in [*(vuln.get("functions") or []), *(vuln.get("functions_new") or [])]:
        function_id = entry.get("functionId") or {}
        function = function_id.get("functionName")
        if not function:
            continue
        owner = _owner_from_path(function_id.get("filePath"), purl)
        class_name = function_id.get("className")
        if class_name and (owner is None or not owner.endswith("." + class_name)):
            owner = f"{owner}.{class_name}" if owner else class_name
        symbol = f"{owner}.{function}" if owner else function
        if symbol not in symbols:
            symbols.append(symbol)
    return symbols


def _owner_from_path(file_path: str | None, purl: str | None) -> str | None:
    if not file_path:
        return None
    path = file_path.replace("\\", "/").lstrip("/")
    for ext in (".py", ".java", ".class"):
        if path.endswith(ext):
            path = path[: -len(ext)]
            break
    if path.endswith("/__init__"):
        path = path[: -len("/__init__")]
    if purl and purl.startswith("pkg:maven/") and "/java/" in path:
        path = path.split("/java/", 1)[1]  # src/main/java/com/acme/X -> com/acme/X
    return path.replace("/", ".") or None
