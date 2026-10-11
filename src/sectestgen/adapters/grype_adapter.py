"""Grype SCAAdapter.

Reads a Grype JSON report (`grype ... -o json`). If no pre-generated report
is given, runs `grype sbom:<sbom> -o json` from `PATH` instead. Grype often
reports GitHub advisory ids (GHSA-...); the matching CVE is taken from
`relatedVulnerabilities` so findings from different tools can be
de-duplicated on CVE.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Iterable

from sectestgen.adapters.cyclonedx import severity_from_text
from sectestgen.core.adapters import SCAAdapter
from sectestgen.core.models import Finding, Pipeline


class GrypeNotFoundError(RuntimeError):
    """Raised when no report is given and the `grype` binary isn't on PATH."""


class GrypeAdapter(SCAAdapter):
    def __init__(self, report: Path | None = None, timeout: int = 300, binary: str = "grype") -> None:
        self.report = Path(report) if report is not None else None
        self.timeout = timeout
        self.binary = binary

    def run(self, sbom: Path) -> Iterable[Finding]:
        payload = self._load_report() if self.report is not None else self._scan(sbom)
        for match in payload.get("matches", []):
            yield self._to_finding(match)

    def _load_report(self) -> dict:
        return json.loads(self.report.read_text(encoding="utf-8-sig"))

    def _scan(self, sbom: Path) -> dict:
        binary_path = shutil.which(self.binary)
        if binary_path is None:
            raise GrypeNotFoundError(
                f"'{self.binary}' not found on PATH; install grype or pass a pre-generated report."
            )
        cmd = [binary_path, f"sbom:{sbom}", "-o", "json", "-q"]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout)
        if proc.returncode != 0:
            raise RuntimeError(f"grype failed (exit {proc.returncode}): {proc.stderr.strip()}")
        return json.loads(proc.stdout)

    def _to_finding(self, match: dict) -> Finding:
        vuln = match.get("vulnerability", {})
        artifact = match.get("artifact", {})
        vuln_id = vuln.get("id", "unknown")
        related = [r.get("id", "") for r in match.get("relatedVulnerabilities", [])]
        cve = vuln_id if vuln_id.startswith("CVE-") else next(
            (r for r in related if r.startswith("CVE-")), None
        )
        fix = vuln.get("fix", {})
        fixed_versions = fix.get("versions") or []
        scores = [c.get("metrics", {}).get("baseScore") for c in vuln.get("cvss", [])]
        scores = [s for s in scores if s is not None]

        return Finding(
            id=f"grype:{vuln_id}:{artifact.get('purl')}",
            pipeline=Pipeline.SCA,
            tool="grype",
            title=f"{cve or vuln_id} in {artifact.get('name')}@{artifact.get('version')}",
            description=vuln.get("description", ""),
            severity=severity_from_text(vuln.get("severity")),
            rule_id=vuln_id,
            package_name=artifact.get("name"),
            package_version=artifact.get("version"),
            purl=artifact.get("purl"),
            cve=cve,
            fixed_version=fixed_versions[0] if fixed_versions else None,
            raw={"match": match, "cvss_score": max(scores) if scores else None},
        )
