"""Adapter contracts that keep the core evidence model independent of any
specific analyzer, framework, SCA provider, or reporting format.

Concrete implementations live under `sectestgen.adapters.*` and are added
incrementally (Semgrep/Bandit/CodeQL for WP1, Dependency-Track/Snyk/Grype
for WP2, ...) without changing anything in `sectestgen.core`.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Iterable

from sectestgen.core.models import Finding


class StaticAnalyzerAdapter(ABC):
    """Runs a SAST tool (Semgrep, Bandit, CodeQL) and yields normalized Findings."""

    @abstractmethod
    def run(self, target: Path) -> Iterable[Finding]: ...


class SCAAdapter(ABC):
    """Reads a dependency-vulnerability source (Dependency-Track, Snyk, Grype)."""

    @abstractmethod
    def run(self, sbom: Path) -> Iterable[Finding]: ...


class FrameworkAdapter(ABC):
    """Discovers routes, user-input sources, and entry points for a web framework."""

    @abstractmethod
    def discover_routes(self, target: Path) -> Iterable[dict]: ...


class ReachabilityEngine(ABC):
    """Decides whether a sink is connected to a framework entry point."""

    @abstractmethod
    def analyze(self, finding: Finding, target: Path) -> Finding: ...


class SandboxExecutor(ABC):
    """Validates a finding inside a network-isolated, resource-limited container."""

    @abstractmethod
    def execute(self, finding: Finding, target: Path) -> Finding: ...


class Classifier(ABC):
    """Assigns the final Classification/Confidence based on all collected evidence."""

    @abstractmethod
    def classify(self, finding: Finding) -> Finding: ...


class Reporter(ABC):
    """Renders findings into an output format (HTML, JSON, SARIF)."""

    @abstractmethod
    def generate(self, findings: Iterable[Finding], output_path: Path) -> Path: ...
