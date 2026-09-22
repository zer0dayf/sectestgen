"""Normalized finding/evidence schema shared by the static and SCA pipelines.

Every adapter (Semgrep, Bandit, CodeQL, Dependency-Track, Snyk, Grype, ...)
must translate its own output into a `Finding`. Downstream components
(reachability engine, sandbox executor, classifier, reporters) only ever
see this shape, so new tools can be added without touching the core.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class Pipeline(str, Enum):
    STATIC = "static"
    SCA = "sca"


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Confidence(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class Classification(str, Enum):
    CONFIRMED = "CONFIRMED"
    REACHABLE = "REACHABLE"
    POTENTIALLY_REACHABLE = "POTENTIALLY_REACHABLE"
    NOT_OBSERVED = "NOT_OBSERVED"
    INCONCLUSIVE = "INCONCLUSIVE"


@dataclass
class SourceLocation:
    file_path: str
    line: int | None = None
    column: int | None = None
    function: str | None = None


@dataclass
class ReachabilityEvidence:
    """Bounded source-to-sink reachability result (static pipeline)."""

    path: list[str] = field(default_factory=list)
    reachable: bool | None = None
    notes: str | None = None


@dataclass
class RuntimeEvidence:
    """Docker sandbox proof-of-concept execution result."""

    harness: str | None = None
    request: dict[str, Any] | None = None
    expected_behavior: str | None = None
    observed_behavior: str | None = None
    logs: str | None = None


@dataclass
class Finding:
    id: str
    pipeline: Pipeline
    tool: str
    title: str = ""
    description: str = ""
    severity: Severity = Severity.INFO
    confidence: Confidence = Confidence.LOW
    classification: Classification = Classification.INCONCLUSIVE

    # Static pipeline fields
    rule_id: str | None = None
    location: SourceLocation | None = None
    sink: str | None = None
    user_input_source: str | None = None
    reachability: ReachabilityEvidence | None = None

    # SCA pipeline fields
    package_name: str | None = None
    package_version: str | None = None
    purl: str | None = None
    cve: str | None = None
    fixed_version: str | None = None

    # Shared
    runtime: RuntimeEvidence | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    raw: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["pipeline"] = self.pipeline.value
        data["severity"] = self.severity.value
        data["confidence"] = self.confidence.value
        data["classification"] = self.classification.value
        data["created_at"] = self.created_at.isoformat()
        return data
