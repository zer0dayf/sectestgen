"""Classifiers: turn reachability/usage evidence into Classification/Confidence.

CONFIRMED is intentionally never assigned here — it requires runtime
evidence from the Docker SandboxExecutor (WP3), not static reachability
alone.
"""

from __future__ import annotations

from sectestgen.core.adapters import Classifier
from sectestgen.core.models import Classification, Confidence, Finding


class DefaultClassifier(Classifier):
    def classify(self, finding: Finding) -> Finding:
        reachability = finding.reachability
        entry_point = bool(finding.raw.get("entry_point"))

        if reachability is None:
            finding.classification = Classification.INCONCLUSIVE
            finding.confidence = Confidence.LOW
            return finding

        if reachability.reachable is True:
            finding.classification = Classification.REACHABLE
            finding.confidence = Confidence.MEDIUM
        elif reachability.reachable is False:
            finding.classification = Classification.NOT_OBSERVED
            finding.confidence = Confidence.MEDIUM
        elif entry_point:
            finding.classification = Classification.POTENTIALLY_REACHABLE
            finding.confidence = Confidence.LOW
        else:
            finding.classification = Classification.INCONCLUSIVE
            finding.confidence = Confidence.LOW

        return finding


class SCAClassifier(Classifier):
    """Turns `ImportUsageReachabilityEngine` evidence into Classification/Confidence.

    Import/reference evidence never yields REACHABLE or CONFIRMED: without
    vulnerable-symbol metadata it can't show the vulnerable code path runs.
    NOT_OBSERVED is "no use was observed", never "safe" — a transitive
    dependency keeps LOW confidence because its parent may still call it.
    """

    def classify(self, finding: Finding) -> Finding:
        usage = finding.raw.get("usage") or {}
        status = usage.get("status")

        if status == "referenced_in_entry_point":
            finding.classification = Classification.POTENTIALLY_REACHABLE
            finding.confidence = Confidence.MEDIUM
        elif status == "referenced":
            finding.classification = Classification.POTENTIALLY_REACHABLE
            finding.confidence = Confidence.LOW
        elif status == "imported_only":
            finding.classification = Classification.NOT_OBSERVED
            finding.confidence = Confidence.LOW
        elif status == "not_imported":
            finding.classification = Classification.NOT_OBSERVED
            finding.confidence = Confidence.MEDIUM if usage.get("direct") is True else Confidence.LOW
        else:
            finding.classification = Classification.INCONCLUSIVE
            finding.confidence = Confidence.LOW

        if usage.get("mapping") == "heuristic" and finding.confidence is Confidence.MEDIUM:
            finding.confidence = Confidence.LOW
        return finding
