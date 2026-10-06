"""Default Classifier: turns reachability evidence into Classification/Confidence.

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
