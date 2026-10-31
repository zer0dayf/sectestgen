"""Classifiers: turn reachability/usage/runtime evidence into Classification/Confidence.

Static evidence alone never yields CONFIRMED. CONFIRMED (HIGH confidence)
is assigned only when the Docker SandboxExecutor observed the expected
behavior at runtime (`finding.runtime.observed is True`). A run that did
not observe it keeps the static classification - non-observation is not
proof of safety - but lowers a REACHABLE/POTENTIALLY_REACHABLE result to
LOW confidence, since the suspected behavior could not be triggered.
"""

from __future__ import annotations

from sectestgen.core.adapters import Classifier
from sectestgen.core.models import Classification, Confidence, Finding


def apply_runtime_evidence(finding: Finding) -> Finding:
    runtime = finding.runtime
    if runtime is None or runtime.observed is None:
        return finding
    if runtime.observed:
        finding.classification = Classification.CONFIRMED
        finding.confidence = Confidence.HIGH
    elif finding.classification in (Classification.REACHABLE, Classification.POTENTIALLY_REACHABLE):
        finding.confidence = Confidence.LOW
    return finding


class DefaultClassifier(Classifier):
    def classify(self, finding: Finding) -> Finding:
        self._classify_static(finding)
        return apply_runtime_evidence(finding)

    @staticmethod
    def _classify_static(finding: Finding) -> None:
        reachability = finding.reachability
        entry_point = bool(finding.raw.get("entry_point"))

        if reachability is None:
            finding.classification = Classification.INCONCLUSIVE
            finding.confidence = Confidence.LOW
        elif reachability.reachable is True:
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


class SCAClassifier(Classifier):
    """Turns `ImportUsageReachabilityEngine` evidence into Classification/Confidence.

    Package-level import/reference evidence never yields REACHABLE: only a
    known vulnerable symbol referenced inside an entry point does. A package
    that is referenced while none of its known vulnerable symbols are stays
    POTENTIALLY_REACHABLE at LOW confidence, because the package's own code
    may reach them. NOT_OBSERVED is "no use was observed", never "safe" — a
    transitive dependency keeps LOW confidence because its parent may still
    call it.
    """

    def classify(self, finding: Finding) -> Finding:
        self._classify_usage(finding)
        return apply_runtime_evidence(finding)

    @staticmethod
    def _classify_usage(finding: Finding) -> None:
        usage = finding.raw.get("usage") or {}
        status = usage.get("status")
        symbol_status = usage.get("symbol_status")

        if symbol_status == "symbol_referenced_in_entry_point":
            finding.classification = Classification.REACHABLE
            finding.confidence = Confidence.MEDIUM
        elif symbol_status == "symbol_referenced":
            finding.classification = Classification.POTENTIALLY_REACHABLE
            finding.confidence = Confidence.MEDIUM
        elif symbol_status == "symbol_not_referenced" and status in ("referenced_in_entry_point", "referenced"):
            finding.classification = Classification.POTENTIALLY_REACHABLE
            finding.confidence = Confidence.LOW
        elif status == "referenced_in_entry_point":
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
