from sectestgen.adapters.classifier import DefaultClassifier
from sectestgen.core.models import Classification, Confidence, Finding, Pipeline, ReachabilityEvidence


def _finding(reachable: bool | None, entry_point: bool) -> Finding:
    finding = Finding(id="t", pipeline=Pipeline.STATIC, tool="test")
    finding.reachability = ReachabilityEvidence(reachable=reachable)
    finding.raw["entry_point"] = entry_point
    return finding


def test_reachable_true_becomes_reachable_classification():
    finding = DefaultClassifier().classify(_finding(True, True))
    assert finding.classification == Classification.REACHABLE
    assert finding.confidence == Confidence.MEDIUM


def test_reachable_false_becomes_not_observed():
    finding = DefaultClassifier().classify(_finding(False, True))
    assert finding.classification == Classification.NOT_OBSERVED


def test_ambiguous_with_entry_point_becomes_potentially_reachable():
    finding = DefaultClassifier().classify(_finding(None, True))
    assert finding.classification == Classification.POTENTIALLY_REACHABLE
    assert finding.confidence == Confidence.LOW


def test_ambiguous_without_entry_point_becomes_inconclusive():
    finding = DefaultClassifier().classify(_finding(None, False))
    assert finding.classification == Classification.INCONCLUSIVE


def test_missing_reachability_evidence_becomes_inconclusive():
    finding = Finding(id="t", pipeline=Pipeline.STATIC, tool="test")
    finding = DefaultClassifier().classify(finding)
    assert finding.classification == Classification.INCONCLUSIVE


def test_never_assigns_confirmed():
    for reachable in (True, False, None):
        for entry_point in (True, False):
            finding = DefaultClassifier().classify(_finding(reachable, entry_point))
            assert finding.classification != Classification.CONFIRMED
