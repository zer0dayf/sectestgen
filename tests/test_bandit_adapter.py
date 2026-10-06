import shutil
from pathlib import Path

import pytest

from sectestgen.adapters.bandit_adapter import BanditAdapter

FIXTURE = Path(__file__).resolve().parent.parent / "fixtures" / "vulnerable_fastapi"

pytestmark = pytest.mark.skipif(shutil.which("bandit") is None, reason="bandit not installed")


def test_finds_known_sink_categories_in_fixture():
    findings = list(BanditAdapter().run(FIXTURE))
    sink_types = {f.sink for f in findings if f.sink is not None}

    assert sink_types >= {"command_execution", "dynamic_evaluation", "unsafe_deserialization", "sql_injection"}


def test_finding_carries_severity_and_confidence():
    findings = list(BanditAdapter().run(FIXTURE))
    eval_finding = next(f for f in findings if f.rule_id == "B307")

    assert eval_finding.tool == "bandit"
    assert eval_finding.severity is not None
    assert eval_finding.confidence is not None
