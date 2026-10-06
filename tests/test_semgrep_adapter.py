import shutil
from pathlib import Path

import pytest

from sectestgen.adapters.semgrep_adapter import SemgrepAdapter

FIXTURE = Path(__file__).resolve().parent.parent / "fixtures" / "vulnerable_fastapi"

pytestmark = pytest.mark.skipif(shutil.which("semgrep") is None, reason="semgrep not installed")


def test_finds_all_five_sink_categories_in_fixture():
    findings = list(SemgrepAdapter().run(FIXTURE))
    sink_types = {f.sink for f in findings}

    assert sink_types == {
        "command_execution",
        "dynamic_evaluation",
        "unsafe_deserialization",
        "path_traversal",
        "sql_injection",
    }


def test_finding_carries_location_and_rule_id():
    findings = list(SemgrepAdapter().run(FIXTURE))
    eval_finding = next(f for f in findings if f.sink == "dynamic_evaluation" and f.location.line == 126)

    assert eval_finding.tool == "semgrep"
    assert eval_finding.rule_id == "rules.semgrep.sectestgen-dynamic-evaluation"
    assert eval_finding.location.file_path.endswith("app.py")
