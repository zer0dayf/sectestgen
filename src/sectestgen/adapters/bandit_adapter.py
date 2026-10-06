"""Bandit StaticAnalyzerAdapter."""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Iterable

from sectestgen.adapters.cwe_map import sink_type_for_cwe_id
from sectestgen.core.adapters import StaticAnalyzerAdapter
from sectestgen.core.models import Confidence, Finding, Pipeline, Severity, SourceLocation

# Bandit's own `issue_cwe` is occasionally imprecise (e.g. B307/eval is
# tagged CWE-78 "OS Command Injection" instead of CWE-95). Its `test_id` is
# unambiguous, so known test ids are checked first and the CWE mapping is
# only a fallback for test ids not listed here.
_TEST_ID_SINK_TYPES = {
    "B307": "dynamic_evaluation",  # eval
    "B102": "dynamic_evaluation",  # exec_used
    "B301": "unsafe_deserialization",  # pickle.loads
    "B403": "unsafe_deserialization",  # import pickle
    "B608": "sql_injection",  # hardcoded SQL expressions
    "B602": "command_execution",
    "B603": "command_execution",
    "B604": "command_execution",
    "B605": "command_execution",
    "B606": "command_execution",
    "B607": "command_execution",
    "B609": "command_execution",
}

_SEVERITY_MAP = {
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}
_CONFIDENCE_MAP = {
    "HIGH": Confidence.HIGH,
    "MEDIUM": Confidence.MEDIUM,
    "LOW": Confidence.LOW,
}


class BanditNotFoundError(RuntimeError):
    """Raised when the `bandit` binary isn't on PATH."""


class BanditAdapter(StaticAnalyzerAdapter):
    def __init__(self, timeout: int = 60, binary: str = "bandit") -> None:
        self.timeout = timeout
        self.binary = binary

    def run(self, target: Path) -> Iterable[Finding]:
        binary_path = shutil.which(self.binary)
        if binary_path is None:
            raise BanditNotFoundError(
                f"'{self.binary}' not found on PATH; install bandit to run the static pipeline."
            )

        with tempfile.TemporaryDirectory() as tmp_dir:
            out_file = Path(tmp_dir) / "bandit.json"
            cmd = [binary_path, "-r", "-f", "json", "-o", str(out_file), "-q", str(target)]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout)
            if proc.returncode not in (0, 1):
                raise RuntimeError(f"bandit failed (exit {proc.returncode}): {proc.stderr.strip()}")
            # Bandit writes its JSON file with a UTF-8 BOM on this toolchain.
            payload = json.loads(out_file.read_text(encoding="utf-8-sig"))

        for index, result in enumerate(payload.get("results", [])):
            yield self._to_finding(result, index)

    def _to_finding(self, result: dict, index: int) -> Finding:
        test_id = result.get("test_id", "bandit-unknown")
        cwe = result.get("issue_cwe") or {}
        sink_type = _TEST_ID_SINK_TYPES.get(test_id) or sink_type_for_cwe_id(cwe.get("id"))

        return Finding(
            id=f"bandit:{test_id}:{result.get('filename')}:{result.get('line_number')}:{index}",
            pipeline=Pipeline.STATIC,
            tool="bandit",
            title=result.get("test_name", test_id),
            description=result.get("issue_text", ""),
            severity=_SEVERITY_MAP.get(result.get("issue_severity", "LOW"), Severity.LOW),
            confidence=_CONFIDENCE_MAP.get(result.get("issue_confidence", "LOW"), Confidence.LOW),
            rule_id=test_id,
            location=SourceLocation(
                file_path=result.get("filename", ""),
                line=result.get("line_number"),
            ),
            sink=sink_type,
            raw=result,
        )
