"""Semgrep StaticAnalyzerAdapter.

Defaults to this project's own FastAPI rule pack
(`rules/semgrep/fastapi_security.yml`) rather than the full `auto` registry
config, so the pipeline is deterministic and works offline. Extra registry
configs (e.g. "p/python") can be layered on by passing `config_paths`.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Iterable, Sequence

from sectestgen.adapters.cwe_map import sink_type_for_cwe_strings
from sectestgen.core.adapters import StaticAnalyzerAdapter
from sectestgen.core.models import Finding, Pipeline, Severity, SourceLocation

DEFAULT_RULES_PATH = Path(__file__).resolve().parent.parent.parent.parent / "rules" / "semgrep" / "fastapi_security.yml"

_SEVERITY_MAP = {
    "ERROR": Severity.HIGH,
    "WARNING": Severity.MEDIUM,
    "INFO": Severity.LOW,
}


class SemgrepNotFoundError(RuntimeError):
    """Raised when the `semgrep` binary isn't on PATH."""


class SemgrepAdapter(StaticAnalyzerAdapter):
    def __init__(
        self,
        config_paths: Sequence[str | Path] | None = None,
        timeout: int = 120,
        binary: str = "semgrep",
    ) -> None:
        self.config_paths = [str(p) for p in config_paths] if config_paths else [str(DEFAULT_RULES_PATH)]
        self.timeout = timeout
        self.binary = binary

    def run(self, target: Path) -> Iterable[Finding]:
        binary_path = shutil.which(self.binary)
        if binary_path is None:
            raise SemgrepNotFoundError(
                f"'{self.binary}' not found on PATH; install semgrep to run the static pipeline."
            )

        cmd = [binary_path, "scan", "--json", "--quiet", "--metrics=off"]
        for cfg in self.config_paths:
            cmd += ["--config", cfg]
        cmd.append(str(target))

        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=self.timeout,
            encoding="utf-8",
            errors="replace",
        )
        if proc.returncode not in (0, 1):  # 1 == findings present, still a clean run
            raise RuntimeError(f"semgrep failed (exit {proc.returncode}): {proc.stderr.strip()}")

        payload = json.loads(proc.stdout or "{}")
        for index, result in enumerate(payload.get("results", [])):
            yield self._to_finding(result, index)

    def _to_finding(self, result: dict, index: int) -> Finding:
        extra = result.get("extra", {})
        metadata = extra.get("metadata", {})
        start = result.get("start", {})
        # Multi-statement patterns (e.g. assign-then-use) span several lines;
        # the sink call itself is usually on the last line of the match.
        end = result.get("end", start)

        cwe_list = metadata.get("cwe")
        if isinstance(cwe_list, str):
            cwe_list = [cwe_list]
        sink_type = metadata.get("sink_type") or sink_type_for_cwe_strings(cwe_list)

        check_id = result.get("check_id", "semgrep-unknown")

        return Finding(
            id=f"semgrep:{check_id}:{result.get('path')}:{start.get('line')}:{index}",
            pipeline=Pipeline.STATIC,
            tool="semgrep",
            title=check_id,
            description=extra.get("message", ""),
            severity=_SEVERITY_MAP.get(extra.get("severity", "INFO"), Severity.INFO),
            rule_id=check_id,
            location=SourceLocation(
                file_path=result.get("path", ""),
                line=end.get("line", start.get("line")),
                column=end.get("col", start.get("col")),
            ),
            sink=sink_type,
            raw=result,
        )
