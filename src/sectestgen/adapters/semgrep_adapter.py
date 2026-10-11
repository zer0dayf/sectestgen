"""Semgrep StaticAnalyzerAdapter.

Defaults to this project's own rule packs (`rules/semgrep/`: FastAPI +
Spring) rather than the full `auto` registry config, so the pipeline is
deterministic and works offline. Extra registry configs (e.g. "p/python")
can be layered on by passing `config_paths` (local runner only).

Runners:
  - "local"  — the `semgrep` binary on PATH.
  - "docker" — the pinned `semgrep/semgrep` image, with `--network none`.
    The project's source files (see `iter_source_files`) and the rule files
    are copied into the container, nothing is mounted from the host. Used
    where the native binary can't run (e.g. blocked by Windows Application
    Control).
  - "auto"   — local, falling back to docker if the binary is missing or
    can't be executed.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tarfile
import tempfile
import uuid
from pathlib import Path, PurePosixPath
from typing import Iterable, Iterator, Sequence

from sectestgen.adapters.cwe_map import sink_type_for_cwe_strings
from sectestgen.core.adapters import StaticAnalyzerAdapter
from sectestgen.core.models import Finding, Pipeline, Severity, SourceLocation

RULES_DIR = Path(__file__).resolve().parent.parent.parent.parent / "rules" / "semgrep"
DEFAULT_RULES_PATHS = [RULES_DIR / "fastapi_security.yml", RULES_DIR / "spring_security.yml"]
DEFAULT_DOCKER_IMAGE = "semgrep/semgrep:1.179.0"
_CONTAINER_SRC = PurePosixPath("/src")
# Every rule in this project's own packs is named `sectestgen-*`. Semgrep
# prefixes local rule ids with a path-derived namespace that differs per
# runner/cwd, so the id is normalized to start at this marker.
_OWN_RULE_MARKER = "sectestgen-"
# Languages the project's rule packs cover. Only these are copied into the
# docker runner's container.
SOURCE_EXTENSIONS = frozenset({".py", ".java"})
# VCS metadata, dependency caches, virtualenvs and build output: never
# first-party source, often huge.
SKIPPED_DIRS = frozenset({
    ".git", ".hg", ".svn", ".idea", ".vscode", ".gradle", ".mvn",
    "node_modules", "target", "build", "dist", "out",
    ".venv", "venv", "env", "__pycache__", ".mypy_cache", ".pytest_cache", ".tox",
})


_RULES_KEY_RE = re.compile(rb"^rules\s*:", re.MULTILINE)


def iter_rule_files(root: Path) -> Iterator[Path]:
    """Semgrep rule files under `root`: YAML files with a top-level `rules:`
    key. Rule collections (e.g. a semgrep-rules checkout) also hold CI and
    tooling YAML, which Semgrep would reject as invalid config."""
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if not d.startswith("."))
        for filename in sorted(filenames):
            if os.path.splitext(filename)[1] not in (".yml", ".yaml"):
                continue
            path = Path(dirpath) / filename
            try:
                if _RULES_KEY_RE.search(path.read_bytes()):
                    yield path
            except OSError:
                continue


def iter_source_files(root: Path) -> Iterator[Path]:
    """Source files under `root` the docker runner scans, skipping
    `SKIPPED_DIRS` without descending into them."""
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIPPED_DIRS)
        for filename in sorted(filenames):
            if os.path.splitext(filename)[1] in SOURCE_EXTENSIONS:
                yield Path(dirpath) / filename

_SEVERITY_MAP = {
    "ERROR": Severity.HIGH,
    "WARNING": Severity.MEDIUM,
    "INFO": Severity.LOW,
}


class SemgrepNotFoundError(RuntimeError):
    """Raised when neither the `semgrep` binary nor docker is available."""


class SemgrepAdapter(StaticAnalyzerAdapter):
    def __init__(
        self,
        config_paths: Sequence[str | Path] | None = None,
        timeout: int = 300,
        binary: str = "semgrep",
        runner: str = "auto",
        docker_image: str = DEFAULT_DOCKER_IMAGE,
        docker_binary: str = "docker",
    ) -> None:
        if runner not in ("auto", "local", "docker"):
            raise ValueError(f"unknown semgrep runner {runner!r}")
        self.config_paths = (
            [str(p) for p in config_paths] if config_paths else [str(p) for p in DEFAULT_RULES_PATHS]
        )
        self.timeout = timeout
        self.binary = binary
        self.runner = runner
        self.docker_image = docker_image
        self.docker_binary = docker_binary
        self.used_runner: str | None = None
        self.staged_files: int | None = None  # files copied into the docker runner

    def run(self, target: Path) -> Iterable[Finding]:
        payload = self._scan(Path(target).resolve())
        for index, result in enumerate(payload.get("results", [])):
            yield self._to_finding(result, index)

    def _scan(self, target: Path) -> dict:
        local = shutil.which(self.binary) if self.runner in ("auto", "local") else None
        if local is not None:
            try:
                payload = self._run_local(local, target)
                self.used_runner = "local"
                return payload
            except OSError:
                # e.g. WinError 4551: the native binary is blocked by policy.
                if self.runner == "local":
                    raise
        elif self.runner == "local":
            raise SemgrepNotFoundError(f"'{self.binary}' not found on PATH; install semgrep.")

        docker = shutil.which(self.docker_binary)
        if docker is None:
            raise SemgrepNotFoundError(
                f"'{self.binary}' is not runnable and '{self.docker_binary}' is not on PATH; "
                "install semgrep or docker to run the static pipeline."
            )
        payload = self._run_docker(docker, target)
        self.used_runner = "docker"
        return payload

    def _run_local(self, binary_path: str, target: Path) -> dict:
        cmd = [binary_path, "scan", "--json", "--quiet", "--metrics=off", "--disable-version-check"]
        for cfg in self.config_paths:
            cmd += ["--config", cfg]
        cmd.append(str(target))
        return self._execute(cmd)

    def _run_docker(self, docker_path: str, target: Path) -> dict:
        """Copy only the source files into a fresh, network-less container and
        scan them on the container's own disk. Bind-mounting a Windows folder
        into Docker Desktop is slow enough per file access that walking a real
        project (with target/, .git/, ...) can take many minutes; a single tar
        stream of just the sources doesn't have that cost."""
        configs = [Path(cfg) for cfg in self.config_paths]
        for cfg in configs:
            if not (cfg.is_file() or cfg.is_dir()):
                raise RuntimeError(
                    "docker runner only supports local rule files/directories "
                    f"(it runs without network); got {str(cfg)!r}"
                )

        base_dir = target.parent if target.is_file() else target
        sources = [target] if target.is_file() else list(iter_source_files(target))
        self.staged_files = len(sources)
        if not sources:
            return {"results": [], "errors": []}

        name = f"sectestgen-semgrep-{uuid.uuid4().hex[:12]}"
        container_configs: list[str] = []
        with tempfile.TemporaryDirectory() as tmp:
            archive = Path(tmp) / "input.tar"
            with tarfile.open(archive, "w") as tar:
                for source in sources:
                    tar.add(source, arcname=f"src/{source.relative_to(base_dir).as_posix()}")
                for index, cfg in enumerate(configs):
                    if cfg.is_file():
                        arcname = f"rules/{index}_{cfg.name}"
                        tar.add(cfg, arcname=arcname)
                    else:
                        arcname = f"rules/{index}"
                        rule_files = list(iter_rule_files(cfg))
                        if not rule_files:
                            raise RuntimeError(f"no Semgrep rule files found under {str(cfg)!r}")
                        for rule_file in rule_files:
                            tar.add(rule_file, arcname=f"{arcname}/{rule_file.relative_to(cfg).as_posix()}")
                    container_configs += ["--config", f"/{arcname}"]

            try:
                self._docker_checked([
                    docker_path, "create", "--name", name, "--network", "none",
                    "-e", "SEMGREP_ENABLE_VERSION_CHECK=0",
                    self.docker_image, "semgrep", "scan", "--json", "--quiet", "--metrics=off",
                    "--disable-version-check", *container_configs, str(_CONTAINER_SRC),
                ])
                with archive.open("rb") as stream:
                    self._docker_checked([docker_path, "cp", "-", f"{name}:/"], stdin=stream)
                payload = self._execute([docker_path, "start", "--attach", name])
            finally:
                # Created containers aren't --rm, and on timeout only the CLI
                # client is killed, so always remove the container explicitly.
                subprocess.run([docker_path, "rm", "--force", name], capture_output=True, timeout=60)

        # Map container paths back onto the host so locations stay usable.
        for result in payload.get("results", []):
            path = PurePosixPath(result.get("path", ""))
            if path.is_relative_to(_CONTAINER_SRC):
                result["path"] = str(base_dir.joinpath(*path.relative_to(_CONTAINER_SRC).parts))
        return payload

    def _docker_checked(self, cmd: list[str], stdin=None) -> None:
        proc = subprocess.run(cmd, stdin=stdin, capture_output=True, timeout=self.timeout)
        if proc.returncode != 0:
            stderr = proc.stderr.decode("utf-8", errors="replace").strip()
            raise RuntimeError(f"docker {cmd[1]} failed (exit {proc.returncode}): {stderr}")

    def _execute(self, cmd: list[str]) -> dict:
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
        return json.loads(proc.stdout or "{}")

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
        if _OWN_RULE_MARKER in check_id:
            check_id = check_id[check_id.index(_OWN_RULE_MARKER):]

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
