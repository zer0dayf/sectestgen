"""Docker SandboxExecutor: runtime validation of reachable findings.

Supported findings - a Python sink inside a discovered FastAPI route, with
a known user-input source and one of the five sink types - become cases
for `harness.py`. All cases of one target run in a single disposable
container:

    docker run -i --rm --network none --read-only --cap-drop ALL
               --security-opt no-new-privileges --user 65534:65534
               --memory 512m --cpus 1 --pids-limit 128 --tmpfs /tmp ...

The target's files (VCS/venv/build folders skipped), the harness and the
plan are streamed in as one tar archive on stdin and unpacked into the
container's tmpfs; nothing is mounted from the host and the container is
removed afterwards, including on timeout.

The sandbox image holds only Python, FastAPI/httpx and the target's
`requirements.txt`. Building it (`build_image`, `sectestgen sandbox build`)
is the one step that needs network; validation itself never does.

Outcome per finding, as `RuntimeEvidence`:
- `observed=True`  - the marker/canary was observed -> CONFIRMED.
- `observed=False` - every variant ran and nothing was observed. This is
  not proof of safety; the static classification is kept.
- `observed=None`  - not validated (unsupported, app failed to load,
  timeout, Docker error), with the reason in `observed_behavior`.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import shutil
import subprocess
import tarfile
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from sectestgen.adapters.semgrep_adapter import SKIPPED_DIRS
from sectestgen.core.adapters import SandboxExecutor
from sectestgen.core.models import Classification, Finding, RuntimeEvidence
from sectestgen.sandbox.harness import RESULT_PREFIX

HARNESS_PATH = Path(__file__).resolve().parent / "harness.py"
INSTALLER_PATH = Path(__file__).resolve().parent / "install_requirements.py"
SUPPORTED_SINKS = frozenset(
    {"command_execution", "dynamic_evaluation", "unsafe_deserialization", "path_traversal", "sql_injection"}
)
# Pinned base image per Python minor version; the target picks one with a
# `.python-version` file (pyenv convention), default 3.11.
BASE_IMAGES = {
    "3.9": "python:3.9.19-slim",
    "3.10": "python:3.10.14-slim",
    "3.11": "python:3.11.9-slim",
    "3.12": "python:3.12.4-slim",
}
DEFAULT_PYTHON = "3.11"
SANDBOX_PACKAGES = ["fastapi==0.111.0", "httpx==0.27.0"]
IMAGE_REPO = "sectestgen-sandbox"
_WORK = "/tmp/work"
_MAX_FILE_BYTES = 5 * 1024 * 1024
_MAX_TOTAL_BYTES = 100 * 1024 * 1024
_SOURCE_RE_SPLIT = " :: "


class SandboxError(RuntimeError):
    """Docker missing, image missing, or the container failed as a whole."""


@dataclass
class SandboxLimits:
    memory: str = "512m"
    cpus: str = "1"
    pids: int = 128
    tmpfs_size: str = "256m"
    case_timeout: int = 20


@dataclass
class _Plan:
    cases: list[dict] = field(default_factory=list)
    finding_case: dict[str, str] = field(default_factory=dict)  # finding id -> case id


def python_version(target: Path) -> str:
    """Python minor version from the target's `.python-version` (if any)."""
    marker = (target if target.is_dir() else target.parent) / ".python-version"
    if marker.is_file():
        words = marker.read_text(encoding="utf-8").split()
        text = words[0] if words else ""
        minor = ".".join(text.split(".")[:2])
        if minor not in BASE_IMAGES:
            raise SandboxError(f"{marker}: unsupported Python {text!r} (supported: {', '.join(BASE_IMAGES)})")
        return minor
    return DEFAULT_PYTHON


def image_tag(target: Path, requirements: Path | None = None) -> str:
    """One image per Python version + requirements file content."""
    target = Path(target)
    python = python_version(target)
    requirements = requirements or _default_requirements(target)
    if requirements is None:
        return f"{IMAGE_REPO}:py{python}-base"
    digest = hashlib.sha256(requirements.read_bytes()).hexdigest()[:12]
    return f"{IMAGE_REPO}:py{python}-req-{digest}"


def _default_requirements(target: Path) -> Path | None:
    candidate = (target if target.is_dir() else target.parent) / "requirements.txt"
    return candidate if candidate.is_file() else None


def dockerfile(with_requirements: bool, python: str = DEFAULT_PYTHON) -> str:
    """The target's own pins win: they are installed first, and FastAPI /
    httpx (needed by the harness) are only added when still missing."""
    lines = [
        f"FROM {BASE_IMAGES[python]}",
        "ENV PIP_DISABLE_PIP_VERSION_CHECK=1 PYTHONDONTWRITEBYTECODE=1",
    ]
    if with_requirements:
        lines += ["COPY requirements.txt install_requirements.py /opt/sectestgen/",
                  "RUN python /opt/sectestgen/install_requirements.py /opt/sectestgen/requirements.txt"]
    for package in SANDBOX_PACKAGES:
        module = package.split("==", 1)[0]
        lines.append(f'RUN python -c "import {module}" 2>/dev/null || pip install --no-cache-dir {package}')
    lines.append('LABEL org.sectestgen.role="sandbox"')
    return "\n".join(lines) + "\n"


def build_image(target: Path, requirements: Path | None = None, docker: str = "docker", timeout: int = 1800) -> str:
    """Build the sandbox image for `target` (needs network for pip)."""
    docker_path = _docker(docker)
    requirements = requirements or _default_requirements(Path(target))
    tag = image_tag(Path(target), requirements)
    context = io.BytesIO()
    with tarfile.open(fileobj=context, mode="w") as tar:
        _add_bytes(tar, "Dockerfile", dockerfile(requirements is not None, python_version(Path(target))).encode())
        if requirements is not None:
            tar.add(requirements, arcname="requirements.txt")
            tar.add(INSTALLER_PATH, arcname="install_requirements.py")
    proc = subprocess.run(
        [docker_path, "build", "-t", tag, "-"], input=context.getvalue(), capture_output=True, timeout=timeout
    )
    if proc.returncode != 0:
        raise SandboxError(f"docker build failed: {proc.stderr.decode('utf-8', 'replace')[-2000:]}")
    return tag


class DockerSandboxExecutor(SandboxExecutor):
    def __init__(
        self,
        routes: list[dict],
        image: str | None = None,
        docker: str = "docker",
        limits: SandboxLimits | None = None,
        timeout: int = 600,
    ) -> None:
        self.routes = routes
        self.image = image
        self.docker = docker
        self.limits = limits or SandboxLimits()
        self.timeout = timeout
        self.last_command: list[str] | None = None
        self.last_error: str | None = None

    def execute(self, finding: Finding, target: Path) -> Finding:
        self.execute_many([finding], target)
        return finding

    def execute_many(self, findings: list[Finding], target: Path) -> list[Finding]:
        target = Path(target).resolve()
        self.last_error = None
        plan = self._plan(findings, target)
        if not plan.cases:
            return findings

        try:
            results = self._run(plan, target)
        except (SandboxError, OSError, subprocess.SubprocessError) as exc:
            self.last_error = str(exc)
            reason = f"not validated: {exc}"
            results = {c["id"]: {"observed": None, "error": reason, "attempts": []} for c in plan.cases}

        cases = {c["id"]: c for c in plan.cases}
        for finding in findings:
            case_id = plan.finding_case.get(finding.id)
            if case_id is not None:
                finding.runtime = _to_evidence(cases[case_id], results.get(case_id))
        return findings

    # --- planning -------------------------------------------------------

    def _plan(self, findings: list[Finding], target: Path) -> _Plan:
        plan = _Plan()
        by_key: dict[tuple, str] = {}
        routes = {(f"{r['method']} {r['path']}", str(Path(r["file_path"]).resolve())): r for r in self.routes}

        for finding in findings:
            reason, case = self._case_for(finding, target, routes)
            if case is None:
                if reason and finding.classification in (
                    Classification.REACHABLE, Classification.POTENTIALLY_REACHABLE
                ):
                    finding.runtime = RuntimeEvidence(observed=None, observed_behavior=f"not validated: {reason}")
                continue
            key = (case["module_file"], case["method"], case["path"], json.dumps(case["target"]), case["sink_type"])
            case_id = by_key.get(key)
            if case_id is None:
                case_id = case["id"] = f"case-{len(plan.cases) + 1}"
                case["nonce"] = uuid.uuid4().hex[:16]
                plan.cases.append(case)
                by_key[key] = case_id
            plan.finding_case[finding.id] = case_id
        return plan

    def _case_for(self, finding: Finding, target: Path, routes: dict) -> tuple[str | None, dict | None]:
        location = finding.location
        if location is None or not location.file_path:
            return "finding has no source location", None
        file_path = Path(location.file_path).resolve()
        if file_path.suffix != ".py":
            return "runtime validation supports Python/FastAPI targets only", None
        if finding.sink not in SUPPORTED_SINKS:
            return f"no runtime validator for sink type {finding.sink!r}", None
        route = routes.get((finding.raw.get("route"), str(file_path)))
        if route is None:
            return "sink is not inside a discovered FastAPI route", None
        source = _parse_source(finding.user_input_source)
        if source is None or not any(
            (s["kind"], s["name"], s.get("field")) == (source["kind"], source["name"], source["field"])
            for s in route["sources"]
        ):
            return "no user-input source to inject into", None
        try:
            module_file = file_path.relative_to(target.parent if target.is_dir() else target.parent.parent)
        except ValueError:
            return "sink file is outside the target", None
        return None, {
            "sink_type": finding.sink,
            "module_file": module_file.as_posix(),
            "method": route["method"],
            "path": route["path"],
            "sources": route["sources"],
            "target": source,
        }

    # --- container ------------------------------------------------------

    def _run(self, plan: _Plan, target: Path) -> dict[str, dict]:
        docker_path = _docker(self.docker)
        image = self.image or image_tag(target)
        inspect = subprocess.run([docker_path, "image", "inspect", image], capture_output=True, timeout=60)
        if inspect.returncode != 0:
            raise SandboxError(
                f"sandbox image {image!r} not found; build it once with `sectestgen sandbox build {target}`"
            )

        archive = _archive(target, plan, self.limits.case_timeout)
        name = f"sectestgen-sandbox-{uuid.uuid4().hex[:12]}"
        limits = self.limits
        cmd = [
            docker_path, "run", "-i", "--rm", "--name", name,
            "--network", "none",
            "--read-only", "--tmpfs", f"/tmp:rw,noexec,nosuid,size={limits.tmpfs_size},mode=1777",
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--user", "65534:65534",
            "--memory", limits.memory, "--memory-swap", limits.memory,
            "--cpus", limits.cpus, "--pids-limit", str(limits.pids),
            "-e", "HOME=/tmp", "-e", "PYTHONDONTWRITEBYTECODE=1",
            "--label", "org.sectestgen.role=sandbox-run",
            image, "sh", "-c",
            f"mkdir -p {_WORK} && tar -x -C {_WORK} && cd /tmp && "
            f"exec python -I {_WORK}/.sectestgen/harness.py {_WORK}/.sectestgen/plan.json {_WORK}",
        ]
        self.last_command = cmd
        try:
            proc = subprocess.run(cmd, input=archive, capture_output=True, timeout=self.timeout)
        except subprocess.TimeoutExpired as exc:
            raise SandboxError(f"sandbox timed out after {self.timeout} s") from exc
        finally:
            subprocess.run([docker_path, "rm", "--force", name], capture_output=True, timeout=60)

        stdout = proc.stdout.decode("utf-8", "replace")
        results = {}
        for line in stdout.splitlines():
            if line.startswith(RESULT_PREFIX):
                result = json.loads(line[len(RESULT_PREFIX):])
                results[result["id"]] = result
        if not results:
            stderr = proc.stderr.decode("utf-8", "replace").strip()
            raise SandboxError(f"sandbox produced no results (exit {proc.returncode}): {stderr[-1500:]}")
        return results


def _to_evidence(case: dict, result: dict | None) -> RuntimeEvidence:
    result = result or {"observed": None, "error": "no result for this case", "attempts": []}
    attempts = result.get("attempts") or []
    winning = next((a for a in attempts if a.get("observed")), attempts[-1] if attempts else None)
    if result.get("observed") is True:
        observed = f"observed with variant {winning['variant']!r} (HTTP {winning.get('status')})"
    elif result.get("observed") is False:
        observed = f"not observed after {len(attempts)} variant(s); not proof of safety"
    else:
        observed = result.get("error") or "not validated"
    return RuntimeEvidence(
        harness=f"sectestgen.sandbox.harness:{case['sink_type']}",
        request=winning.get("request") if winning else None,
        expected_behavior=result.get("expected"),
        observed_behavior=observed,
        logs=_summarize_logs(result, attempts),
        observed=result.get("observed"),
    )


def _summarize_logs(result: dict, attempts: list[dict]) -> str:
    lines = [
        f"{a['variant']}: HTTP {a.get('status', '-')}{' ' + a['error'] if a.get('error') else ''}"
        f"{' OBSERVED' if a.get('observed') else ''}"
        for a in attempts
    ]
    if result.get("error"):
        lines.append(f"error: {result['error']}")
    if result.get("logs"):
        lines.append(result["logs"].strip())
    return "\n".join(lines)[-4000:]


def _parse_source(text: str | None) -> dict | None:
    """`GET /x :: body:payload.expression` -> {kind, name, field}."""
    if not text or _SOURCE_RE_SPLIT not in text:
        return None
    spec = text.split(_SOURCE_RE_SPLIT, 1)[1]
    kind, _, name = spec.partition(":")
    name, _, field_name = name.partition(".")
    if not kind or not name:
        return None
    return {"kind": kind, "name": name, "field": field_name or None}


def _archive(target: Path, plan: _Plan, case_timeout: int) -> bytes:
    """tar of the target (under its own folder name, so it stays importable
    as a package) + the harness and plan under .sectestgen/."""
    root = target if target.is_dir() else target.parent
    buffer = io.BytesIO()
    total = 0
    with tarfile.open(fileobj=buffer, mode="w") as tar:
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = sorted(d for d in dirnames if d not in SKIPPED_DIRS)
            for filename in sorted(filenames):
                path = Path(dirpath) / filename
                size = path.stat().st_size
                if size > _MAX_FILE_BYTES:
                    continue
                total += size
                if total > _MAX_TOTAL_BYTES:
                    raise SandboxError(f"target is larger than {_MAX_TOTAL_BYTES // (1024 * 1024)} MB")
                tar.add(path, arcname=f"{root.name}/{path.relative_to(root).as_posix()}", recursive=False)
        tar.add(HARNESS_PATH, arcname=".sectestgen/harness.py")
        payload = {"cases": plan.cases, "case_timeout": case_timeout}
        _add_bytes(tar, ".sectestgen/plan.json", json.dumps(payload).encode())
    return buffer.getvalue()


def _add_bytes(tar: tarfile.TarFile, name: str, data: bytes) -> None:
    info = tarfile.TarInfo(name)
    info.size = len(data)
    info.mode = 0o644
    tar.addfile(info, io.BytesIO(data))


def _docker(binary: str) -> str:
    path = shutil.which(binary)
    if path is None:
        raise SandboxError(f"'{binary}' not found on PATH; runtime validation needs Docker")
    return path
