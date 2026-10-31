"""Sandbox image build step: install a target's requirements.txt.

Runs inside `docker build` (the only networked sandbox step). Old,
intentionally vulnerable pins often can't be resolved together with each
other or with a modern FastAPI (e.g. requests 2.19.1 wants idna<2.8 while
anyio wants idna>=2.8). The validation only has to import the code path
under test, so on a resolution failure the pins are installed exactly as
written with --no-deps (also when resolution doesn't finish within
RESOLVE_TIMEOUT), and then only dependencies that are *missing* are
added, with the version range the requiring package declares. The mode
used is written to /opt/sectestgen/install-mode so it can be reported.
"""

from __future__ import annotations

import subprocess
import sys
from importlib import metadata
from pathlib import Path

from pip._vendor.packaging.requirements import Requirement  # pip's vendored copy; no extra install


# pip can backtrack for a very long time over unresolvable pins before it
# gives up; the resolved attempt is cut off and the fallback used instead.
RESOLVE_TIMEOUT = 120


def pip(*args: str, timeout: int | None = None) -> int:
    try:
        return subprocess.run([sys.executable, "-m", "pip", *args], timeout=timeout).returncode
    except subprocess.TimeoutExpired:
        print(f"pip gave no result within {timeout} s", flush=True)
        return 1


def missing_requirements() -> list[str]:
    installed = {dist.metadata["Name"].lower().replace("_", "-") for dist in metadata.distributions()}
    missing: dict[str, str] = {}
    for dist in metadata.distributions():
        for spec in dist.requires or []:
            requirement = Requirement(spec)
            if requirement.marker is not None and not requirement.marker.evaluate({"extra": ""}):
                continue
            name = requirement.name.lower().replace("_", "-")
            if name not in installed:
                missing.setdefault(name, str(requirement).split(";", 1)[0].strip())
    return sorted(missing.values())


def main(requirements: str) -> int:
    mode_file = Path("/opt/sectestgen/install-mode")
    if pip("install", "--no-cache-dir", "-r", requirements, timeout=RESOLVE_TIMEOUT) == 0:
        mode_file.write_text("resolved\n")
        return 0

    print("requirements do not resolve together; installing pins with --no-deps", flush=True)
    if pip("install", "--no-cache-dir", "--no-deps", "-r", requirements) != 0:
        return 1
    for _ in range(10):
        missing = missing_requirements()
        if not missing:
            break
        print(f"adding missing dependencies: {', '.join(missing)}", flush=True)
        if pip("install", "--no-cache-dir", "--no-deps", *missing) != 0:
            return 1
    mode_file.write_text("best-effort (pins installed with --no-deps)\n")
    pip("check")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1]))
