"""Public third-party Semgrep rule packs, fetched on demand.

These rules are never vendored into this repository (each pack keeps its
own license); `fetch()` shallow-clones a pack into a per-user cache and
`rule_paths()` returns the Java/Python folders of a fetched pack, which the
static pipeline passes to Semgrep next to the project's own rule packs.

Fetching is the only step that touches the network, and only when the user
runs `sectestgen rules fetch`. Scanning stays offline.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

LANGUAGES = ("java", "python")


@dataclass(frozen=True)
class RulePack:
    name: str
    url: str
    license: str
    description: str
    paths: dict[str, tuple[str, ...]]  # language -> folders inside the checkout


PACKS: dict[str, RulePack] = {
    pack.name: pack
    for pack in (
        RulePack(
            name="semgrep",
            url="https://github.com/semgrep/semgrep-rules.git",
            license="Semgrep Rules License v1.0",
            description="Semgrep community registry rules",
            paths={"java": ("java",), "python": ("python",)},
        ),
        RulePack(
            name="gitlab",
            url="https://gitlab.com/gitlab-org/security-products/sast-rules.git",
            license="MIT",
            description="GitLab SAST rules (find-sec-bugs and Bandit ports)",
            paths={"java": ("java",), "python": ("python",)},
        ),
        RulePack(
            name="elttam",
            url="https://github.com/elttam/semgrep-rules.git",
            license="MIT",
            description="elttam security rules",
            paths={"java": ("rules/java",), "python": ()},
        ),
        RulePack(
            name="elttam-audit",
            url="https://github.com/elttam/semgrep-rules.git",
            license="MIT",
            description="elttam audit rules (broader, noisier)",
            paths={"java": ("rules-audit/java",), "python": ("rules-audit/python",)},
        ),
        RulePack(
            name="trailofbits",
            url="https://github.com/trailofbits/semgrep-rules.git",
            license="AGPL-3.0",
            description="Trail of Bits rules",
            paths={"java": ("jvm",), "python": ("python",)},
        ),
    )
}


class RulePackError(RuntimeError):
    pass


def cache_dir() -> Path:
    override = os.environ.get("SECTESTGEN_RULES_DIR")
    if override:
        return Path(override)
    if sys.platform == "win32" and os.environ.get("LOCALAPPDATA"):
        return Path(os.environ["LOCALAPPDATA"]) / "sectestgen" / "rule-packs"
    return Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache")) / "sectestgen" / "rule-packs"


def checkout_dir(pack: RulePack) -> Path:
    # Packs sharing a repository (elttam / elttam-audit) share one checkout.
    repo = pack.url.rstrip("/").removesuffix(".git").rsplit("/", 2)
    return cache_dir() / f"{repo[-2]}__{repo[-1]}"


def get_pack(name: str) -> RulePack:
    try:
        return PACKS[name]
    except KeyError:
        raise RulePackError(f"unknown rule pack {name!r}; known packs: {', '.join(PACKS)}") from None


def is_fetched(pack: RulePack) -> bool:
    return (checkout_dir(pack) / ".git").is_dir()


def fetch(pack: RulePack, git: str = "git", timeout: int = 600) -> Path:
    """Shallow-clone the pack, or update an existing checkout to the
    remote's latest commit."""
    git_path = shutil.which(git)
    if git_path is None:
        raise RulePackError("'git' not found on PATH; it's needed to fetch rule packs")
    dest = checkout_dir(pack)
    if is_fetched(pack):
        commands = [
            [git_path, "-C", str(dest), "fetch", "--depth", "1", "origin"],
            [git_path, "-C", str(dest), "reset", "--hard", "FETCH_HEAD"],
        ]
    else:
        dest.parent.mkdir(parents=True, exist_ok=True)
        commands = [[git_path, "clone", "--depth", "1", pack.url, str(dest)]]
    for cmd in commands:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if proc.returncode != 0:
            raise RulePackError(f"{' '.join(cmd[1:3])} failed for {pack.name}: {proc.stderr.strip()}")
    return dest


def rule_paths(pack: RulePack, languages: tuple[str, ...] = LANGUAGES) -> list[Path]:
    if not is_fetched(pack):
        raise RulePackError(
            f"rule pack {pack.name!r} is not fetched yet; run `sectestgen rules fetch {pack.name}`"
        )
    root = checkout_dir(pack)
    return [
        root / folder
        for language in languages
        for folder in pack.paths.get(language, ())
        if (root / folder).is_dir()
    ]


def resolve(names: list[str]) -> list[Path]:
    """Rule folders for the given pack names; "all" means every fetched pack."""
    if "all" in names:
        packs = [p for p in PACKS.values() if is_fetched(p)]
        if not packs:
            raise RulePackError("no rule packs fetched yet; run `sectestgen rules fetch --all`")
    else:
        packs = [get_pack(name) for name in dict.fromkeys(names)]
    return [path for pack in packs for path in rule_paths(pack)]
