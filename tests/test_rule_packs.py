import subprocess
from pathlib import Path

import pytest

from sectestgen import rule_packs
from sectestgen.cli import main


@pytest.fixture
def cache(monkeypatch, tmp_path) -> Path:
    monkeypatch.setenv("SECTESTGEN_RULES_DIR", str(tmp_path / "cache"))
    return tmp_path / "cache"


def _fake_checkout(pack: rule_packs.RulePack) -> Path:
    root = rule_packs.checkout_dir(pack)
    (root / ".git").mkdir(parents=True, exist_ok=True)
    for folders in pack.paths.values():
        for folder in folders:
            (root / folder).mkdir(parents=True, exist_ok=True)
    return root


def test_every_pack_has_a_license_and_java_or_python_paths():
    for pack in rule_packs.PACKS.values():
        assert pack.license
        assert any(pack.paths.get(lang) for lang in rule_packs.LANGUAGES)


def test_cache_dir_honours_override(cache):
    assert rule_packs.cache_dir() == cache


def test_packs_sharing_a_repository_share_a_checkout(cache):
    elttam, audit = rule_packs.get_pack("elttam"), rule_packs.get_pack("elttam-audit")
    assert rule_packs.checkout_dir(elttam) == rule_packs.checkout_dir(audit)


def test_resolve_returns_language_folders_of_fetched_packs(cache):
    gitlab = rule_packs.get_pack("gitlab")
    root = _fake_checkout(gitlab)

    assert rule_packs.resolve(["gitlab"]) == [root / "java", root / "python"]


def test_resolve_all_uses_only_fetched_packs(cache):
    root = _fake_checkout(rule_packs.get_pack("trailofbits"))

    assert rule_packs.resolve(["all"]) == [root / "jvm", root / "python"]


def test_resolve_errors_are_actionable(cache):
    with pytest.raises(rule_packs.RulePackError, match="rules fetch gitlab"):
        rule_packs.resolve(["gitlab"])
    with pytest.raises(rule_packs.RulePackError, match="unknown rule pack"):
        rule_packs.resolve(["nope"])
    with pytest.raises(rule_packs.RulePackError, match="no rule packs fetched"):
        rule_packs.resolve(["all"])


def test_fetch_clones_then_updates(cache, monkeypatch):
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd[1:])
        if cmd[1] == "clone":
            (Path(cmd[-1]) / ".git").mkdir(parents=True)
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr("sectestgen.rule_packs.shutil.which", lambda name: "/usr/bin/git")
    monkeypatch.setattr("sectestgen.rule_packs.subprocess.run", fake_run)
    pack = rule_packs.get_pack("elttam")

    dest = rule_packs.fetch(pack)
    rule_packs.fetch(pack)

    assert calls[0] == ["clone", "--depth", "1", pack.url, str(dest)]
    assert calls[1][2:] == ["fetch", "--depth", "1", "origin"]
    assert calls[2][2:] == ["reset", "--hard", "FETCH_HEAD"]


def test_fetch_without_git_fails_clearly(cache, monkeypatch):
    monkeypatch.setattr("sectestgen.rule_packs.shutil.which", lambda name: None)

    with pytest.raises(rule_packs.RulePackError, match="git"):
        rule_packs.fetch(rule_packs.get_pack("gitlab"))


def test_cli_rules_list_shows_status_and_license(cache, capsys):
    _fake_checkout(rule_packs.get_pack("gitlab"))

    assert main(["rules", "list"]) == 0
    out = capsys.readouterr().out
    gitlab_line = next(line for line in out.splitlines() if line.strip().startswith("gitlab"))
    assert "fetched" in gitlab_line and "MIT" in gitlab_line
    assert "not fetched" in next(line for line in out.splitlines() if line.strip().startswith("semgrep"))


def test_cli_static_with_unfetched_pack_exits_with_hint(cache, tmp_path, capsys):
    assert main(["static", str(tmp_path), "--rule-pack", "gitlab", "-o", str(tmp_path / "out")]) == 2
    assert "rules fetch gitlab" in capsys.readouterr().out


def test_cli_static_passes_pack_folders_and_timeout(cache, tmp_path, monkeypatch):
    root = _fake_checkout(rule_packs.get_pack("gitlab"))
    seen = {}

    def fake_pipeline(target, output_dir=None, extra_rules=None, semgrep_timeout=None):
        seen.update(extra_rules=extra_rules, semgrep_timeout=semgrep_timeout)
        from sectestgen.pipeline import PipelineResult

        return PipelineResult(findings=[], routes=[])

    monkeypatch.setattr("sectestgen.cli.run_static_pipeline", fake_pipeline)
    argv = ["static", str(tmp_path), "--rules", "x.yml", "--rule-pack", "gitlab", "--semgrep-timeout", "900"]

    assert main(argv) == 0
    assert seen == {"extra_rules": [Path("x.yml"), root / "java", root / "python"], "semgrep_timeout": 900}
