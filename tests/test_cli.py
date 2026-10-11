from pathlib import Path

from sectestgen.cli import main

FIXTURE = Path(__file__).resolve().parent.parent / "fixtures" / "vulnerable_fastapi"


def test_static_pipeline_runs_against_fixture(tmp_path, capsys):
    exit_code = main(["static", str(FIXTURE), "-o", str(tmp_path)])
    captured = capsys.readouterr()

    assert exit_code == 0
    assert "static" in captured.out
    assert (tmp_path / "report1.json").exists()
    assert (tmp_path / "report1.html").exists()


def test_static_on_missing_target_does_not_crash(tmp_path, capsys):
    exit_code = main(["static", str(tmp_path / "does-not-exist"), "-o", str(tmp_path / "out")])
    captured = capsys.readouterr()

    assert exit_code == 0
    assert "static" in captured.out


def test_no_command_prints_help(capsys):
    exit_code = main([])
    captured = capsys.readouterr()

    assert exit_code == 0
    assert "usage" in captured.out.lower()


def test_sca_pipeline_runs_against_java_fixture(tmp_path, capsys):
    java = FIXTURE.parent / "sca_java"
    exit_code = main(
        ["sca", str(java / "sbom.cdx.json"), "--grype", str(java / "grype.json"), "-o", str(tmp_path)]
    )
    captured = capsys.readouterr()

    assert exit_code == 0
    assert "[sca] 3 finding(s)" in captured.out
    assert (tmp_path / "report2.json").exists()
    assert (tmp_path / "report2.html").exists()


def test_static_accepts_extra_rules(tmp_path, capsys, monkeypatch):
    seen = {}

    def fake_pipeline(target, output_dir=None, extra_rules=None, semgrep_timeout=None):
        seen["extra_rules"] = extra_rules
        from sectestgen.pipeline import PipelineResult

        return PipelineResult(findings=[], routes=[])

    monkeypatch.setattr("sectestgen.cli.run_static_pipeline", fake_pipeline)
    exit_code = main(["static", str(tmp_path), "--rules", "a.yml", "--rules", "more-rules"])

    assert exit_code == 0
    assert seen["extra_rules"] == [Path("a.yml"), Path("more-rules")]
