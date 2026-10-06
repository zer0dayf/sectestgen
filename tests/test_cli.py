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
