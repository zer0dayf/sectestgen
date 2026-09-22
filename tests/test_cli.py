from sectestgen.cli import main


def test_static_stub_runs(capsys):
    exit_code = main(["static", "some/path"])
    captured = capsys.readouterr()

    assert exit_code == 0
    assert "static" in captured.out


def test_no_command_prints_help(capsys):
    exit_code = main([])
    captured = capsys.readouterr()

    assert exit_code == 0
    assert "usage" in captured.out.lower()
