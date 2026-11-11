import json

import pytest

from cloudsentinel import cli


def test_demo_command_succeeds(monkeypatch, capsys):
    monkeypatch.setattr("sys.argv", ["cloudsentinel"])

    exit_code = cli.main()

    report = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert report["source"] == "demo"
    assert report["status"] == "complete"


def test_partial_scan_returns_exit_code_one(monkeypatch, capsys):
    monkeypatch.setattr("sys.argv", ["cloudsentinel", "--live"])

    partial_report = {
        "source": "aws",
        "status": "partial",
        "findings": [],
        "errors": [{
            "operation": "GetAccountSummary",
            "resource": "123456789012",
            "code": "AccessDenied",
        }],
    }

    def simulated_run(*, live, with_analysis):
        assert live is True
        assert with_analysis is False
        return partial_report

    monkeypatch.setattr(cli, "run", simulated_run)

    exit_code = cli.main()

    assert exit_code == 1
    assert json.loads(capsys.readouterr().out) == partial_report


def test_analysis_requires_live_flag(monkeypatch, capsys):
    monkeypatch.setattr("sys.argv", ["cloudsentinel", "--analyze"])

    with pytest.raises(SystemExit) as error:
        cli.main()

    assert error.value.code == 2
    captured = capsys.readouterr()
    assert "--analyze requires --live" in captured.err
    assert captured.out == ""