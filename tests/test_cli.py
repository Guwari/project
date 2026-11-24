import json

from unittest.mock import Mock

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

@pytest.mark.parametrize(
    "scenario,expected_status,expected_rules,expected_exit",
    [
        ("secure", "complete", set(), 0),
        ("exposed", "complete", {"EC2-01", "S3-01"}, 0),
        ("denied", "partial", set(), 1),
    ],
)
def test_cli_demo_scenarios(
    monkeypatch,
    capsys,
    scenario,
    expected_status,
    expected_rules,
    expected_exit,
):
    monkeypatch.setattr(
        "sys.argv",
        ["cloudsentinel", "--scenario", scenario],
    )

    exit_code = cli.main()

    report = json.loads(capsys.readouterr().out)
    assert exit_code == expected_exit
    assert report["source"] == "demo"
    assert report["status"] == expected_status
    assert {finding["rule"] for finding in report["findings"]} == expected_rules

    if scenario == "denied":
        assert report["errors"] == [{
            "operation": "GetPublicAccessBlock",
            "resource": "demo:s3:example-bucket",
            "code": "AccessDenied",
        }]
    else:
        assert report["errors"] == []


@pytest.mark.parametrize(
    "arguments,expected_message",
    [
        (
            ["--scenario", "unknown"],
            "invalid choice",
        ),
        (
            ["--live", "--scenario", "secure"],
            "--scenario is available only for local demos",
        ),
    ],
)
def test_cli_rejects_invalid_scenario_arguments(
    monkeypatch,
    capsys,
    arguments,
    expected_message,
):
    monkeypatch.setattr("sys.argv", ["cloudsentinel", *arguments])
    simulated_run = Mock()
    monkeypatch.setattr(cli, "run", simulated_run)

    with pytest.raises(SystemExit) as error:
        cli.main()

    assert error.value.code == 2
    captured = capsys.readouterr()
    assert expected_message in captured.err
    assert captured.out == ""
    simulated_run.assert_not_called()