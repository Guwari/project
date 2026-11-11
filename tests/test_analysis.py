import json
from unittest.mock import Mock

import pytest
from botocore.exceptions import ClientError

from cloudsentinel.analysis import analyze

MODEL = "arn:aws:bedrock:us-east-1::foundation-model/test-model"


@pytest.fixture
def report():
    return {
        "findings": [
            {"rule": "EC2-01", "resource": "private-resource-one", "title": "private-tag"},
            {"rule": "EC2-01", "resource": "private-resource-two"},
            {"rule": "private-unknown-rule"},
        ],
        "errors": [{"code": "private-error"}],
    }


def response(text, stop_reason="end_turn"):
    return {
        "stopReason": stop_reason,
        "output": {"message": {"content": [{"text": text}]}},
    }


def test_analysis_sends_only_aggregated_rule_data(report):
    advisory = {
        "summary": "Review broad SSH access.",
        "next_steps": ["Restrict SSH to approved sources."],
    }
    client = Mock()
    client.converse.return_value = response(json.dumps(advisory))

    assert analyze(report, client, MODEL) == {"status": "ok", **advisory}

    client.converse.assert_called_once()
    request = client.converse.call_args.kwargs
    assert request["modelId"] == MODEL
    assert request["inferenceConfig"]["maxTokens"] == 512
    assert "toolConfig" not in request
    assert "private-" not in json.dumps(request)
    assert json.loads(request["messages"][0]["content"][0]["text"]) == [
        {"rule": "EC2-01", "count": 2, "severity": "high",
         "title": "Security group allows unrestricted SSH ingress"}
    ]


@pytest.mark.parametrize("text,stop_reason", [
    ("not JSON", "end_turn"),
    ('{"summary":"Review SSH.","next_steps":"Restrict access."}', "end_turn"),
    ('{"summary":"Review SSH.","next_steps":["Restrict access."],"severity":"low"}', "end_turn"),
    ('{"summary":"Review SSH.","next_steps":["Restrict access."]}', "max_tokens"),
])
def test_analysis_rejects_invalid_model_output(report, text, stop_reason):
    client = Mock()
    client.converse.return_value = response(text, stop_reason)

    assert analyze(report, client, MODEL) == {"status": "invalid_output"}


def test_analysis_handles_bedrock_failure(report):
    client = Mock()
    client.converse.side_effect = ClientError(
        {"Error": {"Code": "AccessDeniedException", "Message": "Simulated denial"}},
        "Converse",
    )

    assert analyze(report, client, MODEL) == {"status": "unavailable"}
    client.converse.assert_called_once()


def test_analysis_skips_bedrock_without_findings():
    client = Mock()

    assert analyze({"findings": []}, client, MODEL) == {"status": "no_findings"}
    client.converse.assert_not_called()
