import boto3
import pytest
from botocore.stub import Stubber

from cloudsentinel.scanner import Report, check_trails

REGION = "us-east-1"
ACCOUNT = "123456789012"
SCOPE = f"{ACCOUNT}:{REGION}"
TRAIL = f"arn:aws:cloudtrail:{REGION}:{ACCOUNT}:trail/test"


@pytest.mark.parametrize(
    "scenario,expected_rules,expected_status",
    [
        ("secure", set(), "complete"),
        ("no_trails", {"CT-01"}, "complete"),
        ("logging_disabled", {"CT-01"}, "complete"),
        ("validation_disabled", {"CT-02"}, "complete"),
        ("access_denied", set(), "partial"),
    ],
)
def test_cloudtrail_checks(scenario, expected_rules, expected_status):
    sdk = boto3.Session(
        aws_access_key_id="testing",
        aws_secret_access_key="testing",
        region_name=REGION,
    )
    client = sdk.client("cloudtrail")
    report = Report()

    trails = []
    if scenario != "no_trails":
        trails = [{
            "TrailARN": TRAIL,
            "LogFileValidationEnabled": scenario != "validation_disabled",
        }]

    with Stubber(client) as stub:
        stub.add_response(
            "describe_trails",
            {"trailList": trails},
            {"includeShadowTrails": True},
        )

        if scenario == "access_denied":
            stub.add_client_error(
                "get_trail_status",
                service_error_code="AccessDeniedException",
                http_status_code=403,
                expected_params={"Name": TRAIL},
            )
        elif trails:
            stub.add_response(
                "get_trail_status",
                {"IsLogging": scenario != "logging_disabled"},
                {"Name": TRAIL},
            )

        check_trails(client, SCOPE, report)
        stub.assert_no_pending_responses()

    result = report.export("test")
    assert result["status"] == expected_status
    assert {finding["rule"] for finding in result["findings"]} == expected_rules

    if scenario == "access_denied":
        assert result["errors"] == [{
            "operation": "GetTrailStatus",
            "resource": TRAIL,
            "code": "AccessDeniedException",
        }]
    else:
        assert result["errors"] == []