from contextlib import ExitStack
from unittest.mock import Mock

import boto3
import pytest
from botocore.stub import Stubber

from cloudsentinel.scanner import scan

REGION = "us-east-1"
ACCOUNT = "123456789012"
TRAIL = f"arn:aws:cloudtrail:{REGION}:{ACCOUNT}:trail/test"


@pytest.mark.parametrize(
    "summary,expected_rules,expected_status",
    [
        (
            {"AccountMFAEnabled": 1, "AccountAccessKeysPresent": 0},
            set(),
            "complete",
        ),
        (
            {"AccountMFAEnabled": 0, "AccountAccessKeysPresent": 0},
            {"IAM-01"},
            "complete",
        ),
        (
            {"AccountMFAEnabled": 1, "AccountAccessKeysPresent": 1},
            {"IAM-02"},
            "complete",
        ),
        (
            {"AccountAccessKeysPresent": 0},
            set(),
            "partial",
        ),
    ],
    ids=["secure", "root-mfa-disabled", "root-access-keys", "missing-mfa-data"],
)
def test_iam_account_checks(summary, expected_rules, expected_status):
    sdk = boto3.Session(
        aws_access_key_id="testing",
        aws_secret_access_key="testing",
        region_name=REGION,
    )
    session = Mock()

    with ExitStack() as stack:
        clients = {}
        stubs = {}
        for service in ("sts", "s3", "iam", "ec2", "cloudtrail"):
            clients[service] = sdk.client(service)
            stubs[service] = stack.enter_context(Stubber(clients[service]))

        session.client.side_effect = lambda service, **kwargs: clients[service]

        stubs["sts"].add_response(
            "get_caller_identity", {"Account": ACCOUNT}, {}
        )
        stubs["s3"].add_response("list_buckets", {"Buckets": []}, {})
        stubs["iam"].add_response(
            "get_account_summary", {"SummaryMap": summary}, {}
        )
        stubs["ec2"].add_response(
            "describe_security_groups", {"SecurityGroups": []}, {}
        )
        stubs["cloudtrail"].add_response(
            "describe_trails",
            {"trailList": [{
                "TrailARN": TRAIL,
                "LogFileValidationEnabled": True,
            }]},
            {"includeShadowTrails": True},
        )
        stubs["cloudtrail"].add_response(
            "get_trail_status", {"IsLogging": True}, {"Name": TRAIL}
        )

        report = scan(session, (REGION,))

        for stub in stubs.values():
            stub.assert_no_pending_responses()

    assert report["status"] == expected_status
    assert {finding["rule"] for finding in report["findings"]} == expected_rules

    if expected_status == "partial":
        assert report["errors"] == [{
            "operation": "GetAccountSummary",
            "resource": ACCOUNT,
            "code": "MissingAccountMFAEnabled",
        }]
    else:
        assert report["errors"] == []