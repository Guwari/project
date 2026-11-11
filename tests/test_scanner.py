from contextlib import ExitStack
from unittest.mock import Mock
from cloudsentinel.scanner import Report, check_group

import boto3
import pytest
from botocore.stub import Stubber

from cloudsentinel.scanner import BLOCK_FLAGS, scan

REGION = "us-east-1"
ACCOUNT = "123456789012"
BUCKET = "sentinel-test-bucket"
TRAIL = f"arn:aws:cloudtrail:{REGION}:{ACCOUNT}:trail/test"


@pytest.mark.parametrize("scenario", ["secure", "exposed", "denied"])
def test_scan_with_simulated_aws(scenario):
    # Dummy credentials and stubbed clients keep the test offline.
    sdk = boto3.Session(
        aws_access_key_id="testing", aws_secret_access_key="testing", region_name=REGION
    )
    session = Mock()
    with ExitStack() as stack:
        clients = {}
        stubs = {}
        for name in ("sts", "s3", "iam", "ec2", "cloudtrail"):
            clients[name] = sdk.client(name)
            stubs[name] = stack.enter_context(Stubber(clients[name]))
        session.client.side_effect = lambda service, **kwargs: clients[service]

        stubs["sts"].add_response("get_caller_identity", {"Account": ACCOUNT}, {})
        s3 = stubs["s3"]
        s3.add_response("list_buckets", {"Buckets": [{"Name": BUCKET}]}, {})
        bucket_args = {"Bucket": BUCKET, "ExpectedBucketOwner": ACCOUNT}
        if scenario == "denied":
            s3.add_client_error(
                "get_public_access_block", service_error_code="AccessDenied",
                http_status_code=403, expected_params=bucket_args,
            )
        else:
            s3.add_response(
                "get_public_access_block",
                {"PublicAccessBlockConfiguration": {
                    flag: scenario == "secure" for flag in BLOCK_FLAGS
                }},
                bucket_args,
            )
        s3.add_response("get_bucket_policy_status",
                        {"PolicyStatus": {"IsPublic": False}}, bucket_args)
        s3.add_response("get_bucket_versioning", {"Status": "Enabled"}, bucket_args)
        stubs["iam"].add_response("get_account_summary", {"SummaryMap": {
            "AccountMFAEnabled": 1, "AccountAccessKeysPresent": 0,
        }}, {})
        ec2 = stubs["ec2"]
        ec2.add_response(
            "describe_security_groups",
            {
                "SecurityGroups": [{"GroupId": "sg-first-page", "IpPermissions": []}],
                "NextToken": "second-page",
            },
            {},
        )
        ec2.add_response(
            "describe_security_groups",
            {
                "SecurityGroups": [
                    {
                        "GroupId": "sg-second-page",
                        "IpPermissions": [
                            {
                                "IpProtocol": "tcp",
                                "FromPort": 22,
                                "ToPort": 22,
                                "IpRanges": [
                                    {
                                        "CidrIp": "0.0.0.0/0"
                                        if scenario == "exposed"
                                        else "192.0.2.10/32"
                                    }
                                ],
                            }
                        ],
                    }
                ]
            },
            {"NextToken": "second-page"},
        )
        stubs["cloudtrail"].add_response("describe_trails", {"trailList": [
            {"TrailARN": TRAIL, "LogFileValidationEnabled": True}
        ]}, {"includeShadowTrails": True})
        stubs["cloudtrail"].add_response("get_trail_status", {"IsLogging": True},
                                         {"Name": TRAIL})

        report = scan(session, (REGION,))

        for stub in stubs.values():
            stub.assert_no_pending_responses()

    assert report["source"] == "aws"
    assert report["status"] == ("partial" if scenario == "denied" else "complete")
    assert {finding["rule"] for finding in report["findings"]} == (
        {"EC2-01", "S3-01"} if scenario == "exposed" else set()
    )
    assert report["errors"] == ([
        {"operation": "GetPublicAccessBlock", "resource": f"{ACCOUNT}:s3:{BUCKET}",
         "code": "AccessDenied"}
    ] if scenario == "denied" else [])

@pytest.mark.parametrize(
    "permission,expected_rules",
    [
        (
            {
                "IpProtocol": "tcp",
                "FromPort": 3389,
                "ToPort": 3389,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            },
            {"EC2-02"},
        ),
        (
            {
                "IpProtocol": "-1",
                "Ipv6Ranges": [{"CidrIpv6": "::/0"}],
            },
            {"EC2-01", "EC2-02", "EC2-03"},
        ),
        (
            {
                "IpProtocol": "tcp",
                "FromPort": 3389,
                "ToPort": 3389,
                "IpRanges": [{"CidrIp": "192.0.2.10/32"}],
            },
            set(),
        ),
    ],
)
def test_security_group_protocol_checks(permission, expected_rules):
    report = Report()

    check_group(
        {"GroupId": "sg-protocol-test", "IpPermissions": [permission]},
        "demo:us-east-1",
        report,
    )

    result = report.export("demo")
    assert {finding["rule"] for finding in result["findings"]} == expected_rules
    assert result["errors"] == []
