import boto3
import pytest
from botocore.stub import Stubber

from cloudsentinel.scanner import BLOCK_FLAGS, Report, check_bucket

ACCOUNT = "123456789012"
BUCKET = "sentinel-test-bucket"
ARGS = {"Bucket": BUCKET, "ExpectedBucketOwner": ACCOUNT}


@pytest.mark.parametrize(
    "scenario,expected_rules",
    [
        ("secure", set()),
        ("public_policy", {"S3-02"}),
        ("suspended_versioning", {"S3-03"}),
        ("missing_block", {"S3-01"}),
        ("missing_policy", set()),
        ("missing_versioning", {"S3-03"}),
    ],
)
def test_bucket_checks(scenario, expected_rules):
    session = boto3.Session(
        aws_access_key_id="testing",
        aws_secret_access_key="testing",
        region_name="us-east-1",
    )
    client = session.client("s3")
    report = Report()

    with Stubber(client) as stub:
        if scenario == "missing_block":
            stub.add_client_error(
                "get_public_access_block",
                service_error_code="NoSuchPublicAccessBlockConfiguration",
                http_status_code=404,
                expected_params=ARGS,
            )
        else:
            stub.add_response(
                "get_public_access_block",
                {"PublicAccessBlockConfiguration": {
                    flag: True for flag in BLOCK_FLAGS
                }},
                ARGS,
            )

        if scenario == "missing_policy":
            stub.add_client_error(
                "get_bucket_policy_status",
                service_error_code="NoSuchBucketPolicy",
                http_status_code=404,
                expected_params=ARGS,
            )
        else:
            stub.add_response(
                "get_bucket_policy_status",
                {"PolicyStatus": {"IsPublic": scenario == "public_policy"}},
                ARGS,
            )

        versioning = {"Status": "Enabled"}
        if scenario == "suspended_versioning":
            versioning = {"Status": "Suspended"}
        elif scenario == "missing_versioning":
            versioning = {}

        stub.add_response("get_bucket_versioning", versioning, ARGS)

        check_bucket(client, BUCKET, ACCOUNT, report)
        stub.assert_no_pending_responses()

    result = report.export("test")
    assert result["status"] == "complete"
    assert result["errors"] == []
    assert {finding["rule"] for finding in result["findings"]} == expected_rules