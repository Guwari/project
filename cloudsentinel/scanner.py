"""Read-only AWS configuration checks."""
from contextlib import contextmanager
from dataclasses import dataclass, field
from hashlib import sha256

from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

AWS_CONFIG = Config(connect_timeout=3, read_timeout=10, retries={"total_max_attempts": 2})
RULES = {
    "S3-01": ("medium", "Bucket-level public access block is incomplete", "Enable all four bucket public access block settings."),
    "S3-02": ("high", "Bucket policy is classified as public", "Review the policy and remove unintended public grants."),
    "S3-03": ("low", "Bucket versioning is disabled or suspended", "Enable versioning and review lifecycle costs."),
    "EC2-01": ("high", "Security group allows unrestricted SSH ingress", "Restrict SSH to approved sources or use managed session access."),
    "EC2-02": ("high", "Security group allows unrestricted RDP ingress", "Restrict RDP to approved sources."),
    "EC2-03": ("high", "Security group allows all protocols from the internet", "Allow only required protocols from approved sources."),
    "IAM-01": ("high", "Account summary reports root MFA disabled", "Verify root credential status and enable MFA where applicable."),
    "IAM-02": ("high", "Root access keys exist", "Remove root access keys after verifying dependencies."),
    "CT-01": ("medium", "No logging trail was found in the region", "Verify organization coverage and enable logging if required."),
    "CT-02": ("medium", "Logging trail has log file validation disabled", "Enable log file integrity validation."),
}
BLOCK_FLAGS = (
    "BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"
)
ANYWHERE = {"0.0.0.0/0", "::/0"}


@dataclass
class Report:
    findings: dict = field(default_factory=dict)
    errors: list = field(default_factory=list)

    def add(self, rule, resource):
        severity, title, remediation = RULES[rule]
        key = sha256(f"{rule}:{resource}".encode()).hexdigest()
        self.findings[key] = {
            "id": key, "rule": rule, "resource": resource, "severity": severity,
            "title": title, "remediation": remediation,
        }

    @contextmanager
    def coverage(self, operation, resource):
        try:
            yield
        except ClientError as exc:
            self.errors.append({"operation": operation, "resource": resource,
                                "code": exc.response["Error"]["Code"]})
        except BotoCoreError as exc:
            self.errors.append({"operation": operation, "resource": resource,
                                "code": type(exc).__name__})

    def export(self, source):
        return {"source": source, "status": "partial" if self.errors else "complete",
                "findings": [self.findings[key] for key in sorted(self.findings)],
                "errors": self.errors}


def check_bucket(client, name, account, report):
    args = {"Bucket": name, "ExpectedBucketOwner": account}
    resource = f"{account}:s3:{name}"
    with report.coverage("GetPublicAccessBlock", resource):
        try:
            block = client.get_public_access_block(**args)["PublicAccessBlockConfiguration"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchPublicAccessBlockConfiguration":
                raise
            block = {}
        if not all(block.get(flag) for flag in BLOCK_FLAGS):
            report.add("S3-01", resource)

    with report.coverage("GetBucketPolicyStatus", resource):
        try:
            if client.get_bucket_policy_status(**args)["PolicyStatus"]["IsPublic"]:
                report.add("S3-02", resource)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchBucketPolicy":
                raise

    with report.coverage("GetBucketVersioning", resource):
        if client.get_bucket_versioning(**args).get("Status") != "Enabled":
            report.add("S3-03", resource)


def check_group(group, scope, report):
    resource = f"{scope}:ec2:{group['GroupId']}"
    for permission in group.get("IpPermissions", []):
        sources = {item["CidrIp"] for item in permission.get("IpRanges", [])}
        sources.update(item["CidrIpv6"] for item in permission.get("Ipv6Ranges", []))
        if sources.isdisjoint(ANYWHERE):
            continue
        protocol = permission["IpProtocol"]
        if protocol == "-1":
            report.add("EC2-03", resource)
        if protocol in {"tcp", "6", "-1"}:
            for port, rule in [(22, "EC2-01"), (3389, "EC2-02")]:
                if protocol == "-1" or permission["FromPort"] <= port <= permission["ToPort"]:
                    report.add(rule, resource)


def check_trails(client, scope, report):
    with report.coverage("DescribeTrails", scope):
        trails = client.describe_trails(includeShadowTrails=True)["trailList"]
        logging = False
        status_unknown = False
        for trail in trails:
            arn = trail["TrailARN"]
            before = len(report.errors)
            with report.coverage("GetTrailStatus", arn):
                if client.get_trail_status(Name=arn)["IsLogging"]:
                    logging = True
                    if trail.get("LogFileValidationEnabled") is False:
                        report.add("CT-02", arn)
            status_unknown |= len(report.errors) > before
        if not logging and not status_unknown:
            report.add("CT-01", scope)


def scan(session, regions):
    home = regions[0]
    report = Report()

    def client(service, region=home):
        return session.client(service, region_name=region, config=AWS_CONFIG)

    with report.coverage("GetCallerIdentity", "account"):
        account = client("sts").get_caller_identity()["Account"]
    if report.errors:
        return report.export("aws")

    with report.coverage("ListBuckets", account):
        for page in client("s3").get_paginator("list_buckets").paginate():
            for bucket in page.get("Buckets", []):
                check_bucket(client("s3", bucket.get("BucketRegion") or home),
                             bucket["Name"], account, report)

    with report.coverage("GetAccountSummary", account):
        summary = client("iam").get_account_summary()["SummaryMap"]
        for key, value, rule in [
            ("AccountMFAEnabled", 0, "IAM-01"), ("AccountAccessKeysPresent", 1, "IAM-02")
        ]:
            if key not in summary:
                report.errors.append({"operation": "GetAccountSummary", "resource": account,
                                      "code": f"Missing{key}"})
            elif summary[key] == value:
                report.add(rule, account)

    for region in regions:
        scope = f"{account}:{region}"
        with report.coverage("DescribeSecurityGroups", scope):
            for page in client("ec2", region).get_paginator("describe_security_groups").paginate():
                for group in page["SecurityGroups"]:
                    check_group(group, scope, report)
        check_trails(client("cloudtrail", region), scope, report)
    return report.export("aws")


def demo():
    report = Report()
    check_group({"GroupId": "sg-demo", "IpPermissions": [
        {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
         "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}
    ]}, "demo:us-east-1", report)
    report.add("S3-01", "demo:s3:example-bucket")
    return report.export("demo")
