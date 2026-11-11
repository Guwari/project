# Security rule catalog

| Rule | Severity | Trigger | Interpretation limit |
| --- | --- | --- | --- |
| S3-01 | Medium | Any bucket-level public access block setting is missing or false | Account and organization settings can provide additional protection |
| S3-02 | High | AWS classifies the bucket policy as public | Effective access also depends on public access blocks and other controls |
| S3-03 | Low | Bucket versioning is absent or suspended | Existing object versions and lifecycle policies require separate review |
| EC2-01 | High | IPv4 or IPv6 unrestricted ingress permits TCP port 22 or all protocols | Actual reachability depends on routes, network controls, and attached resources |
| EC2-02 | High | IPv4 or IPv6 unrestricted ingress permits TCP port 3389 or all protocols | Actual reachability depends on routes, network controls, and attached resources |
| EC2-03 | High | IPv4 or IPv6 unrestricted ingress permits all protocols | Attachment and reachability require separate review |
| IAM-01 | High | Account summary reports root MFA disabled | Root credential management and account context require review |
| IAM-02 | High | Account summary reports root access keys present | Key usage and dependencies require separate review |
| CT-01 | Medium | No logging trail is found in the region | This check evaluates trails, with scope limited to the queried region and visible inventory |
| CT-02 | Medium | A logging trail reports log file validation disabled | This checks the setting without verifying delivered logs |

## Coverage errors

Failed AWS reads are recorded in the report's `errors` list and make its
status `partial`. An empty findings list in a partial report cannot establish
that all inspected configurations are secure.

## AI analysis

Severity and findings come from deterministic rules. Optional Bedrock
analysis receives aggregate rule data and returns advisory text.