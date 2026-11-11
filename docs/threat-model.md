# CloudSentinel AI threat model

## Scope

The current system runs through a local CLI or FastAPI server. It scans synthetic data by default. Live scanning and Bedrock analysis require explicit configuration. Terraform defines scanner and analysis roles and an optional budget.

## Assets to protect

- AWS credentials and role sessions.
- Resource identifiers and configuration findings in scan reports.
- The integrity of deterministic findings and coverage errors.
- Bedrock invocation permissions and spending.
- Source code, dependencies, and CI configuration.

## Trust boundaries and controls

| Boundary | Threat | Current control | Remaining risk |
| --- | --- | --- | --- |
| Operator to local API | Unauthorized scans | Server is run on loopback and live API scanning is disabled by default | The API has no authentication. Local processes can access it |
| Scanner to AWS | Excessive access | Terraform grants configuration reads through a dedicated scanner role | Effective permissions and role assumption need live verification |
| AWS responses to report | Missing data creates false assurance | Failed reads create coverage errors and mark the report partial | Configuration checks have documented scope limits |
| Report to Bedrock | Sensitive data or malicious resource text enters the prompt | The analyzer builds an allowlisted payload from known rule definitions and counts | Payload handling needs continued review when new fields are introduced |
| Bedrock to operator | Incorrect or malformed advice | Response schema and length checks constrain output. Findings and severity come from deterministic rules | Schema-valid advice can still be inaccurate and needs human review |
| Operator to inference service | Unexpected spending | Analysis is explicit, output is bounded, and SDK retries are disabled for inference | Repeated executions can accumulate charges. Budget alerts arrive after billing updates |
| Repository to CI | Credentials exposed during checks | Current CI uses simulated AWS responses and requires no AWS secrets | Dependencies and workflow actions execute code and require ongoing review |

## Before a shared deployment

Add authentication, authorization, request quotas, protected report storage, and durable audit records. Review effective IAM permissions and verify the selected model in the intended AWS region.

## Evidence and limitations

The offline test suite covers scanner findings, pagination, coverage failures, API behavior, and Bedrock payload and response handling. GitHub Actions runs the tests and validates Terraform.

Live AWS scanning, role assumption, model access, and budget email delivery remain pending verification.