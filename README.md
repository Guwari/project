# CloudSentinel AI

CloudSentinel AI is an AWS cloud security posture scanner. It uses
deterministic rules to flag configuration issues and can optionally use
Amazon Bedrock to explain findings. The Bedrock request contains aggregate
rule data, while resource identifiers stay in the scan report.

## Run the local demo

With Python 3.11 or later, run these commands from the project root:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[test]'
.venv/bin/cloudsentinel
```

The demo uses synthetic data. Expect a complete report with `EC2-01`
(unrestricted SSH) and `S3-01` (incomplete S3 public access blocking).

## Run the tests

```bash
.venv/bin/python -m pytest -q
```

The tests simulate AWS and Bedrock responses. They cover secure and exposed
configurations, denied reads, and invalid model output.

## Validate Terraform locally

With Terraform installed, run this from the project root:

```bash
terraform -chdir=infra init -backend=false
terraform -chdir=infra validate
```

Terraform defines separate scanner and Bedrock roles and an optional monthly
budget with email alerts. Initialization downloads the AWS provider.
Local validation requires no AWS credentials.

## Project status

The offline demo and simulated tests have passed. The Terraform configuration
has been validated locally. Live AWS scanning, Bedrock inference, and budget
email delivery are pending live verification.

See [the architecture and roadmap](docs/architecture.md).


See the [threat model](docs/threat-model.md) for security boundaries,
current controls, and remaining verification work.
