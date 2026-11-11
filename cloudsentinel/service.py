import os
import re

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from .analysis import MODEL_CONFIG, analyze
from .scanner import demo, scan


def run(*, live=False, with_analysis=False):
    if not live:
        return demo()

    profile = os.environ.get("CS_SCAN_PROFILE")
    regions = tuple(dict.fromkeys(os.environ.get("CS_REGIONS", "").split(",")))
    if not profile or not 1 <= len(regions) <= 5 or any(
        not re.fullmatch(r"[a-z]{2}(?:-[a-z]+)+-\d+", region) for region in regions
    ):
        raise ValueError("Set CS_SCAN_PROFILE and one to five comma-separated CS_REGIONS.")
    if with_analysis:
        ai_profile = os.environ.get("CS_AI_PROFILE")
        model = os.environ.get("CS_MODEL_ARN")
        if not ai_profile or ai_profile == profile or not model or not re.fullmatch(
            r"arn:aws:bedrock:[a-z]{2}(?:-[a-z]+)+-\d+::foundation-model/[a-zA-Z0-9.:-]+", model
        ):
            raise ValueError("Set a separate CS_AI_PROFILE and a regional CS_MODEL_ARN.")

    report = scan(boto3.Session(profile_name=profile), regions)
    if with_analysis and report["findings"]:
        try:
            client = boto3.Session(profile_name=ai_profile).client(
                "bedrock-runtime", region_name=model.split(":")[3], config=MODEL_CONFIG
            )
            report["analysis"] = analyze(report, client, model)
        except (BotoCoreError, ClientError):
            report["analysis"] = {"status": "unavailable"}
    elif with_analysis:
        report["analysis"] = {"status": "no_findings"}
    return report
