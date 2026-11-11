"""Optional advisory analysis with an allowlisted data projection."""
import json
from collections import Counter

from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError
from pydantic import BaseModel, ConfigDict, Field

from .scanner import RULES

MODEL_CONFIG = Config(connect_timeout=3, read_timeout=30, retries={"total_max_attempts": 1})


class Advisory(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    summary: str = Field(min_length=1, max_length=1000)
    next_steps: list[str] = Field(min_length=1, max_length=5)


def analyze(report, client, model_id):
    counts = Counter(f["rule"] for f in report["findings"] if f["rule"] in RULES)
    if not counts:
        return {"status": "no_findings"}
    projection = [
        {"rule": rule, "count": min(count, 999), "severity": RULES[rule][0],
         "title": RULES[rule][1]}
        for rule, count in sorted(counts.items())
    ]
    try:
        response = client.converse(
            modelId=model_id,
            system=[{"text": "You are a cloud security reviewer. Provide general defensive "
                             "advice from these aggregate findings. Do not assume effective "
                             "exposure or name specific resources. Return only JSON with "
                             "a summary string and a next_steps array of up to five short strings."}],
            messages=[{"role": "user", "content": [{"text": json.dumps(projection)}]}],
            inferenceConfig={"maxTokens": 512, "temperature": 0},
        )
        if response["stopReason"] != "end_turn":
            return {"status": "invalid_output"}
        blocks = response["output"]["message"]["content"]
        if any(set(block) != {"text"} for block in blocks):
            return {"status": "invalid_output"}
        output = Advisory.model_validate_json("".join(block["text"] for block in blocks))
        if any(not step.strip() or len(step) > 400 for step in output.next_steps):
            return {"status": "invalid_output"}
        return {"status": "ok", **output.model_dump()}
    except (BotoCoreError, ClientError):
        return {"status": "unavailable"}
    except (KeyError, ValueError, TypeError):
        return {"status": "invalid_output"}
