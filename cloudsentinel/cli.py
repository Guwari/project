import argparse
import json
import sys

from botocore.exceptions import BotoCoreError, ClientError

from .service import run


def main():
    parser = argparse.ArgumentParser(description="CloudSentinel AI posture scanner")
    parser.add_argument("--live", action="store_true", help="Read AWS configuration")
    parser.add_argument("--analyze", action="store_true", help="Invoke Bedrock once")
    args = parser.parse_args()
    if args.analyze and not args.live:
        parser.error("--analyze requires --live")
    try:
        report = run(live=args.live, with_analysis=args.analyze)
    except ValueError as exc:
        parser.error(str(exc))
    except (BotoCoreError, ClientError) as exc:
        print(f"AWS session unavailable ({type(exc).__name__}).", file=sys.stderr)
        return 2
    print(json.dumps(report, indent=2))
    return 1 if report["status"] == "partial" else 0
