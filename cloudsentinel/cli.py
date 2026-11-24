import argparse
import json
import sys

from botocore.exceptions import BotoCoreError, ClientError

from .service import run


def main():
    parser = argparse.ArgumentParser(description="CloudSentinel AI posture scanner")
    parser.add_argument("--live", action="store_true", help="Read AWS configuration")
    parser.add_argument("--analyze", action="store_true", help="Invoke Bedrock once")
    parser.add_argument(
        "--scenario",
        choices=["secure", "exposed", "denied"],
        help="Select a local demo scenario. Defaults to exposed.",
    )
    args = parser.parse_args()

    if args.analyze and not args.live:
        parser.error("--analyze requires --live")
    if args.scenario is not None and args.live:
        parser.error("--scenario is available only for local demos")

    options = {
        "live": args.live,
        "with_analysis": args.analyze,
    }
    if args.scenario is not None:
        options["scenario"] = args.scenario

    try:
        report = run(**options)
    except ValueError as exc:
        parser.error(str(exc))
    except (BotoCoreError, ClientError) as exc:
        print(f"AWS session unavailable ({type(exc).__name__}).", file=sys.stderr)
        return 2

    print(json.dumps(report, indent=2))
    return 1 if report["status"] == "partial" else 0