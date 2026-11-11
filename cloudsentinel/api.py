import os
from threading import Lock

from botocore.exceptions import BotoCoreError, ClientError
from fastapi import FastAPI, HTTPException, Response

from .service import run

app = FastAPI(title="CloudSentinel AI")
scan_lock = Lock()


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/scans")
def create_scan(response: Response, live: bool = False):
    if live and os.getenv("CS_API_LIVE") != "1":
        raise HTTPException(403, "Live API scans are disabled.")
    if not scan_lock.acquire(blocking=False):
        raise HTTPException(409, "A scan is already running.")
    try:
        response.headers["Cache-Control"] = "no-store"
        return run(live=live)
    except ValueError as exc:
        raise HTTPException(503, str(exc)) from exc
    except (BotoCoreError, ClientError) as exc:
        raise HTTPException(503, "AWS session unavailable.") from exc
    finally:
        scan_lock.release()
