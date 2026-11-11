from fastapi.testclient import TestClient

from cloudsentinel.api import app
from unittest.mock import Mock
from cloudsentinel import api

client = TestClient(app)


def test_health():
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_demo_scan_returns_expected_findings():
    response = client.post("/scans")

    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"

    report = response.json()
    assert report["source"] == "demo"
    assert report["status"] == "complete"
    assert {finding["rule"] for finding in report["findings"]} == {
        "EC2-01",
        "S3-01",
    }
    assert report["errors"] == []


def test_live_scan_is_disabled_by_default(monkeypatch):
    monkeypatch.delenv("CS_API_LIVE", raising=False)

    response = client.post("/scans", params={"live": "true"})

    assert response.status_code == 403
    assert response.json() == {"detail": "Live API scans are disabled."}

def test_overlapping_scan_is_rejected():
    acquired = api.scan_lock.acquire(blocking=False)
    assert acquired, "The scan lock should be available before this test."

    try:
        response = client.post("/scans")
    finally:
        api.scan_lock.release()

    assert response.status_code == 409
    assert response.json() == {"detail": "A scan is already running."}

    # Confirm that scans work after the existing scan releases its lock.
    assert client.post("/scans").status_code == 200


def test_invalid_live_configuration_releases_lock(monkeypatch):
    monkeypatch.setenv("CS_API_LIVE", "1")
    simulated_run = Mock(side_effect=ValueError("Simulated missing configuration."))
    monkeypatch.setattr(api, "run", simulated_run)

    response = client.post("/scans", params={"live": "true"})

    assert response.status_code == 503
    assert response.json() == {"detail": "Simulated missing configuration."}
    simulated_run.assert_called_once_with(live=True)

    # Restore the real runner and confirm that the offline demo still works.
    monkeypatch.undo()
    assert client.post("/scans").status_code == 200