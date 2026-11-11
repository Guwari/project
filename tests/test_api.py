from fastapi.testclient import TestClient

from cloudsentinel.api import app

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