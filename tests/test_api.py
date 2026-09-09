from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_health_endpoint() -> None:
    assert client.get("/healthz").json() == {"status": "ok"}


def test_parse_endpoint_returns_structure(phish: bytes) -> None:
    response = client.post("/v1/parse", files={"file": ("phish_m365.eml", phish)})
    assert response.status_code == 200
    body = response.json()
    assert body["subject"] == "Your password expires in 24 hours"
    assert body["origin_ip"] == "185.243.115.44"
    assert body["filename"] == "phish_m365.eml"


def test_empty_upload_is_rejected_with_a_useful_message() -> None:
    response = client.post("/v1/parse", files={"file": ("empty.eml", b"")})
    assert response.status_code == 400
    assert "empty" in response.json()["detail"].lower()
