"""The findings layer: every rule run against one message."""

from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import app
from app.parser import parse_eml
from app.rules import findings_for

client = TestClient(app)


def codes(raw: bytes) -> set[str]:
    return {finding.code for finding in findings_for(parse_eml(raw))}


def test_the_phishing_sample_raises_the_expected_rules(phish: bytes) -> None:
    assert {"DMARC_FAIL", "LOOKALIKE_DOMAIN", "REPLY_TO_MISMATCH"} <= codes(phish)


def test_a_genuine_message_raises_nothing(legit: bytes) -> None:
    assert codes(legit) == set()


def test_findings_are_ordered_worst_first(phish: bytes) -> None:
    severities = [f.severity for f in findings_for(parse_eml(phish))]
    assert severities == sorted(severities, key=lambda s: {"high": 0, "medium": 1, "info": 2}[s])


def test_analyze_endpoint_returns_findings(phish: bytes) -> None:
    response = client.post("/v1/analyze", files={"file": ("phish.eml", phish)})
    assert response.status_code == 200
    body = response.json()
    assert body["auth"]["dmarc"] == "fail"
    assert any(f["code"] == "LOOKALIKE_DOMAIN" for f in body["findings"])


def test_parse_endpoint_still_works(phish: bytes) -> None:
    assert client.post("/v1/parse", files={"file": ("p.eml", phish)}).status_code == 200
