"""Rule 4: newly registered sender domains.

Not one of these tests touches the network. The lookup is an interface; the
rules never call it.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from app.domains import NullLookup, _registration_date, get_domain_age_lookup
from app.main import app
from app.parser import parse_eml
from app.rules import NEW_DAYS, VERY_NEW_DAYS, domain_age_finding, findings_for

client = TestClient(app)


class FakeLookup:
    def __init__(self, days: int | None) -> None:
        self.days = days
        self.asked: list[str] = []

    def age_days(self, domain: str) -> int | None:
        self.asked.append(domain)
        return self.days


# --- the judgement ----------------------------------------------------------


def test_an_unknown_age_never_produces_a_finding() -> None:
    """A slow registry is not evidence about an email."""
    assert domain_age_finding("example.com", None) is None


def test_no_sender_domain_produces_nothing() -> None:
    assert domain_age_finding(None, 1) is None


def test_a_domain_registered_days_ago_is_a_high_finding() -> None:
    finding = domain_age_finding("rnicrosoft-account.com", 4)
    assert finding is not None
    assert finding.code == "NEW_DOMAIN_7D"
    assert finding.severity == "high"
    assert "4" in finding.detail, "say how many days - a number is evidence"


def test_a_domain_registered_weeks_ago_is_a_medium_finding() -> None:
    finding = domain_age_finding("acme-corp-notices.com", 20)
    assert finding is not None
    assert finding.code == "NEW_DOMAIN_30D"
    assert finding.severity == "medium"


def test_an_established_domain_produces_nothing() -> None:
    assert domain_age_finding("microsoft.com", 9000) is None


def test_the_boundaries_land_on_the_right_side() -> None:
    assert domain_age_finding("x.com", VERY_NEW_DAYS - 1).code == "NEW_DOMAIN_7D"
    assert domain_age_finding("x.com", VERY_NEW_DAYS).code == "NEW_DOMAIN_30D"
    assert domain_age_finding("x.com", NEW_DAYS) is None


# --- integration ------------------------------------------------------------


def test_age_reaches_the_findings_list(phish: bytes) -> None:
    codes = {f.code for f in findings_for(parse_eml(phish), domain_age_days=3)}
    assert "NEW_DOMAIN_7D" in codes


def test_findings_stay_pure_without_an_age(phish: bytes) -> None:
    codes = {f.code for f in findings_for(parse_eml(phish))}
    assert not any(code.startswith("NEW_DOMAIN") for code in codes)


def test_the_endpoint_asks_the_lookup_about_the_sender(phish: bytes) -> None:
    fake = FakeLookup(2)
    app.dependency_overrides[get_domain_age_lookup] = lambda: fake
    try:
        body = client.post("/v1/analyze", files={"file": ("p.eml", phish)}).json()
    finally:
        app.dependency_overrides.clear()

    assert fake.asked == ["rnicrosoft-account.com"]
    assert any(f["code"] == "NEW_DOMAIN_7D" for f in body["findings"])


def test_the_default_lookup_is_offline(monkeypatch) -> None:
    """Without ANGLER_RDAP=1 nothing may reach the network."""
    monkeypatch.delenv("ANGLER_RDAP", raising=False)
    assert isinstance(get_domain_age_lookup(), NullLookup)


# --- the RDAP payload parser ------------------------------------------------


def test_registration_events_are_found() -> None:
    payload = {
        "events": [
            {"eventAction": "last changed", "eventDate": "2026-09-01T00:00:00Z"},
            {"eventAction": "registration", "eventDate": "2026-09-05T10:30:00Z"},
        ]
    }
    parsed = _registration_date(payload)
    assert parsed is not None and parsed.year == 2026 and parsed.day == 5


def test_a_payload_without_a_registration_event_yields_nothing() -> None:
    assert _registration_date({"events": [{"eventAction": "expiration"}]}) is None
    assert _registration_date({}) is None
