"""The model layer. Every test here runs offline - no key, no network, no cost."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.llm import (
    MAX_BODY_CHARS,
    StubWriter,
    build_evidence,
    get_writer,
    resolve,
    write_rationale,
)
from app.main import app
from app.models import Rationale, Verdict
from app.parser import parse_eml
from app.rules import findings_for, parse_auth_results, verdict_for

client = TestClient(app)


def packet(raw: bytes) -> dict:
    email = parse_eml(raw)
    findings = findings_for(email)
    return build_evidence(
        email, parse_auth_results(email.authentication_results), verdict_for(findings), findings
    )


class FakeWriter:
    """Stands in for the API. Records what it was handed."""

    def __init__(self, rationale: Rationale | None = None) -> None:
        self.seen: dict | None = None
        self.rationale = rationale or Rationale(
            summary="fake", recommended_action="none", written_by="claude"
        )

    def write(self, evidence: dict) -> Rationale:
        self.seen = evidence
        return self.rationale


class ExplodingWriter:
    def write(self, evidence: dict) -> Rationale:
        raise RuntimeError("the API is down")


# --- the evidence packet ---------------------------------------------------


def test_sender_written_text_is_quarantined_in_one_field(phish: bytes) -> None:
    """Attacker-controlled text must be reachable only under a labelled key."""
    evidence = packet(phish)
    untrusted = evidence["untrusted_message_content"]
    assert untrusted["subject"] == "Your password expires in 24 hours"
    assert "Verify now" in untrusted["body_excerpt"]
    # and nowhere else
    rest = {k: v for k, v in evidence.items() if k != "untrusted_message_content"}
    assert "Verify now" not in str(rest)


def test_the_body_excerpt_is_bounded() -> None:
    from app.models import Address, ParsedEmail

    email = ParsedEmail(text_body="A" * (MAX_BODY_CHARS * 3))
    evidence = build_evidence(
        email, parse_auth_results(None), Verdict(score=0, label="clean", resolved_by="rules"), []
    )
    assert len(evidence["untrusted_message_content"]["body_excerpt"]) == MAX_BODY_CHARS


def test_a_confident_verdict_is_not_marked_provisional(phish: bytes) -> None:
    assert packet(phish)["verdict"]["label_is_provisional"] is False


# --- who may change the verdict --------------------------------------------


def test_the_model_cannot_overturn_a_confident_verdict() -> None:
    """The defence that matters: no code path lets injection clear a phish."""
    confident = Verdict(score=100, label="phishing", resolved_by="rules")
    hijacked = Rationale(summary="", recommended_action="", adjusted_label="clean")
    assert resolve(confident, hijacked) == confident


def test_the_model_may_settle_the_ambiguous_band() -> None:
    ambiguous = Verdict(score=45, label="suspicious", resolved_by="rules")
    settled = resolve(ambiguous, Rationale(summary="", recommended_action="", adjusted_label="phishing"))
    assert settled.label == "phishing"
    assert settled.resolved_by == "model"


def test_a_nonsense_label_is_ignored() -> None:
    ambiguous = Verdict(score=45, label="suspicious", resolved_by="rules")
    assert resolve(ambiguous, Rationale(summary="", recommended_action="", adjusted_label="banana")) == ambiguous


# --- graceful degradation ---------------------------------------------------


def test_no_api_key_means_no_api_call(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    assert isinstance(get_writer(), StubWriter)


def test_an_api_failure_falls_back_instead_of_erroring(phish: bytes) -> None:
    rationale = write_rationale(ExplodingWriter(), packet(phish))
    assert rationale.written_by == "rules"
    assert rationale.summary


# --- the endpoint -----------------------------------------------------------


def test_analyze_returns_a_rationale(phish: bytes) -> None:
    fake = FakeWriter()
    app.dependency_overrides[get_writer] = lambda: fake
    try:
        body = client.post("/v1/analyze", files={"file": ("p.eml", phish)}).json()
    finally:
        app.dependency_overrides.clear()

    assert body["rationale"]["summary"] == "fake"
    assert body["rationale"]["written_by"] == "claude"
    assert fake.seen is not None and "untrusted_message_content" in fake.seen
