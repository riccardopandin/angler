"""Weekend 2, rule 1: turn the Authentication-Results header into a verdict.

These tests are the specification. Make them pass by writing app/rules.py.
"""

from __future__ import annotations

from app.parser import parse_eml
from app.rules import parse_auth_results


def test_forged_message_fails_every_check(phish: bytes) -> None:
    auth = parse_auth_results(parse_eml(phish).authentication_results)
    assert auth.spf == "softfail"
    assert auth.dkim == "none"
    assert auth.dmarc == "fail"


def test_the_published_policy_is_captured(phish: bytes) -> None:
    auth = parse_auth_results(parse_eml(phish).authentication_results)
    assert auth.dmarc_policy == "quarantine"


def test_a_genuine_message_passes_every_check(legit: bytes) -> None:
    auth = parse_auth_results(parse_eml(legit).authentication_results)
    assert auth.spf == "pass"
    assert auth.dkim == "pass"
    assert auth.dmarc == "pass"
    assert auth.dmarc_policy == "reject"


def test_a_message_with_no_auth_header_yields_nothing(legit: bytes) -> None:
    auth = parse_auth_results(None)
    assert auth.spf is None
    assert auth.dkim is None
    assert auth.dmarc is None
