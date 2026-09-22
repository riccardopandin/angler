"""Weekend 2, rule 1: turn the Authentication-Results header into a verdict.

These tests are the specification. Make them pass by writing app/rules.py.
"""

from __future__ import annotations

from app.parser import parse_eml
from app.rules import (
    detect_lookalike,
    is_punycode,
    normalize_homoglyphs,
    parse_auth_results,
)


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


# --- Rule 2: lookalike sender domains --------------------------------------


def test_rn_normalizes_to_m() -> None:
    assert normalize_homoglyphs("rnicrosoft-account.com") == "microsoft-account.com"


def test_cyrillic_characters_normalize_to_latin() -> None:
    assert normalize_homoglyphs("pаypal.com") == "paypal.com"


def test_a_lookalike_names_the_brand_it_imitates() -> None:
    assert detect_lookalike("rnicrosoft-account.com") == "microsoft"


def test_the_real_domain_is_not_a_lookalike() -> None:
    assert detect_lookalike("microsoft.com") is None
    assert detect_lookalike("okta.com") is None


def test_a_subdomain_of_the_real_domain_is_fine() -> None:
    assert detect_lookalike("ut.okta.com") is None


def test_an_unrelated_domain_is_not_a_lookalike() -> None:
    assert detect_lookalike("spartans.ut.edu") is None


def test_punycode_is_flagged() -> None:
    assert is_punycode("xn--pypal-4ve.com") is True
    assert is_punycode("login.xn--micrsoft-w4a.com") is True
    assert is_punycode("paypal.com") is False


def test_the_phishing_sample_is_caught(phish: bytes) -> None:
    sender = parse_eml(phish).from_addresses[0]
    assert detect_lookalike(sender.domain) == "microsoft"
