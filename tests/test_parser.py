"""These tests define what the parser must extract. Read them as the spec."""

from __future__ import annotations

from app.parser import parse_eml


def test_sender_address_and_domain(phish: bytes) -> None:
    parsed = parse_eml(phish)
    sender = parsed.from_addresses[0]
    assert sender.address == "security@rnicrosoft-account.com"
    assert sender.domain == "rnicrosoft-account.com"
    assert sender.display_name == "Microsoft 365 Security"


def test_reply_to_points_somewhere_else(phish: bytes) -> None:
    parsed = parse_eml(phish)
    assert parsed.from_addresses[0].domain != parsed.reply_to[0].domain


def test_routing_chain_is_oldest_first(phish: bytes) -> None:
    parsed = parse_eml(phish)
    assert len(parsed.hops) == 3
    assert parsed.hops[0].index == 1
    assert parsed.hops[0].ip == "185.243.115.44"
    assert parsed.hops[-1].ip == "104.47.55.12"


def test_origin_ip_is_the_oldest_hop(phish: bytes) -> None:
    assert parse_eml(phish).origin_ip == "185.243.115.44"


def test_authentication_results_are_captured_verbatim(phish: bytes) -> None:
    results = parse_eml(phish).authentication_results
    assert results is not None
    assert "dmarc=fail" in results


def test_anchor_text_can_disagree_with_href(phish: bytes) -> None:
    parsed = parse_eml(phish)
    assert len(parsed.links) == 2
    login = parsed.links[0]
    assert login.host == "login.rnicrosoft-account.com"
    assert login.anchor_text == "https://login.microsoftonline.com"
    assert login.host not in (login.anchor_text or "")


def test_both_bodies_are_extracted(phish: bytes) -> None:
    parsed = parse_eml(phish)
    assert parsed.text_body is not None and "Verify now" in parsed.text_body
    assert parsed.html_body is not None and "<b>24 hours</b>" in parsed.html_body


def test_no_attachments_in_this_sample(phish: bytes) -> None:
    assert parse_eml(phish).attachments == []


def test_a_clean_message_parses_too(legit: bytes) -> None:
    parsed = parse_eml(legit)
    assert parsed.from_addresses[0].domain == "okta.com"
    assert parsed.reply_to == []
    assert len(parsed.hops) == 1
    assert len(parsed.links) == 1
