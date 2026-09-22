"""Rule 5: the aggregate score.

These tests deliberately do NOT check exact point values - those are your
judgement call. They check that the judgement is internally consistent.
"""

from __future__ import annotations

from app.models import Finding
from app.parser import parse_eml
from app.rules import (
    PHISHING_AT,
    SUSPICIOUS_AT,
    _WEIGHTS,
    findings_for,
    label_for_score,
    score_for,
    verdict_for,
)


def finding(code: str, severity: str = "high") -> Finding:
    return Finding(code=code, severity=severity, title=code, detail="")


def test_every_rule_carries_some_weight() -> None:
    """A rule worth firing is worth scoring. Zero means you forgot one."""
    assert all(weight > 0 for weight in _WEIGHTS.values()), (
        "these still score zero: "
        + ", ".join(code for code, weight in _WEIGHTS.items() if weight == 0)
    )


def test_a_lookalike_domain_outweighs_a_missing_signature() -> None:
    """Impersonating a brand is worse than simply being unsigned."""
    assert _WEIGHTS["LOOKALIKE_DOMAIN"] > _WEIGHTS["DKIM_MISSING"]


def test_dmarc_failure_outweighs_spf_failure() -> None:
    """DMARC failing means alignment failed, which subsumes SPF."""
    assert _WEIGHTS["DMARC_FAIL"] > _WEIGHTS["SPF_FAIL"]


def test_no_single_medium_finding_is_enough_to_condemn() -> None:
    """One weak signal must never reach the phishing threshold on its own."""
    for code in ("DKIM_MISSING", "SPF_FAIL", "REPLY_TO_MISMATCH"):
        assert score_for([finding(code, "medium")]) < PHISHING_AT, code


def test_the_score_is_capped_at_100() -> None:
    every = [finding(code) for code in _WEIGHTS]
    assert score_for(every) <= 100


def test_thresholds_map_to_labels() -> None:
    assert label_for_score(PHISHING_AT) == "phishing"
    assert label_for_score(PHISHING_AT - 1) == "suspicious"
    assert label_for_score(SUSPICIOUS_AT) == "suspicious"
    assert label_for_score(SUSPICIOUS_AT - 1) == "clean"
    assert label_for_score(0) == "clean"


def test_the_phishing_sample_is_condemned(phish: bytes) -> None:
    verdict = verdict_for(findings_for(parse_eml(phish)))
    assert verdict.score >= PHISHING_AT
    assert verdict.label == "phishing"


def test_the_genuine_sample_is_clean(legit: bytes) -> None:
    verdict = verdict_for(findings_for(parse_eml(legit)))
    assert verdict.score == 0
    assert verdict.label == "clean"


def test_the_verdict_records_how_it_was_reached(phish: bytes) -> None:
    assert verdict_for(findings_for(parse_eml(phish))).resolved_by == "rules"
