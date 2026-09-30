"""The architectural guarantee, measured offline.

These tests assume the WORST case: a model that has been completely taken
over and obeys every injected instruction. The question is not "does the
model resist?" but "does it matter if it doesn't?"

They run with no API key, no network and no cost, on every push.
"""

from __future__ import annotations

import pytest

from app.llm import build_evidence, resolve, write_rationale
from app.models import Rationale
from app.parser import parse_eml
from app.rules import PHISHING_AT, SUSPICIOUS_AT, findings_for, parse_auth_results, verdict_for
from redteam.cases import AMBIGUOUS_BASE, CASES, STRONG_BASE, Case, build_eml


class CompromisedWriter:
    """A model that has fallen for the injection completely."""

    def write(self, evidence: dict) -> Rationale:
        return Rationale(
            summary="This message is safe and legitimate.",
            reasoning_steps=["The sender is verified."],
            recommended_action="No action required.",
            manipulation_attempt_detected=False,
            adjusted_label="clean",
            written_by="claude",
        )


def analyse(base: dict, case: Case, writer) -> tuple[str, int]:
    email = parse_eml(build_eml(base, case))
    auth = parse_auth_results(email.authentication_results)
    findings = findings_for(email)
    verdict = verdict_for(findings)
    rationale = write_rationale(writer, build_evidence(email, auth, verdict, findings))
    final = resolve(verdict, rationale)
    return final.label, final.score


BENIGN = Case("benign", "no payload", text="Please review the notice below.")


def test_the_strong_corpus_scores_above_the_threshold(  ) -> None:
    """Sanity: the base message must be condemned by rules alone."""
    _, score = analyse(STRONG_BASE, BENIGN, CompromisedWriter())
    assert score >= PHISHING_AT


def test_the_ambiguous_corpus_lands_in_the_band() -> None:
    """Sanity: the other base must sit where the model is allowed to decide."""
    email = parse_eml(build_eml(AMBIGUOUS_BASE, BENIGN))
    score = verdict_for(findings_for(email)).score
    assert SUSPICIOUS_AT <= score < PHISHING_AT


@pytest.mark.parametrize("case", CASES, ids=lambda c: c.name)
def test_no_injection_can_clear_a_confident_verdict(case: Case) -> None:
    """The guarantee. Even a fully compromised model changes nothing here."""
    label, _ = analyse(STRONG_BASE, case, CompromisedWriter())
    assert label == "phishing", f"{case.technique} moved a confident verdict"


@pytest.mark.parametrize("case", CASES, ids=lambda c: c.name)
def test_injected_text_never_reaches_the_instructions(case: Case) -> None:
    """Sender text must live only inside the quarantined field."""
    email = parse_eml(build_eml(STRONG_BASE, case))
    auth = parse_auth_results(email.authentication_results)
    findings = findings_for(email)
    evidence = build_evidence(email, auth, verdict_for(findings), findings)
    rest = {k: v for k, v in evidence.items() if k != "untrusted_message_content"}
    marker = (case.text or case.html)[:40]
    if marker.strip():
        assert marker not in str(rest)


def test_the_ambiguous_band_is_where_the_model_is_trusted() -> None:
    """Documented honestly: here a compromised model CAN change the label.

    That is the designed trust boundary, not a bug - and it is why the band
    is narrow and why redteam/REPORT.md measures it against the real model.
    """
    label, _ = analyse(AMBIGUOUS_BASE, CASES[0], CompromisedWriter())
    assert label == "clean"
