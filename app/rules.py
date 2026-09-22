"""Detection rules. Each one turns raw evidence into a judgement.

Rule 1: read the receiving mail server's authentication verdict.
"""

from __future__ import annotations

import re

from app.models import AuthResults, Finding, ParsedEmail, Verdict


def _method(raw: str, name: str) -> str | None:
    """Pull one method's result out of the header.

    The header looks like this, all on one line:
        mx.ut.edu; spf=softfail smtp.mailfrom=relay.xyz; dkim=none;
        dmarc=fail (p=QUARANTINE) header.from=example.com

    So `_method(raw, "spf")` finds `spf=` and returns what follows it.
    """
    match = re.search(rf"\b{name}=([a-z]+)", raw, re.IGNORECASE)
    return match.group(1).lower() if match else None


def _policy(raw: str) -> str | None:
    """The domain's published DMARC policy, written as (p=QUARANTINE)."""
    match = re.search(r"\(p=([a-z]+)\)", raw, re.IGNORECASE)
    return match.group(1).lower() if match else None


def parse_auth_results(raw: str | None) -> AuthResults:
    """Turn the Authentication-Results header into a structured verdict."""
    if not raw:
        return AuthResults()

    return AuthResults(
        spf=_method(raw, "spf"),
        dkim=_method(raw, "dkim"),
        dmarc=_method(raw, "dmarc"),
        dmarc_policy=_policy(raw),
    )


# ---------------------------------------------------------------------------
# Rule 2: lookalike sender domains
# ---------------------------------------------------------------------------

# Character pairs that render almost identically at normal reading size.
# "rn" is the classic: at 11pt, rnicrosoft.com reads as microsoft.com.
# The Cyrillic entries are different Unicode codepoints that draw the same
# glyph as their Latin counterparts.
_HOMOGLYPHS = {
    "rn": "m",
    "vv": "w",
    "1": "l",
    "0": "o",
    "а": "a",  # Cyrillic
    "е": "e",  # Cyrillic
    "о": "o",  # Cyrillic
    "с": "c",  # Cyrillic
    "р": "p",  # Cyrillic
}

# Brands worth impersonating, and the domains that legitimately belong to them.
_BRANDS = {
    "microsoft": {"microsoft.com", "microsoftonline.com", "office.com", "live.com"},
    "okta": {"okta.com"},
    "paypal": {"paypal.com"},
    "google": {"google.com", "gmail.com"},
    "apple": {"apple.com", "icloud.com"},
}


def normalize_homoglyphs(domain: str) -> str:
    """Rewrite visual confusions into what a reader THINKS they are seeing.

    normalize_homoglyphs("rnicrosoft-account.com") -> "microsoft-account.com"
    """
    domain = domain.lower()
    for wrong, right in _HOMOGLYPHS.items():
        domain = domain.replace(wrong, right)
    return domain

def is_punycode(domain: str) -> bool:
    """True if any label is punycode - an ASCII encoding of non-Latin characters.

    "xn--pypal-4ve.com" renders in a browser as a Cyrillic-laced "paypal.com".
    Punycode in a sender domain is almost never innocent.
    """
    domain = domain.lower()
    return domain.startswith("xn--") or ".xn--" in domain


def _is_legitimate(domain: str, legitimate: set[str]) -> bool:
    """The domain itself, or a subdomain of it. ut.okta.com belongs to Okta."""
    return any(domain == known or domain.endswith("." + known) for known in legitimate)


def detect_lookalike(domain: str) -> str | None:
    """Return the brand this domain is imitating, or None if it's clean.

    Order matters: a domain that legitimately belongs to the brand is cleared
    before the lookalike check runs, otherwise microsoft.com flags itself.
    """
    domain = domain.lower().strip(".")
    normalized = normalize_homoglyphs(domain)

    for brand, legitimate in _BRANDS.items():
        if _is_legitimate(domain, legitimate):
            return None
        if brand in normalized:
            return brand
    return None


# ---------------------------------------------------------------------------
# Assembling the findings
# ---------------------------------------------------------------------------

_SEVERITY_ORDER = {"high": 0, "medium": 1, "info": 2}


def findings_for(email: ParsedEmail) -> list[Finding]:
    """Run every rule against one parsed message, worst finding first."""
    found: list[Finding] = []
    auth = parse_auth_results(email.authentication_results)

    if auth.dmarc == "fail":
        policy = auth.dmarc_policy or "none"
        found.append(
            Finding(
                code="DMARC_FAIL",
                severity="high",
                title="DMARC failed",
                detail=(
                    "The domain in the visible From header is not authenticated. "
                    f"That domain publishes p={policy}, which is what it asks "
                    "receivers to do with messages like this one."
                ),
            )
        )

    if auth.dkim in {"none", "fail"}:
        found.append(
            Finding(
                code="DKIM_MISSING" if auth.dkim == "none" else "DKIM_FAIL",
                severity="medium",
                title="No valid DKIM signature",
                detail=(
                    "Nothing cryptographically ties this message to the domain "
                    "it claims to come from."
                ),
            )
        )

    if auth.spf in {"fail", "softfail"}:
        found.append(
            Finding(
                code="SPF_FAIL",
                severity="medium",
                title=f"SPF {auth.spf}",
                detail=(
                    "The server that sent this message is not on the list of "
                    "servers the sending domain authorises."
                ),
            )
        )

    sender = email.from_addresses[0] if email.from_addresses else None
    domain = sender.domain if sender else None

    if domain:
        brand = detect_lookalike(domain)
        if brand:
            found.append(
                Finding(
                    code="LOOKALIKE_DOMAIN",
                    severity="high",
                    title=f"Sender domain imitates {brand}",
                    detail=(
                        f"{domain} is not a {brand} domain, but reads as one at "
                        "normal size. Character substitutions like rn for m "
                        "survive every technical check because the attacker "
                        "genuinely owns the lookalike domain."
                    ),
                )
            )

        if is_punycode(domain):
            found.append(
                Finding(
                    code="PUNYCODE_DOMAIN",
                    severity="high",
                    title="Sender domain uses punycode",
                    detail=(
                        f"{domain} encodes non-Latin characters that a mail "
                        "client renders as something else entirely."
                    ),
                )
            )

    reply_domain = email.reply_to[0].domain if email.reply_to else None
    if domain and reply_domain and reply_domain != domain:
        found.append(
            Finding(
                code="REPLY_TO_MISMATCH",
                severity="medium",
                title="Replies go to a different domain",
                detail=(
                    f"The message presents itself as {domain} but replies would "
                    f"be delivered to {reply_domain}."
                ),
            )
        )

    found.sort(key=lambda f: _SEVERITY_ORDER.get(f.severity, 9))
    return found


# ---------------------------------------------------------------------------
# Rule 5: scoring
# ---------------------------------------------------------------------------

# How many points each finding contributes to the risk score.
#
# Every false positive costs an analyst's time, and a tool that cries wolf
# gets switched off - so signals with innocent explanations stay cheap.
# The tests check that these choices are internally consistent, not that they
# match any particular number.
_WEIGHTS: dict[str, int] = {
    # A domain that exists to impersonate a brand has no innocent explanation.
    "LOOKALIKE_DOMAIN": 45,
    "PUNYCODE_DOMAIN": 40,
    # DMARC failing means alignment failed, which subsumes SPF. Scored once.
    "DMARC_FAIL": 35,
    # Deliberately cheap: forwarders and mailing lists break these on
    # legitimate mail constantly. Weighted high, they quarantine newsletters.
    "DKIM_FAIL": 15,
    "DKIM_MISSING": 10,
    "SPF_FAIL": 10,
    # Real signal, but support desks and ticketing systems do this legitimately.
    "REPLY_TO_MISMATCH": 15,
}

# Above this, the rules alone are confident enough and the model is never
# asked to classify - it only writes the explanation (M3).
PHISHING_AT = 70

# Between the two, the message is ambiguous. This is the band where the model
# earns its cost.
SUSPICIOUS_AT = 35


def score_for(findings: list[Finding]) -> int:
    """Add up the weights of everything that fired, capped at 100."""
    return min(sum(_WEIGHTS.get(f.code, 0) for f in findings), 100)


def label_for_score(score: int) -> str:
    if score >= PHISHING_AT:
        return "phishing"
    if score >= SUSPICIOUS_AT:
        return "suspicious"
    return "clean"


def verdict_for(findings: list[Finding]) -> Verdict:
    score = score_for(findings)
    return Verdict(score=score, label=label_for_score(score), resolved_by="rules")
