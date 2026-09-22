"""Detection rules. Each one turns raw evidence into a judgement.

Rule 1: read the receiving mail server's authentication verdict.
"""

from __future__ import annotations

import re

from app.models import AuthResults


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
