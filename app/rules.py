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
