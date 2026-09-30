"""How old is this domain?

The rules layer does no I/O at all - it is handed facts and returns
judgements. This module is where the network lives, behind an interface, so
that `findings_for` stays a pure function and the whole test suite runs
offline. That separation is the reason 99 tests finish in under two seconds.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Protocol

RDAP_ENDPOINT = "https://rdap.org/domain/{domain}"
TIMEOUT_SECONDS = 4.0


class DomainAgeLookup(Protocol):
    """Anything that can say how many days ago a domain was registered."""

    def age_days(self, domain: str) -> int | None: ...


class NullLookup:
    """Answers "I don't know" to everything. The default, and what tests use.

    A rule that cannot get an answer must not guess one. Returning None makes
    the age rule silently not fire, which is the safe direction.
    """

    def age_days(self, domain: str) -> int | None:
        return None


class RdapLookup:
    """Queries RDAP, the structured replacement for WHOIS.

    Results are cached for the process lifetime: a message with six links to
    the same host should cost one lookup, not six. Any failure - timeout,
    unknown TLD, malformed response - returns None rather than raising,
    because a registry being slow is not evidence about an email.
    """

    def __init__(self, timeout: float = TIMEOUT_SECONDS) -> None:
        self._timeout = timeout
        self._cache: dict[str, int | None] = {}

    def age_days(self, domain: str) -> int | None:
        domain = domain.lower().strip(".")
        if domain in self._cache:
            return self._cache[domain]
        self._cache[domain] = self._fetch(domain)
        return self._cache[domain]

    def _fetch(self, domain: str) -> int | None:
        request = urllib.request.Request(
            RDAP_ENDPOINT.format(domain=domain),
            headers={"Accept": "application/rdap+json", "User-Agent": "angler/0.4"},
        )
        try:
            with urllib.request.urlopen(request, timeout=self._timeout) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except (urllib.error.URLError, TimeoutError, ValueError, OSError):
            return None

        registered = _registration_date(payload)
        if registered is None:
            return None
        return max((datetime.now(timezone.utc) - registered).days, 0)


def _registration_date(payload: dict) -> datetime | None:
    """RDAP records lifecycle events in an `events` array."""
    for event in payload.get("events", []) or []:
        if event.get("eventAction") == "registration":
            raw = event.get("eventDate")
            if not raw:
                return None
            try:
                parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
            except ValueError:
                return None
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    return None


def get_domain_age_lookup() -> DomainAgeLookup:
    """Opt in with ANGLER_RDAP=1. Off by default: the public demo should not
    fire a registry query for every visitor, and tests must never touch the
    network by accident."""
    return RdapLookup() if os.environ.get("ANGLER_RDAP", "").strip() == "1" else NullLookup()
