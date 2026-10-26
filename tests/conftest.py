from __future__ import annotations

from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


def load(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


@pytest.fixture(autouse=True)
def no_api_key(monkeypatch: pytest.MonkeyPatch) -> None:
    """app.main loads .env on import, so a developer's real key is in the
    environment. No test may ever reach the API because of it."""
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)


@pytest.fixture
def phish() -> bytes:
    return load("phish_m365.eml")


@pytest.fixture
def legit() -> bytes:
    return load("legit_okta.eml")
