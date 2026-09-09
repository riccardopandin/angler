from __future__ import annotations

from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


def load(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


@pytest.fixture
def phish() -> bytes:
    return load("phish_m365.eml")


@pytest.fixture
def legit() -> bytes:
    return load("legit_okta.eml")
