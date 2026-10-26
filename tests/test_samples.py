"""The built-in ambiguous sample and its saved model response. Offline throughout.

The saved response in these tests is written into a temporary directory. The
real `ambiguous.rationale.json` is produced by `python -m app.capture_sample`
with a live key, never by a test.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import app.main as main_module
from app.llm import StubWriter, get_writer
from app.main import app
from app.models import Rationale
from app.parser import parse_eml
from app.rules import PHISHING_AT, SUSPICIOUS_AT, findings_for, verdict_for
from app.samples import (
    CACHED_WRITER_LABEL,
    SAMPLES_DIR,
    CachedWriter,
    cached_rationale,
    sample_bytes,
    sha256_hex,
    writer_for,
)

client = TestClient(app)


@pytest.fixture
def sample() -> bytes:
    raw = sample_bytes("ambiguous")
    assert raw is not None
    return raw


@pytest.fixture
def saved_dir(tmp_path: Path, sample: bytes) -> Path:
    """A samples directory holding the .eml and a saved response for it."""
    (tmp_path / "ambiguous.eml").write_bytes(sample)
    write_saved(tmp_path, sha256_hex(sample))
    return tmp_path


def write_saved(directory: Path, digest: str, adjusted_label: str = "suspicious") -> None:
    payload = {
        "sample_sha256": digest,
        "model": "test-model",
        "captured_at": "2026-10-26T00:00:00+00:00",
        "rationale": {
            "summary": "Saved summary.",
            "reasoning_steps": ["DMARC failed.", "Replies go to another domain."],
            "recommended_action": "Verify with IT through a known channel.",
            "adjusted_label": adjusted_label,
            "written_by": "claude",
        },
    }
    (directory / "ambiguous.rationale.json").write_text(json.dumps(payload), encoding="utf-8")


@pytest.fixture(autouse=True)
def keyless():
    """Pin the writer to the offline fallback whatever .env holds locally."""
    app.dependency_overrides[get_writer] = StubWriter
    yield
    app.dependency_overrides.clear()


# --- the sample itself -----------------------------------------------------


def test_the_ambiguous_sample_scores_inside_the_model_band(sample: bytes) -> None:
    verdict = verdict_for(findings_for(parse_eml(sample)))
    assert SUSPICIOUS_AT <= verdict.score < PHISHING_AT


def test_sample_endpoint_serves_the_exact_bytes(sample: bytes) -> None:
    response = client.get("/v1/samples/ambiguous")
    assert response.status_code == 200
    assert response.content == sample
    assert response.headers["content-type"].startswith("message/rfc822")


def test_unknown_sample_is_a_404_and_never_reads_a_path() -> None:
    assert client.get("/v1/samples/nope").status_code == 404
    assert client.get("/v1/samples/..%2Fparser.py").status_code == 404


def test_the_sample_analyses_without_a_saved_response(sample: bytes) -> None:
    """Works before the owner has run the capture script."""
    response = client.post("/v1/analyze", files={"file": ("ambiguous_sample.eml", sample)})
    assert response.status_code == 200
    assert response.json()["verdict"]["label"] == "suspicious"


# --- the cache -------------------------------------------------------------


def test_cached_rationale_is_labelled_cached(saved_dir: Path, sample: bytes) -> None:
    rationale = cached_rationale(sample, saved_dir)
    assert rationale is not None
    assert rationale.written_by == CACHED_WRITER_LABEL
    assert rationale.summary == "Saved summary."


def test_a_different_message_never_gets_the_saved_response(saved_dir: Path, sample: bytes) -> None:
    assert cached_rationale(sample + b"\nX-Extra: 1\n", saved_dir) is None


def test_a_stale_saved_response_is_ignored(tmp_path: Path, sample: bytes) -> None:
    (tmp_path / "ambiguous.eml").write_bytes(sample)
    write_saved(tmp_path, "0" * 64)
    assert cached_rationale(sample, tmp_path) is None


def test_missing_or_corrupt_saved_response_falls_back(tmp_path: Path, sample: bytes) -> None:
    (tmp_path / "ambiguous.eml").write_bytes(sample)
    assert cached_rationale(sample, tmp_path) is None
    (tmp_path / "ambiguous.rationale.json").write_text("{not json", encoding="utf-8")
    assert cached_rationale(sample, tmp_path) is None


def test_a_live_model_always_beats_the_cache(saved_dir: Path, sample: bytes) -> None:
    class Live:
        def write(self, evidence: dict) -> Rationale:
            return Rationale(summary="live", recommended_action="x", written_by="claude")

    live = Live()
    assert writer_for(live, sample, saved_dir) is live


def test_only_the_keyless_fallback_is_swapped(saved_dir: Path, sample: bytes) -> None:
    assert isinstance(writer_for(StubWriter(), sample, saved_dir), CachedWriter)
    assert isinstance(writer_for(StubWriter(), b"other message", saved_dir), StubWriter)


def test_real_saved_response_if_present_matches_the_sample(sample: bytes) -> None:
    """Guards the committed fixture: skipped until the owner captures it."""
    saved = SAMPLES_DIR / "ambiguous.rationale.json"
    if not saved.exists():
        pytest.skip("run `python -m app.capture_sample` to create it")
    assert cached_rationale(sample) is not None


def test_analyze_serves_the_cached_response_and_honours_its_label(
    saved_dir: Path, sample: bytes, monkeypatch: pytest.MonkeyPatch
) -> None:
    write_saved(saved_dir, sha256_hex(sample), adjusted_label="phishing")
    monkeypatch.setattr(main_module, "writer_for", lambda w, raw: writer_for(w, raw, saved_dir))

    body = client.post("/v1/analyze", files={"file": ("a.eml", sample)}).json()

    assert body["rationale"]["written_by"] == CACHED_WRITER_LABEL
    assert body["rationale"]["summary"] == "Saved summary."
    # Inside the ambiguous band the model's proposed label is allowed to stand,
    # and the score is still the rules' own.
    assert body["verdict"]["label"] == "phishing"
    assert body["verdict"]["resolved_by"] == "model"
    assert body["verdict"]["score"] == 50
