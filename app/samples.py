"""Built-in sample messages, and the saved model response for one of them.

The public demo runs without an API key, so a visitor would never see what the
model writes for an ambiguous message. The owner runs that message once with a
real key (`python -m app.capture_sample`) and commits the response next to the
.eml. This module serves it back.

The cache can only ever answer for the exact sample. It is keyed on the
SHA-256 of the uploaded bytes, and the saved file records the hash of the
message it was written for, so editing the .eml invalidates it rather than
attaching a stale explanation to different content.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from pydantic import ValidationError

from app.llm import RationaleWriter, StubWriter
from app.models import Rationale

SAMPLES_DIR = Path(__file__).parent / "samples"

# Name used in the URL -> file stem inside SAMPLES_DIR. A closed list: the
# sample endpoint never builds a path from user input.
SAMPLES: dict[str, str] = {"ambiguous": "ambiguous"}

CACHED_WRITER_LABEL = "claude-cached"


def sample_bytes(name: str, directory: Path = SAMPLES_DIR) -> bytes | None:
    stem = SAMPLES.get(name)
    return (directory / f"{stem}.eml").read_bytes() if stem else None


def sha256_hex(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def cached_rationale(raw: bytes, directory: Path = SAMPLES_DIR) -> Rationale | None:
    """The saved model response for this exact message, or None.

    Every failure - no file yet, unreadable JSON, a hash that does not match -
    returns None so the caller falls back to the rules-only rationale.
    """
    digest = sha256_hex(raw)
    for stem in SAMPLES.values():
        eml, saved = directory / f"{stem}.eml", directory / f"{stem}.rationale.json"
        if not eml.is_file() or not saved.is_file() or sha256_hex(eml.read_bytes()) != digest:
            continue
        try:
            payload = json.loads(saved.read_text(encoding="utf-8"))
            if payload.get("sample_sha256") != digest:
                return None
            rationale = Rationale(**payload["rationale"])
        except (OSError, ValueError, KeyError, TypeError, ValidationError):
            return None
        return rationale.model_copy(update={"written_by": CACHED_WRITER_LABEL})
    return None


class CachedWriter:
    """Returns a saved rationale, ignoring the evidence it is handed."""

    def __init__(self, rationale: Rationale) -> None:
        self._rationale = rationale

    def write(self, evidence: dict) -> Rationale:
        return self._rationale


def writer_for(writer: RationaleWriter, raw: bytes, directory: Path = SAMPLES_DIR) -> RationaleWriter:
    """Swap in the saved response, but only for the offline fallback.

    A configured model always wins, so running locally with a key still calls
    the model. Only the keyless StubWriter is replaced, and only when the
    upload is byte-for-byte the sample.
    """
    if not isinstance(writer, StubWriter):
        return writer
    saved = cached_rationale(raw, directory)
    return CachedWriter(saved) if saved else writer
