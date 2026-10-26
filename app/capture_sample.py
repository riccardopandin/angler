"""Record the model's real response for the ambiguous sample.

Run once, locally, with a key in .env or the environment:

    python -m app.capture_sample

It calls the live model on `app/samples/ambiguous.eml` and saves the response
to `app/samples/ambiguous.rationale.json`. Commit that file and the public
demo can show the model's explanation without holding a key. Re-run it after
any change to the sample or to the prompt.
"""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone

from dotenv import load_dotenv

from app.llm import DEFAULT_MODEL, ClaudeWriter, build_evidence
from app.parser import parse_eml
from app.rules import PHISHING_AT, SUSPICIOUS_AT, findings_for, parse_auth_results, verdict_for
from app.samples import SAMPLES_DIR, sample_bytes, sha256_hex


def main() -> int:
    load_dotenv()
    key = os.environ.get("ANTHROPIC_API_KEY", "").strip()
    if not key:
        print("Set ANTHROPIC_API_KEY (in .env or the environment) and re-run.", file=sys.stderr)
        return 1

    raw = sample_bytes("ambiguous")
    assert raw is not None
    email = parse_eml(raw, filename="ambiguous.eml")
    findings = findings_for(email)
    verdict = verdict_for(findings)
    if not SUSPICIOUS_AT <= verdict.score < PHISHING_AT:
        print(f"Score {verdict.score} is outside the ambiguous band; fix the sample first.", file=sys.stderr)
        return 1

    evidence = build_evidence(email, parse_auth_results(email.authentication_results), verdict, findings)
    # Called directly, with no fallback: a failure here must be loud, not cached.
    rationale = ClaudeWriter(api_key=key).write(evidence)

    out = SAMPLES_DIR / "ambiguous.rationale.json"
    out.write_text(
        json.dumps(
            {
                "sample_sha256": sha256_hex(raw),
                "model": DEFAULT_MODEL,
                "captured_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "rationale": rationale.model_dump(),
            },
            indent=2,
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )
    print(f"Rules score {verdict.score}; model proposed {rationale.adjusted_label!r}. Saved {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
