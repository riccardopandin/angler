# Angler

Mail forensics for phishing triage. Drop in a raw `.eml`, get back the
evidence needed to judge it: envelope and header mismatches, the routing
chain read oldest hop first, every link with the text that hid it, and
attachment hashes.

**Live: https://angler.onrender.com** - hosted on Render's free tier, so the
first request after 15 minutes of inactivity takes ~50 seconds while the
container wakes up. Subsequent requests are immediate.

**Status: M1 - deterministic parsing.** No scoring and no model yet; see
`SPEC.md` for the milestone plan.

## Run it

    python3 -m venv .venv && source .venv/bin/activate
    pip install -r requirements-dev.txt
    pytest -q
    uvicorn app.main:app --reload

Then open http://127.0.0.1:8000 and drop `tests/fixtures/phish_m365.eml`
onto the page.

## API

    POST /v1/parse    multipart form field `file`, a .eml up to 25 MB
    GET  /healthz

The response shape is `ParsedEmail` in `app/models.py`.

## Design notes

- **Standard library only for parsing.** The `email` package with
  `policy.default` handles MIME, encodings and folded headers correctly.
  A third-party parser would be one more thing to justify.
- **The parser never touches the network.** No URL found in a message is
  ever requested, no DNS lookup is made during parsing. Domain reputation
  is a separate layer (M2) behind an interface, so tests stay offline.
- **Attachments are hashed, never opened.** Filename, MIME type, size and
  SHA-256 only.
- **`Received` headers are reversed on the way in.** They arrive newest
  first, which is the opposite of how anyone reads a route.

## Limitations

Known and deliberate at this milestone: authentication results are captured
verbatim but not evaluated, and messages
inside `message/rfc822` attachments are not parsed recursively.
