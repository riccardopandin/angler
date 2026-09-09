# Angler - working instructions for Claude Code

## What this is
A mail forensics console. Input: a raw `.eml` file. Output: a structured
verdict an analyst can check - header authentication, routing chain,
extracted URLs and indicators, and a written rationale.

Read `SPEC.md` before making changes. It defines scope per milestone.

## Stack - do not extend it without asking
- Python 3.11+, FastAPI, uvicorn, pydantic v2
- Standard library `email` package for MIME parsing. No third-party email parsers.
- pytest for tests
- Vanilla HTML/CSS/JS for the UI. No framework, no build step.
- Deployed as a Docker container on Fly.io

## Rules
1. **No new dependencies without asking me first.** Every dependency is
   something I have to explain in an interview.
2. **No network calls in unit tests.** Anything that hits RDAP, DNS or an
   API goes behind an interface and is faked in tests.
3. **Every parsing function gets a test against a real `.eml` fixture** in
   `tests/fixtures/`. No testing against hand-built dicts.
4. **Secrets come from environment variables only.** Never hardcode a key,
   never commit `.env`, never log a full API key.
5. **Never execute or render attachment or email content.** Attachments are
   hashed and described, never opened. HTML is parsed, never rendered
   server-side.
6. Type hints on every function signature. Small functions, one job each.
7. Explain what you changed and why in plain language after each change. If
   I could not defend it in an interview, it does not go in.

## Commands
- Install: `pip install -r requirements-dev.txt`
- Test: `pytest -q`
- Run locally: `uvicorn app.main:app --reload` then open http://127.0.0.1:8000
- Deploy: `fly deploy`

## Definition of done for any change
- `pytest -q` passes
- The feature is reachable from the UI or the API, not just from a test
- README updated if behaviour visible to a user changed
