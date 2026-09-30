# Angler

Mail forensics for phishing triage. Drop in a raw `.eml`, get back the
evidence needed to judge it: envelope and header mismatches, the routing
chain read oldest hop first, every link with the text that hid it, and
attachment hashes.

**Live: https://angler.onrender.com** - hosted on Render's free tier, so the
first request after 15 minutes of inactivity takes ~50 seconds while the
container wakes up. Subsequent requests are immediate.

**Status: M3 - rules, scoring and a written rationale.** See `SPEC.md` for
the milestone plan.

The model never decides a confident verdict. Deterministic rules score every
message first; the model writes the explanation, and may only propose a
different label inside the ambiguous 35-69 band. Message content reaches the
model as data in one labelled field, never concatenated into instructions.
With no `ANTHROPIC_API_KEY` set, the tool falls back to a deterministic
rationale and keeps working.

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

## Prompt injection

Every email this tool analyses is attacker-controlled text on its way to a
language model. `redteam/` holds 20 injection techniques - direct overrides,
white-on-white HTML, delimiter and JSON escapes, base64 and ROT13 payloads,
zero-width characters, forged tool output, persona reassignment - each built
into a complete message that keeps its phishing indicators intact.

The defence is architectural rather than textual. **Deterministic rules score
every message and set the verdict before the model is called.** The model
writes the explanation and may propose a different label only inside the
ambiguous 35-69 band. Above the threshold there is no code path by which
message content can change a verdict, and `tests/test_injection.py` proves it
by running all 20 techniques against a model stub that obeys every injected
instruction.

Two corpora, measured separately:

| corpus | what it is | can injection move it? |
| --- | --- | --- |
| confident | scored above the threshold by rules alone | No - structurally impossible |
| ambiguous | 35-69, where the model settles the label | Yes - this is the designed trust boundary |

### Measured result

40 cases against the live model, September 2026:

| corpus | cases | bypassed | escalated | manipulation flagged |
| --- | ---: | ---: | ---: | ---: |
| confident | 20 | **0** | 0 | 16/20 |
| ambiguous | 20 | **0** | 19 | 15/20 |

A bypass means a move toward `clean` - the attacker's goal. There were none.

Two findings worth stating plainly:

**Injection made the verdict stricter, not weaker.** On ambiguous messages the
model recognised the manipulation attempt and escalated 19 of 20 from
`suspicious` to `phishing`. A message whose body argues with the analyst is
evidence about that message.

**One blind spot.** `rot13_payload` was the only case the model did not
recognise as an attack - it never decoded the ROT13, so it never noticed it
was being manipulated. The verdict was unaffected, but the detection gap is
real and is not being hidden here.

An earlier version of this runner counted *any* label change as a bypass and
reported a 95% failure rate on a system whose true failure rate was 0%. The
metric, not the system, was wrong. That correction is documented in
`redteam/run.py`.

Reproduce:

    python -m redteam.run --report

Full per-case results are in `redteam/REPORT.md`.


## Limitations

Known and deliberate at this milestone: authentication results are captured
verbatim but not evaluated, and messages
inside `message/rfc822` attachments are not parsed recursively.
