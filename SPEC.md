# Angler - specification

## Problem
A phishing email is judged in seconds by someone with 40 other alerts open.
The evidence needed to judge it correctly - authentication results, the real
routing origin, where a link actually goes - is buried in headers nobody
reads. Angler surfaces that evidence and states a verdict that can be
checked, not trusted.

## Non-goals
- Not a mail gateway. It analyses one message on request.
- Not a sandbox. Attachments are hashed, never opened or executed.
- Not a threat intel platform. It reports indicators; blocking is elsewhere.

## Milestones

### M1 - Parse and deploy (this weekend)
Deterministic extraction only. No scoring, no model.
- `POST /v1/parse` accepts an `.eml` upload, returns the parsed structure
- Extract: envelope addresses, subject, date, message-id, reply-to
- Extract: the `Received` chain, oldest hop first, with IPs
- Extract: text and HTML bodies, all URLs with their anchor text
- Extract: attachment names, MIME types, sizes, SHA-256 hashes
- A single page at `/` that uploads a file and shows the result
- Deployed to a public URL

Done when: a stranger can open the URL, drop an `.eml`, and see real
parsed output.

### M2 - Rules engine
Scoring, no model yet. SPF/DKIM/DMARC evaluation, homoglyph and punycode
detection, anchor-text vs href mismatch, domain age via RDAP, weighted risk
score with a documented threshold.

### M3 - Model layer and report UI
Structured output for ambiguous cases, written rationale for all cases.
The full report screen.

### M4 - Evidence
Labelled corpus run, published metrics (precision, recall, false positive
rate), prompt-injection test suite, hardening, README.

## Data contract
The parse response shape is defined by `ParsedEmail` in `app/models.py`.
It is additive-only: fields may be added, never renamed or removed, because
M2 and M3 build on top of it.

## Security posture of the tool itself
The tool ingests hostile input by definition. Therefore:
- Uploads are capped at 25 MB and read into memory once, never to disk
- HTML is parsed with a tolerant parser, never rendered or executed
- No URL found in an email is ever requested by the parser
- From M3 on, email content reaching a language model is passed as data,
  never concatenated into instructions
