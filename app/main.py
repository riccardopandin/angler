"""HTTP surface. Thin on purpose - the work is in app/parser.py and app/rules.py."""

from __future__ import annotations

from pathlib import Path

from fastapi import Depends, FastAPI, File, HTTPException, UploadFile
from dotenv import load_dotenv
from fastapi.responses import FileResponse

from app.llm import RationaleWriter, build_evidence, get_writer, resolve, write_rationale
from app.models import Analysis, ParsedEmail
from app.parser import MAX_BYTES, parse_eml
from app.rules import findings_for, parse_auth_results, verdict_for

# Local development reads .env. In production Render supplies real
# environment variables and this call finds nothing, which is correct.
load_dotenv()

app = FastAPI(title="Angler", version="0.3.0")

STATIC_DIR = Path(__file__).parent / "static"


async def _read_upload(file: UploadFile) -> bytes:
    raw = await file.read()
    if not raw:
        raise HTTPException(status_code=400, detail="That file is empty. Upload a saved .eml message.")
    if len(raw) > MAX_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"That file is over the {MAX_BYTES // (1024 * 1024)} MB limit. Strip large attachments and retry.",
        )
    return raw


@app.get("/healthz", include_in_schema=False)
def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/", include_in_schema=False)
def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.post("/v1/parse", response_model=ParsedEmail)
async def parse(file: UploadFile = File(...)) -> ParsedEmail:
    """Extraction only. No judgement."""
    raw = await _read_upload(file)
    return parse_eml(raw, filename=file.filename)


@app.post("/v1/analyze", response_model=Analysis)
async def analyze(
    file: UploadFile = File(...),
    writer: RationaleWriter = Depends(get_writer),
) -> Analysis:
    """Extraction, every detection rule, and a written rationale.

    The writer arrives by dependency injection so tests can substitute a fake
    and never touch the network.
    """
    raw = await _read_upload(file)
    email = parse_eml(raw, filename=file.filename)
    auth = parse_auth_results(email.authentication_results)
    findings = findings_for(email)
    verdict = verdict_for(findings)

    evidence = build_evidence(email, auth, verdict, findings)
    rationale = write_rationale(writer, evidence)
    verdict = resolve(verdict, rationale)

    return Analysis(
        email=email,
        auth=auth,
        verdict=verdict,
        rationale=rationale,
        findings=findings,
    )
