"""HTTP surface. Thin on purpose - the work is in app/parser.py and app/rules.py."""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import FileResponse

from app.models import Analysis, ParsedEmail
from app.parser import MAX_BYTES, parse_eml
from app.rules import findings_for, parse_auth_results

app = FastAPI(title="Angler", version="0.2.0")

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
async def analyze(file: UploadFile = File(...)) -> Analysis:
    """Extraction plus every detection rule."""
    raw = await _read_upload(file)
    email = parse_eml(raw, filename=file.filename)
    return Analysis(
        email=email,
        auth=parse_auth_results(email.authentication_results),
        findings=findings_for(email),
    )
