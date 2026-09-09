"""HTTP surface. Thin on purpose - all the work is in app/parser.py."""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import FileResponse

from app.models import ParsedEmail
from app.parser import MAX_BYTES, parse_eml

app = FastAPI(title="Angler", version="0.1.0")

STATIC_DIR = Path(__file__).parent / "static"


@app.get("/healthz", include_in_schema=False)
def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/", include_in_schema=False)
def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.post("/v1/parse", response_model=ParsedEmail)
async def parse(file: UploadFile = File(...)) -> ParsedEmail:
    raw = await file.read()
    if not raw:
        raise HTTPException(status_code=400, detail="That file is empty. Upload a saved .eml message.")
    if len(raw) > MAX_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"That file is over the {MAX_BYTES // (1024 * 1024)} MB limit. Strip large attachments and retry.",
        )
    return parse_eml(raw, filename=file.filename)
