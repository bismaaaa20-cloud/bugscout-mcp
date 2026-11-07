"""REST API adapter for the existing BugScout analysis engine.

The original bugscout_mcp.py remains the source of truth for analysis rules.
This module exposes those functions over HTTPS for GPT Actions.
"""
from __future__ import annotations

import io
import os
import zipfile
from pathlib import PurePosixPath
from typing import Annotated

from dotenv import load_dotenv

# Load local development settings before reading any environment variables.
# On Render, dashboard Environment Variables take precedence over this optional file.
load_dotenv()

from fastapi import Depends, FastAPI, File, Header, HTTPException, UploadFile
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

import bugscout_mcp as engine

TOKEN = os.environ.get("BUGSCOUT_API_TOKEN", "")
if len(TOKEN) < 32:
    raise RuntimeError("Set BUGSCOUT_API_TOKEN to a random secret of at least 32 characters.")

engine.COMPILERS_ENABLED = os.environ.get("BUGSCOUT_ENABLE_COMPILERS", "").lower() in {"1", "true", "yes"}
engine.WORKERS = max(1, min(int(os.environ.get("BUGSCOUT_WORKERS", "10")), 16))
MAX_UPLOAD_BYTES = 1_000_000
MAX_ZIP_BYTES = 10_000_000
MAX_ZIP_FILES = 50
ALLOWED_SUFFIXES = set(engine.EXT)

app = FastAPI(
    title="BugScout API",
    summary="Code bug and error checks for GPT Actions",
    description=(
        "BugScout checks code for likely bugs. It is not a security scanner. "
        "SEND means no issue was found by the available checks, not that code is secure "
        "or guaranteed correct."
    ),
    version="1.0.0",
    openapi_version="3.1.0",
)

def require_bearer(authorization: Annotated[str | None, Header()] = None):
    expected = f"Bearer {TOKEN}"
    import hmac
    if authorization is None or not hmac.compare_digest(authorization, expected):
        raise HTTPException(status_code=401, detail="Unauthorized",
                            headers={"WWW-Authenticate": "Bearer"})
    return True

Auth = Annotated[bool, Depends(require_bearer)]

class CodeRequest(BaseModel):
    code: str = Field(..., min_length=1, description="Complete source code to inspect.")
    language: str = Field("", description="Optional language hint, e.g. python, lua, luau, javascript.")

@app.get("/health", operation_id="healthCheck", tags=["system"])
def health():
    return {"status": "ok", "service": "BugScout API"}

@app.post("/gate/check", operation_id="gateCheck", tags=["code"])
def gate_check(body: CodeRequest, _: Auth):
    if engine.too_big(body.code):
        raise HTTPException(status_code=413, detail=f"Code larger than {MAX_UPLOAD_BYTES} bytes.")
    return engine.gate_view(engine.analyze(body.code, body.language, ""))

@app.post("/analyze/code", operation_id="analyzeCode", tags=["code"])
def analyze_code(body: CodeRequest, _: Auth):
    if engine.too_big(body.code):
        raise HTTPException(status_code=413, detail=f"Code larger than {MAX_UPLOAD_BYTES} bytes.")
    return engine.analyze(body.code, body.language, "")

async def read_upload(file: UploadFile) -> tuple[str, str]:
    name = PurePosixPath((file.filename or "uploaded.txt").replace("\\", "/")).name
    data = await file.read(MAX_UPLOAD_BYTES + 1)
    if len(data) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="File exceeds 1 MB.")
    if not name or name.startswith("."):
        raise HTTPException(status_code=400, detail="Invalid filename.")
    try:
        code = engine.decode_text(data)
    except (UnicodeError, ValueError):
        raise HTTPException(status_code=415, detail="File is not readable text.")
    return name, code

@app.post("/gate/check-file", operation_id="gateCheckFile", tags=["files"])
async def gate_check_file(_: Auth, file: UploadFile = File(...)):
    name, code = await read_upload(file)
    if engine.too_big(code):
        raise HTTPException(status_code=413, detail="File exceeds 1 MB.")
    return {"file": name, **engine.gate_view(engine.analyze(code, "", name))}

@app.post("/analyze/file", operation_id="analyzeFile", tags=["files"])
async def analyze_file(_: Auth, file: UploadFile = File(...)):
    name, code = await read_upload(file)
    if engine.too_big(code):
        raise HTTPException(status_code=413, detail="File exceeds 1 MB.")
    return {"file": name, **engine.analyze(code, "", name)}

@app.post("/analyze/archive", operation_id="analyzeArchive", tags=["files"])
async def analyze_archive(_: Auth, file: UploadFile = File(...)):
    """Inspect source files in a ZIP; never extracts paths to disk."""
    raw = await file.read(MAX_ZIP_BYTES + 1)
    if len(raw) > MAX_ZIP_BYTES:
        raise HTTPException(status_code=413, detail="ZIP exceeds 10 MB.")
    try:
        archive = zipfile.ZipFile(io.BytesIO(raw))
    except (zipfile.BadZipFile, OSError):
        raise HTTPException(status_code=400, detail="Invalid ZIP archive.")
    results = []
    more = False
    total_uncompressed = 0
    for info in archive.infolist():
        path = PurePosixPath(info.filename)
        if info.is_dir() or path.is_absolute() or ".." in path.parts:
            continue
        if any(part.startswith(".") or part in engine.SKIP_DIRS for part in path.parts):
            continue
        if path.suffix.lower() not in ALLOWED_SUFFIXES:
            continue
        if len(results) >= MAX_ZIP_FILES:
            more = True
            break
        if info.file_size > MAX_UPLOAD_BYTES:
            results.append({"file": info.filename, "error": "File exceeds 1 MB."})
            continue
        total_uncompressed += info.file_size
        if total_uncompressed > 20_000_000:
            raise HTTPException(status_code=413, detail="Expanded ZIP exceeds 20 MB.")
        try:
            content = engine.decode_text(archive.read(info))
            report = engine.analyze(content, "", path.name)
            results.append({
                "file": info.filename,
                "language": report["language"],
                "verdict": report["verdict"],
                "can_send": report["can_send"],
                "syntax_ok": report["syntax"]["ok"],
                "syntax_verified": report["syntax_verified"],
                "findings": report["findings"],
                "truncated": report["truncated"],
            })
        except (RuntimeError, ValueError, OSError, KeyError) as exc:
            results.append({"file": info.filename, "error": f"Could not analyze ({type(exc).__name__})."})
    counts = {}
    for result in results:
        verdict = result.get("verdict", "ERROR")
        counts[verdict] = counts.get(verdict, 0) + 1
    return {"scanned": len(results), "more_files_not_scanned": more,
            "verdicts": counts, "results": results}

@app.get("/languages", operation_id="supportedLanguages", tags=["system"])
def supported_languages(_: Auth):
    return engine.supported_languages()

@app.get("/guide", operation_id="getBugScoutGuide", tags=["system"])
def guide(_: Auth):
    return {"guide": engine.guide()}

@app.post("/prompts/send-script", operation_id="getSendScriptPrompt", tags=["system"])
def send_script(body: dict, _: Auth):
    request = str(body.get("request", "")).strip()
    if not request:
        raise HTTPException(status_code=400, detail="request is required.")
    return {"prompt": engine.send_script(request)}

@app.exception_handler(Exception)
async def unexpected_error_handler(request, exc):
    import logging
    logging.getLogger("bugscout.api").exception("Unhandled API error")
    return JSONResponse(status_code=500, content={"detail": "Internal server error."})
