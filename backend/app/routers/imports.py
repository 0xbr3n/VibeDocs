"""
Excel tracker import (PT Risk Register).

Two-step flow so the consultant can review/fix before any DB writes:

    POST /api/imports/tracker/preview?report_id={id}        (multipart .xlsx)
        -> ParsedTracker JSON + cached_id token

    POST /api/imports/tracker/commit
        body: { cached_id, skip_blocked, promote_new_to_library }
        -> persists ReportFinding rows + auto-creates pending_review
           FindingLibrary entries for novel titles.

For Nessus CSV (Infra VA) use POST /api/scans/nessus (parsers.py).
"""
from __future__ import annotations
import time
import uuid
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import Report, ReportVersion, User
from ..auth import get_current_user
from ..services import risk_register_parser
from .permissions import require_access, AccessLevel


router = APIRouter(prefix="/api/imports", tags=["imports"])

_MAX_TRACKER_BYTES = 20 * 1024 * 1024   # 20 MB


# In-memory preview cache (TTL 30 min). For multi-worker deployments swap for Redis.
# Cache value: (timestamp, parsed, report_id, template_id, user_id)
_PREVIEW_CACHE: dict[str, tuple[float, risk_register_parser.ParsedTracker, int, int, int]] = {}
_PREVIEW_TTL = 30 * 60


def _cache_put(parsed, report_id: int, template_id: int, user_id: int) -> str:
    token = uuid.uuid4().hex
    _PREVIEW_CACHE[token] = (time.time(), parsed, report_id, template_id, user_id)
    _prune_cache()
    return token


def _cache_get(token: str):
    _prune_cache()
    return _PREVIEW_CACHE.get(token)


def _prune_cache():
    now = time.time()
    for k in [k for k, (t, *_) in _PREVIEW_CACHE.items() if now - t > _PREVIEW_TTL]:
        _PREVIEW_CACHE.pop(k, None)


def _latest_version(db: Session, report_id: int) -> ReportVersion:
    r = db.get(Report, report_id)
    if not r:
        raise HTTPException(404, "Report not found")
    if not r.versions:
        raise HTTPException(400, "Report has no version yet")
    return r.versions[-1]


@router.post("/tracker/preview")
async def preview_tracker(
    report_id: int = Query(..., description="Target report - used to scope library matches"),
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    if not (file.filename or "").lower().endswith((".xlsx", ".xlsm")):
        raise HTTPException(400, "Upload an .xlsx or .xlsm workbook")

    report = db.get(Report, report_id)
    if not report:
        raise HTTPException(404, "Report not found")
    require_access(db, user, report, need=AccessLevel.edit)

    chunks: list[bytes] = []
    _total = 0
    while True:
        chunk = await file.read(65536)
        if not chunk:
            break
        _total += len(chunk)
        if _total > _MAX_TRACKER_BYTES:
            raise HTTPException(413, "Tracker file exceeds the 20 MB upload limit.")
        chunks.append(chunk)
    contents = b"".join(chunks)
    try:
        parsed = risk_register_parser.preview(contents, db=db, template_id=report.template_id)
    except ValueError as e:
        raise HTTPException(400, str(e))

    token = _cache_put(parsed, report_id=report.id,
                        template_id=report.template_id, user_id=user.id)
    return {"cached_id": token, **parsed.to_dict()}


class TrackerCommitRequest(BaseModel):
    cached_id: str
    skip_blocked: bool = True
    promote_new_to_library: bool = True


@router.post("/tracker/commit")
def commit_tracker(
    payload: TrackerCommitRequest,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    item = _cache_get(payload.cached_id)
    if not item:
        raise HTTPException(400, "Preview expired or unknown cached_id - re-upload the tracker")
    _, parsed, report_id, template_id, preview_user_id = item
    if preview_user_id != user.id:
        raise HTTPException(403, "This preview token belongs to a different user")

    report = db.get(Report, report_id)
    if not report:
        raise HTTPException(404, "Report not found")
    require_access(db, user, report, need=AccessLevel.edit)
    version = _latest_version(db, report_id)
    result = risk_register_parser.commit(
        parsed,
        template_id=template_id,
        report_version_id=version.id,
        db=db, user=user,
        skip_blocked=payload.skip_blocked,
        promote_new_to_library=payload.promote_new_to_library,
    )
    _PREVIEW_CACHE.pop(payload.cached_id, None)
    return {
        "ok": True,
        "report_id": report_id,
        "report_version_id": version.id,
        "findings_created": result.findings_created,
        "library_pending_created": result.library_pending_created,
        "skipped": result.skipped,
        "skipped_rows": result.skipped_rows,
    }


@router.delete("/tracker/preview/{cached_id}")
def discard_preview(cached_id: str, _: User = Depends(get_current_user)):
    existed = _PREVIEW_CACHE.pop(cached_id, None) is not None
    return {"ok": True, "discarded": existed}
