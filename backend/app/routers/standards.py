"""
Reference standards (OWASP Top 10, NIST, CWE catalogues) registry.

Admin can upload a new version when frameworks update (OWASP 2027,
NIST CSF 3.0, etc.) and toggle which version is active. Findings keep
references resolved to specific (standard_code, entry_id) so older
reports stay accurate when newer versions are added.

Bundled seed: OWASP Top 10 2021 entries inserted on first run.

Endpoints:
  GET    /api/standards                    list (filter by is_active)
  GET    /api/standards/{id}               full standard with entries
  POST   /api/standards                    upload new (admin)
  PUT    /api/standards/{id}/activate      flip active flag (admin)
  DELETE /api/standards/{id}               delete (admin, rare)
"""
import json
import logging as _log_s
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import ReferenceStandard, User, Role, AuditLog
from ..auth import get_current_user, require_roles

_logger = _log_s.getLogger(__name__)


router = APIRouter(prefix="/api/standards", tags=["standards"])

_MAX_STANDARDS_BYTES = 5 * 1024 * 1024   # 5 MB


class StandardOut(BaseModel):
    id: int
    code: str
    name: str
    version: str
    is_active: bool
    entry_count: int

    class Config:
        from_attributes = True


def _summary(s: ReferenceStandard) -> dict:
    return {
        "id": s.id, "code": s.code, "name": s.name, "version": s.version,
        "is_active": s.is_active, "description": s.description,
        "entry_count": len(s.entries or []),
        "uploaded_at": s.uploaded_at.isoformat() if s.uploaded_at else None,
    }


@router.get("")
def list_standards(active_only: bool = False,
                   db: Session = Depends(get_db),
                   _: User = Depends(get_current_user)):
    q = db.query(ReferenceStandard)
    if active_only:
        q = q.filter(ReferenceStandard.is_active == True)  # noqa
    rows = q.order_by(ReferenceStandard.code, ReferenceStandard.version.desc()).all()
    return {"items": [_summary(s) for s in rows]}


@router.get("/{sid}")
def get_standard(sid: int, db: Session = Depends(get_db),
                 _: User = Depends(get_current_user)):
    s = db.get(ReferenceStandard, sid)
    if not s:
        raise HTTPException(404, "Standard not found")
    return {**_summary(s), "entries": s.entries or []}


@router.post("")
async def upload_standard(
    code: str = Form(..., description="e.g. 'owasp_top10' or 'nist_csf'"),
    name: str = Form(...),
    version: str = Form(..., description="e.g. '2021' or '2027'"),
    description: str = Form(""),
    activate_immediately: bool = Form(False),
    file: UploadFile = File(..., description="JSON or CSV with the entries"),
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(Role.admin, Role.senior)),
):
    """Upload a new standard. File format:

    JSON: [{"id": "A01:2021", "title": "Broken Access Control", "url": "..."}, ...]

    CSV: id,title,url
         A01:2021,Broken Access Control,https://owasp.org/Top10/A01_2021/
         ...
    """
    chunks: list[bytes] = []
    _total = 0
    while True:
        chunk = await file.read(65536)
        if not chunk:
            break
        _total += len(chunk)
        if _total > _MAX_STANDARDS_BYTES:
            raise HTTPException(413, "Standards file exceeds the 5 MB upload limit.")
        chunks.append(chunk)
    contents = b"".join(chunks)
    fname = file.filename or ""
    entries: list[dict] = []

    try:
        if fname.lower().endswith(".json"):
            data = json.loads(contents.decode("utf-8"))
            if not isinstance(data, list):
                raise ValueError("JSON must be a list of {id, title, url} objects")
            entries = data
        elif fname.lower().endswith(".csv"):
            import csv, io
            reader = csv.DictReader(io.StringIO(contents.decode("utf-8")))
            entries = [{"id": r["id"], "title": r["title"], "url": r.get("url", "")} for r in reader]
        else:
            raise ValueError("Upload .json or .csv")
    except Exception as e:
        _logger.warning("Standards file parse failed: %s", e)
        raise HTTPException(400, "Could not parse the uploaded file. Please ensure it is a valid .json or .csv standards export.")

    # Sanity check
    if not entries:
        raise HTTPException(400, "No entries parsed")
    for e in entries:
        if not (isinstance(e, dict) and "id" in e and "title" in e):
            raise HTTPException(400, "Each entry needs id and title")

    # Replace existing version if any
    existing = (db.query(ReferenceStandard)
                  .filter(ReferenceStandard.code == code,
                          ReferenceStandard.version == version)
                  .first())
    if existing:
        existing.entries = entries
        existing.name = name
        existing.description = description
        if activate_immediately:
            # Deactivate other versions of this code
            (db.query(ReferenceStandard)
               .filter(ReferenceStandard.code == code,
                       ReferenceStandard.id != existing.id)
               .update({"is_active": False}))
            existing.is_active = True
        std = existing
        action = "standard.update"
    else:
        if activate_immediately:
            (db.query(ReferenceStandard)
               .filter(ReferenceStandard.code == code)
               .update({"is_active": False}))
        std = ReferenceStandard(
            code=code, name=name, version=version,
            description=description, entries=entries,
            is_active=bool(activate_immediately),
            uploaded_by_id=user.id,
        )
        db.add(std)
        action = "standard.create"
    db.add(AuditLog(actor_id=user.id, action=action,
                    object_type="reference_standard",
                    detail={"code": code, "version": version, "entries": len(entries)}))
    db.commit()
    db.refresh(std)
    return {"ok": True, **_summary(std)}


@router.put("/{sid}/activate")
def activate_standard(sid: int, deactivate_others: bool = True,
                      db: Session = Depends(get_db),
                      user: User = Depends(require_roles(Role.admin, Role.senior))):
    """Set this standard as active. When deactivate_others=True (default),
    other versions of the same code are turned off. Findings continue to
    reference whichever version they were originally tagged with.
    """
    s = db.get(ReferenceStandard, sid)
    if not s:
        raise HTTPException(404, "Standard not found")
    if deactivate_others:
        (db.query(ReferenceStandard)
           .filter(ReferenceStandard.code == s.code, ReferenceStandard.id != sid)
           .update({"is_active": False}))
    s.is_active = True
    db.add(AuditLog(actor_id=user.id, action="standard.activate",
                    object_type="reference_standard", object_id=sid,
                    detail={"code": s.code, "version": s.version}))
    db.commit()
    return {"ok": True, "id": sid, "is_active": True}


@router.delete("/{sid}")
def delete_standard(sid: int, db: Session = Depends(get_db),
                    user: User = Depends(require_roles(Role.admin))):
    s = db.get(ReferenceStandard, sid)
    if not s:
        raise HTTPException(404, "Standard not found")
    db.delete(s)
    db.add(AuditLog(actor_id=user.id, action="standard.delete",
                    object_type="reference_standard", object_id=sid,
                    detail={"code": s.code, "version": s.version}))
    db.commit()
    return {"ok": True, "deleted": sid}
