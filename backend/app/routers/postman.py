"""
API VAPT — Postman collection import.

Consultants on an API VAPT engagement upload the client's Postman collection.
The parser counts endpoints by HTTP method (GET / POST / PUT / etc.) and
groups them by folder, then stores the summary on the project. The Word
template can then reference {{ postman_summary }} in the executive summary
to auto-populate the scope sentence.

Endpoints:
  POST   /api/projects/{pid}/postman          upload + parse + store
  GET    /api/projects/{pid}/postman          retrieve stored summary
  DELETE /api/projects/{pid}/postman          clear

Parsing is preview-then-commit on a single call: the consultant uploads,
gets back the parsed endpoint list and counts, and that result is persisted
to project.details["postman_summary"] immediately. They can re-upload to
overwrite.
"""
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import Project, User, AuditLog, Role
from ..auth import get_current_user
from ..services.postman_parser import parse_postman, build_scope_summary


router = APIRouter(tags=["postman"])


def _require_project_access(project, user: User, db: Session) -> None:
    """Raise 403 if the user has no access to the project.

    Allows admin/senior roles and any user who is the project lead or has
    created a report in the project — consistent with the Nmap import check
    in routers/parsers.py.
    """
    if user.role in (Role.admin, Role.senior):
        return
    if project.lead_id == user.id:
        return
    from ..models import Report as _Report
    accessible = (
        db.query(_Report.id)
          .filter(_Report.project_id == project.id,
                  _Report.created_by_id == user.id)
          .limit(1).scalar()
    )
    if not accessible:
        raise HTTPException(403, "You do not have access to this project")


@router.post("/api/projects/{pid}/postman")
async def upload_postman_collection(
    pid: int,
    file: UploadFile = File(...),
    notes: str = Form(""),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Upload a Postman collection. Returns the parsed summary and persists
    it on the project so the report generator can use it."""
    project = db.get(Project, pid)
    if not project:
        raise HTTPException(404, "Project not found")
    _require_project_access(project, user, db)

    if not file.filename or not file.filename.lower().endswith(".json"):
        raise HTTPException(400, "Upload the Postman collection as a .json file")

    _MAX_POSTMAN_BYTES = 25 * 1024 * 1024   # 25 MB
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = await file.read(65536)
        if not chunk:
            break
        total += len(chunk)
        if total > _MAX_POSTMAN_BYTES:
            raise HTTPException(413, "Postman collection exceeds the 25 MB upload limit.")
        chunks.append(chunk)
    contents = b"".join(chunks)

    parsed = parse_postman(contents)

    if parsed.get("errors") and parsed["total"] == 0:
        raise HTTPException(400, {"error": "Could not parse collection",
                                  "details": parsed["errors"]})

    summary_sentence = build_scope_summary(parsed)

    # Persist
    details = dict(getattr(project, "details", None) or {})
    details["postman_summary"] = {
        "filename":  file.filename,
        "name":      parsed["name"],
        "schema":    parsed["schema"],
        "total":     parsed["total"],
        "counts":    parsed["counts"],
        "folders":   parsed["folders"],
        "scope_sentence": summary_sentence,
        "uploaded_by": user.username,
        "notes":     notes,
    }
    # Keep the full endpoint list separately -- it can get long for big APIs
    details["postman_endpoints"] = parsed["endpoints"]
    project.details = details

    db.add(AuditLog(actor_id=user.id, action="postman.upload",
                    object_type="project", object_id=pid,
                    detail={"endpoints": parsed["total"], "filename": file.filename}))
    db.commit()

    return {
        "ok": True,
        "summary": details["postman_summary"],
        "endpoints_preview": parsed["endpoints"][:25],
        "endpoints_total": parsed["total"],
        "warnings": parsed.get("errors", []),
    }


@router.get("/api/projects/{pid}/postman")
def get_postman_summary(pid: int,
                        db: Session = Depends(get_db),
                        user: User = Depends(get_current_user)):
    project = db.get(Project, pid)
    if not project:
        raise HTTPException(404, "Project not found")
    _require_project_access(project, user, db)
    details = getattr(project, "details", None) or {}
    return {
        "summary":   details.get("postman_summary"),
        "endpoints": details.get("postman_endpoints", []),
    }


@router.delete("/api/projects/{pid}/postman")
def clear_postman(pid: int,
                  db: Session = Depends(get_db),
                  user: User = Depends(get_current_user)):
    project = db.get(Project, pid)
    if not project:
        raise HTTPException(404, "Project not found")
    _require_project_access(project, user, db)
    details = dict(getattr(project, "details", None) or {})
    had = "postman_summary" in details
    details.pop("postman_summary", None)
    details.pop("postman_endpoints", None)
    project.details = details
    db.add(AuditLog(actor_id=user.id, action="postman.clear",
                    object_type="project", object_id=pid, detail={}))
    db.commit()
    return {"ok": True, "had_summary": had}
