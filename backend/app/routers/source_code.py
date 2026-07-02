"""
Source-code integrity verification endpoints.

Engagements that include source-code review can record the hash of the
artifact the client sent. We compute MD5 + SHA256 on upload and compare
against whatever the client provided, building an audit trail in case
the client later disputes the scope.

Endpoints:
  POST   /api/projects/{pid}/source-code/verify    upload + verify
  GET    /api/projects/{pid}/source-code           list all verification records
  DELETE /api/projects/{pid}/source-code/{idx}     remove a record

The upload itself is NOT persisted -- we only keep the hash record. This
keeps storage minimal and avoids accidentally retaining client source
beyond the engagement. If the team wants the file too, set
SOURCE_CODE_STORE_FILES=true in env (TODO).
"""
from pathlib import Path
import tempfile
import os

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import Project, User, AuditLog
from ..auth import get_current_user
from ..services.source_code_verifier import (
    compute_hashes_path, verify_against_client, overall_status_label
)
from .permissions import require_project_visibility


router = APIRouter(tags=["source_code"])


@router.post("/api/projects/{pid}/source-code/verify")
async def verify_source_code(
    pid: int,
    file: UploadFile = File(..., description="The source code archive received from the client"),
    client_md5: str = Form(""),
    client_sha256: str = Form(""),
    notes: str = Form(""),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Compute MD5 + SHA256 of the uploaded file, compare against client-provided
    hashes, persist the verification record on the project.

    The uploaded file is hashed in a tempfile and then deleted -- we keep
    only the hash record. Use the engagement's secure storage for the actual
    source code.
    """
    project = db.get(Project, pid)
    if not project:
        raise HTTPException(404, "Project not found")
    require_project_visibility(db, user, project)
    if not file.filename:
        raise HTTPException(400, "Missing filename")

    # Stream the upload into a tempfile (avoids holding large archives in memory).
    # 1 GB cap: source code archives larger than this are unusual and would risk
    # filling the container's /tmp partition.
    _MAX_SC_BYTES = 1 * 1024 * 1024 * 1024
    fd, tmp_path_str = tempfile.mkstemp()
    tmp_path = Path(tmp_path_str)
    try:
        total_written = 0
        with os.fdopen(fd, "wb") as tf:
            while True:
                chunk = await file.read(1024 * 1024)
                if not chunk:
                    break
                total_written += len(chunk)
                if total_written > _MAX_SC_BYTES:
                    raise HTTPException(413, "Source archive exceeds the 1 GB upload limit.")
                tf.write(chunk)
        md5_hex, sha256_hex, size = compute_hashes_path(tmp_path)
    finally:
        try:
            tmp_path.unlink(missing_ok=True)
        except Exception:
            pass

    record = verify_against_client(
        filename=file.filename,
        size_bytes=size,
        computed_md5=md5_hex,
        computed_sha256=sha256_hex,
        client_md5=client_md5 or None,
        client_sha256=client_sha256 or None,
        received_by_username=user.username,
        notes=notes or None,
    )

    # Append to project.details list
    details = dict(getattr(project, "details", None) or {})
    history = list(details.get("source_code_hashes", []))
    history.append(record)
    details["source_code_hashes"] = history
    project.details = details

    db.add(AuditLog(actor_id=user.id, action="source_code.verify",
                    object_type="project", object_id=pid,
                    detail={"filename": file.filename, "result": record["result"]}))
    db.commit()

    return {
        "ok": True,
        "record": record,
        "label": overall_status_label(record),
    }


@router.get("/api/projects/{pid}/source-code")
def list_records(pid: int,
                 db: Session = Depends(get_db),
                 user: User = Depends(get_current_user)):
    project = db.get(Project, pid)
    if not project:
        raise HTTPException(404, "Project not found")
    require_project_visibility(db, user, project)
    records = (getattr(project, "details", None) or {}).get("source_code_hashes", [])
    return {
        "items": [
            {**r, "label": overall_status_label(r)}
            for r in records
        ],
    }


@router.delete("/api/projects/{pid}/source-code/{idx}")
def delete_record(pid: int, idx: int,
                  db: Session = Depends(get_db),
                  user: User = Depends(get_current_user)):
    project = db.get(Project, pid)
    if not project:
        raise HTTPException(404, "Project not found")
    require_project_visibility(db, user, project)
    details = dict(getattr(project, "details", None) or {})
    history = list(details.get("source_code_hashes", []))
    if idx < 0 or idx >= len(history):
        raise HTTPException(404, "Record not found")
    removed = history.pop(idx)
    details["source_code_hashes"] = history
    project.details = details
    db.add(AuditLog(actor_id=user.id, action="source_code.delete",
                    object_type="project", object_id=pid,
                    detail={"filename": removed.get("filename")}))
    db.commit()
    return {"ok": True, "removed": removed.get("filename")}
