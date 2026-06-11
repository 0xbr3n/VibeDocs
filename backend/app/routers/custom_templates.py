"""
Client-supplied custom Word template management.

A client may have its own report template (their logo, their styling).
Consultants upload the .docx; the file goes under UPLOAD_DIR/custom_templates/
and the path is recorded against either the Project (used for all reports
in that engagement) or the Report (single-report override).

The uploader runs a placeholder check so consultants catch missing
required placeholders before generating.

Endpoints:
  POST /api/projects/{pid}/custom-template
  POST /api/reports/{rid}/custom-template
  DELETE /api/projects/{pid}/custom-template
  DELETE /api/reports/{rid}/custom-template
  GET  /api/templates/placeholders          -- reference doc for client teams
"""
from pathlib import Path
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import Project, Report, User, AuditLog, Role
from ..auth import get_current_user
from ..services.template_resolver import (
    validate_custom_template, save_custom_template_upload
)


router = APIRouter(tags=["custom_templates"])

_MAX_CUSTOM_TEMPLATE_BYTES = 30 * 1024 * 1024   # 30 MB


@router.post("/api/projects/{pid}/custom-template")
async def upload_project_template(
    pid: int,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Upload a client's Word template for this entire project."""
    project = db.get(Project, pid)
    if not project:
        raise HTTPException(404, "Project not found")
    if user.role not in (Role.admin, Role.senior) and project.lead_id != user.id:
        accessible = (db.query(Report.id)
                        .filter(Report.project_id == pid,
                                Report.created_by_id == user.id)
                        .limit(1).scalar())
        if not accessible:
            raise HTTPException(403, "You do not have access to this project")
    if not (file.filename or "").lower().endswith(".docx"):
        raise HTTPException(400, "Upload a .docx file")

    chunks: list[bytes] = []
    _total = 0
    while True:
        chunk = await file.read(65536)
        if not chunk:
            break
        _total += len(chunk)
        if _total > _MAX_CUSTOM_TEMPLATE_BYTES:
            raise HTTPException(413, "Template file exceeds the 30 MB upload limit.")
        chunks.append(chunk)
    contents = b"".join(chunks)
    stored = save_custom_template_upload(
        contents, scope="project", scope_id=pid, original_filename=file.filename or "template.docx",
    )

    validation = validate_custom_template(stored)

    details = dict(getattr(project, "details", None) or {})
    details["custom_template_path"] = str(stored)
    details["custom_template_filename"] = file.filename
    details["custom_template_validation"] = validation
    project.details = details

    db.add(AuditLog(
        actor_id=user.id, action="project.custom_template.upload",
        object_type="project", object_id=pid,
        detail={"filename": file.filename, "valid": validation["valid"]},
    ))
    db.commit()
    return {"ok": True, "stored_path": str(stored), "validation": validation}


@router.delete("/api/projects/{pid}/custom-template")
def remove_project_template(pid: int,
                            db: Session = Depends(get_db),
                            user: User = Depends(get_current_user)):
    project = db.get(Project, pid)
    if not project:
        raise HTTPException(404, "Project not found")
    if user.role not in (Role.admin, Role.senior) and project.lead_id != user.id:
        accessible = (db.query(Report.id)
                        .filter(Report.project_id == pid,
                                Report.created_by_id == user.id)
                        .limit(1).scalar())
        if not accessible:
            raise HTTPException(403, "You do not have access to this project")
    details = dict(getattr(project, "details", None) or {})
    removed = details.pop("custom_template_path", None)
    details.pop("custom_template_filename", None)
    details.pop("custom_template_validation", None)
    project.details = details
    db.add(AuditLog(actor_id=user.id, action="project.custom_template.remove",
                    object_type="project", object_id=pid, detail={}))
    db.commit()
    return {"ok": True, "had_template": removed is not None}


@router.post("/api/reports/{rid}/custom-template")
async def upload_report_template(
    rid: int,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Upload a custom template just for this one report (overrides any
    project-level template)."""
    from .permissions import require_access, AccessLevel
    report = db.get(Report, rid)
    if not report:
        raise HTTPException(404, "Report not found")
    require_access(db, user, report, need=AccessLevel.edit)

    if not (file.filename or "").lower().endswith(".docx"):
        raise HTTPException(400, "Upload a .docx file")

    chunks: list[bytes] = []
    _total = 0
    while True:
        chunk = await file.read(65536)
        if not chunk:
            break
        _total += len(chunk)
        if _total > _MAX_CUSTOM_TEMPLATE_BYTES:
            raise HTTPException(413, "Template file exceeds the 30 MB upload limit.")
        chunks.append(chunk)
    contents = b"".join(chunks)
    stored = save_custom_template_upload(
        contents, scope="report", scope_id=rid, original_filename=file.filename or "template.docx",
    )
    validation = validate_custom_template(stored)

    details = dict(getattr(report, "details", None) or {})
    details["custom_template_path"] = str(stored)
    details["custom_template_filename"] = file.filename
    details["custom_template_validation"] = validation
    report.details = details

    db.add(AuditLog(actor_id=user.id, action="report.custom_template.upload",
                    object_type="report", object_id=rid,
                    detail={"filename": file.filename, "valid": validation["valid"]}))
    db.commit()
    return {"ok": True, "stored_path": str(stored), "validation": validation}


@router.delete("/api/reports/{rid}/custom-template")
def remove_report_template(rid: int,
                           db: Session = Depends(get_db),
                           user: User = Depends(get_current_user)):
    from .permissions import require_access, AccessLevel
    report = db.get(Report, rid)
    if not report:
        raise HTTPException(404, "Report not found")
    require_access(db, user, report, need=AccessLevel.edit)
    details = dict(getattr(report, "details", None) or {})
    removed = details.pop("custom_template_path", None)
    details.pop("custom_template_filename", None)
    details.pop("custom_template_validation", None)
    report.details = details
    db.add(AuditLog(actor_id=user.id, action="report.custom_template.remove",
                    object_type="report", object_id=rid, detail={}))
    db.commit()
    return {"ok": True, "had_template": removed is not None}


@router.get("/api/templates/placeholders")
def documentation(_: User = Depends(get_current_user)):
    """Reference doc for consultants / clients who want to author a
    compatible template. Returns the placeholders the generator fills in.
    """
    return {
        "required": [
            {"placeholder": "{{ project.client_name }}", "where": "Cover page"},
            {"placeholder": "{%p for f in findings %} ... {%p endfor %}",
             "where": "Findings detail loop"},
        ],
        "recommended": [
            {"placeholder": "{{ project.name }}", "where": "Cover, header"},
            {"placeholder": "{{ report.version }}", "where": "Footer, cover"},
            {"placeholder": "{{ report.is_draft }}", "where": "Conditional 'DRAFT' watermark logic"},
            {"placeholder": "{{ severity_counts['Critical'] }}", "where": "Executive summary"},
            {"placeholder": "{{ severity_chart }}", "where": "Executive summary (InlineImage)"},
            {"placeholder": "{{ sections.executive_summary }}", "where": "Exec summary prose"},
            {"placeholder": "{{ sections.methodology }}", "where": "Methodology section"},
            {"placeholder": "{%tr for f in findings %}...{%tr endfor %}",
             "where": "Findings summary table row loop"},
        ],
        "per_finding_fields": [
            "f.title", "f.severity", "f.cvss_score", "f.cvss_vector",
            "f.description", "f.impact", "f.poc_steps", "f.remediation",
            "f.references", "f.affected_asset", "f.status",
            "f.retest_notes", "f.screenshot_objs",
        ],
        "notes": [
            "Use {%p for ... %} for paragraph-level loops (one block per finding).",
            "Use {%tr for ... %} for table-row loops (summary tables).",
            "Screenshots are pre-wrapped as InlineImage objects via the {{ f.screenshot_objs }} list.",
        ],
    }
