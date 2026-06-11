"""
Free-edit mode endpoints for report prose.

Three-layer architecture (admin > consultant > fallback):

  Master sections (admin only):
    GET    /api/templates/{template_id}/sections
    PUT    /api/templates/{template_id}/sections/{key}

  Per-report overrides (anyone with edit access on the report):
    GET    /api/reports/{report_id}/sections          (resolved view)
    PUT    /api/reports/{report_id}/sections/{key}    (override)
    DELETE /api/reports/{report_id}/sections/{key}    (revert to master)
"""
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import (
    User, Role, ReportTemplate, TemplateSection, Report, ReportSectionOverride, AuditLog
)
from ..auth import get_current_user, require_roles
from ..services.section_resolver import (
    resolve_sections, list_section_definitions, DEFAULT_SECTION_KEYS
)


router = APIRouter(tags=["sections"])


class SectionUpdate(BaseModel):
    body: str
    title: Optional[str] = None
    order: Optional[int] = None


# ---------- Master sections (admin) ----------

@router.get("/api/templates/{template_id}/sections")
def list_master_sections(template_id: int,
                          db: Session = Depends(get_db),
                          _: User = Depends(require_roles(Role.admin, Role.senior))):
    """Return all sections defined for a template, including DEFAULT keys
    that haven't been customised yet (with fallback text)."""
    template = db.get(ReportTemplate, template_id)
    if not template:
        raise HTTPException(404, "Template not found")
    return {
        "template_id": template_id,
        "template_name": template.name,
        "sections": list_section_definitions(db, template_id),
    }


@router.put("/api/templates/{template_id}/sections/{key}")
def upsert_master_section(template_id: int, key: str, payload: SectionUpdate,
                          db: Session = Depends(get_db),
                          user: User = Depends(require_roles(Role.admin, Role.senior))):
    """Admins (and seniors) edit the master prose for a template section.
    Future-generated reports inherit the new text.
    """
    template = db.get(ReportTemplate, template_id)
    if not template:
        raise HTTPException(404, "Template not found")

    s = (db.query(TemplateSection)
           .filter(TemplateSection.template_id == template_id,
                   TemplateSection.key == key)
           .first())
    if s:
        s.body = payload.body
        if payload.title is not None:
            s.title = payload.title
        if payload.order is not None:
            s.order = payload.order
        s.updated_by_id = user.id
        action = "template.section.update"
    else:
        s = TemplateSection(
            template_id=template_id,
            key=key,
            body=payload.body,
            title=payload.title or key.replace("_", " ").title(),
            order=payload.order or 0,
            updated_by_id=user.id,
        )
        db.add(s)
        action = "template.section.create"

    db.add(AuditLog(actor_id=user.id, action=action,
                    object_type="template_section", object_id=template_id,
                    detail={"key": key, "len": len(payload.body)}))
    db.commit()
    db.refresh(s)
    return {
        "key": s.key, "title": s.title, "body": s.body,
        "order": s.order,
        "updated_at": s.updated_at.isoformat() if s.updated_at else None,
        "is_master_defined": True,
    }


# ---------- Per-report overrides ----------

@router.get("/api/reports/{report_id}/sections")
def get_report_sections(report_id: int,
                        db: Session = Depends(get_db),
                        user: User = Depends(get_current_user)):
    """Return the fully-resolved sections (override > master > fallback)
    plus a flag per key indicating whether the report has its own override.
    """
    from .permissions import require_access
    report = db.get(Report, report_id)
    if not report:
        raise HTTPException(404, "Report not found")
    require_access(db, user, report)

    resolved = resolve_sections(db, template_id=report.template_id, report_id=report_id)
    overrides = {o.key for o in db.query(ReportSectionOverride)
                                   .filter(ReportSectionOverride.report_id == report_id)
                                   .all()}
    masters = list_section_definitions(db, report.template_id)
    master_keys = {m["key"]: m for m in masters}

    out = []
    for key in DEFAULT_SECTION_KEYS + [k for k in master_keys if k not in DEFAULT_SECTION_KEYS]:
        master = master_keys.get(key, {})
        out.append({
            "key": key,
            "title": master.get("title", key.replace("_", " ").title()),
            "body": resolved.get(key, ""),
            "has_override": key in overrides,
            "master_body": master.get("body", ""),
        })
    return {"report_id": report_id, "sections": out}


@router.put("/api/reports/{report_id}/sections/{key}")
def upsert_report_override(report_id: int, key: str, payload: SectionUpdate,
                           db: Session = Depends(get_db),
                           user: User = Depends(get_current_user)):
    from .permissions import require_access, AccessLevel
    report = db.get(Report, report_id)
    if not report:
        raise HTTPException(404, "Report not found")
    require_access(db, user, report, need=AccessLevel.edit)

    o = (db.query(ReportSectionOverride)
           .filter(ReportSectionOverride.report_id == report_id,
                   ReportSectionOverride.key == key)
           .first())
    if o:
        o.body = payload.body
        o.updated_by_id = user.id
        action = "report.section.override_update"
    else:
        o = ReportSectionOverride(
            report_id=report_id, key=key,
            body=payload.body, updated_by_id=user.id,
        )
        db.add(o)
        action = "report.section.override_create"

    db.add(AuditLog(actor_id=user.id, action=action,
                    object_type="report_section_override", object_id=report_id,
                    detail={"key": key, "len": len(payload.body)}))
    db.commit()
    return {"key": key, "body": payload.body, "has_override": True}


@router.delete("/api/reports/{report_id}/sections/{key}")
def revert_report_override(report_id: int, key: str,
                           db: Session = Depends(get_db),
                           user: User = Depends(get_current_user)):
    """Revert to the master prose for this section."""
    from .permissions import require_access, AccessLevel
    report = db.get(Report, report_id)
    if not report:
        raise HTTPException(404, "Report not found")
    require_access(db, user, report, need=AccessLevel.edit)

    o = (db.query(ReportSectionOverride)
           .filter(ReportSectionOverride.report_id == report_id,
                   ReportSectionOverride.key == key)
           .first())
    if o:
        db.delete(o)
        db.add(AuditLog(actor_id=user.id, action="report.section.override_revert",
                        object_type="report_section_override", object_id=report_id,
                        detail={"key": key}))
        db.commit()
    return {"ok": True, "reverted": True, "key": key}
