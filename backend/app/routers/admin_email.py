"""
Admin-editable email template management.

Endpoints (all admin-only):

  GET    /api/admin/email-templates              list all
  GET    /api/admin/email-templates/{key}        single
  PUT    /api/admin/email-templates/{key}        update subject / text / html
  POST   /api/admin/email-templates/{key}/preview
                                                 render an UNSAVED draft against
                                                 a sample context — admins can
                                                 see what the email will look
                                                 like before saving
  POST   /api/admin/email-templates/{key}/test
                                                 send the CURRENT (saved) version
                                                 to a recipient email so the
                                                 admin can confirm SMTP works

  POST   /api/admin/email-templates/reseed       reseed any missing keys from
                                                 the in-code defaults (does NOT
                                                 overwrite existing rows)
"""
from __future__ import annotations
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Body, Depends, HTTPException
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import User, Role, EmailTemplate, AuditLog
from ..auth import require_roles
from ..services import email_templates as _email_tmpls
from ..services.email_send import send_mail


router = APIRouter(prefix="/api/admin/email-templates", tags=["admin-email"])


class TemplateOut(BaseModel):
    key: str
    description: Optional[str] = None
    subject: str
    body_text: str
    body_html: str
    updated_at: Optional[datetime] = None
    updated_by_id: Optional[int] = None
    allowed_variables: list[str] = []

    class Config:
        from_attributes = True


class TemplateUpdate(BaseModel):
    subject: str
    body_text: str
    body_html: str


def _row_to_out(row: EmailTemplate) -> TemplateOut:
    return TemplateOut(
        key=row.key,
        description=row.description,
        subject=row.subject,
        body_text=row.body_text,
        body_html=row.body_html,
        updated_at=row.updated_at,
        updated_by_id=row.updated_by_id,
        allowed_variables=sorted(_email_tmpls.ALLOWED_VARS.get(row.key, set())),
    )


@router.get("", response_model=list[TemplateOut])
def list_templates(
    db: Session = Depends(get_db),
    _: User = Depends(require_roles(Role.admin)),
):
    rows = db.query(EmailTemplate).order_by(EmailTemplate.key).all()
    return [_row_to_out(r) for r in rows]


@router.get("/{key}", response_model=TemplateOut)
def get_template(
    key: str,
    db: Session = Depends(get_db),
    _: User = Depends(require_roles(Role.admin)),
):
    row = db.query(EmailTemplate).filter(EmailTemplate.key == key).first()
    if not row:
        raise HTTPException(404, f"Template '{key}' not found")
    return _row_to_out(row)


@router.put("/{key}", response_model=TemplateOut)
def update_template(
    key: str,
    payload: TemplateUpdate,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(Role.admin)),
):
    row = db.query(EmailTemplate).filter(EmailTemplate.key == key).first()
    if not row:
        raise HTTPException(404, f"Template '{key}' not found")
    # Validate the draft compiles + renders against the sample context.
    test = _email_tmpls.render_preview(
        key, payload.subject, payload.body_text, payload.body_html,
    )
    if not test["ok"]:
        raise HTTPException(400, f"Template render failed: {test['error']}")

    row.subject = payload.subject
    row.body_text = payload.body_text
    row.body_html = payload.body_html
    row.updated_by_id = user.id
    db.add(AuditLog(actor_id=user.id, action="email_template.update",
                    object_type="email_template", object_id=row.id,
                    detail={"key": key}))
    db.commit()
    db.refresh(row)
    return _row_to_out(row)


class PreviewRequest(BaseModel):
    subject: str
    body_text: str
    body_html: str


@router.post("/{key}/preview")
def preview_template(
    key: str,
    payload: PreviewRequest,
    _: User = Depends(require_roles(Role.admin)),
):
    """Render the draft against a sample context. Returns rendered
    `subject`, `body_text`, `body_html` plus the variable allow-list so
    admins know what placeholders they can use."""
    out = _email_tmpls.render_preview(
        key, payload.subject, payload.body_text, payload.body_html,
    )
    out["allowed_variables"] = sorted(_email_tmpls.ALLOWED_VARS.get(key, set()))
    return out


class TestSendRequest(BaseModel):
    to: EmailStr


@router.post("/{key}/test")
def test_send(
    key: str,
    payload: TestSendRequest,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(Role.admin)),
):
    """Render the CURRENT (saved) template against a sample context and
    send it to `to`. Useful for verifying SMTP wiring is correct after
    editing the template."""
    row = db.query(EmailTemplate).filter(EmailTemplate.key == key).first()
    if not row:
        raise HTTPException(404, f"Template '{key}' not found")

    # Sample context (reuse the preview helper to keep behaviour in
    # lockstep with the preview button)
    sample = _email_tmpls._sample_context(key)  # noqa: SLF001
    subject, body_text, body_html = _email_tmpls.render_template(db, key, sample)
    ok = send_mail(payload.to, subject, body_text=body_text, body_html=body_html)
    db.add(AuditLog(actor_id=user.id, action="email_template.test_send",
                    object_type="email_template", object_id=row.id,
                    detail={"key": key, "to": str(payload.to), "ok": bool(ok)}))
    db.commit()
    return {"ok": ok, "to": str(payload.to)}


@router.post("/reseed")
def reseed(
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(Role.admin)),
):
    """Add any template keys missing from the DB. Does NOT overwrite
    existing rows — admin edits are preserved."""
    summary = _email_tmpls.seed_default_email_templates(db)
    db.add(AuditLog(actor_id=user.id, action="email_template.reseed",
                    detail=summary))
    db.commit()
    return summary
