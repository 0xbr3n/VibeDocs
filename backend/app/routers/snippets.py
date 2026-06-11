"""
Reusable text snippet management.

Consultants pick boilerplate paragraphs from the snippet library when
filling in finding fields. The picker is contextual: when adding a
description, only `category=description` snippets are shown; when on a
Web VAPT report, snippets tagged for Web take precedence.

Endpoints:
  GET    /api/snippets?category=...&template_id=...&q=...   list with filters
  POST   /api/snippets                                      create new
  PUT    /api/snippets/{id}                                 update
  DELETE /api/snippets/{id}                                 delete
  POST   /api/snippets/{id}/use                             increments use_count
                                                            (drives popularity sort)
"""
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import or_, desc
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import TextSnippet, User, Role, ReportTemplate, AuditLog
from ..auth import get_current_user


router = APIRouter(prefix="/api/snippets", tags=["snippets"])


class SnippetCreate(BaseModel):
    title: str
    body: str
    category: str
    template_id: Optional[int] = None
    tags: list[str] = []
    language: str = "en"


class SnippetUpdate(BaseModel):
    title: Optional[str] = None
    body: Optional[str] = None
    category: Optional[str] = None
    template_id: Optional[int] = None
    tags: Optional[list[str]] = None
    language: Optional[str] = None


def _serialize(s: TextSnippet) -> dict:
    return {
        "id": s.id,
        "title": s.title,
        "body": s.body,
        "category": s.category,
        "template_id": s.template_id,
        "tags": s.tags or [],
        "language": s.language,
        "use_count": s.use_count,
        "created_by_id": s.created_by_id,
        "created_at": s.created_at.isoformat() if s.created_at else None,
    }


@router.get("")
def list_snippets(
    category: Optional[str] = None,
    template_id: Optional[int] = None,
    q: Optional[str] = None,
    language: Optional[str] = None,
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
):
    """List snippets sorted by popularity then recency. Template-specific
    snippets and global snippets (template_id IS NULL) both appear when
    template_id is provided; this keeps the picker useful even for new templates.
    """
    query = db.query(TextSnippet)
    if category:
        query = query.filter(TextSnippet.category == category)
    if template_id is not None:
        # Snippets either scoped to this template OR globally scoped
        query = query.filter(or_(
            TextSnippet.template_id == template_id,
            TextSnippet.template_id.is_(None),
        ))
    if language:
        query = query.filter(TextSnippet.language == language)
    if q:
        pat = f"%{q}%"
        query = query.filter(or_(
            TextSnippet.title.ilike(pat),
            TextSnippet.body.ilike(pat),
        ))
    rows = (query.order_by(desc(TextSnippet.use_count), desc(TextSnippet.id))
                 .limit(100).all())
    return {"items": [_serialize(s) for s in rows]}


@router.post("")
def create_snippet(payload: SnippetCreate,
                   db: Session = Depends(get_db),
                   user: User = Depends(get_current_user)):
    if payload.template_id:
        if not db.get(ReportTemplate, payload.template_id):
            raise HTTPException(404, "Template not found")
    s = TextSnippet(
        title=payload.title,
        body=payload.body,
        category=payload.category,
        template_id=payload.template_id,
        tags=payload.tags,
        language=payload.language,
        created_by_id=user.id,
    )
    db.add(s)
    db.add(AuditLog(actor_id=user.id, action="snippet.create",
                    object_type="snippet", object_id=None,
                    detail={"title": payload.title, "category": payload.category}))
    db.commit()
    db.refresh(s)
    return _serialize(s)


@router.put("/{snippet_id}")
def update_snippet(snippet_id: int, payload: SnippetUpdate,
                   db: Session = Depends(get_db),
                   user: User = Depends(get_current_user)):
    s = db.get(TextSnippet, snippet_id)
    if not s:
        raise HTTPException(404, "Snippet not found")
    if s.created_by_id != user.id and user.role not in (Role.admin, Role.senior):
        raise HTTPException(403, "Only the author or admins can edit a snippet")
    for f in ("title", "body", "category", "template_id", "tags", "language"):
        v = getattr(payload, f)
        if v is not None:
            setattr(s, f, v)
    db.add(AuditLog(actor_id=user.id, action="snippet.update",
                    object_type="snippet", object_id=s.id, detail={}))
    db.commit()
    db.refresh(s)
    return _serialize(s)


@router.delete("/{snippet_id}")
def delete_snippet(snippet_id: int,
                   db: Session = Depends(get_db),
                   user: User = Depends(get_current_user)):
    s = db.get(TextSnippet, snippet_id)
    if not s:
        raise HTTPException(404, "Snippet not found")
    if s.created_by_id != user.id and user.role not in (Role.admin, Role.senior):
        raise HTTPException(403, "Only the author or admins can delete")
    db.delete(s)
    db.add(AuditLog(actor_id=user.id, action="snippet.delete",
                    object_type="snippet", object_id=snippet_id, detail={}))
    db.commit()
    return {"ok": True, "deleted": snippet_id}


@router.post("/{snippet_id}/use")
def increment_use(snippet_id: int,
                  db: Session = Depends(get_db),
                  _: User = Depends(get_current_user)):
    """Bump the use count when a consultant pastes this snippet.
    Drives the popularity ranking in the picker so common snippets surface
    to the top over time.
    """
    s = db.get(TextSnippet, snippet_id)
    if not s:
        raise HTTPException(404, "Not found")
    s.use_count = (s.use_count or 0) + 1
    db.commit()
    return {"id": snippet_id, "use_count": s.use_count}
