"""
Per-consultant sticky notes API.

Backs the floating terminal-style widget on every page. Notes live
strictly per-user — no sharing, no team visibility. The widget
treats them as a checklist (toggleable `is_done`) but doesn't
enforce any structure beyond that.

Endpoints:
  GET    /api/notes          list the current user's notes
  POST   /api/notes          create one (body: {content})
  PATCH  /api/notes/{id}     update content and/or is_done
  DELETE /api/notes/{id}     remove one
  DELETE /api/notes          wipe ALL of the user's notes
"""
from __future__ import annotations
import re
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, validator
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import User, UserNote
from ..auth import get_current_user


router = APIRouter(prefix="/api/notes", tags=["notes"])


# Hard cap on per-user notes — the widget shows a list, not a paginator,
# so a runaway count would slow rendering. Generous limit; users hitting
# this can clear / archive their oldest entries.
MAX_NOTES_PER_USER = 200
# Length cap so a paste-bomb doesn't blow up storage. Plenty for a
# multi-line scratch note.
MAX_CONTENT_LEN = 2000


# ---- Injection-pattern guard --------------------------------------
#
# Notes are persisted as plain text and rendered via `textContent` in
# the widget (NOT innerHTML), so SQLi / XSS / template injection are
# already impossible at the DOM level. This block exists because the
# user explicitly asked for the system to REFUSE inputs containing
# the typical pen-tester injection tokens — defence in depth.
#
# Every entry is `(regex, human-readable label)`. The regex is applied
# with `re.search` so a single occurrence anywhere in the note body
# triggers the rejection.
_BLOCKED_TOKENS: list[tuple[str, str]] = [
    (r"['\"]",                "quote characters (' or \")"),
    (r";",                    "semicolon (;)"),
    (r"`",                    "backtick (`)"),
    (r"--+",                  "SQL-style comment (-- / --+)"),
    (r"/\*|\*/",              "C-style comment (/* */)"),
    (r"//",                   "line-comment marker (//)"),
    (r"(?:^|\s)#",            "hash comment (#)"),
    (r"\{\{|\}\}",            "Jinja2 expression braces ({{ }})"),
    (r"\{%|%\}",              "Jinja2 statement tags ({% %})"),
    (r"\$\{[^}]*\}",          "shell template expansion (${...})"),
    (r"<\s*script",           "<script> tag"),
    (r"<[^>]+\son\w+\s*=",   "HTML on*= event handler"),
    (r"\bjavascript\s*:",     "javascript: URI"),
]
_BLOCKED_COMPILED = [(re.compile(p, re.IGNORECASE), label)
                     for p, label in _BLOCKED_TOKENS]


def _reject_injection_tokens(s: str) -> None:
    """Raise `HTTPException(400)` when the input contains any token
    on the `_BLOCKED_TOKENS` list. Called from both `NoteCreate` and
    `NoteUpdate` Pydantic validators so every write path is gated."""
    for rx, label in _BLOCKED_COMPILED:
        if rx.search(s):
            raise HTTPException(
                400,
                f"Note rejected — input contains a blocked pattern: {label}. "
                "Strip it and try again.",
            )


# ---------- Schemas ----------

class NoteOut(BaseModel):
    id: int
    content: str
    is_done: bool
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class NoteCreate(BaseModel):
    content: str = Field(..., min_length=1, max_length=MAX_CONTENT_LEN)

    @validator("content")
    def _safe_content(cls, v):
        _reject_injection_tokens(v)
        stripped = v.strip()
        if not stripped:
            raise HTTPException(400, "Note content cannot be blank or whitespace-only.")
        return stripped


class NoteUpdate(BaseModel):
    content: Optional[str] = Field(None, min_length=1, max_length=MAX_CONTENT_LEN)
    is_done: Optional[bool] = None

    @validator("content")
    def _safe_content(cls, v):
        if v is not None:
            _reject_injection_tokens(v)
            stripped = v.strip()
            if not stripped:
                raise HTTPException(400, "Note content cannot be blank or whitespace-only.")
            return stripped
        return v


# ---------- Helpers ----------

def _owned_note(db: Session, note_id: int, user: User) -> UserNote:
    """Fetch a note by id and verify it belongs to the calling user.
    404 (not 403) on a foreign note so an attacker can't enumerate
    which note ids exist by probing other users' rows."""
    n = db.get(UserNote, note_id)
    if not n or n.user_id != user.id:
        raise HTTPException(404, "Note not found")
    return n


# ---------- Endpoints ----------

@router.get("", response_model=list[NoteOut])
def list_notes(db: Session = Depends(get_db),
               user: User = Depends(get_current_user)):
    """Return the calling user's notes, newest first. Sort by
    `created_at` so a re-opened widget reads top-to-bottom as a
    timeline of what the consultant jotted down."""
    return (db.query(UserNote)
              .filter(UserNote.user_id == user.id)
              .order_by(UserNote.created_at.desc())
              .all())


@router.post("", response_model=NoteOut)
def create_note(payload: NoteCreate,
                db: Session = Depends(get_db),
                user: User = Depends(get_current_user)):
    """Create a new note. Refuses the request when the user already
    has `MAX_NOTES_PER_USER` notes so a runaway client (or a typo'd
    keyboard shortcut) can't fill the table."""
    count = (db.query(UserNote)
               .filter(UserNote.user_id == user.id)
               .count())
    if count >= MAX_NOTES_PER_USER:
        raise HTTPException(
            400,
            f"Note limit reached ({MAX_NOTES_PER_USER}). "
            "Delete some old notes before adding more.")
    n = UserNote(
        user_id=user.id,
        content=payload.content.strip(),
        is_done=False,
    )
    db.add(n); db.commit(); db.refresh(n)
    return n


@router.patch("/{note_id}", response_model=NoteOut)
def update_note(note_id: int, payload: NoteUpdate,
                db: Session = Depends(get_db),
                user: User = Depends(get_current_user)):
    """Toggle `is_done` and/or replace `content`. Both fields are
    optional — pass only what you want to change."""
    n = _owned_note(db, note_id, user)
    if payload.content is not None:
        n.content = payload.content.strip()
    if payload.is_done is not None:
        n.is_done = payload.is_done
    db.commit(); db.refresh(n)
    return n


@router.delete("/{note_id}")
def delete_note(note_id: int,
                db: Session = Depends(get_db),
                user: User = Depends(get_current_user)):
    """Hard-delete a single note. Idempotent — repeating the call
    just returns the same 404 the second time."""
    n = _owned_note(db, note_id, user)
    db.delete(n); db.commit()
    return {"ok": True, "deleted_id": note_id}


@router.delete("")
def clear_notes(db: Session = Depends(get_db),
                user: User = Depends(get_current_user)):
    """Wipe every note belonging to the calling user. Used by the
    widget's `clear` command. No confirmation prompt server-side —
    the client is expected to confirm before calling."""
    n = (db.query(UserNote)
           .filter(UserNote.user_id == user.id)
           .delete(synchronize_session=False))
    db.commit()
    return {"ok": True, "deleted": int(n or 0)}
