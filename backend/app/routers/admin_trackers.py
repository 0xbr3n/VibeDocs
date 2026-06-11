"""Admin endpoints for managing the bundled VibeDocs tracker Excel
templates (the `.xlsx` files in `TRACKER_TEMPLATES_DIR`).

These mirror the existing Word-template admin surface but for the
loose Excel files in `report-templates/`. The .xlsx files are not
DB-modelled (they're located by filename pattern by the
`tracker_templates` service); endpoints here key everything off the
filename rather than an int id.

Endpoints
---------
    GET    /api/admin/tracker-templates
        List every .xlsx / .xlsm file under TRACKER_TEMPLATES_DIR
        along with its size, mtime, and the report-template `code`s
        it would be picked for (computed via the service's
        `pick_tracker_template` for each code).

    GET    /api/admin/tracker-templates/{filename}/download
        Stream a specific tracker file back to the admin (preserves
        the original filename so re-uploading round-trips cleanly).

    POST   /api/admin/tracker-templates/{filename}/replace
        Replace the bytes of a specific tracker file with the .xlsx
        the admin uploads. Old file is backed up with a `.bak.<ts>`
        suffix so the admin can restore via SSH if a bad upload
        breaks the export.

    POST   /api/admin/tracker-templates/upload
        Upload a NEW tracker file (filename taken from the upload).
        Used when adding a brand-new variant (e.g. an OT-specific
        tracker) without overwriting an existing one. Refuses to
        overwrite — use the replace endpoint for that.

Authorisation
-------------
Admin-only. Tracker swaps affect every consultant's export pipeline
so they sit on the same auth tier as the Word-template admin
operations. Senior users can still see diagnostics via the existing
`tracker_templates.diagnose()` helper through the report-edit page.
"""
from __future__ import annotations

import logging
import re
import shutil
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File
from fastapi.responses import FileResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import User, Role, AuditLog
from ..auth import require_roles
from ..services import tracker_templates as _tpl
from ..services.upload_utils import stream_save as _stream_save

_MAX_TRACKER_BYTES = 20 * 1024 * 1024   # 20 MB — VibeDocs Excel trackers


router = APIRouter(prefix="/api/admin/tracker-templates",
                   tags=["admin-trackers"])

logger = logging.getLogger(__name__)


# Filenames are user-controlled when uploading "new" files, so reject
# anything that smells like a path-traversal or shell-escape attempt
# before we let it land on disk. We keep the filename regex tight
# (alnum + space + a small set of punctuation) because every VibeDocs
# tracker name we've ever seen falls inside it.
_SAFE_FILENAME = re.compile(r"^[A-Za-z0-9 _\-().+]+\.(xlsx|xlsm)$")


def _validate_filename(name: str) -> str:
    """Strict allow-list filename check. Returns the validated name or
    raises 400 — callers should never see anything but a plain
    `.xlsx` / `.xlsm` filename pass through.
    """
    name = (name or "").strip()
    if not name:
        raise HTTPException(400, "Filename is required")
    # Block path components even if the regex would accept them — `..`
    # and OS-specific separators must never appear.
    if "/" in name or "\\" in name or ".." in name:
        raise HTTPException(400, "Filename must not contain path separators")
    if not _SAFE_FILENAME.match(name):
        raise HTTPException(
            400,
            "Filename must be alphanumeric (plus spaces, _-.() ) and end "
            "in .xlsx or .xlsm",
        )
    if name.startswith("~$"):
        raise HTTPException(400, "Office lock-file names (~$…) are not allowed")
    return name


def _resolve(name: str) -> Path:
    """Resolve a validated filename inside TRACKER_TEMPLATES_DIR with
    no traversal. Raises 404 if the file isn't present.
    """
    base = Path(_tpl._tracker_dir()).resolve()
    target = (base / name).resolve()
    # Defence-in-depth — even though the regex is strict, double-check
    # that the resolved path is still under the base directory.
    if base not in target.parents and target != base:
        raise HTTPException(400, "Filename resolves outside the templates folder")
    if not target.exists() or not target.is_file():
        raise HTTPException(404, f"Tracker template not found: {name}")
    return target


# ---------- List ----------

@router.get("")
def list_tracker_templates(
    _: User = Depends(require_roles(Role.admin, Role.senior)),
):
    """Return every tracker file in `TRACKER_TEMPLATES_DIR` with the
    code(s) it would back. Senior + admin can read this surface so
    they can verify the bundle is intact without needing write access.
    """
    folder = _tpl._tracker_dir()
    if not folder.exists():
        return {
            "folder": str(folder),
            "folder_exists": False,
            "files": [],
            "type_label_map": _tpl.TRACKER_TYPE_BY_CODE,
        }
    # Group each file with the codes that would resolve to it via the
    # picker. This way the admin sees "this file backs api_vapt +
    # web_vapt + …" inline on the row instead of opening the diagnose
    # blob in a modal.
    matches_per_code: dict[str, str] = {}
    for code in _tpl.TRACKER_TYPE_BY_CODE.keys():
        picked = _tpl.pick_tracker_template(code)
        if picked is not None:
            matches_per_code[code] = picked.name

    files: list[dict] = []
    for p in sorted(folder.iterdir(), key=lambda x: x.name.lower()):
        if not p.is_file():
            continue
        if p.name.startswith("~$"):
            continue
        if p.suffix.lower() not in {".xlsx", ".xlsm"}:
            continue
        stat = p.stat()
        # Which template codes would resolve to this exact file?
        codes_for_file = sorted(
            c for c, fname in matches_per_code.items() if fname == p.name
        )
        files.append({
            "filename": p.name,
            "size": stat.st_size,
            "modified_at": datetime.fromtimestamp(
                stat.st_mtime, tz=timezone.utc).isoformat(),
            "matches_codes": codes_for_file,
            # The canonical label that this filename's `XXX <Label> Tracking
            # List` prefix encodes. Empty if the filename doesn't match the
            # convention — those files won't be picked by the export route
            # but the admin can still download / replace them.
            "tracker_label": _extract_label_from_filename(p.name),
        })
    return {
        "folder": str(folder),
        "folder_exists": True,
        "files": files,
        "type_label_map": _tpl.TRACKER_TYPE_BY_CODE,
    }


_LABEL_RE = re.compile(
    r"^XXX\s+(?P<label>.+?)\s+Tracking\s+List\b",
    re.IGNORECASE,
)


def _extract_label_from_filename(name: str) -> str:
    """Pull the "<Label>" out of "XXX <Label> Tracking List …" so the
    admin UI can show what type a file backs even when the filename
    is the only signal.
    """
    m = _LABEL_RE.match(name)
    if not m:
        return ""
    return m.group("label").strip()


# ---------- Download ----------

@router.get("/{filename:path}/download")
def download_tracker_template(
    filename: str,
    _: User = Depends(require_roles(Role.admin, Role.senior)),
):
    """Stream the named tracker file back. Uses :path so filenames
    with dots ("v0.1.xlsx") and spaces ("Web VAPT Tracking List.xlsx")
    pass through cleanly.
    """
    safe = _validate_filename(filename)
    p = _resolve(safe)
    return FileResponse(
        path=str(p),
        filename=safe,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    )


# ---------- Replace ----------

@router.post("/{filename:path}/replace")
def replace_tracker_template(
    filename: str,
    xlsx_file: UploadFile = File(...),
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(Role.admin)),
):
    """Replace an existing tracker file with the admin's upload. The
    existing file is backed up to `<name>.bak.<unix_ts>` in the same
    directory before the new bytes land, so a bad upload can be
    rolled back via SSH.
    """
    safe = _validate_filename(filename)
    target = _resolve(safe)
    upload_name = (xlsx_file.filename or "").lower()
    if not (upload_name.endswith(".xlsx") or upload_name.endswith(".xlsm")):
        raise HTTPException(400, "Upload must be a .xlsx or .xlsm file")

    backup_path = target.with_name(f"{target.name}.bak.{int(time.time())}")
    try:
        shutil.copy2(str(target), str(backup_path))
    except Exception as e:                                      # pragma: no cover
        logger.warning("backup of %s failed: %s", target, e)
        backup_path = None

    try:
        _stream_save(xlsx_file.file, target, max_bytes=_MAX_TRACKER_BYTES)
    except HTTPException as e:
        raise
    except OSError as e:
        # Most likely cause: the bind mount is still :ro. Surface a
        # clear error rather than a generic 500 so the admin knows
        # the deploy needs to update docker-compose.yml + recreate.
        raise HTTPException(
            500,
            f"Could not write {target.name!r}: {e}. "
            "Check the report-templates bind mount is read-write in "
            "docker-compose.yml and that the container was recreated "
            "after the change.",
        )

    new_size = target.stat().st_size
    try:
        db.add(AuditLog(
            actor_id=user.id, action="tracker_template.replace",
            object_type="tracker_template", object_id=None,
            detail={
                "filename": safe,
                "uploaded_filename": xlsx_file.filename,
                "size": new_size,
                "backup": backup_path.name if backup_path else None,
            },
        ))
        db.commit()
    except Exception:                                           # pragma: no cover
        db.rollback()
    return {
        "ok": True,
        "filename": safe,
        "size": new_size,
        "backup": backup_path.name if backup_path else None,
    }


# ---------- Upload-new ----------

@router.post("/upload")
def upload_new_tracker_template(
    xlsx_file: UploadFile = File(...),
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(Role.admin)),
):
    """Upload a NEW tracker file. The destination filename is taken
    from the upload itself (sanitised). Refuses to overwrite an
    existing file — that path goes through the `/replace` endpoint
    so the previous file is backed up first.
    """
    if not xlsx_file.filename:
        raise HTTPException(400, "Upload has no filename")
    safe = _validate_filename(xlsx_file.filename)
    folder = Path(_tpl._tracker_dir())
    folder.mkdir(parents=True, exist_ok=True)
    target = folder / safe
    if target.exists():
        raise HTTPException(
            409,
            f"{safe!r} already exists. Use the Replace action on the "
            "existing row to swap it (the old file is backed up first).",
        )
    try:
        _stream_save(xlsx_file.file, target, max_bytes=_MAX_TRACKER_BYTES)
    except HTTPException:
        raise
    except OSError as e:
        raise HTTPException(
            500,
            f"Could not write {safe!r}: {e}. "
            "Check the report-templates bind mount is read-write.",
        )
    new_size = target.stat().st_size
    try:
        db.add(AuditLog(
            actor_id=user.id, action="tracker_template.upload",
            object_type="tracker_template", object_id=None,
            detail={"filename": safe, "size": new_size},
        ))
        db.commit()
    except Exception:                                           # pragma: no cover
        db.rollback()
    return {"ok": True, "filename": safe, "size": new_size}


# ---------- Diagnose ----------

@router.get("/diagnose")
def diagnose_trackers(
    _: User = Depends(require_roles(Role.admin, Role.senior)),
):
    """Re-export the existing `tracker_templates.diagnose()` snapshot
    through the admin namespace so the UI can show it without
    knowing the legacy endpoint URL.
    """
    return _tpl.diagnose()


# ============================================================
# Central tasking-assignment table (the "VAPT type → templates" map)
# ============================================================
#
# Each ReportTemplate row IS a VAPT tasking type. It already binds a
# single Word .docx via `docx_filename`. This pair of endpoints
# exposes / mutates the OTHER half of the binding: the Excel tracker
# the export route uses for the same tasking.
#
# Listing both bindings in one place ("Tasking Assignments" admin
# tab) lets an admin see at a glance what's wired to what and swap
# either side without leaving the tab.

_WORD_FILENAME_RE = re.compile(r"^[A-Za-z0-9 _\-().+]+\.docx$")


def _list_available_word_templates() -> list[dict]:
    """Enumerate every .docx in `settings.TEMPLATE_DIR`. Returns a
    list of `{filename, size}` dicts (sorted by filename, case-
    insensitive) for the Tasking Assignments dropdown. Office lock
    files (`~$...`) are skipped.
    """
    from ..config import settings as _settings
    folder = Path(_settings.TEMPLATE_DIR)
    out: list[dict] = []
    if not folder.exists():
        return out
    for p in sorted(folder.iterdir(), key=lambda x: x.name.lower()):
        if not p.is_file() or p.name.startswith("~$"):
            continue
        if p.suffix.lower() != ".docx":
            continue
        out.append({"filename": p.name, "size": p.stat().st_size})
    return out


def _validate_word_filename(name: str) -> str:
    """Mirror of `_validate_filename` but tighter — Word templates
    must end in `.docx` (no `.docm` since the renderer doesn't
    support macros) and live in TEMPLATE_DIR (not the tracker dir).
    """
    name = (name or "").strip()
    if not name:
        raise HTTPException(400, "Word template filename is required")
    if "/" in name or "\\" in name or ".." in name:
        raise HTTPException(400, "Filename must not contain path separators")
    if not _WORD_FILENAME_RE.match(name):
        raise HTTPException(
            400,
            "Word filename must be alphanumeric (plus spaces, _-.() ) "
            "and end in .docx",
        )
    if name.startswith("~$"):
        raise HTTPException(400, "Office lock-file names (~$…) are not allowed")
    return name


@router.get("/assignments", include_in_schema=False)
def list_assignments(
    db: Session = Depends(get_db),
    _: User = Depends(require_roles(Role.admin, Role.senior)),
):
    """Return one row per VAPT tasking type with both its Word
    template and Excel tracker assignment.

    `tracker_filename` is the admin's explicit pick. `tracker_resolved`
    is what the picker would ACTUALLY use right now (override + path
    existence check, falling back to the legacy filename pattern). The
    two diverge when the override is missing on disk; the UI surfaces
    that as a warning.

    Word-side: `docx_filename` is the file currently bound to the
    tasking. `docx_exists` flags whether the file is present on disk
    (a missing file means generation would 500). The
    `available_word_templates` list at the top level powers the
    dropdown — every .docx under TEMPLATE_DIR is offered as a
    candidate, so admins can repoint a tasking at any uploaded
    template (canonical OR admin-uploaded `<code>__<uuid>.docx`).
    """
    from ..models import ReportTemplate
    from ..config import settings as _settings

    folder = Path(_tpl._tracker_dir())
    available_trackers: list[str] = []
    if folder.exists():
        for p in sorted(folder.iterdir(), key=lambda x: x.name.lower()):
            if (p.is_file() and not p.name.startswith("~$")
                    and p.suffix.lower() in {".xlsx", ".xlsm"}):
                available_trackers.append(p.name)

    available_word = _list_available_word_templates()
    word_dir = Path(_settings.TEMPLATE_DIR)

    rows = (db.query(ReportTemplate)
              .order_by(ReportTemplate.name)
              .all())
    out: list[dict] = []
    for r in rows:
        resolved = _tpl.pick_tracker_template(r.code)
        explicit = getattr(r, "tracker_filename", None)
        # Flag the "override set but missing on disk" foot-gun. Admin
        # sees a warning in the UI and can re-bind.
        override_broken = bool(
            explicit and folder.exists()
            and not (folder / explicit).exists()
        )
        # Same flag for the Word side — if the bound .docx is gone
        # (admin manually deleted it from word_templates/), surfacing
        # the missing-file state lets the admin re-pick before a
        # render attempt 500s.
        docx_present = bool(r.docx_filename) and (word_dir / r.docx_filename).exists()
        out.append({
            "id": r.id,
            "code": r.code,
            "name": r.name,
            "is_active": r.is_active,
            # Word side
            "docx_filename": r.docx_filename,
            "docx_original_filename": r.original_filename,
            "docx_exists": docx_present,
            # Tracker side
            "tracker_filename": explicit,
            "tracker_resolved": resolved.name if resolved else None,
            "tracker_legacy_label": _tpl.tracker_type_for_code(r.code),
            "tracker_override_broken": override_broken,
        })
    return {
        "available_trackers": available_trackers,
        "available_word_templates": available_word,
        "type_label_map": _tpl.TRACKER_TYPE_BY_CODE,
        "rows": out,
    }


class _AssignmentPatch(BaseModel):
    # NULL or "" clears the override (fall back to legacy filename
    # pattern). Any other value must be an existing file in
    # TRACKER_TEMPLATES_DIR or the endpoint returns 400.
    tracker_filename: Optional[str] = None
    # Bind a different Word .docx to this VAPT tasking. Setting this
    # changes `ReportTemplate.docx_filename` so the next render uses
    # the new file. Must exist in `settings.TEMPLATE_DIR`. Passing
    # the same value as is currently bound is a no-op; `null` is
    # NOT accepted here (every tasking must have SOME Word template
    # bound — to remove a tasking entirely, use the admin Replace /
    # Delete flows on the Report Templates tab).
    docx_filename: Optional[str] = None


@router.patch("/assignments/{template_id}")
def patch_assignment(
    template_id: int,
    payload: _AssignmentPatch,
    db: Session = Depends(get_db),
    actor: User = Depends(require_roles(Role.admin)),
):
    """Bind a specific tracker filename and / or Word .docx to a
    VAPT tasking type. Either side can be changed independently — a
    payload with only `tracker_filename` updates the Excel binding
    and leaves the Word side alone, and vice versa. The endpoint
    validates that any new file actually exists on disk so a typo
    can't silently break exports or report generation.
    """
    from ..models import ReportTemplate
    from ..config import settings as _settings

    row = db.get(ReportTemplate, template_id)
    if row is None:
        raise HTTPException(404, "VAPT tasking type not found")

    # ---- Tracker side ----
    tracker_changed = False
    previous_tracker = getattr(row, "tracker_filename", None)
    new_tracker: Optional[str] = previous_tracker
    if payload.tracker_filename is not None or "tracker_filename" in payload.model_fields_set:
        cleaned: Optional[str] = None
        if payload.tracker_filename:
            cleaned = _validate_filename(payload.tracker_filename)
            target = Path(_tpl._tracker_dir()) / cleaned
            if not target.exists():
                raise HTTPException(
                    400,
                    f"Tracker file {cleaned!r} does not exist under "
                    "TRACKER_TEMPLATES_DIR. Upload the file first via the "
                    "Tracker Templates tab.",
                )
        if previous_tracker != cleaned:
            row.tracker_filename = cleaned
            new_tracker = cleaned
            tracker_changed = True

    # ---- Word side ----
    docx_changed = False
    previous_docx = row.docx_filename
    new_docx = previous_docx
    if payload.docx_filename is not None:
        cleaned_docx = _validate_word_filename(payload.docx_filename)
        target_docx = Path(_settings.TEMPLATE_DIR) / cleaned_docx
        if not target_docx.exists():
            raise HTTPException(
                400,
                f"Word template {cleaned_docx!r} does not exist under "
                "TEMPLATE_DIR. Upload it first via the Report Templates "
                "tab.",
            )
        if previous_docx != cleaned_docx:
            row.docx_filename = cleaned_docx
            # Mark `original_filename` as None — the file lives at
            # the on-disk name verbatim now, not a hashed admin
            # upload alias. Keeps the Report Templates table from
            # showing a stale "Admin upload" pill on a file that
            # was actually a re-binding rather than a fresh upload.
            row.original_filename = None
            new_docx = cleaned_docx
            docx_changed = True

    if not tracker_changed and not docx_changed:
        return {"ok": True, "no_change": True,
                "tracker_filename": new_tracker,
                "docx_filename": new_docx}

    db.commit()

    try:
        detail: dict = {"code": row.code}
        if tracker_changed:
            detail["tracker_filename"] = {"previous": previous_tracker,
                                           "new": new_tracker}
        if docx_changed:
            detail["docx_filename"] = {"previous": previous_docx,
                                        "new": new_docx}
        action = "tasking_assignment.set_tracker" if tracker_changed and not docx_changed \
            else ("tasking_assignment.set_word" if docx_changed and not tracker_changed
                  else "tasking_assignment.set_both")
        db.add(AuditLog(
            actor_id=actor.id, action=action,
            object_type="report_template", object_id=row.id,
            detail=detail,
        ))
        db.commit()
    except Exception:                                       # pragma: no cover
        db.rollback()
    return {"ok": True,
            "tracker_filename": new_tracker,
            "docx_filename": new_docx}


# ---------- Delete ----------

@router.delete("/{filename:path}")
def delete_tracker_template(
    filename: str,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(Role.admin)),
):
    """Hard-delete a tracker file. Backed up first under
    `<name>.bak.<unix_ts>` so the admin can restore via SSH if the
    deletion was a mistake. Only the file itself is removed — no DB
    rows because trackers aren't DB-modelled.
    """
    safe = _validate_filename(filename)
    target = _resolve(safe)
    backup_path = target.with_name(f"{target.name}.bak.{int(time.time())}")
    try:
        shutil.copy2(str(target), str(backup_path))
    except Exception as e:                                      # pragma: no cover
        logger.warning("backup of %s failed: %s", target, e)
        backup_path = None
    try:
        target.unlink()
    except OSError as e:
        logger.error("Could not delete tracker template %r: %s", safe, e)
        raise HTTPException(500, "Could not delete the tracker template file. Contact an administrator.")
    try:
        db.add(AuditLog(
            actor_id=user.id, action="tracker_template.delete",
            object_type="tracker_template", object_id=None,
            detail={"filename": safe,
                    "backup": backup_path.name if backup_path else None},
        ))
        db.commit()
    except Exception:                                           # pragma: no cover
        db.rollback()
    return {"ok": True, "filename": safe,
            "backup": backup_path.name if backup_path else None}
