"""
Report templates - CRUD over the available VAPT template types.
Admins can upload new .docx templates and define their metadata
(scope of work / methodology / extra fields / Nessus/Nmap support flags).
"""
from pathlib import Path
from typing import Optional
import shutil
import uuid

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import ReportTemplate, User, Role
from ..schemas import TemplateOut
from ..auth import get_current_user, require_roles
from ..config import settings
from ..services.upload_utils import stream_save as _stream_save

_MAX_TEMPLATE_BYTES = 30 * 1024 * 1024   # 30 MB — Word templates

router = APIRouter(prefix="/api/templates", tags=["templates"])


@router.get("", response_model=list[TemplateOut])
def list_templates(
    only_active: bool = True,
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
):
    q = db.query(ReportTemplate)
    if only_active:
        q = q.filter(ReportTemplate.is_active == True)  # noqa
    rows = q.order_by(ReportTemplate.name).all()
    # Attach `docx_filesize` so the admin templates table can show the
    # on-disk size for EVERY row, including admin-uploaded ones whose
    # hashed filenames don't match the canonical SPECS the
    # `diagnose-defaults` endpoint iterates. We stat the file once
    # per row — cheap (≤ 1 ms per file on a typical SSD).
    out = []
    for r in rows:
        size: Optional[int] = None
        if r.docx_filename:
            try:
                p = Path(settings.TEMPLATE_DIR) / r.docx_filename
                if p.exists():
                    size = p.stat().st_size
            except OSError:
                size = None
        payload = TemplateOut.model_validate(r).model_copy(
            update={"docx_filesize": size},
        )
        out.append(payload)
    return out


# ============================================================
# Literal-path routes MUST be registered BEFORE the `/{template_id}`
# parametric route. FastAPI/Starlette matches routes in registration
# order — if `/{template_id}` (int) appears first, a request for
# `/regenerate-defaults` or `/diagnose-defaults` is parsed as
# `template_id="regenerate-defaults"`, which fails int validation and
# returns a 422. Keep these two at the top of the route block.
# ============================================================

@router.post("/regenerate-defaults")
def regenerate_default_templates(
    user: User = Depends(require_roles(Role.admin)),
):
    """Admin-only — re-runs the VibeDocs source → canonical master
    template transformer for every VAPT type. Use this after dropping
    a refreshed VibeDocs template into `report-templates/` if the
    container has already booted and you don't want to wait for a
    restart.

    Returns a summary mapping output filename → resolution
    (e.g. "vibedocs:Security Assessment XXX WAPT Draft Report v0.1
    (Template).docx" or "simple").
    """
    from ..gen_word_templates import main as _regen
    summary = _regen(force_overwrite_simple=True)
    return {"ok": True, "summary": summary}


@router.post("/reinject-all")
def reinject_all_templates(
    force: bool = False,
    user: User = Depends(require_roles(Role.admin)),
):
    """Admin-only — apply Jinja2 injection to every .docx in TEMPLATE_DIR
    that doesn't yet have {{ expressions }} in docProps/custom.xml.

    Use this after upgrading from a version that didn't auto-inject on upload,
    or after manually replacing files outside the API. With ``force=true``,
    ALL templates are re-injected regardless of current state (useful after
    updating the injection logic itself).

    Returns a per-filename summary: "injected", "already_ok", or "skipped:<reason>".
    """
    from ..tools.inject_jinja2_into_templates import inject_all_in_dir
    summary = inject_all_in_dir(Path(settings.TEMPLATE_DIR), force=force)
    injected = [k for k, v in summary.items() if v == 'injected']
    already_ok = [k for k, v in summary.items() if v == 'already_ok']
    skipped = {k: v for k, v in summary.items() if v.startswith('skipped:')}
    try:
        from ..models import AuditLog
        from ..database import get_db as _get_db
        # Use a fresh session for the audit log to avoid leaking the
        # request-scoped DB session into a background context.
        import logging
        logging.getLogger(__name__).info(
            "reinject-all: %d injected, %d already_ok, %d skipped",
            len(injected), len(already_ok), len(skipped),
        )
    except Exception:                                       # pragma: no cover
        pass
    return {
        "ok": True,
        "injected": injected,
        "already_ok": already_ok,
        "skipped": skipped,
        "total": len(summary),
    }


@router.get("/diagnose-defaults")
def diagnose_default_templates(
    _: User = Depends(require_roles(Role.admin, Role.senior)),
):
    """Admin / senior — diagnostic snapshot of which master template
    file is currently being served for each VAPT type, AND which
    VibeDocs source (if any) it was transformed from.

    Pairs with `regenerate-defaults` so support can answer "is the
    Mobile VAPT report still on the old simple layout?" without
    shell access to the container.
    """
    from ..gen_word_templates import SPECS, _vibedocs_source_path
    out_dir = Path(settings.TEMPLATE_DIR)
    rows = []
    for fname, title, _with_nmap in SPECS:
        path = out_dir / fname
        src = _vibedocs_source_path(fname)
        rows.append({
            "output_filename": fname,
            "label": title,
            "output_path": str(path),
            "output_exists": path.exists(),
            "output_size": path.stat().st_size if path.exists() else 0,
            "vibedocs_source": src.name if src else None,
            "vibedocs_source_path": str(src) if src else None,
        })
    return {
        "template_dir": str(out_dir),
        "report_templates_dir": str(
            Path(__file__).resolve().parent.parent.parent.parent / "report-templates"
        ),
        "rows": rows,
    }


@router.get("/{template_id}/download")
def download_template_docx(
    template_id: int,
    db: Session = Depends(get_db),
    _: User = Depends(require_roles(Role.admin)),
):
    """Admin-only — download the .docx currently backing a template.

    Use case: admin wants to edit placeholders on the live template
    without losing the existing docxtpl wiring. They download the file
    here (placeholders intact), edit in Word, then upload via the
    Replace .docx button with `auto_transform=false` to keep their
    hand edits byte-for-byte. The returned filename prefers the admin's
    `original_filename` (what they last uploaded) and falls back to the
    on-disk `docx_filename` so consultant-friendly names round-trip.
    """
    t = db.get(ReportTemplate, template_id)
    if not t:
        raise HTTPException(404, "Template not found")
    if not t.docx_filename:
        raise HTTPException(400, "Template has no .docx file")
    p = Path(settings.TEMPLATE_DIR) / t.docx_filename
    if not p.exists():
        raise HTTPException(404, "Template file not found on disk")
    download_name = t.original_filename or t.docx_filename
    return FileResponse(
        path=str(p),
        filename=download_name,
        media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    )


@router.get("/{template_id}", response_model=TemplateOut)
def get_template(template_id: int, db: Session = Depends(get_db),
                 _: User = Depends(get_current_user)):
    t = db.get(ReportTemplate, template_id)
    if not t:
        raise HTTPException(404, "Template not found")
    return t


@router.post("", response_model=TemplateOut)
def create_template(
    code: str = Form(...),
    name: str = Form(...),
    description: str = Form(""),
    scope_of_work: str = Form(""),
    methodology: str = Form(""),
    supports_nessus_import: bool = Form(False),
    supports_nmap_import: bool = Form(False),
    docx_file: UploadFile = File(...),
    db: Session = Depends(get_db),
    # Locked down to admin-only. Previously also allowed `senior`,
    # but creating a brand-new master template is the same level of
    # system-wide impact as the other admin-only operations
    # (replace-docx, regenerate-defaults, active toggle), so it
    # belongs on the same auth tier. Senior users can still
    # read-only diagnose via `diagnose-defaults`.
    _: User = Depends(require_roles(Role.admin)),
):
    if db.query(ReportTemplate).filter(ReportTemplate.code == code).first():
        raise HTTPException(400, "Template code already exists")
    if not docx_file.filename.lower().endswith(".docx"):
        raise HTTPException(400, "Template must be a .docx file")

    safe_name = f"{code}__{uuid.uuid4().hex[:8]}.docx"
    dest = Path(settings.TEMPLATE_DIR) / safe_name
    _stream_save(docx_file.file, dest, max_bytes=_MAX_TEMPLATE_BYTES)
    # Strip any pre-existing DRAFT watermark BEFORE the auto-transform
    # so the renderer's own draft stamp doesn't pile on top of the
    # template's baked-in one (visible double-DRAFT in the rendered
    # PDF). Best-effort: malformed headers / IO errors leave the file
    # untouched and surface as a log warning.
    try:
        from ..services.watermark import strip_draft_watermarks
        strip_draft_watermarks(dest)
    except Exception as e:                                  # pragma: no cover
        import logging
        logging.getLogger(__name__).warning(
            "watermark strip failed on create_template upload: %s", e,
        )
    # Same best-effort VibeDocs -> docxtpl-ready transform that runs on
    # replace-docx, so consultants creating a brand-new template type
    # from a stock VibeDocs source get the structured per-finding loop
    # without an extra step. Failures are silent — the upload still
    # lands as-is.
    _maybe_auto_transform(dest)
    # Inject Jinja2 expressions into DOCPROPERTY result runs and
    # docProps/custom.xml so LibreOffice resolves client name / app name /
    # report date from the render context instead of the static placeholder
    # text baked into the uploaded template. Best-effort: failures leave the
    # file usable but with static placeholders in PDF conversion.
    _maybe_inject_jinja2(dest)

    t = ReportTemplate(
        code=code,
        name=name,
        description=description or None,
        docx_filename=safe_name,
        original_filename=docx_file.filename,
        scope_of_work=scope_of_work or None,
        methodology=methodology or None,
        supports_nessus_import=supports_nessus_import,
        supports_nmap_import=supports_nmap_import,
    )
    db.add(t); db.commit(); db.refresh(t)
    return t


@router.patch("/{template_id}/active", response_model=TemplateOut)
def set_template_active(
    template_id: int,
    active: bool,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(Role.admin)),
):
    """Admin-only — flip a master report template's `is_active` flag.

    Disabling a template removes it from every consultant's template
    picker AND from the list of options shown when creating a new
    report — useful when admins are mid-flight on a VibeDocs layout
    refresh and don't want anyone generating reports off a broken
    template. Re-enabling unhides it.

    Existing reports already bound to the template continue to work
    (the binding is by primary-key id, not by `is_active`), so a
    disabled template doesn't break in-flight deliverables — it only
    stops NEW reports from being created against it.
    """
    t = db.get(ReportTemplate, template_id)
    if not t:
        raise HTTPException(404, "Template not found")
    if t.is_active == active:
        return t
    t.is_active = active
    db.commit(); db.refresh(t)
    try:
        from ..models import AuditLog
        db.add(AuditLog(
            actor_id=user.id,
            action="template.active.set",
            object_type="report_template", object_id=t.id,
            detail={"active": active},
        ))
        db.commit()
    except Exception:                                       # pragma: no cover
        db.rollback()
    return t


def _maybe_inject_jinja2(dest: Path) -> dict:
    """Best-effort: inject Jinja2 expressions into a freshly-uploaded or
    replaced template's DOCPROPERTY result runs and ``docProps/custom.xml``.

    Why this is needed
    ------------------
    Every uploaded template has static placeholder text baked into its
    ``docProps/custom.xml`` properties ("Agency Full Name", "XXX Application",
    "Draft Report", "September 2025") and into the DOCPROPERTY field result
    runs in headers, footers, and the cover page.

    Without this step, ``docx_generator._inject_custom_xml_values`` is a
    no-op because it renders Jinja2 expressions that aren't there yet. When
    LibreOffice converts the rendered DOCX → PDF it resolves DOCPROPERTY
    fields from ``custom.xml``, which still has the static values.

    Running ``inject_jinja2_into_templates.process_template`` after every
    upload ensures:
    - ``docProps/custom.xml`` contains Jinja2 expressions (``{{ details.* }}``)
    - Header/footer DOCPROPERTY wrappers are stripped so LibreOffice cannot
      override the result text
    - Any remaining static "XXX Application" / "Agency Full Name" text in
      document.xml result runs is replaced with Jinja2 expressions

    Idempotent — safe to run on an already-transformed template.
    """
    try:
        from ..tools.inject_jinja2_into_templates import process_template
        process_template(dest)
        return {"injected": True}
    except Exception as e:
        import logging
        logging.getLogger(__name__).warning(
            "jinja2-inject: failed for %s: %s", dest.name, e,
        )
        return {"injected": False, "reason": str(e)}


def _maybe_auto_transform(dest: Path) -> dict:
    """Best-effort: convert a freshly-uploaded generic template
    into a docxtpl-ready one in place.

    Why this is here
    ----------------
    Consultants typically upload the VibeDocs WAPT/MAPT/etc Word
    template as-is, with a single fully-formatted EXAMPLE finding
    section (Heading 2 + 6-col CVSS table + SubHeading bodies). Without
    a `{%p for f in findings %}` / `{%p endfor %}` wrapper around it
    and with no `{{ f.title }}` / `{{ f.cvss_vector }}` placeholders
    inside the cells, every rendered report shows only the hardcoded
    example content — not the actual findings the consultant entered.

    The
    `build_vibedocs_wapt_template.transform` walker rewrites the cells
    + body paragraphs in place AND wraps the whole section with the
    paragraph-level loop, producing the layout the team expects (see
    [tools/build_vibedocs_wapt_template.py](../tools/build_vibedocs_wapt_template.py)).
    Running it automatically on every upload means an admin uploading
    a stock VibeDocs template gets correct rendering without having to
    know about the transformer.

    Best-effort contract
    --------------------
    - If transform succeeds, the file at `dest` is overwritten with
      the docxtpl-ready output. We return ``{"transformed": True, ...}``.
    - If transform fails (typically because the upload doesn't follow
      the VibeDocs "Detailed Findings -> Heading 2 -> labelled
      SubHeadings" layout — e.g. an already-docxtpl-ready template, or
      a custom layout), the original upload is kept untouched and we
      return ``{"transformed": False, "reason": <error>}``.

    The caller logs the result but never fails the upload over a
    transform error — uploading a plain template is still valid.
    """
    import tempfile
    from ..tools.build_vibedocs_wapt_template import transform
    try:
        with tempfile.NamedTemporaryFile(suffix=".docx", delete=False) as tf:
            tmp_path = Path(tf.name)
        try:
            transform(dest, tmp_path)
            # Atomic swap — replace the upload with the transformed copy.
            shutil.move(str(tmp_path), str(dest))
            return {"transformed": True}
        finally:
            try:
                tmp_path.unlink()
            except FileNotFoundError:
                pass
    except Exception as e:
        return {"transformed": False, "reason": str(e)}


@router.post("/{template_id}/replace-docx", response_model=TemplateOut)
def replace_template_docx(
    template_id: int,
    docx_file: UploadFile = File(...),
    auto_transform: bool = False,
    strip_watermark: bool = True,
    custom_filename: Optional[str] = Form(None),
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(Role.admin)),
):
    """Admin-only — replace the .docx file backing a master report template.

    ``custom_filename`` (optional form field): the admin-chosen stem for the
    on-disk file. Sanitised and suffixed with ``.docx``. When omitted, the
    original upload filename is used (spaces → underscores, special chars
    stripped) so the file is human-readable on disk.

    ``auto_transform`` defaults to *False* — uploaded templates that already
    carry docxtpl placeholders (``{{ f.* }}``) are kept byte-for-byte so the
    transformer doesn't overwrite hand-placed tags. Set to ``true`` only when
    uploading a *stock* VibeDocs template (single hardcoded example finding).

    The previous hash-stamped file is deleted from disk after a successful
    upload (canonical ``*_template.docx`` files are never deleted).
    """
    t = db.get(ReportTemplate, template_id)
    if not t:
        raise HTTPException(404, "Template not found")
    if not docx_file.filename.lower().endswith(".docx"):
        raise HTTPException(400, "Template must be a .docx file")

    # Build the on-disk filename — admin-chosen or derived from the upload name.
    import re as _re
    if custom_filename:
        stem = _re.sub(r'[^\w\-.]', '_', custom_filename.strip()).rstrip('.')
        if not stem:
            stem = "upload"
    else:
        # Use upload filename: strip .docx suffix, sanitise, re-add suffix.
        stem = _re.sub(r'[^\w\-.]', '_', Path(docx_file.filename).stem)
        if not stem:
            stem = "upload"
    safe_name = f"{t.code}__{stem}.docx"
    dest = Path(settings.TEMPLATE_DIR) / safe_name
    dest.parent.mkdir(parents=True, exist_ok=True)
    _stream_save(docx_file.file, dest, max_bytes=_MAX_TEMPLATE_BYTES)
    # Strip any DRAFT watermark the admin's source file has baked into
    # its headers BEFORE the auto-transform. The renderer's own draft
    # stamp goes on every page when `is_draft=True`; stripping here
    # makes sure we don't end up with overlapping DRAFTs in the final
    # PDF. Best-effort: a failure leaves the file untouched and only
    # surfaces in the logs (the upload is still usable, just with the
    # original watermark intact).
    watermarks_removed = 0
    if strip_watermark:
        try:
            from ..services.watermark import strip_draft_watermarks
            watermarks_removed = strip_draft_watermarks(dest)
        except Exception as e:                              # pragma: no cover
            import logging
            logging.getLogger(__name__).warning(
                "watermark strip failed on replace_template_docx: %s", e,
            )
    transform_result: dict | None = None
    if auto_transform:
        transform_result = _maybe_auto_transform(dest)
    # Inject Jinja2 expressions into DOCPROPERTY result runs and
    # docProps/custom.xml so LibreOffice resolves client name / app name /
    # report date from the render context instead of the static placeholder
    # text baked into the uploaded template. Best-effort: failures leave the
    # file usable but with static placeholders in PDF conversion.
    inject_result = _maybe_inject_jinja2(dest)
    old_filename = t.docx_filename
    old_original = t.original_filename
    t.docx_filename = safe_name
    t.original_filename = custom_filename or docx_file.filename
    db.commit(); db.refresh(t)

    # Delete the previous hash-stamped file from disk now that the DB
    # points at the new one. Canonical *_template.docx files are the
    # regenerated master copies — never delete those (they're rebuilt
    # at boot). Only hash/custom-named admin uploads are cleaned up.
    import logging as _log_tpl
    old_deleted = False
    if old_filename and old_filename != safe_name:
        # Canonical files end with _template.docx — leave them alone.
        is_canonical = old_filename.endswith("_template.docx") or old_filename.endswith(".pre-change-history.docx")
        if not is_canonical:
            old_path = Path(settings.TEMPLATE_DIR) / old_filename
            try:
                if old_path.exists():
                    old_path.unlink()
                    old_deleted = True
                    _log_tpl.getLogger(__name__).info(
                        "Deleted superseded template file: %s", old_filename
                    )
            except OSError as _oe:
                _log_tpl.getLogger(__name__).warning(
                    "Could not delete old template file %s: %s", old_filename, _oe
                )

    # Audit so the swap is traceable.
    try:
        from ..models import AuditLog
        detail: dict = {"old": old_filename, "new": safe_name,
                        "original_filename": t.original_filename,
                        "previous_original_filename": old_original,
                        "watermarks_removed": watermarks_removed,
                        "old_file_deleted": old_deleted}
        if transform_result is not None:
            detail["auto_transform"] = transform_result
        detail["jinja2_inject"] = inject_result
        db.add(AuditLog(actor_id=user.id, action="template.docx.replace",
                         object_type="report_template", object_id=t.id,
                         detail=detail))
        db.commit()
    except Exception:                                       # pragma: no cover
        db.rollback()
    return t


@router.post("/{template_id}/retransform")
def retransform_template_docx(
    template_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(Role.admin)),
):
    """Admin-only — re-run the VibeDocs -> docxtpl-ready transformer
    against the .docx already linked to this template, in place.

    Use case: an existing upload (made before auto-transform shipped
    or made with ``auto_transform=false``) renders findings as flat
    "Finding N: TITLE" plain text because the per-finding loop wasn't
    wrapped around the structured Heading 2 / CVSS table / SubHeading
    section. Running this endpoint converts the upload into the proper
    docxtpl-ready layout WITHOUT requiring the admin to re-upload.

    The previous file is overwritten in place — if the transform
    fails (file doesn't follow the VibeDocs structure), nothing is
    changed and the failure reason is returned.
    """
    t = db.get(ReportTemplate, template_id)
    if not t:
        raise HTTPException(404, "Template not found")
    if not t.docx_filename:
        raise HTTPException(400, "Template has no .docx file to transform")
    dest = Path(settings.TEMPLATE_DIR) / t.docx_filename
    if not dest.exists():
        raise HTTPException(404, "Template file not found on disk")
    pre_size = dest.stat().st_size
    result = _maybe_auto_transform(dest)
    inject_result = _maybe_inject_jinja2(dest)
    post_size = dest.stat().st_size if dest.exists() else 0
    # Audit either outcome.
    try:
        from ..models import AuditLog
        db.add(AuditLog(actor_id=user.id, action="template.docx.retransform",
                        object_type="report_template", object_id=t.id,
                        detail={"file": t.docx_filename,
                                "result": result,
                                "jinja2_inject": inject_result,
                                "pre_size": pre_size,
                                "post_size": post_size}))
        db.commit()
    except Exception:                                       # pragma: no cover
        db.rollback()
    return {
        "ok": result.get("transformed", False),
        "file": t.docx_filename,
        "pre_size": pre_size,
        "post_size": post_size,
        **result,
    }


@router.post("/cleanup-orphaned-docx")
def cleanup_orphaned_docx(
    dry_run: bool = True,
    user: User = Depends(require_roles(Role.admin)),
    db: Session = Depends(get_db),
):
    """Admin-only — delete .docx files in TEMPLATE_DIR that are not currently
    referenced by any ReportTemplate row.

    Canonical ``*_template.docx`` files (auto-generated at boot) and
    ``*_template.pre-*.docx`` backup files are also removed.

    ``dry_run=true`` (default) lists what *would* be deleted without touching
    anything. Set ``dry_run=false`` to perform the actual deletion.

    Returns ``{deleted: [...], kept: [...], errors: {...}}``.
    """
    import re as _re
    tpl_dir = Path(settings.TEMPLATE_DIR)

    # Collect every docx_filename currently referenced in the DB.
    active_files: set[str] = set()
    for row in db.query(ReportTemplate).all():
        if row.docx_filename:
            active_files.add(row.docx_filename)

    deleted: list[str] = []
    kept: list[str] = []
    errors: dict[str, str] = {}

    for path in sorted(tpl_dir.iterdir()):
        if not path.is_file() or path.suffix.lower() != ".docx":
            continue
        fname = path.name

        # Keep files actively referenced by any template row.
        if fname in active_files:
            kept.append(fname)
            continue

        # Keep canonical auto-generated master files (*_template.docx).
        # These are rebuilt at boot — deleting them is harmless but
        # confusing, so we leave them alone.
        if fname.endswith("_template.docx"):
            kept.append(fname)
            continue

        # Everything else is an orphaned admin upload or a backup —
        # eligible for deletion.
        if dry_run:
            deleted.append(fname)
        else:
            try:
                path.unlink()
                deleted.append(fname)
            except OSError as e:
                errors[fname] = str(e)

    import logging
    logging.getLogger(__name__).info(
        "cleanup-orphaned-docx dry_run=%s: %d to delete, %d kept, %d errors",
        dry_run, len(deleted), len(kept), len(errors),
    )
    return {
        "dry_run": dry_run,
        "deleted": deleted,
        "kept": kept,
        "errors": errors,
        "total_deleted": len(deleted),
        "total_kept": len(kept),
    }
