"""
Reports router.

Endpoints:
  POST   /api/reports                        create a new report (creates v0.1)
  GET    /api/reports/by-project/{pid}       list reports under a project
  GET    /api/reports/{rid}                  report details + all versions
  POST   /api/reports/{rid}/versions         create a new version (auto-increments)
  GET    /api/reports/versions/{vid}         version details (includes findings)
  GET    /api/reports/versions/{vid}/findings list findings in this version
  POST   /api/reports/versions/{vid}/findings/from-library/{lib_id}
                                             insert a library finding into this version
  POST   /api/reports/versions/{vid}/findings/manual
                                             insert a manual finding
  PUT    /api/reports/findings/{fid}         edit a project finding
  POST   /api/reports/findings/{fid}/screenshots
                                             upload screenshots for a finding
  POST   /api/reports/findings/{fid}/retest  update retest section (status, notes,
                                             client statement, optionally screenshots)
  POST   /api/reports/findings/{fid}/retest/screenshots
                                             upload retest evidence
  DELETE /api/reports/findings/{fid}         remove a finding
  POST   /api/reports/versions/{vid}/generate generate .docx (and optionally .pdf)
  GET    /api/reports/versions/{vid}/download?fmt=docx|pdf
                                             download the generated file
"""
from pathlib import Path
from datetime import datetime
from typing import Optional
import html as _html
import re
import shutil
import uuid

from fastapi import (
    APIRouter, Depends, HTTPException, UploadFile, File, Form, Query
)
from fastapi.responses import FileResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session, selectinload

from ..database import get_db
from ..models import (
    Report, ReportVersion, ReportFinding, FindingLibrary,
    Project, ReportTemplate, User, Role, AccessLevel,
    FindingStatus, Severity, AuditLog, ReportReviewStatus,
)
from ..schemas import (
    ReportCreate, ReportOut, ReportFindingCreate, ReportFindingOut,
    RetestUpdate, GenerateRequest,
)
from ..auth import get_current_user
from ..config import settings
from ..services.docx_generator import render_report, convert_to_pdf, next_version
from ..services.cvss_v4 import parse_vector, severity_for_score
from .permissions import require_access, effective_access
from ..services.html_sanitize import sanitize as _sanitize_html
from ..services import report_encryption as _enc
from ..services import placeholder_check as _ph_check
from ..services.upload_utils import stream_save as _stream_save
from sqlalchemy.orm.attributes import flag_modified
import logging as _log_r

_logger = _log_r.getLogger(__name__)

# Finding fields that accept Quill rich-text HTML. Sanitised on every write
# (bleach allow-list). Plain-text data continues to work because the
# sanitiser is a no-op on input with no markup.
_RICH_TEXT_FIELDS = (
    "description", "impact", "remediation", "references",
    "poc_steps", "retest_notes", "client_statement",
)


def _sanitise_finding_fields(obj) -> None:
    """Mutate `obj` so its rich-text attributes are sanitised HTML.
    Accepts either a Pydantic model (ReportFindingCreate / RetestUpdate)
    or a plain dict. Silent no-op for None values."""
    for key in _RICH_TEXT_FIELDS:
        if isinstance(obj, dict):
            if obj.get(key) is not None:
                obj[key] = _sanitize_html(obj[key])
        else:
            val = getattr(obj, key, None)
            if val is not None:
                setattr(obj, key, _sanitize_html(val))

router = APIRouter(prefix="/api/reports", tags=["reports"])


# ===== Helpers =====

def _audit(db: Session, user: User, action: str, obj_type: str, obj_id: int, detail: dict = None):
    db.add(AuditLog(actor_id=user.id, action=action, object_type=obj_type,
                    object_id=obj_id, detail=detail or {}))


_MAX_SCREENSHOT_BYTES = 10 * 1024 * 1024   # 10 MB per image
_MAX_FREEDIT_DOCX_BYTES = 50 * 1024 * 1024  # 50 MB — hand-edited Word documents


def _save_screenshots(files: list[UploadFile], subdir: str) -> list[str]:
    target = Path(settings.UPLOAD_DIR) / subdir
    target.mkdir(parents=True, exist_ok=True)
    paths: list[str] = []
    for f in files:
        ext = Path(f.filename or "").suffix.lower() or ".png"
        if ext not in {".png", ".jpg", ".jpeg", ".gif", ".webp"}:
            raise HTTPException(400, f"Unsupported image type: {ext}")
        name = f"{uuid.uuid4().hex}{ext}"
        dest = target / name
        _stream_save(f.file, dest, max_bytes=_MAX_SCREENSHOT_BYTES)
        paths.append(str(dest))
    return paths


def _require_finding(db: Session, fid: int) -> ReportFinding:
    f = db.get(ReportFinding, fid)
    if not f:
        raise HTTPException(404, "Finding not found")
    return f


def _require_version(db: Session, vid: int) -> ReportVersion:
    v = db.get(ReportVersion, vid)
    if not v:
        raise HTTPException(404, "Report version not found")
    return v


def _sanitise_details(d: dict) -> dict:
    """Normalise report.details so every array field is always a list.

    hydrateDetails() in the browser calls .join() on tester_names and
    client_contacts. If either is stored as a plain string the call throws
    TypeError and kills ALL JavaScript on the page (save, calendar, findings).

    This function is idempotent — calling it on already-correct data is a no-op.
    """
    if not isinstance(d, dict):
        return d
    # Fields that must be lists of strings
    _str_list_fields = {
        "tester_names": ",",
        "client_contacts": "\n",
        "user_roles_tested": ",",
        "aws_account_ids": "\n",
    }
    for key, sep in _str_list_fields.items():
        val = d.get(key)
        if val is None:
            continue
        if isinstance(val, str):
            d[key] = [s.strip() for s in val.split(sep) if s.strip()]
        elif not isinstance(val, list):
            d[key] = [str(val)]
    # login_credentials must be a list of dicts
    creds = d.get("login_credentials")
    if creds is not None and not isinstance(creds, list):
        d["login_credentials"] = []
    # scanning_tools must be a list of dicts
    tools = d.get("scanning_tools")
    if tools is not None and not isinstance(tools, list):
        d["scanning_tools"] = []
    return d


def _report_of_version(db: Session, v: ReportVersion) -> Report:
    r = db.get(Report, v.report_id)
    if not r:
        raise HTTPException(404, "Parent report not found")
    return r


def _report_of_finding(db: Session, f: ReportFinding) -> Report:
    rv = db.get(ReportVersion, f.report_version_id)
    if not rv:
        raise HTTPException(404, "Parent version not found")
    return _report_of_version(db, rv)


def _require_version_with_access(db: Session, vid: int, user: User,
                                  need: AccessLevel = AccessLevel.view) -> ReportVersion:
    """Resolve a version and enforce that the caller has report-level access."""
    v = _require_version(db, vid)
    require_access(db, user, _report_of_version(db, v), need=need)
    return v


def _require_finding_with_access(db: Session, fid: int, user: User,
                                  need: AccessLevel = AccessLevel.edit) -> ReportFinding:
    """Resolve a finding and enforce that the caller has report-level access."""
    f = _require_finding(db, fid)
    require_access(db, user, _report_of_finding(db, f), need=need)
    return f


# ===== Report-level scope import (Nessus CSV / Excel tracker) =====
# Moved here from the project router because a single project can host
# many different report types (Web VAPT, Thick Client, Infra VAPT, IoT, …)
# and the consultant only wants the Nessus / tracker importer on
# infrastructure-flavoured reports. The gate is the existing
# `ReportTemplate.supports_nessus_import` flag, which the seed marks
# True on infra_va / infra_vapt; admins can flip it on iot templates
# from the templates admin page.
#
# Data destination: the parsed targets land on the parent project's
# `scope_targets` JSON list — that's where the DOCX generator already
# reads scope from, so the existing render path keeps working.


def _require_scope_import_supported(report: Report, db: Session) -> ReportTemplate:
    """Block the scope-import endpoints on report types that don't make
    sense for them (Web/API/Mobile/Thick Client). Returns the template
    object for the caller's convenience.
    """
    tpl = db.get(ReportTemplate, report.template_id)
    if not tpl:
        raise HTTPException(404, "Report template missing")
    if not getattr(tpl, "supports_nessus_import", False):
        raise HTTPException(
            400,
            f"Scope import isn't available for this report type ({tpl.code}). "
            "It's enabled on Infra VA / Infra VAPT / IoT report templates "
            "(any template flagged supports_nessus_import).",
        )
    return tpl


@router.post("/{rid}/scope/parse")
def parse_report_scope_file(
    rid: int,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Dry-run parse of a Nessus CSV / Excel tracker uploaded for this
    report. Returns the targets we'd add to the parent project; caller
    previews + confirms via /scope/apply.
    """
    from ..services import scope_import as _scope_import

    report = db.get(Report, rid)
    if not report:
        raise HTTPException(404, "Report not found")
    require_access(db, user, report, need=AccessLevel.edit)
    _require_scope_import_supported(report, db)

    suffix = Path(file.filename or "").suffix.lower()
    if suffix not in (".csv", ".xlsx", ".xls", ".xlsm"):
        raise HTTPException(400, f"Unsupported file type: {suffix or '(none)'}. "
                                  "Use a Nessus CSV or an Excel tracker.")

    import tempfile, os as _os
    tmp_fd, tmp_path_str = tempfile.mkstemp(suffix=suffix)
    _os.close(tmp_fd)
    tmp_path = Path(tmp_path_str)
    try:
        _stream_save(file.file, tmp_path, max_bytes=10 * 1024 * 1024)
        try:
            result = _scope_import.parse_any(tmp_path)
        except HTTPException:
            raise
        except Exception as e:
            _logger.warning("Scope file parse failed for report %s: %s", report.id, e)
            raise HTTPException(400, "Could not parse the uploaded scope file. Please check the format and try again.")
    finally:
        try: tmp_path.unlink(missing_ok=True)
        except Exception: pass

    project = db.get(Project, report.project_id)
    existing = list((project.scope_targets if project else None) or [])
    new_targets = [t for t in result["targets"] if t not in existing]
    return {
        "report_id": rid,
        "project_id": report.project_id,
        "source": result["source"],
        "host_count": result["host_count"],
        "warnings": result["warnings"],
        "existing_targets": existing,
        "new_targets": new_targets,
        "all_targets": existing + new_targets,
    }


class _ApplyScopePayload(BaseModel):
    targets: list[str]
    mode: str = "merge"  # "merge" | "replace"


@router.post("/{rid}/scope/apply")
def apply_report_scope(
    rid: int,
    payload: _ApplyScopePayload,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Persist the user-confirmed scope onto the report's parent project.

    `mode=merge` (default) appends new targets to the project's existing
    scope; `mode=replace` overwrites it. Either way duplicates are
    dropped and ordering preserved. Edit-level access on the report is
    sufficient — we don't require the caller to be the project lead
    because they already had to be granted edit on the report itself.
    """
    report = db.get(Report, rid)
    if not report:
        raise HTTPException(404, "Report not found")
    require_access(db, user, report, need=AccessLevel.edit)
    # Deliberately NOT gated by supports_nessus_import: the parser is
    # infra-only (parse_report_scope_file enforces that), but a manual
    # scope tweak from the report edit page should work on any report —
    # consultants need to be able to correct a wrong URL on a Web VAPT
    # report without uploading a Nessus file.

    project = db.get(Project, report.project_id)
    if not project:
        raise HTTPException(404, "Parent project missing")

    if payload.mode not in ("merge", "replace"):
        raise HTTPException(400, "mode must be 'merge' or 'replace'")

    base = list(project.scope_targets or []) if payload.mode == "merge" else []
    seen = set(base)
    out = list(base)
    for t in payload.targets or []:
        t = (t or "").strip()
        if t and t not in seen:
            seen.add(t); out.append(t)
    project.scope_targets = out
    flag_modified(project, "scope_targets")

    _audit(db, user, "report.scope.import", "report", rid,
           {"project_id": project.id, "applied_count": len(out),
            "mode": payload.mode})
    db.commit()
    return {"ok": True, "scope_targets": out, "count": len(out),
            "project_id": project.id, "report_id": rid}


# ===== Reports =====

@router.post("", response_model=ReportOut)
def create_report(payload: ReportCreate, db: Session = Depends(get_db),
                  user: User = Depends(get_current_user)):
    """Create a brand-new report. The current user becomes the owner (created_by_id)
    and gets implicit admin access. They can immediately start adding findings via
    POST /versions/{vid}/findings/manual -- no Excel tracker required.
    """
    if not db.get(Project, payload.project_id):
        raise HTTPException(404, "Project not found")
    if not db.get(ReportTemplate, payload.template_id):
        raise HTTPException(404, "Template not found")

    # Validate `report_kind` against the canonical kind set used by the
    # versions table. Falling back to a default would silently let
    # bogus values through, producing "Uncategorised" rows downstream;
    # better to refuse the create with a clear 400.
    kind_norm = (payload.report_kind or "").strip().lower()
    if kind_norm not in _REPORT_KINDS:
        raise HTTPException(
            400,
            f"report_kind must be one of {sorted(_REPORT_KINDS)} — got "
            f"{payload.report_kind!r}.",
        )

    # Auto-stamp `report_date` to today on creation. The renderer
    # exposes it as `{{ details.report_date }}` in the Word template
    # and the tracker exporter stamps it into the "Date Raised"
    # column of every Risk Register row. Consultants used to have to
    # set it manually on the report-details form, which most forgot
    # and shipped reports with an empty date column. Auto-filled at
    # creation here; re-stamped on every Generate (see the generate
    # endpoint) so the date always reflects when the deliverable was
    # actually produced rather than the original create timestamp.
    initial_details = dict(payload.details or {})
    if not initial_details.get("report_date"):
        initial_details["report_date"] = datetime.utcnow().strftime("%Y-%m-%d")
    # Auto-populate tester_names from the creating user if not supplied.
    # Store as a list — the JS hydrateDetails() calls .join() on this value
    # and will throw a TypeError if it receives a plain string.
    if not initial_details.get("tester_names"):
        initial_details["tester_names"] = [user.full_name or user.username]

    # Carry-over engagement-static fields from the most recent sibling
    # report in the SAME project. Use case from the team: an Infra-VA
    # *rescan* is a brand-new Report (not just a new version) inside an
    # existing engagement — the consultant shouldn't have to re-type
    # the client owner / user roles / client contacts that were already
    # captured on the previous quarter's report. Scope IPs are already
    # shared because they live on `project.scope_targets`; these three
    # live on `report.details` (per-report) so they DON'T auto-share
    # across separate reports and must be explicitly copied. Only fill
    # keys the caller didn't already provide, so an explicit override
    # in the create payload always wins. `report_date` is deliberately
    # NOT carried — each report dates itself.
    _CARRY_KEYS = (
        "client_owner", "user_roles_tested", "client_contacts",
        "client_contact", "user_roles", "scope_targets_snapshot",
        "login_credentials", "source_ip",
    )
    prev_sibling = (
        db.query(Report)
          .filter(Report.project_id == payload.project_id)
          .order_by(Report.created_at.desc(), Report.id.desc())
          .first()
    )
    if prev_sibling and prev_sibling.details:
        carried = []
        for k in _CARRY_KEYS:
            if k not in initial_details and prev_sibling.details.get(k) not in (None, "", [], {}):
                initial_details[k] = prev_sibling.details[k]
                carried.append(k)
        if carried:
            initial_details["_carried_from_report_id"] = prev_sibling.id

    # Normalise all array-typed fields before storing — prevents type mismatches
    # (e.g. tester_names stored as string) from breaking hydrateDetails() JS.
    _sanitise_details(initial_details)

    r = Report(
        project_id=payload.project_id,
        template_id=payload.template_id,
        name=payload.name,
        current_version=payload.initial_version or "0.1",
        details=initial_details,
        created_by_id=user.id,
    )
    db.add(r); db.flush()
    # Create the initial empty version. The notes string mirrors the
    # convention `create_new_version` uses for subsequent versions: a
    # `[kind]` prefix that the versions-list template strips to render
    # the Report-type badge. Without this prefix the initial version
    # would render as "Uncategorised".
    v = ReportVersion(
        report_id=r.id, version=r.current_version,
        generated_by_id=user.id,
        notes=f"[{kind_norm}] Initial draft",
    )
    db.add(v)
    _audit(db, user, "report.create", "report", r.id, {"name": r.name})
    db.commit(); db.refresh(r)
    return r


@router.get("/by-project/{project_id}", response_model=list[ReportOut])
def list_for_project(project_id: int, db: Session = Depends(get_db),
                     user: User = Depends(get_current_user)):
    """Lists reports in a project that the current user can see. Admins/leads see all;
    others see only reports they own or have been granted access to.
    """
    from .permissions import effective_access
    rows = (db.query(Report)
              .filter(Report.project_id == project_id)
              .order_by(Report.created_at.desc()).all())
    return [r for r in rows if effective_access(db, user, r) is not None]


@router.get("/{report_id}")
def get_report(report_id: int, db: Session = Depends(get_db),
               user: User = Depends(get_current_user)):
    from .permissions import require_access
    r = db.get(Report, report_id)
    if not r:
        raise HTTPException(404, "Report not found")
    my_access = require_access(db, user, r)  # view+ required
    return {
        "report": ReportOut.model_validate(r).model_dump(),
        "my_access": my_access.value,
        "is_owner": (r.created_by_id == user.id),
        "versions": [
            {
                "id": v.id,
                "version": v.version,
                "is_draft": v.is_draft,
                "notes": v.notes,
                "created_at": v.created_at,
                "generated_by_id": v.generated_by_id,
                "has_docx": bool(v.generated_docx_path),
                "has_pdf": bool(v.generated_pdf_path),
            }
            for v in r.versions
        ],
    }


class _ChangeTemplatePayload(BaseModel):
    """Body for POST /api/reports/{rid}/template.

    Either `template_id` (a master ReportTemplate id) or
    `custom_template_id` (an approved CustomTemplate id) — or BOTH:
    `template_id` picks the master, `custom_template_id` overrides the
    .docx layout for this report only.

    `custom_template_id=null` clears any previously-set custom layout
    while leaving the master template unchanged.
    """
    template_id: Optional[int] = None
    custom_template_id: Optional[int] = None
    # Sentinel: when true and custom_template_id is None, the existing
    # custom override is removed. Lets the UI explicitly say "go back to
    # the master template" without rebuilding the whole payload.
    clear_custom: bool = False


@router.post("/{report_id}/template")
def change_report_template(
    report_id: int,
    payload: _ChangeTemplatePayload,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Re-bind this report to a different master template and/or a
    different approved custom template. Requires edit access.

    The endpoint exists separately from PUT /{report_id} so the
    consultant can change layout without sending the whole report
    body, and so the audit trail records template changes distinctly.
    """
    from .permissions import require_access, AccessLevel
    from ..models import CustomTemplate, TemplateStatus

    r = db.get(Report, report_id)
    if not r:
        raise HTTPException(404, "Report not found")
    require_access(db, user, r, need=AccessLevel.edit)

    changed: dict = {}

    # ---- Master template swap ----
    if payload.template_id is not None and payload.template_id != r.template_id:
        new_master = db.get(ReportTemplate, payload.template_id)
        if not new_master:
            raise HTTPException(404, "Master template not found")
        if not getattr(new_master, "is_active", True):
            raise HTTPException(400, "That master template is inactive")
        changed["template_id"] = {"from": r.template_id, "to": new_master.id,
                                   "code": new_master.code, "name": new_master.name}
        r.template_id = new_master.id

    # ---- Custom-layout override ----
    details = dict(r.details or {})
    if payload.custom_template_id is not None:
        ct = db.get(CustomTemplate, payload.custom_template_id)
        if not ct:
            raise HTTPException(404, "Custom template not found")
        # Only approved customs are picky-able — drafts / pending / rejected
        # stay private to their uploader.
        if ct.status != TemplateStatus.approved:
            # ...unless the caller IS the uploader (lets the owner test
            # their own draft before submitting for review).
            if ct.uploaded_by_id != user.id and user.role.value != "admin":
                raise HTTPException(
                    400, "Custom template isn't approved yet — only its "
                         "uploader or an admin can use it.")
        # Resolve the on-disk path the same way the generator does.
        from .custom_template_editor import _resolve_docx_path
        cpath = _resolve_docx_path(ct)
        if not cpath or not cpath.exists():
            raise HTTPException(
                410, "Custom template's .docx is missing on disk. "
                     "Have the uploader re-upload it.")
        prev = details.get("custom_template_path")
        details["custom_template_path"] = str(cpath)
        details["custom_template_id"] = ct.id
        changed["custom_template"] = {
            "from_path": prev, "to_path": str(cpath),
            "id": ct.id, "name": ct.name,
        }
    elif payload.clear_custom:
        if "custom_template_path" in details or "custom_template_id" in details:
            changed["custom_template"] = {
                "cleared": True,
                "was_path": details.get("custom_template_path"),
                "was_id":   details.get("custom_template_id"),
            }
        details.pop("custom_template_path", None)
        details.pop("custom_template_id", None)

    if changed:
        r.details = details
        flag_modified(r, "details")
        _audit(db, user, "report.template.change", "report", r.id, changed)
        db.commit()
        db.refresh(r)

    # Return the resolved layout the next render would use, so the UI
    # can show "now using: X" without an extra fetch.
    return {
        "ok": True,
        "report_id": r.id,
        "template_id": r.template_id,
        "template_code": r.template.code if r.template else None,
        "template_name": r.template.name if r.template else None,
        "custom_template_id": (r.details or {}).get("custom_template_id"),
        "custom_template_path": (r.details or {}).get("custom_template_path"),
        "changed": list(changed.keys()),
    }


@router.put("/{report_id}", response_model=ReportOut)
def update_report(report_id: int, payload: dict,
                  db: Session = Depends(get_db),
                  user: User = Depends(get_current_user)):
    """Patch a report's name and/or details. Accepts a partial dict.
    Requires edit access.
    """
    from .permissions import require_access, AccessLevel
    r = db.get(Report, report_id)
    if not r:
        raise HTTPException(404, "Report not found")
    require_access(db, user, r, need=AccessLevel.edit)
    if "name" in payload and payload["name"]:
        r.name = payload["name"]
    if "details" in payload and isinstance(payload["details"], dict):
        merged = dict(r.details or {})
        merged.update(payload["details"])
        _sanitise_details(merged)
        r.details = merged
        flag_modified(r, "details")
    if "report_sections" in payload and isinstance(payload["report_sections"], list):
        # Validate and normalise each section entry.
        clean_sections = []
        for s in payload["report_sections"]:
            if not isinstance(s, dict):
                continue
            label = str(s.get("label") or "").strip()
            if not label:
                continue
            clean_sections.append({
                "idx": int(s.get("idx", len(clean_sections))),
                "label": label,
                "scope_name": str(s.get("scope_name") or "").strip(),
                "scope_urls": [str(u).strip() for u in (s.get("scope_urls") or []) if str(u).strip()],
            })
        r.report_sections = clean_sections
        flag_modified(r, "report_sections")
    _audit(db, user, "report.update", "report", r.id, {"keys": list(payload.keys())})
    db.commit(); db.refresh(r)
    return r


_REPORT_KINDS = ("initial", "retest", "final", "update")
_VERSION_RE = re.compile(r"^\d+\.\d+$")
# Used by `set_version_report_kind` and the create-new-version paths
# to find / strip the `[kind]` prefix that the versions-list template
# parses to render the Report-type badge.
_KIND_PREFIX_RE = re.compile(
    r"^\s*\[(initial|retest|final|update)\]\s*",
    re.IGNORECASE,
)


@router.patch("/versions/{version_id}/report-kind")
def set_version_report_kind(
    version_id: int,
    kind: str = Query(
        ...,
        pattern="^(initial|retest|final|update)$",
        description="Required. One of initial / retest / final / update.",
    ),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Backfill or re-tag the report-type marker on an existing version.

    Used by the versions list's inline edit-type control so a consultant
    can fix a version that was created before report-type was mandatory
    (legacy versions read as "Uncategorised" in the table) or correct a
    mis-classification without bumping a new version.

    Mechanically: we rewrite the version's `notes` field to carry a
    `[kind] …` prefix. The free-text portion is preserved — only the
    prefix is replaced. Requires edit access on the parent report.
    """
    from .permissions import require_access, AccessLevel
    rv = db.get(ReportVersion, version_id)
    if not rv:
        raise HTTPException(404, "Version not found")
    require_access(db, user, rv.report, need=AccessLevel.edit)

    kind_norm = kind.strip().lower()
    if kind_norm not in _REPORT_KINDS:
        raise HTTPException(
            400,
            f"kind must be one of {sorted(_REPORT_KINDS)} — got {kind!r}.",
        )

    # Strip any existing `[kind]` prefix on the notes so a second
    # re-tag doesn't accumulate them as `[final] [retest] …`.
    raw = (rv.notes or "").strip()
    stripped = _KIND_PREFIX_RE.sub("", raw, count=1).strip()
    if not stripped:
        stripped = "Initial draft" if kind_norm == "initial" else ""
    rv.notes = f"[{kind_norm}] " + stripped if stripped else f"[{kind_norm}]"

    _audit(db, user, "report.version.report_kind.set",
           "report_version", rv.id,
           {"version": rv.version, "kind": kind_norm})
    db.commit()
    return {
        "ok":         True,
        "version_id": rv.id,
        "report_kind": kind_norm,
        "notes":      rv.notes,
    }


@router.post("/{report_id}/versions")
def create_new_version(
    report_id: int,
    kind: str = Query("minor", pattern="^(minor|major)$",
                      description="Used when no explicit `version` override is supplied."),
    version: Optional[str] = Query(
        None,
        description="Optional explicit version like '0.3', '1.4', '2.0'. "
                    "If set, `kind` is ignored and this exact value is used.",
    ),
    report_kind: Optional[str] = Query(
        None,
        description="Initial / Retest / Final / Update — stored on the new "
                    "version so the deliverable can be picked apart later.",
    ),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Bump version. Copies all findings from latest into the new one. Requires edit access.

    Two ways to pick the new version number:
      • Default ("minor"): increment the existing minor digit (0.1 → 0.2).
      • Major: bump the major digit and reset minor to zero (0.7 → 1.0).
      • Explicit `version=X.Y`: use the provided string verbatim. Must be
        unique within the report (collision returns 409) and strictly
        ahead of the current latest (going backwards is rejected so a
        consultant can't accidentally overwrite-by-name).
    """
    from .permissions import require_access, AccessLevel
    r = db.get(Report, report_id)
    if not r:
        raise HTTPException(404, "Report not found")
    require_access(db, user, r, need=AccessLevel.edit)

    latest = r.versions[-1] if r.versions else None
    if version:
        # Manual override path.
        v = version.strip()
        if not _VERSION_RE.match(v):
            raise HTTPException(400, "Version must look like X.Y (digits only) — e.g. 0.3, 1.4, 2.0.")
        existing = {rv.version for rv in r.versions}
        if v in existing:
            raise HTTPException(409, f"Version {v} already exists on this report.")
        # Refuse moving backwards: parse both as (major, minor) tuples.
        if latest:
            try:
                cur_major, cur_minor = (int(x) for x in latest.version.split("."))
                new_major, new_minor = (int(x) for x in v.split("."))
                if (new_major, new_minor) <= (cur_major, cur_minor):
                    raise HTTPException(
                        400,
                        f"Version {v} is not strictly ahead of the current latest "
                        f"({latest.version}). Pick a higher number.",
                    )
            except ValueError:
                pass  # Unexpected, but don't 500 — fall through.
        new_ver = v
    else:
        new_ver = next_version(latest.version if latest else "0.0", kind)

    # Report kind: stored on the version's notes prefix because we don't
    # want to grow another ENUM column for a per-version classifier. The
    # detail.html version row can read the prefix to render a badge.
    report_kind_norm = (report_kind or "").strip().lower() or None
    if report_kind_norm and report_kind_norm not in _REPORT_KINDS:
        raise HTTPException(
            400,
            f"report_kind must be one of {', '.join(_REPORT_KINDS)} — got {report_kind!r}."
        )
    base_note = f"Created from {latest.version if latest else 'scratch'}"
    notes = (f"[{report_kind_norm}] " + base_note) if report_kind_norm else base_note

    nv = ReportVersion(report_id=r.id, version=new_ver,
                       generated_by_id=user.id,
                       notes=notes)
    db.add(nv); db.flush()

    if latest:
        for f in latest.findings:
            db.add(ReportFinding(
                report_version_id=nv.id,
                library_id=f.library_id,
                title=f.title, description=f.description, impact=f.impact,
                remediation=f.remediation, references=f.references,
                affected_asset=f.affected_asset, poc_steps=f.poc_steps,
                severity=f.severity, cvss_vector=f.cvss_vector,
                cvss_score=f.cvss_score, status=f.status,
                # Carry CWE forward into the new version so any per-report
                # override the consultant set on v0.1 doesn't get reset when
                # they bump to v0.2.
                cwe=f.cwe,
                retest_notes=f.retest_notes, retest_evidence=f.retest_evidence or [],
                client_statement=f.client_statement,
                added_by_id=f.added_by_id, added_at=f.added_at,
                source=f.source, source_ref=f.source_ref,
                screenshots=f.screenshots or [],
                # Carry per-finding xlsx attachments forward too —
                # the 3 grouped Infra-pipeline findings each carry
                # an Excel workbook reference; without this the new
                # version would render without the icons + the
                # tracker "Refer to the attached file" suffix
                # would point at nothing.
                attachments=(list(f.attachments) if f.attachments else []),
            ))
    r.current_version = new_ver

    # Update the report's tester_names to the version creator and mark
    # them as the owner so the new version's Report Details always reflect
    # who is doing this round of testing.
    _KIND_TO_REPORT_TYPE = {
        "retest":  "Retest Report",
        "final":   "Final Report",
        "update":  "Report Update",
        "initial": "Initial Report",
    }
    new_details = dict(r.details or {})
    new_details["tester_names"] = user.full_name or user.username
    if report_kind_norm and report_kind_norm in _KIND_TO_REPORT_TYPE:
        new_details["report_type"] = _KIND_TO_REPORT_TYPE[report_kind_norm]
    r.details = new_details
    flag_modified(r, "details")
    # Also transfer report ownership to the person creating this version
    # so they become the primary point of contact for the new round.
    r.created_by_id = user.id

    _audit(db, user, "report.version.create", "report_version", nv.id,
           {"report_id": r.id, "version": new_ver})
    db.commit(); db.refresh(nv)
    return {"version_id": nv.id, "version": new_ver}


# ===== Findings inside a version =====

@router.get("/versions/{vid}/findings", response_model=list[ReportFindingOut])
def list_version_findings(vid: int, db: Session = Depends(get_db),
                          user: User = Depends(get_current_user)):
    _require_version_with_access(db, vid, user, need=AccessLevel.view)
    findings = (
        db.query(ReportFinding)
        .filter(ReportFinding.report_version_id == vid)
        .order_by(ReportFinding.added_at)
        .all()
    )
    return findings


@router.post("/versions/{vid}/rerate-cvss31")
def rerate_cvss31(vid: int, db: Session = Depends(get_db),
                  user: User = Depends(get_current_user)):
    """Re-rate every CVSS:4.0-scored finding in this version to CVSS:3.1.

    For each finding whose vector is a v4.0 vector, derive the equivalent
    v3.1 base vector, recompute the v3.1 base score (via the `cvss` lib),
    and update the finding's severity accordingly. Findings already on v3.1
    (or with no/invalid vector) are left untouched. The report's
    most-severe-first ordering and severity colours are applied at the next
    render/preview, so no re-sort is needed here.
    """
    v = _require_version_with_access(db, vid, user, need=AccessLevel.edit)
    from ..services.cvss_convert import is_cvss4, cvss4_to_cvss31
    findings = (
        db.query(ReportFinding)
        .filter(ReportFinding.report_version_id == vid)
        .all()
    )
    converted = 0
    skipped = 0
    errors: list[str] = []
    for f in findings:
        if not is_cvss4(f.cvss_vector):
            skipped += 1
            continue
        try:
            v31, score, sev = cvss4_to_cvss31(f.cvss_vector)
        except Exception as e:
            errors.append(f"{f.title}: {e}")
            skipped += 1
            continue
        f.cvss_vector = v31
        f.cvss_score = score
        try:
            f.severity = Severity(sev)
        except ValueError:
            pass
        converted += 1
    if converted:
        _audit(db, user, "finding.rerate.cvss31", "report_version", v.id,
               {"converted": converted, "skipped": skipped})
        db.commit()
    return {
        "converted": converted,
        "skipped": skipped,
        "total": len(findings),
        "errors": errors[:20],
    }


@router.post("/versions/{vid}/rerate-cvss40")
def rerate_cvss40(vid: int, db: Session = Depends(get_db),
                  user: User = Depends(get_current_user)):
    """Re-rate every CVSS:3.x-scored finding in this version BACK to CVSS:4.0.

    The reverse of rerate-cvss31. IMPORTANT: CVSS 4.0 has subsequent-system
    impact metrics (SC/SI/SA) that don't exist in 3.1 — they are emitted as N
    and the consultant must review them per finding. The UI shows this caveat.
    """
    v = _require_version_with_access(db, vid, user, need=AccessLevel.edit)
    from ..services.cvss_convert import is_cvss31, cvss31_to_cvss4
    findings = (
        db.query(ReportFinding)
        .filter(ReportFinding.report_version_id == vid)
        .all()
    )
    converted = 0
    skipped = 0
    errors: list[str] = []
    for f in findings:
        if not is_cvss31(f.cvss_vector):
            skipped += 1
            continue
        try:
            v40, score, sev = cvss31_to_cvss4(f.cvss_vector)
        except Exception as e:
            errors.append(f"{f.title}: {e}")
            skipped += 1
            continue
        f.cvss_vector = v40
        f.cvss_score = score
        try:
            f.severity = Severity(sev)
        except ValueError:
            pass
        converted += 1
    if converted:
        _audit(db, user, "finding.rerate.cvss40", "report_version", v.id,
               {"converted": converted, "skipped": skipped})
        db.commit()
    return {
        "converted": converted,
        "skipped": skipped,
        "total": len(findings),
        "errors": errors[:20],
        "disclaimer": ("CVSS 4.0 subsequent-system metrics SC/SI/SA were set to "
                       "None — review and set them per finding where applicable."),
    }


@router.post("/versions/{vid}/upload-edited")
def upload_edited_report(vid: int, file: UploadFile = File(...),
                         db: Session = Depends(get_db),
                         user: User = Depends(get_current_user)):
    """Accept a consultant-edited .docx for this version.

    Two effects:
      1. The uploaded file becomes the version's served DOCX (so a later
         DOCX download / PDF export uses the consultant's edited copy).
      2. Each finding's Status is read out of the document and synced back
         onto the VibeDocs ReportFinding records — so marking a finding "Closed"
         or "False Positive" in Word is reflected in VibeDocs automatically.
         Severity / score are NOT touched (a False Positive keeps its
         original severity).
    """
    v = _require_version_with_access(db, vid, user, need=AccessLevel.edit)
    if not (file.filename or "").lower().endswith(".docx"):
        raise HTTPException(400, "Upload a Word .docx file.")

    out_dir = Path(settings.REPORT_DIR) / str(v.report_id)
    out_dir.mkdir(parents=True, exist_ok=True)
    stem = f"{v.report.name.replace(' ', '_')}_v{v.version}"
    dest = out_dir / f"{stem}_edited.docx"
    try:
        _stream_save(file.file, dest, max_bytes=100 * 1024 * 1024)
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(400, "Could not save the uploaded file.")

    # Validate it's a real docx before trusting it as the served copy.
    try:
        from docx import Document as _Docx
        _Docx(str(dest))
    except Exception:
        try: dest.unlink(missing_ok=True)
        except Exception: pass
        raise HTTPException(400, "That file isn't a readable Word document.")

    v.generated_docx_path = str(dest)
    # A consultant-edited upload supersedes any stale generated PDF — clear it
    # so the next PDF export is produced from the edited DOCX, not the old one.
    v.generated_pdf_path = None

    findings = (
        db.query(ReportFinding)
        .filter(ReportFinding.report_version_id == vid)
        .order_by(ReportFinding.added_at)
        .all()
    )
    from ..services.docx_status_import import (
        parse_finding_statuses, parse_finding_severities,
    )
    id_titles = [(f.id, f.title) for f in findings]
    parsed = parse_finding_statuses(dest, id_titles)
    parsed_sev = parse_finding_severities(dest, id_titles)

    fmap = {f.id: f for f in findings}
    status_changes: list[dict] = []
    severity_changes: list[dict] = []
    for fid, status_str in parsed.items():
        f = fmap.get(fid)
        if f is None:
            continue
        try:
            new_status = FindingStatus(status_str)
        except ValueError:
            continue
        if f.status != new_status:
            status_changes.append({
                "id": fid, "title": f.title,
                "old": f.status.value if f.status else None,
                "new": status_str,
            })
            f.status = new_status

    for fid, sev_str in parsed_sev.items():
        f = fmap.get(fid)
        if f is None:
            continue
        try:
            new_sev = Severity(sev_str)
        except ValueError:
            continue
        if f.severity != new_sev:
            severity_changes.append({
                "id": fid, "title": f.title,
                "old": f.severity.value if f.severity else None,
                "new": sev_str,
            })
            f.severity = new_sev

    _audit(db, user, "report.upload_edited", "report_version", v.id,
           {"findings_parsed": len(parsed),
            "status_changes": len(status_changes),
            "severity_changes": len(severity_changes)})
    db.commit()
    return {
        "saved": dest.name,
        "total_findings": len(findings),
        "findings_parsed": len(parsed),
        "status_changes": status_changes,
        "severity_changes": severity_changes,
    }


@router.post("/versions/{vid}/findings/from-library/{lib_id}",
             response_model=ReportFindingOut)
def add_from_library(vid: int, lib_id: int, db: Session = Depends(get_db),
                     user: User = Depends(get_current_user)):
    v = _require_version_with_access(db, vid, user, need=AccessLevel.edit)
    lib = db.get(FindingLibrary, lib_id)
    if not lib:
        raise HTTPException(404, "Library finding not found")
    f = ReportFinding(
        report_version_id=v.id,
        library_id=lib.id,
        title=lib.title, description=lib.description, impact=lib.impact,
        remediation=lib.remediation, references=lib.references,
        severity=lib.default_severity, cvss_vector=lib.default_cvss_vector,
        cvss_score=lib.default_cvss_score,
        # Inherit the library's CWE so the consultant doesn't have to
        # re-type it. They can still override it on the per-report
        # finding card after add.
        cwe=lib.cwe,
        added_by_id=user.id, source="library", source_ref=str(lib.id),
    )
    db.add(f); _audit(db, user, "finding.add.library", "report_finding", 0,
                      {"version_id": v.id, "library_id": lib.id})
    db.commit(); db.refresh(f)
    return f


@router.post("/versions/{vid}/findings/manual", response_model=ReportFindingOut)
def add_manual(vid: int, payload: ReportFindingCreate,
               db: Session = Depends(get_db),
               user: User = Depends(get_current_user)):
    v = _require_version_with_access(db, vid, user, need=AccessLevel.edit)
    _sanitise_finding_fields(payload)
    if payload.cvss_vector:
        try:
            parse_vector(payload.cvss_vector)
        except ValueError as e:
            raise HTTPException(400, f"Invalid CVSS vector: {e}")
    if payload.cvss_score is not None and not payload.severity:
        payload.severity = Severity(severity_for_score(payload.cvss_score))
    f = ReportFinding(
        report_version_id=v.id,
        library_id=payload.library_id,
        **{k: v for k, v in payload.model_dump().items() if k != "library_id"},
        added_by_id=user.id,
        source="manual" if payload.library_id is None else "library",
    )
    db.add(f); _audit(db, user, "finding.add.manual", "report_finding", 0,
                      {"version_id": v.id, "title": payload.title})
    db.commit(); db.refresh(f)
    return f


@router.get("/findings/{fid}/placeholders")
def check_finding_placeholders(fid: int, db: Session = Depends(get_db),
                                user: User = Depends(get_current_user)):
    """Scan a single project-finding for unresolved placeholder tokens
    (`[DESCRIBE ...]`, `[DELETE IF IRRELEVANT]`, empty Request/Response
    code blocks, TODO markers, etc). Used by the report-edit UI to warn
    the consultant before the finding ends up in a delivered DOCX."""
    f = _require_finding_with_access(db, fid, user, need=AccessLevel.view)
    return _ph_check.scan_finding(f)


# ============================================================
# Infra Scan Pipeline — first-scan / recurring / retest routes
# ============================================================
#
# Surfaces the existing VA-Recurring / VA-Retest toolkit pipelines
# directly on the report editor for Infra VA / Infra VAPT taskings.
# See `services.infra_pipeline` for the orchestrator + the rules
# that map pipeline categories to the 3 grouped library findings.

@router.post("/versions/{vid}/infra-pipeline/run")
async def run_infra_pipeline_endpoint(
    vid: int,
    pipeline: str = Form(...),
    current_csvs: Optional[list[UploadFile]] = File(None),
    risk_accept: Optional[list[UploadFile]] = File(None),
    prev_tracker: Optional[list[UploadFile]] = File(None),
    original_tracker: Optional[UploadFile] = File(None),
    new_ip_action: str = Form("include"),
    enable_version_check: bool = Form(True),
    # Optional custom comment column to add to every output row
    # (e.g. "VibeDocs Comments" + default value "Pending review").
    # When `custom_comment_col` is blank both fields are ignored.
    custom_comment_col: str = Form(""),
    custom_comment_default: str = Form(""),
    # Collapse same-(finding_name, port) rows in the by-category
    # workbooks into one row with comma-joined IPs. Lets the client
    # see one row per finding+port and the list of affected IPs at
    # a glance instead of one row per (finding, host, port) triple.
    group_ips_in_by_category: bool = Form(False),
    # When True, findings with blank / NaN / None / Informational risk
    # values in the Uncategorised workbook are auto-imported as
    # Informational severity findings. Default False (skip them).
    include_informational: bool = Form(False),
    # Comma-separated list of category keys to skip when creating
    # grouped finding rows. The pipeline still runs for those categories
    # (they appear in the result ZIP) but no ReportFinding is created.
    # Example: "Insecure Service Configurations,Information Disclosure"
    skip_categories: str = Form(""),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Run the Infra Scan Pipeline on the supplied CSVs and persist
    the results on this report version.

    pipeline:
        "first_scan" — equivalent to recurring with no risk-accept
                       / prev-tracker inputs (clean categorisation)
        "recurring"  — full VA-Recurring pipeline
        "retest"     — VA-Retest tracker-update pipeline; requires
                       `original_tracker` to be supplied

    Only Infra VA / Infra VAPT templates are eligible (other
    taskings have their own scan-import flows). The check is a soft
    guard — the actual pipeline runs against any CSV the caller
    uploads; the template code constraint is enforced to keep the
    UI in step.
    """
    rv = _require_version_with_access(db, vid, user, need=AccessLevel.edit)
    tpl_code = (rv.report.template.code if rv.report and rv.report.template
                 else "")
    if tpl_code not in ("infra_va", "infra_vapt", "ot_vapt"):
        raise HTTPException(
            400,
            "Infra Scan Pipeline is only available on Infra VA / Infra "
            "VAPT / OT VAPT reports — this report's template is "
            f"{tpl_code!r}.",
        )

    # Materialise UploadFile bytes into (filename, bytes) tuples up-
    # front so the orchestrator doesn't have to worry about async
    # context. Empty multi-file inputs come through as a list with
    # a single empty UploadFile in some browsers — filter those out.
    current_tuples: list[tuple[str, bytes]] = []
    for f in (current_csvs or []):
        if f and f.filename:
            current_tuples.append((f.filename, await f.read()))

    risk_tuples: list[tuple[str, bytes]] = []
    for f in (risk_accept or []):
        if f and f.filename:
            risk_tuples.append((f.filename, await f.read()))

    prev_tuples: list[tuple[str, bytes]] = []
    for f in (prev_tracker or []):
        if f and f.filename:
            prev_tuples.append((f.filename, await f.read()))

    original_tuple: Optional[tuple[str, bytes]] = None
    if original_tracker and original_tracker.filename:
        original_tuple = (original_tracker.filename,
                          await original_tracker.read())

    from ..services import infra_pipeline as _ip
    try:
        skip_cats = {s.strip() for s in skip_categories.split(",") if s.strip()}
        result = _ip.run_infra_pipeline(
            db, rv, user,
            pipeline=pipeline,
            current_csvs=current_tuples,
            risk_accept=risk_tuples or None,
            prev_tracker=prev_tuples or None,
            original_tracker=original_tuple,
            new_ip_action=new_ip_action,
            enable_version_check=enable_version_check,
            custom_comment_col=custom_comment_col,
            custom_comment_default=custom_comment_default,
            group_ips_in_by_category=group_ips_in_by_category,
            include_informational=include_informational,
            skip_categories=skip_cats or None,
        )
    except ValueError as e:
        raise HTTPException(400, str(e))
    except Exception as e:                                  # pragma: no cover
        _logger.exception("infra pipeline run failed for version %s", rv.id)
        raise HTTPException(500, "Pipeline failed. Please try again or contact an administrator.")

    _audit(db, user, "report.infra_pipeline.run", "report_version", rv.id,
           {"pipeline": pipeline,
            "csvs": [n for n, _ in current_tuples],
            "groups_attached": [g["library_title"] for g in result["groups_attached"]],
            "summary": {k: v for k, v in (result.get("summary") or {}).items()
                         if not isinstance(v, (list, dict))}})
    db.commit()
    return result


@router.get("/versions/{vid}/infra-pipeline/download")
def download_infra_pipeline_result(
    vid: int,
    file: str = Query(..., description="Disk filename returned in the run response"),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Stream a previously-generated pipeline result ZIP back to the
    consultant. `file` is the bare disk filename returned in the
    `result_zip_url` field of the run response — no path components
    allowed.
    """
    rv = _require_version_with_access(db, vid, user, need=AccessLevel.view)
    # Filename allow-list — block traversal.
    import re as _re
    if not _re.match(r"^[A-Za-z0-9._\-]+\.zip$", file):
        raise HTTPException(400, "Invalid result filename.")
    base = Path(settings.UPLOAD_DIR) / "infra_pipeline" / str(rv.report_id) / rv.version
    target = (base / file).resolve()
    if base.resolve() not in target.parents:
        raise HTTPException(400, "Filename resolves outside the pipeline folder.")
    if not target.exists():
        raise HTTPException(404, "Result ZIP not found.")
    from fastapi.responses import FileResponse
    return FileResponse(
        path=str(target), filename=file, media_type="application/zip",
    )


# ============================================================
# Per-finding attachment download + re-upload
# ============================================================

@router.get("/findings/{fid}/attachments")
def list_finding_attachments(
    fid: int, db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """List the attachment metadata for a single finding."""
    f = _require_finding_with_access(db, fid, user, need=AccessLevel.view)
    return {"attachments": list(f.attachments or [])}


@router.get("/findings/{fid}/attachments/{key}")
def download_finding_attachment(
    fid: int, key: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Download a single attachment by its stable key (the filename)."""
    f = _require_finding_with_access(db, fid, user, need=AccessLevel.view)
    for a in (f.attachments or []):
        if isinstance(a, dict) and (a.get("key") or a.get("filename")) == key:
            disk = Path(a.get("path") or "")
            if not disk.exists():
                raise HTTPException(404, "Attachment file missing on disk.")
            from fastapi.responses import FileResponse
            return FileResponse(
                path=str(disk), filename=a.get("filename") or key,
                media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            )
    raise HTTPException(404, f"No attachment with key {key!r} on this finding.")


@router.post("/findings/{fid}/attachments/{key}")
async def replace_finding_attachment(
    fid: int, key: str,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Replace the bytes of an existing attachment in-place. Used
    when the consultant has manually re-categorised entries in one
    of the grouped xlsx workbooks and wants the report to use their
    edited copy on the next Generate.
    """
    f = _require_finding_with_access(db, fid, user, need=AccessLevel.edit)
    _MAX_ATTACHMENT_BYTES = 20 * 1024 * 1024
    _chunks: list[bytes] = []
    _att_total = 0
    while True:
        _att_chunk = await file.read(65536)
        if not _att_chunk:
            break
        _att_total += len(_att_chunk)
        if _att_total > _MAX_ATTACHMENT_BYTES:
            raise HTTPException(413, "Attachment exceeds the 20 MB upload limit.")
        _chunks.append(_att_chunk)
    data = b"".join(_chunks)
    if not data:
        raise HTTPException(400, "Uploaded file is empty.")
    from ..services.infra_pipeline import replace_attachment
    try:
        updated = replace_attachment(f, key, data, user)
    except ValueError as e:
        raise HTTPException(404, str(e))
    db.commit()
    _audit(db, user, "report.finding.attachment.replace",
           "report_finding", f.id,
           {"key": key, "uploaded_filename": file.filename})
    db.commit()
    return {"ok": True, "attachment": updated}


@router.get("/versions/{vid}/placeholders")
def check_version_placeholders(vid: int, db: Session = Depends(get_db),
                                user: User = Depends(get_current_user)):
    """Bulk scan: every finding in this version. The UI uses this to
    paint per-finding "needs customisation" badges and to disable the
    submit-for-review button when blockers exist."""
    v = _require_version_with_access(db, vid, user, need=AccessLevel.view)
    return _ph_check.summarise_unresolved(v.findings)


@router.post("/from-library-preview/{lib_id}")
def preview_library_finding(lib_id: int, db: Session = Depends(get_db),
                             user: User = Depends(get_current_user)):
    """Return the unresolved-token scan for a library finding *before*
    the user inserts it. Powers the confirmation modal on the library
    card so consultants are forced to see — and acknowledge — which
    fields they'll need to customise."""
    lib = db.get(FindingLibrary, lib_id)
    if not lib:
        raise HTTPException(404, "Library finding not found")
    return {
        "library_id": lib.id,
        "title": lib.title,
        **_ph_check.scan_finding(lib),
    }


@router.put("/findings/{fid}", response_model=ReportFindingOut)
def update_finding(fid: int, payload: ReportFindingCreate,
                   db: Session = Depends(get_db),
                   user: User = Depends(get_current_user)):
    f = _require_finding_with_access(db, fid, user, need=AccessLevel.edit)
    _sanitise_finding_fields(payload)
    if payload.cvss_vector:
        try:
            parse_vector(payload.cvss_vector)
        except ValueError as e:
            raise HTTPException(400, f"Invalid CVSS vector: {e}")
    for k, val in payload.model_dump().items():
        if k == "library_id":
            continue
        setattr(f, k, val)
    _audit(db, user, "finding.update", "report_finding", f.id, {})
    db.commit(); db.refresh(f)
    return f


def _normalize_screenshot(entry):
    """Accept either a legacy string path or a `{path, caption}` dict and
    return `{path: str, caption: str}`. Old findings stored screenshots
    as a flat path list; the new schema stores per-image captions so the
    Excel tracker export can write captions next to embedded images.
    Both forms are accepted forever so legacy rows keep rendering.
    """
    if isinstance(entry, str):
        return {"path": entry, "caption": ""}
    if isinstance(entry, dict) and entry.get("path"):
        return {"path": str(entry["path"]),
                "caption": str(entry.get("caption") or "")}
    return None


def _normalize_screenshots(value):
    """Normalise a finding's stored `screenshots` JSON value into a list
    of `{path, caption}` dicts. Drops any entry that doesn't parse."""
    if not value:
        return []
    out = []
    for x in value:
        n = _normalize_screenshot(x)
        if n:
            out.append(n)
    return out


@router.post("/findings/{fid}/screenshots", response_model=ReportFindingOut)
def upload_screenshots(fid: int,
                       files: list[UploadFile] = File(...),
                       captions: list[str] = Form(default=[]),
                       db: Session = Depends(get_db),
                       user: User = Depends(get_current_user)):
    """Upload one or more screenshot images for a finding.

    Each file may optionally be paired with a caption — pass the
    captions as repeated `captions` form fields in the same order as
    the files. Missing captions are stored as the empty string so the
    consultant can add them later via PUT /findings/{fid}/screenshots.
    """
    f = _require_finding_with_access(db, fid, user, need=AccessLevel.edit)
    paths = _save_screenshots(files, subdir=f"findings/{f.id}")
    existing = _normalize_screenshots(f.screenshots)
    for i, p in enumerate(paths):
        cap = captions[i] if i < len(captions) else ""
        existing.append({"path": p, "caption": (cap or "").strip()})
    f.screenshots = existing
    flag_modified(f, "screenshots")
    _audit(db, user, "finding.screenshot.upload", "report_finding", f.id,
           {"count": len(paths)})
    db.commit(); db.refresh(f)
    return f


class ScreenshotsUpdate(BaseModel):
    """Replace the entire screenshots list — used to edit captions or
    reorder thumbnails without re-uploading. Each entry MUST already
    have a path that the server wrote (we don't accept arbitrary paths
    from the client; instead we verify every path matches one already
    on the finding)."""
    screenshots: list[dict] = []


@router.get("/findings/{fid}/screenshots/file")
def get_screenshot_file(fid: int, name: str,
                        db: Session = Depends(get_db),
                        user: User = Depends(get_current_user)):
    """Serve a screenshot file attached to a finding.

    Auth: the caller must have view+ access to the finding's report.
    The `name` is the filename portion only (basename) — we look it up
    against the finding's stored screenshot list rather than trusting
    a client-supplied filesystem path. This prevents directory
    traversal AND prevents reading arbitrary files even if a path
    leak occurred elsewhere.
    """
    f = _require_finding_with_access(db, fid, user, need=AccessLevel.view)
    base = Path(name).name              # strip any directory components
    candidates = _normalize_screenshots(f.screenshots)
    target: Optional[Path] = None
    for s in candidates:
        if Path(s["path"]).name == base:
            target = Path(s["path"]); break
    # Retest evidence shares the same lookup pattern — accept either bucket.
    if target is None:
        for sp in (f.retest_evidence or []):
            if isinstance(sp, str) and Path(sp).name == base:
                target = Path(sp); break
    if target is None or not target.exists():
        raise HTTPException(404, "Screenshot not found on this finding")
    ext = target.suffix.lower()
    media = {
        ".png":  "image/png", ".jpg": "image/jpeg",
        ".jpeg": "image/jpeg", ".gif": "image/gif",
        ".webp": "image/webp",
    }.get(ext, "application/octet-stream")
    return FileResponse(str(target), media_type=media, filename=target.name)


@router.put("/findings/{fid}/screenshots", response_model=ReportFindingOut)
def update_screenshots(fid: int, payload: ScreenshotsUpdate,
                       db: Session = Depends(get_db),
                       user: User = Depends(get_current_user)):
    """Update captions / reorder / delete screenshots in a single call.

    Security model: the client may only reference paths that are
    *already* attached to this finding. New uploads MUST go through
    POST /screenshots so file content is sanitised. This avoids a
    consultant smuggling an arbitrary file path onto the finding via
    the JSON API.
    """
    f = _require_finding_with_access(db, fid, user, need=AccessLevel.edit)
    existing = {x["path"] for x in _normalize_screenshots(f.screenshots)}
    cleaned: list[dict] = []
    for entry in payload.screenshots or []:
        n = _normalize_screenshot(entry)
        if not n:
            continue
        if n["path"] not in existing:
            raise HTTPException(
                400,
                "Unknown screenshot path — upload new files via POST "
                "/screenshots and use this endpoint only for captions / "
                "reorder / delete."
            )
        cleaned.append(n)
    f.screenshots = cleaned
    flag_modified(f, "screenshots")
    _audit(db, user, "finding.screenshot.update", "report_finding", f.id,
           {"count": len(cleaned)})
    db.commit(); db.refresh(f)
    return f


@router.post("/findings/{fid}/retest", response_model=ReportFindingOut)
def update_retest(fid: int, payload: RetestUpdate,
                  db: Session = Depends(get_db),
                  user: User = Depends(get_current_user)):
    f = _require_finding_with_access(db, fid, user, need=AccessLevel.edit)
    _sanitise_finding_fields(payload)
    if payload.retest_notes is not None:
        f.retest_notes = payload.retest_notes
    if payload.status is not None:
        f.status = payload.status
    if payload.client_statement is not None:
        f.client_statement = payload.client_statement
    if payload.client_statement_date is not None:
        f.client_statement_date = payload.client_statement_date or None
    if payload.client_statements is not None:
        # Normalise to a list of {date, text}; drop empty rows.
        clean = []
        for s in (payload.client_statements or []):
            if not isinstance(s, dict):
                continue
            txt = str(s.get("text") or "").strip()
            if not txt:
                continue
            clean.append({"date": str(s.get("date") or "").strip(), "text": txt})
        f.client_statements = clean
        flag_modified(f, "client_statements")
        # Keep the legacy single-comment fields mirrored to the first entry (or
        # cleared) so anything still reading them — and the render fallback —
        # stays correct.
        if clean:
            f.client_statement = clean[0]["text"]
            f.client_statement_date = clean[0]["date"] or None
        else:
            f.client_statement = None
            f.client_statement_date = None
    if payload.retest_entries is not None:
        # Normalise dated retest entries — same shape as client_statements.
        r_clean = []
        for s in (payload.retest_entries or []):
            if not isinstance(s, dict):
                continue
            txt = str(s.get("text") or "").strip()
            if not txt:
                continue
            r_clean.append({"date": str(s.get("date") or "").strip(), "text": txt})
        f.retest_entries = r_clean
        flag_modified(f, "retest_entries")
    _audit(db, user, "finding.retest.update", "report_finding", f.id,
           {"status": f.status.value if f.status else None})
    db.commit(); db.refresh(f)
    return f


@router.post("/findings/{fid}/retest/screenshots", response_model=ReportFindingOut)
def upload_retest_screens(fid: int, files: list[UploadFile] = File(...),
                          captions: list[str] = Form(default=[]),
                          db: Session = Depends(get_db),
                          user: User = Depends(get_current_user)):
    f = _require_finding_with_access(db, fid, user, need=AccessLevel.edit)
    paths = _save_screenshots(files, subdir=f"retest/{f.id}")
    existing = _normalize_screenshots(f.retest_evidence)
    for i, p in enumerate(paths):
        cap = captions[i] if i < len(captions) else ""
        existing.append({"path": p, "caption": (cap or "").strip()})
    f.retest_evidence = existing
    flag_modified(f, "retest_evidence")
    _audit(db, user, "finding.retest.screenshot", "report_finding", f.id,
           {"count": len(paths)})
    db.commit(); db.refresh(f)
    return f


class RetestEvidenceUpdate(BaseModel):
    """Replace the retest evidence list — used to edit captions or reorder
    without re-uploading. Each entry must reference a path already attached."""
    retest_evidence: list[dict] = []


@router.put("/findings/{fid}/retest/screenshots", response_model=ReportFindingOut)
def update_retest_screenshots(fid: int, payload: RetestEvidenceUpdate,
                               db: Session = Depends(get_db),
                               user: User = Depends(get_current_user)):
    """Update captions / reorder / delete retest evidence in a single call."""
    f = _require_finding_with_access(db, fid, user, need=AccessLevel.edit)
    existing_paths = {
        x["path"] for x in _normalize_screenshots(f.retest_evidence)
    }
    cleaned: list[dict] = []
    for entry in payload.retest_evidence or []:
        n = _normalize_screenshot(entry)
        if not n:
            continue
        if n["path"] not in existing_paths:
            raise HTTPException(
                400,
                "Unknown retest evidence path — upload via POST "
                "/retest/screenshots first."
            )
        cleaned.append(n)
    f.retest_evidence = cleaned
    flag_modified(f, "retest_evidence")
    _audit(db, user, "finding.retest.screenshot.update", "report_finding", f.id,
           {"count": len(cleaned)})
    db.commit(); db.refresh(f)
    return f


@router.delete("/findings/{fid}")
def delete_finding(fid: int, db: Session = Depends(get_db),
                   user: User = Depends(get_current_user)):
    # Must have edit access on the parent report AND be the author
    # (or senior/admin / report-admin via require_access edit).
    f = _require_finding_with_access(db, fid, user, need=AccessLevel.edit)
    if f.added_by_id != user.id and user.role not in (Role.admin, Role.senior):
        # Allow a report-admin to delete others' findings too.
        report = _report_of_finding(db, f)
        if effective_access(db, user, report) != AccessLevel.admin:
            raise HTTPException(403, "Only the author, senior+, or a report admin can delete")
    _audit(db, user, "finding.delete", "report_finding", f.id, {"title": f.title})
    db.delete(f); db.commit()
    return {"ok": True}


@router.delete("/versions/{vid}")
def delete_report_version(
    vid: int,
    confirm_older: bool = Query(
        False,
        description=(
            "Required when deleting a version that ISN'T the latest. "
            "Forces the caller to acknowledge they're nuking history."
        ),
    ),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Hard-delete a single report version. Cascades to every
    ReportFinding row on the version (the SQLAlchemy relationship
    is configured with `cascade='all, delete-orphan'` on
    `Report.versions` + on `ReportVersion.findings`, so a plain
    `db.delete(rv)` cleans up the lot).

    Safeguards:
      * Edit access on the parent report is required.
      * Deleting an OLDER version (i.e. not the latest by row order
        on the parent) is allowed only when `?confirm_older=true`
        is supplied. The UI flips this flag after a second
        type-the-version confirm dialog — protects against
        accidentally wiping v0.1 when the consultant meant to
        wipe v0.3.
      * Deleting the LAST remaining version is also blocked — a
        report needs at least one version for the renderer + the
        versions list to render. To wipe everything the consultant
        should delete the parent report instead (planned).
      * Refuses to delete a `published` version. Publication is
        the immutable-final-deliverable signal — undoing it via
        a delete would erase the audit trail.
    """
    rv = _require_version_with_access(db, vid, user, need=AccessLevel.edit)
    r = rv.report

    if (rv.review_status or "") == ReportReviewStatus.published.value:
        raise HTTPException(
            400,
            "Cannot delete a PUBLISHED version directly. Call "
            "`POST /api/reports/versions/{vid}/reopen-draft?confirm_unpublish=true` "
            "first to unlock the immutable-final artefact (audited), "
            "then re-issue this DELETE. The Re-open-as-draft button on "
            "the versions page does this for you.",
        )

    # Order by creation time so "latest" matches the versions-list UI.
    versions_sorted = sorted(
        list(r.versions),
        key=lambda v: (v.created_at or datetime.min, v.id),
    )
    if len(versions_sorted) <= 1:
        raise HTTPException(
            400,
            "Cannot delete the only version on this report. Delete the "
            "report itself if you want to wipe everything.",
        )

    is_latest = (versions_sorted[-1].id == rv.id)
    if not is_latest and not confirm_older:
        raise HTTPException(
            400,
            f"Version {rv.version!r} is NOT the latest on this report. "
            "Re-issue with `?confirm_older=true` if you really want to "
            "wipe an older version — this is a destructive action and "
            "you can't undo it.",
        )

    # If we're deleting the currently-tagged `current_version` on
    # the parent Report, point it at whatever the new latest is so
    # the report row stays consistent.
    deleted_version_str = rv.version
    if r.current_version == deleted_version_str:
        # New latest is the version immediately before the one
        # we're deleting (or, if we're deleting the latest, the
        # one before that).
        remaining = [v for v in versions_sorted if v.id != rv.id]
        if remaining:
            r.current_version = remaining[-1].version

    _audit(db, user, "report.version.delete", "report_version", rv.id, {
        "report_id": r.id,
        "version": deleted_version_str,
        "was_latest": is_latest,
        "finding_count": len(rv.findings or []),
    })

    db.delete(rv)
    db.commit()
    return {
        "ok": True,
        "deleted_version": deleted_version_str,
        "was_latest": is_latest,
        "new_current_version": r.current_version,
        "remaining_versions": len(r.versions),
    }


@router.delete("/versions/{vid}/findings")
def delete_all_findings(
    vid: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Wipe every `ReportFinding` row on a report version in one
    request. Use case: the consultant ran the Infra Scan Pipeline,
    got 376 auto-imported findings, and decided to start over with
    a different categorisation / pipeline option set rather than
    clicking Delete 376 times.

    Permission model — same as the per-finding delete:
      * Edit-level access on the parent report is required
      * Author-owned findings can be deleted by their author OR
        anyone with admin-level access (admin / senior / report
        admin / project lead). Mixed authorship is supported —
        rows the caller can delete are dropped; rows they can't
        are kept and reported in the response.

    Returns a count of rows actually removed + a list of titles
    that were skipped because of authorship. The 403 case (caller
    has no edit access on the version at all) bubbles via the
    existing `_require_version_with_access` guard.
    """
    rv = _require_version_with_access(db, vid, user, need=AccessLevel.edit)
    deleted_titles: list[str] = []
    kept_titles: list[str] = []
    # Compute "can-delete-others-work" once outside the loop so a
    # 200-row version doesn't hit the DB 200 times for the access
    # check.
    is_admin_caller = user.role in (Role.admin, Role.senior)
    is_report_admin = (
        is_admin_caller
        or effective_access(db, user, rv.report) == AccessLevel.admin
    )

    for f in list(rv.findings):
        if f.added_by_id == user.id or is_report_admin:
            deleted_titles.append(f.title)
            db.delete(f)
        else:
            kept_titles.append(f.title)

    _audit(db, user, "finding.delete.all", "report_version", rv.id, {
        "deleted_count": len(deleted_titles),
        "skipped_count": len(kept_titles),
    })
    db.commit()
    return {
        "ok": True,
        "deleted_count": len(deleted_titles),
        "skipped_count": len(kept_titles),
        # Cap returned titles so a 5000-finding wipe doesn't bloat
        # the response payload. The audit row stores the counts
        # only — full titles are recoverable from the audit
        # detail JSON if needed.
        "deleted_titles_sample": deleted_titles[:25],
        "skipped_titles_sample": kept_titles[:25],
    }


# ===== Generation =====

_VERSION_KIND_LABELS = {
    "retest": "Retest report",
    "final": "Final report",
    "update": "Report update",
    "initial": "Initial draft report",
}


def _version_description(notes: str | None) -> str:
    """Derive a human-readable change description from the version notes prefix."""
    import re as _re
    m = _re.match(r"\[(\w+)\]", notes or "")
    if m:
        return _VERSION_KIND_LABELS.get(m.group(1).lower(), "Updated report")
    return "Initial draft report"


def _format_window(raw: str | None) -> tuple[str, str]:
    """Format a testing window 'YYYY-MM-DD - YYYY-MM-DD' / '… to …' into
    'D Month YYYY - D Month YYYY'. Returns (display, end_date_str). Free text is
    returned as-is with an empty end date."""
    raw = (raw or "").strip()
    if not raw:
        return "", ""
    import re as _re
    m = _re.match(r"(\d{4}-\d{2}-\d{2})\s*(?:[-–]|to)\s*(\d{4}-\d{2}-\d{2})",
                  raw, _re.IGNORECASE)
    if m:
        try:
            s = datetime.strptime(m.group(1), "%Y-%m-%d")
            e = datetime.strptime(m.group(2), "%Y-%m-%d")
            return (f"{s.strftime('%-d %B %Y')} - {e.strftime('%-d %B %Y')}",
                    e.strftime('%-d %B %Y'))
        except ValueError:
            return raw, ""
    return raw, ""


def _fmt_one_mgmt_date(iso_date: str | None) -> str:
    """ISO 'YYYY-MM-DD' -> 'DD-MM-YYYY' (passes through unparseable text)."""
    d = (iso_date or "").strip()
    if not d:
        return ""
    try:
        return datetime.strptime(d, "%Y-%m-%d").strftime("%d-%m-%Y")
    except ValueError:
        return d


def _render_mgmt_comments(f) -> str:
    """Build the Management Comments field from a finding's list of dated
    comments. Each renders as its own "[DD-MM-YYYY]\\n\\n<text>" block (docxtpl
    converts the newlines to line breaks), so retests/updates append a new dated
    section under the earlier ones. Falls back to the legacy single comment."""
    stmts = list(getattr(f, "client_statements", None) or [])
    if not stmts:
        txt = (getattr(f, "client_statement", "") or "").strip()
        if txt:
            stmts = [{"date": getattr(f, "client_statement_date", "") or "", "text": txt}]
    blocks = []
    for s in stmts:
        if not isinstance(s, dict):
            continue
        text = str(s.get("text") or "").strip()
        if not text:
            continue
        d = _fmt_one_mgmt_date(s.get("date"))
        blocks.append(f"[{d}]\n\n{text}" if d else text)
    return "\n\n".join(blocks)


def _render_retest_entries(f) -> str:
    """Build the Retest Follow-Up field from a finding's list of dated retest
    entries. Same "[DD-MM-YYYY]\\n\\n<text>" format as management comments.
    Falls back to the legacy scalar retest_notes when no entries list exists."""
    entries = list(getattr(f, "retest_entries", None) or [])
    if not entries:
        return (getattr(f, "retest_notes", "") or "").strip()
    blocks = []
    for s in entries:
        if not isinstance(s, dict):
            continue
        text = str(s.get("text") or "").strip()
        if not text:
            continue
        d = _fmt_one_mgmt_date(s.get("date"))
        blocks.append(f"[{d}]\n\n{text}" if d else text)
    return "\n\n".join(blocks)


def _build_distribution_list(details: dict) -> list[dict]:
    """Rows for the Word report's Distribution List table.

    Prefers the new free-form `distribution_list` — a list of
    `{name, role, purpose}` the user defines themselves (any role/title).
    Falls back to the legacy fixed Agency-POC / Engagement-Partner /
    Director / Manager fields for reports created before the flexible UI.
    """
    rows = details.get("distribution_list")
    if isinstance(rows, list):
        out = []
        for r in rows:
            if not isinstance(r, dict):
                continue
            name = str(r.get("name") or "").strip()
            role = str(r.get("role") or "").strip()
            purpose = str(r.get("purpose") or "").strip() or "Recipient"
            if name or role:
                out.append({"name": name, "role": role, "purpose": purpose})
        if out:
            return out
    # Legacy fallback (pre-flexible-UI reports).
    legacy = [
        (details.get("dist_poc_1"), "Agency POC", "Reviewer"),
        (details.get("dist_poc_2"), "Agency POC", "Reviewer"),
        (details.get("dist_ep"), "Engagement Partner", "Reviewer"),
        (details.get("dist_ed"), "Engagement Director", "Reviewer"),
        (details.get("dist_em"), "Engagement Manager", "Author"),
    ]
    return [{"name": str(n).strip(), "role": role, "purpose": purpose}
            for (n, role, purpose) in legacy if n and str(n).strip()]


def _build_context(rv: ReportVersion, db: Session) -> dict:
    """Assemble the docxtpl render context from the report version.

    Side-channel `_embed_attachments` key (under the returned dict)
    carries a list of `{marker, xlsx_path, filename, label}` entries
    the docx_generator's post-render pass uses to OLE-embed each
    grouped finding's xlsx as a clickable Excel icon. The render
    pipeline pops the key before passing the context to docxtpl —
    it never reaches the template.
    """
    # Pre-load the library relationship for all findings in one IN query so
    # accessing f.library below doesn't trigger N+1 lazy loads (one per finding).
    db.query(ReportFinding).filter(
        ReportFinding.report_version_id == rv.id
    ).options(selectinload(ReportFinding.library)).all()

    r = rv.report
    project = r.project
    template = r.template

    findings_sorted = sorted(
        rv.findings,
        key=lambda f: (
            {"Critical": 0, "High": 1, "Medium": 2, "Low": 3,
             "Informational": 4}.get(f.severity.value if f.severity else "Informational", 5),
            -(float(f.cvss_score) if f.cvss_score else 0.0),
        )
    )

    findings_dicts = []
    # Side-channel list the docx_generator's OLE-embed post-render
    # pass consumes. Each entry is keyed by a marker string that
    # appears verbatim in the rendered docx (the "Refer to the
    # attached file: foo.xlsx" suffix below) — the pass searches
    # for it, deletes it, and injects an OLE icon + caption in its
    # place. We collect these as we walk the findings.
    embed_attachments: list[dict] = []
    # Sequential counter across ALL findings — ensures "Figure 1", "Figure 2", …
    # regardless of which findings carry attachments and how many each has.
    fig_counter = 0
    for idx, f in enumerate(findings_sorted, 1):
        # Per-finding attachments (Infra Scan Pipeline categorised
        # workbooks). The Word template renders {{ f.description }}
        # in the Observations section — when there's an attachment,
        # append a pointer line + register an OLE-embed task.
        attachments_list = list(getattr(f, "attachments", None) or [])
        att_names = [a.get("filename") for a in attachments_list
                     if isinstance(a, dict) and a.get("filename")]
        description_with_att = f.description or ""
        if att_names:
            # Each attachment gets its own unique marker paragraph so
            # the OLE post-render pass can locate and replace each one
            # independently. A single combined paragraph (the old code)
            # was cleared after the first embed, causing all subsequent
            # attachments on the same finding to be silently skipped.
            ptr_htmls: list[str] = []
            for att in attachments_list:
                if not isinstance(att, dict):
                    continue
                fname = att.get("filename")
                if not fname:
                    continue
                # HTML-escape the filename so "&" / "<" in names survive
                # the html_to_subdoc parse without corrupting the markup.
                ptr_htmls.append(
                    f"<p>Refer to the attached file: {_html.escape(fname)}</p>"
                )
            if ptr_htmls:
                joined = "\n".join(ptr_htmls)
                description_with_att = (
                    f"{description_with_att}\n{joined}"
                    if description_with_att.strip() else joined
                )
            # Register each attachment for OLE embedding. The post-render
            # pass searches for the marker text, clears that paragraph,
            # and injects an OLE icon + caption paragraph in its place.
            for att in attachments_list:
                if not isinstance(att, dict):
                    continue
                disk_path = att.get("path")
                fname = att.get("filename")
                lbl = (att.get("label")
                       or f"Attachment for {f.title}")
                if disk_path and fname:
                    fig_counter += 1
                    embed_attachments.append({
                        "marker":    f"Refer to the attached file: {fname}",
                        "xlsx_path": disk_path,
                        "filename":  fname,
                        "label":     f"Figure {fig_counter}: {lbl}",
                    })

        findings_dicts.append({
            "index": idx,
            "chapter_idx": f.chapter_idx if f.chapter_idx is not None else 0,
            "title": f.title,
            # Severity display: "Informational" is shown as "Info" across the
            # deliverable. Informational findings carry status "NA" (they're
            # advisory, not an open/closed defect) in BOTH the summary table
            # and the per-finding detail section.
            "severity": (
                "Info" if (f.severity and f.severity.value == "Informational")
                else (f.severity.value if f.severity else "Info")
            ),
            "status": (
                "NA" if (f.severity and f.severity.value == "Informational")
                else (f.status.value if f.status else "Open")
            ),
            "cvss_vector": f.cvss_vector or "",
            "cvss_score": f.cvss_score if f.cvss_score is not None else "",
            "cwe": f.cwe or "",
            # cwe_id: just "CWE-22" without the long description, for summary tables.
            "cwe_id": (lambda _m: _m.group(1) if _m else "")(
                __import__('re').match(r'(CWE-\d+)', f.cwe or "")
            ),
            "owasp_category": (f.library.owasp_category if f.library else None) or "",
            "description": description_with_att,
            "impact": f.impact or "",
            "remediation": f.remediation or "",
            "references": f.references or "",
            "affected_asset": f.affected_asset or "",
            "poc_steps": f.poc_steps or "",
            # Retest notes — rendered from dated entries if present, legacy
            # scalar retest_notes otherwise (backward compatible).
            "retest_notes": _render_retest_entries(f),
            # Management Comments — one dated block per entry, e.g.
            # "[11-06-2026]\n\n<comment>\n\n[15-07-2026]\n\n<comment>".
            "client_statement": _render_mgmt_comments(f),
            "screenshots": f.screenshots or [],
            "retest_evidence": f.retest_evidence or [],
            "added_by_id": f.added_by_id,
            # Surface the raw attachment list so templates can
            # reference {{ f.attachments }} (each entry has
            # `filename`, `label`, `key`) for richer rendering.
            "attachments": [
                {"filename": a.get("filename"), "label": a.get("label", ""),
                 "key": a.get("key") or a.get("filename")}
                for a in attachments_list if isinstance(a, dict)
            ],
        })

    # Severity tallies for the executive summary. NOTE: findings_dicts now
    # carry the DISPLAY severity ("Info" for informational), but the template
    # reads {{ severity_counts.Informational }}, so we count back under the
    # canonical "Informational" key — otherwise informational findings vanish
    # from the exec-summary "observations" count.
    sev_counts = {k: 0 for k in ("Critical", "High", "Medium", "Low", "Informational")}
    for f in findings_dicts:
        _sev = "Informational" if f["severity"] in ("Info", "Informational") else f["severity"]
        sev_counts[_sev] = sev_counts.get(_sev, 0) + 1

    # Pull the latest Nmap import for this project if present
    nmap_rows: list[dict] = []
    for si in reversed(project.scan_imports):
        if si.scan_type == "nmap" and si.parsed_data.get("ports"):
            nmap_rows = si.parsed_data["ports"]
            break

    # Resolve per-report / per-template prose sections
    # (per-report overrides > master template prose > hardcoded fallbacks)
    from ..services.section_resolver import resolve_sections
    sections_dict = resolve_sections(db, template_id=template.id, report_id=r.id)

    # Per-project artifacts attached during the engagement -- exposed to the
    # Word template so the executive summary can auto-populate scope.
    # Postman: only meaningful on API VAPT reports but harmless elsewhere.
    # Source-code hashes: relevant when source code review was in scope.
    proj_details = getattr(project, "details", None) or {}
    postman_summary = proj_details.get("postman_summary") or {}
    source_code_records = proj_details.get("source_code_hashes") or []

    # Report-level testing_window (from Report Details form) overrides project dates.
    # The form stores it as "YYYY-MM-DD - YYYY-MM-DD"; we format to "D Month YYYY to D Month YYYY"
    # so {{ project.testing_window }} renders consistently regardless of the source.
    _rdetails = r.details or {}
    # Initial (fieldwork) testing window. `_testing_end_str` = its last day,
    # formatted "D Month YYYY" (used on the exec-summary findings-table caption).
    _computed_tw, _testing_end_str = _format_window(_rdetails.get("testing_window"))
    if not _computed_tw:
        _computed_tw = (
            f"{project.testing_start.strftime('%-d %B %Y') if project.testing_start else '?'} "
            f"- {project.testing_end.strftime('%-d %B %Y') if project.testing_end else '?'}"
        )
        if project.testing_end:
            _testing_end_str = project.testing_end.strftime('%-d %B %Y')

    # Retest / follow-up window (Report Details "Follow-up testing window"
    # field). Populated when generating a retest / report-update.
    _retest_tw, _retest_end = _format_window(_rdetails.get("testing_window_followup"))

    # Is this a retest / follow-up / report-update? Drives whether the §2.5
    # Timeline prose shows the retest dates instead of the initial ones.
    _rtype = str(_rdetails.get("report_type") or "Initial Report").lower()
    _is_retest = ("retest" in _rtype) or ("update" in _rtype) or ("follow" in _rtype)

    # Prose timeline ("conducted between the period of …") + the exec-summary
    # "as of" date: use the retest window for retest reports (when set), else
    # the initial window. The schedule table shows BOTH (fieldwork + follow-up).
    _prose_tw = _retest_tw if (_is_retest and _retest_tw) else _computed_tw
    _prose_end = _retest_end if (_is_retest and _retest_end) else _testing_end_str

    _raw_tnames = (r.details or {}).get("tester_names", [])
    _tester_names_str = ", ".join(
        t for t in (
            _raw_tnames if isinstance(_raw_tnames, list) else ([_raw_tnames] if _raw_tnames else [])
        ) if t
    )

    # Agency / client display name = long form + short form, e.g.
    # "Ministry of Health (MOH)". The short form comes from the Report Details
    # "Agency short form" field; when set it's appended to the client name
    # everywhere {{ project.client_name }} / {{ details.client_name }} renders
    # (cover, exec summary, footers).
    _client_short = str((r.details or {}).get("client_short") or "").strip()
    _base_client = (r.details or {}).get("client_name") or project.client_name or ""
    _client_display = (
        f"{_base_client} ({_client_short})"
        if (_client_short and _base_client and f"({_client_short})" not in _base_client)
        else _base_client
    )

    return {
        "project": {
            "name": project.name,
            "client_name": _client_display,
            "sector": project.sector or "",
            "scope_description": project.scope_description or "",
            "scope_targets": project.scope_targets or [],
            "testing_start": project.testing_start.isoformat() if project.testing_start else "",
            "testing_end": project.testing_end.isoformat() if project.testing_end else "",
            # §2.5 Timeline prose + exec-summary period. Shows the retest dates
            # for retest/report-update reports (when set), else the initial
            # fieldwork dates. The schedule table carries both separately.
            "testing_window": _prose_tw,
            # Fieldwork (initial) + Follow-up (retest) windows for the §2.5
            # "Overview of Security Testing Schedule" table.
            "fieldwork_window": _computed_tw,
            "followup_window": _retest_tw,
            # Company entity name selected at project creation; drives the footer,
            # Confidentiality Statement, Executive Summary, and Introduction.
            "company_alias": proj_details.get("company_alias") or "",
        },
        "report": {
            "name":    r.name,
            "version": rv.version,
            "is_draft": rv.is_draft,
            "type":       (r.details or {}).get("report_type") or "Initial Report",
            # doc_version mirrors rv.version so {{ report.doc_version }} == {{ report.version }}
            "doc_version": rv.version,
        },
        "template": {
            "code": template.code,
            "name": template.name,
            "scope_of_work": template.scope_of_work or "",
            "methodology": template.methodology or "",
        },
        # `sections` is the new editable-prose mechanism. Word template
        # places {{ sections.executive_summary }}, {{ sections.methodology }},
        # etc. wherever the team wants the prose to appear. Each report's
        # resolved sections are baked into the rendered DOCX so historical
        # output stays stable when masters change.
        "sections": sections_dict,
        # Postman scope auto-population (API VAPT). Template uses:
        #   {{ postman_summary.scope_sentence }}    e.g.
        #   "The assessment covered 47 endpoints across 6 functional areas (12 GET, ...)"
        #   {{ postman_summary.total }}
        #   {% for m, n in postman_summary.counts.items() %}{{ m }}: {{ n }}{% endfor %}
        "postman_summary": postman_summary,
        # Source-code integrity record(s) for the engagement (zero or more).
        # Template can render a chain-of-custody table:
        #   {% for s in source_code_hashes %}{{ s.filename }} | {{ s.computed_sha256 }} | {{ s.result }}{% endfor %}
        "source_code_hashes": source_code_records,
        # Merge project-level fields into `details` so templates can use
        # {{ details.client_name }} as an alias for {{ project.client_name }}.
        # Templates edited in Word sometimes use `details.*` for all fields;
        # this bridge keeps them working without requiring a template re-edit.
        "details": {
            **(r.details or {}),
            # Fill in client_name from the project if not already in report.details.
            # Uses the long+short display form (e.g. "Ministry of Health (MOH)").
            "client_name": _client_display,
            # Fall back to project.name for application_name if not explicitly set.
            "application_name": (r.details or {}).get("application_name") or project.name or "",
            # Default report_type to "Initial Report" if never set.
            "report_type": (r.details or {}).get("report_type") or "Initial Report",
            # Always use the version being generated — overrides any stale value in r.details.
            "doc_version": rv.version,
            # Company alias selected at the project level; exposed as
            # {{ details.company_alias }} for footer, Confidentiality
            # Statement, Executive Summary, and Introduction placeholders.
            "company_alias": proj_details.get("company_alias") or "",
            # Normalize tester_names to a list so `| join(', ')` in templates works
            # correctly. On initial report creation it's stored as a plain string;
            # later edits (tracker auto-populate) store it as a list.
            "tester_names": (
                [t for t in (r.details or {}).get("tester_names", []) if t]
                if isinstance((r.details or {}).get("tester_names"), list)
                else (
                    [(r.details or {}).get("tester_names")]
                    if (r.details or {}).get("tester_names")
                    else []
                )
            ),
            # Human-readable date for Word templates. DB stores ISO "YYYY-MM-DD"
            # (useful for HTML date inputs and the tracker exporter), but Word
            # templates replaced "September 2025" / "14 August 2024" patterns
            # so they expect "D Month YYYY" (e.g. "15 November 2024").
            # %-d is Linux-only (no leading zero); the container runs Linux.
            "report_date": datetime.strptime(
                (r.details or {}).get("report_date") or
                datetime.utcnow().strftime("%Y-%m-%d"),
                "%Y-%m-%d"
            ).strftime("%-d %B %Y"),
            # Four-digit year used in the footer copyright line and the
            # custom.xml reportYear property (post-render injection).
            "report_year": datetime.strptime(
                (r.details or {}).get("report_date") or
                datetime.utcnow().strftime("%Y-%m-%d"),
                "%Y-%m-%d"
            ).strftime("%Y"),
        },
        # scope_text: flat newline-joined string of all scope targets, usable
        # in Word templates as {{ scope_text }} for a simple block of URLs/IPs.
        # \a is docxtpl's paragraph-break sentinel inside a table cell.
        # \n would be normalised to whitespace by the XML parser (invisible).
        "scope_text": "\a".join(project.scope_targets or []),
        # scanning_tools: list of {tool_name, version, last_update} dicts entered
        # in Report Details. Available as {{ scanning_tools }} (top-level) or
        # {{ details.scanning_tools }} for template consistency.
        "scanning_tools": (r.details or {}).get("scanning_tools") or [],
        # Distribution List table rows ({name, role, purpose}). User-defined
        # in Report Details; the Word template loops over `distribution_list`.
        "distribution_list": _build_distribution_list(r.details or {}),
        "findings": findings_dicts,
        "severity_counts": sev_counts,
        "total_findings": len(findings_dicts),
        # GovTech CSG ICT RMM section/column toggle (Report Details). Default ON;
        # when off, the §2.6.2 methodology section AND the per-finding "GovTech
        # CSG ICT RMM Risk Rating" column are stripped from the rendered report.
        "rmm_enabled": bool((r.details or {}).get("rmm_enabled", True)),
        # "as of" date for the exec-summary findings-table caption = last day of
        # the (retest-aware) testing window (falls back to the report date).
        "findings_as_of": (_prose_end or datetime.strptime(
            (r.details or {}).get("report_date") or datetime.utcnow().strftime("%Y-%m-%d"),
            "%Y-%m-%d").strftime("%-d %B %Y")),
        # Dominant CVSS version across the findings ("3.1" / "4.0"). Templates
        # can render {{ cvss_version }}; the post-render relabel pass also uses
        # it to update the per-finding "CVSS <ver> Risk Rating" detail header
        # after a re-rate so it matches the actual stored vectors.
        "cvss_version": (
            "3.1" if (
                sum(1 for fd in findings_dicts
                    if (fd.get("cvss_vector") or "").upper().startswith("CVSS:3."))
                >= max(1, sum(1 for fd in findings_dicts
                              if (fd.get("cvss_vector") or "").upper().startswith("CVSS:4.")))
                and any((fd.get("cvss_vector") or "").upper().startswith("CVSS:3.")
                        for fd in findings_dicts)
            ) else "4.0"
        ),
        "nmap_rows": nmap_rows,
        # All versions of this report, oldest-first — used by the
        # Document Change History table: {%tr for h in change_history %}
        # revised_by: prefer tester_names from report details (engagement team)
        # over the system account that happened to click Generate.
        "change_history": [
            {
                "version_date": v.created_at.strftime("%-d %B %Y"),
                "version_no":   v.version,
                "description":  _version_description(v.notes),
                "revised_by": (
                    _tester_names_str or (
                        (v.generated_by.full_name or v.generated_by.username)
                        if v.generated_by else ""
                    )
                ),
            }
            for v in r.versions  # already ordered by created_at ASC
        ],
        # Side-channel for the docx post-render pass. Stripped from
        # the context before docxtpl sees it so the key never
        # reaches the Word template. See render_report() in
        # services/docx_generator.py for the consumer.
        "_embed_attachments": embed_attachments,
        # Combined-report test sections. Non-empty when the consultant defined
        # multiple test types (e.g. Web VAPT + API VAPT). The post-render
        # _add_combined_chapter_headings pass uses this to insert Heading 1
        # chapter separators between groups of findings.
        # Each entry: {idx, label, scope_name, scope_urls: [str]}
        "report_sections": list(r.report_sections or []),
        # Side-channel: per-finding chapter_idx values (parallel to findings).
        # Used by the docx_generator post-render pass to split findings by chapter.
        "_finding_chapter_idxs": [f_dict.get("chapter_idx") for f_dict in findings_dicts],
    }


@router.post("/versions/{vid}/generate")
def generate(vid: int, payload: GenerateRequest,
             db: Session = Depends(get_db),
             user: User = Depends(get_current_user)):
    rv = _require_version_with_access(db, vid, user, need=AccessLevel.edit)

    # Serialize concurrent generate requests for the same version so two
    # simultaneous clicks don't race to write the same output file or leave
    # rv in an inconsistent state. pg_advisory_xact_lock() is transaction-
    # scoped — the lock is released automatically when db.commit() fires.
    # Works across multiple uvicorn workers because all share one PG server.
    from sqlalchemy import text as _sql_text
    db.execute(_sql_text("SELECT pg_advisory_xact_lock(:vid)"), {"vid": vid})

    # Pick the right .docx template: per-report override > per-project override > master
    from ..services.template_resolver import resolve_template_path
    try:
        template_path = resolve_template_path(db, rv.report)
    except FileNotFoundError as e:
        import logging as _log_r
        _log_r.getLogger(__name__).error("Template not found for report %s: %s", rv.id, e)
        raise HTTPException(500, "Report template not available. Contact an administrator.")
    if not template_path.exists():
        import logging as _log_r
        _log_r.getLogger(__name__).error("Template file missing on disk: %s", template_path)
        raise HTTPException(500, "Report template not available. Contact an administrator.")

    # Auto-version-bump on Generate is OFF by design. Consultants
    # bump the version explicitly via the "New version" flow when
    # they move from the initial report to a retest / final / update
    # — those are distinct engagement-level deliverables and deserve
    # an explicit decision. Auto-bumping on every Generate
    # click churned the version history with spurious 0.1 → 0.2 →
    # 0.3 jumps for re-renders of the same content. The legacy
    # `increment_version` field on `GenerateRequest` is kept on the
    # schema for backward-compatibility with API clients but is now
    # silently ignored. The dedicated `POST /api/reports/{rid}/versions`
    # endpoint is the single source of truth for creating new
    # versions.
    _ = payload.increment_version       # noqa: F841 — intentional silent ignore

    # Auto-stamp `report_date` to today ONLY if the consultant has not
    # already set one. Overwriting an explicit date on every Generate
    # was silently reverting user-set values (e.g. a backdated report
    # date) back to today every time they hit Generate.
    cur_details = dict(rv.report.details or {})
    if not cur_details.get("report_date"):
        cur_details["report_date"] = datetime.utcnow().strftime("%Y-%m-%d")
        rv.report.details = cur_details
        from sqlalchemy.orm.attributes import flag_modified as _flag_modified
        _flag_modified(rv.report, "details")

    # Effective draft flag: the consultant's intent OR the workflow itself
    # being in-review. A version under review is always shown to the
    # reviewer with the DRAFT watermark, regardless of `is_draft`.
    in_review = (rv.review_status == ReportReviewStatus.in_review)
    effective_draft = bool(payload.is_draft) or in_review
    # Approved AND published versions both suppress the DRAFT watermark.
    # Earlier this was published-only, which forced consultants to also
    # "publish" before they could ship a clean PDF — but in practice the
    # reviewer's `approve` action is the meaningful sign-off. Promoting
    # approved to "no watermark" lets the reviewer hand back a clean
    # report immediately without an extra publish step. The
    # consultant's `is_draft` checkbox is overridden in BOTH directions
    # so an approved report can't accidentally ship watermarked.
    if rv.review_status in (ReportReviewStatus.approved,
                             ReportReviewStatus.published):
        effective_draft = False
    rv.is_draft = effective_draft
    rv.notes = payload.notes or rv.notes

    context = _build_context(rv, db)

    out_dir = Path(settings.REPORT_DIR) / str(rv.report_id)
    out_dir.mkdir(parents=True, exist_ok=True)
    stem = f"{rv.report.name.replace(' ', '_')}_v{rv.version}"
    docx_out = out_dir / f"{stem}.docx"

    # Render the severity-breakdown chart as a PNG. The Word template
    # embeds it via {{ severity_chart }} (an InlineImage wrapped by the
    # generator). If the template doesn't reference {{ severity_chart }},
    # the PNG is still produced and stored alongside the report -- consultants
    # can paste it manually if needed.
    from ..services.severity_chart import render_severity_chart
    chart_path = out_dir / f"{stem}_severity_chart.png"
    try:
        render_severity_chart(context["severity_counts"], chart_path)
        context["severity_chart_path"] = str(chart_path)
    except Exception as e:
        # Chart is non-fatal -- the report still renders without it
        context["severity_chart_path"] = None
        context.setdefault("warnings", []).append(f"Severity chart generation failed: {e}")

    # Render DOCX. If this fails, surface the actual error to the caller
    # rather than a generic 500 — saves a round-trip to the server logs.
    # We pass `effective_draft` rather than `payload.is_draft` so the
    # docx + pdf paths agree on watermark state: an approved/published
    # report renders WITHOUT a DRAFT even if the consultant left the
    # "Draft" checkbox ticked (they're often the same person who
    # approved it; one stray checkbox shouldn't ship a draft-stamped
    # final). Conversely, an `in_review` version always gets the
    # DRAFT — the consultant can't disable it until it clears review.
    # Capture the embed-attachments list BEFORE render_report consumes
    # it. The renderer pops `_embed_attachments` from the context to
    # keep the key out of docxtpl's view, so a later `context.get(...)`
    # in this function returns None — read it now and stash it for the
    # PDF post-pass below. List of dicts; empty means "no grouped
    # findings have xlsx workbooks to attach".
    attachments_for_pdf = list(context.get("_embed_attachments") or []) \
        if isinstance(context, dict) else []

    try:
        render_report(
            template_path=template_path,
            output_path=docx_out,
            context=context,
            is_draft=effective_draft,
        )
    except Exception as e:
        _logger.exception("DOCX render failed for version %s (template=%s)", vid, template_path.name)
        raise HTTPException(500, "Report generation failed. Please try again or contact an administrator.")
    rv.generated_docx_path = str(docx_out)

    pdf_path = None
    if payload.as_pdf:
        try:
            # When the user is generating a draft (or the version is in
            # review), stamp the DRAFT overlay onto the PDF too — the VML
            # watermark inside the DOCX often vanishes through LibreOffice.
            pdf_path = convert_to_pdf(docx_out, out_dir, draft_watermark=effective_draft)
            rv.generated_pdf_path = str(pdf_path)
        except Exception as e:
            import logging as _log_r
            _log_r.getLogger(__name__).exception("PDF conversion failed for version %s", vid)
            raise HTTPException(500, "PDF conversion failed. Please try again or contact an administrator.")

        # ---- PDF file-attachment post-pass ----
        # The DOCX renderer OLE-embeds each grouped finding's xlsx as
        # a clickable Excel icon, but LibreOffice's docx→pdf converter
        # cannot carry that OLE object into the PDF — it survives only
        # as a static icon image. PDF has its own attachment mechanism
        # (PDF §7.11 embedded-files), so we run a separate post-pass
        # that attaches each xlsx INSIDE the PDF. The resulting PDF
        # shows the workbook in Adobe Reader / browser PDF viewer
        # attachment panels and can be extracted with pdfdetach, so
        # the deliverable carries its data even when emailed standalone.
        # Failure here is non-fatal — the PDF is already written; the
        # "Refer to the attached file:" prose still tells the reader
        # what's missing.
        if attachments_for_pdf:
            try:
                from ..services.docx_attachments import embed_pdf_attachments
                n = embed_pdf_attachments(pdf_path, attachments_for_pdf)
                if n:
                    import logging
                    logging.getLogger(__name__).info(
                        "embed_pdf_attachments: attached %d xlsx file(s) to %s",
                        n, pdf_path.name,
                    )
            except Exception as e:
                import logging
                logging.getLogger(__name__).warning(
                    "PDF attachment post-pass failed (non-fatal): %s", e
                )

    # ---- Optional: package DOCX + PDF into an AES-256 encrypted ZIP ----
    zip_path: Optional[Path] = None
    saved_password_id: Optional[str] = None
    if payload.encrypt:
        project = db.get(Project, rv.report.project_id)
        if not project:
            raise HTTPException(500, "Parent project not found")

        # Resolve the plaintext password from either: a stored project
        # password (reuse) OR a freshly supplied one. Exactly one branch
        # must succeed.
        plaintext_pw: Optional[str] = None
        if payload.reuse_password_id:
            try:
                plaintext_pw = _enc.get_project_password_plaintext(
                    project, payload.reuse_password_id
                )
            except ValueError as e:
                import logging as _log_r
                _log_r.getLogger(__name__).error("Password decryption failed for project %s: %s", project.id, e)
                raise HTTPException(500, "Could not retrieve the stored password. Contact an administrator.")
            if plaintext_pw is None:
                raise HTTPException(404, "Reused password id not found on this project")
        elif payload.encrypt_password:
            plaintext_pw = payload.encrypt_password
            try:
                _enc.validate_password(plaintext_pw)
            except ValueError as e:
                raise HTTPException(400, f"Bad password: {e}")
        else:
            raise HTTPException(
                400,
                "Encryption requested but no password provided. "
                "Set encrypt_password (new) or reuse_password_id (existing).",
            )

        zip_out = out_dir / f"{stem}.zip"
        files_to_zip = [docx_out]
        if pdf_path:
            files_to_zip.append(pdf_path)
        try:
            _enc.build_encrypted_zip(
                files=files_to_zip,
                output_path=zip_out,
                password=plaintext_pw,
            )
            zip_path = zip_out
        except Exception as e:
            import logging as _log_r
            _log_r.getLogger(__name__).exception("Encrypted ZIP build failed for version %s", vid)
            raise HTTPException(500, "Failed to build encrypted archive. Please try again.")

        # Remember the zip path on the parent Report so the download
        # endpoint can find it. (ReportVersion has no JSON column — we
        # piggy-back on Report.details to avoid a schema migration.)
        rep_details = dict(rv.report.details or {})
        zips = dict(rep_details.get("encrypted_zips") or {})
        zips[str(rv.id)] = {
            "path": str(zip_out),
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "by_user_id": user.id,
            "from_password_id": payload.reuse_password_id,
        }
        rep_details["encrypted_zips"] = zips
        rv.report.details = rep_details
        flag_modified(rv.report, "details")

        # Save / touch the project-scoped password record so siblings can reuse it.
        if payload.reuse_password_id:
            _enc.touch_project_password(project, payload.reuse_password_id, rv.report.id)
            flag_modified(project, "details")
            saved_password_id = payload.reuse_password_id
        elif payload.encrypt_save_password and plaintext_pw:
            rec = _enc.save_project_password(
                project, plaintext_pw,
                label=payload.encrypt_password_label,
                user_id=user.id,
                report_id=rv.report.id,
            )
            flag_modified(project, "details")
            saved_password_id = rec["id"]

    _audit(db, user, "report.generate", "report_version", rv.id,
           {"version": rv.version, "is_draft": payload.is_draft,
            "pdf": bool(pdf_path), "encrypted": bool(zip_path),
            "saved_password_id": saved_password_id})
    db.commit()

    return {
        "version_id": rv.id,
        "version": rv.version,
        "docx_path": str(docx_out),
        "pdf_path": str(pdf_path) if pdf_path else None,
        "zip_path": str(zip_path) if zip_path else None,
        "saved_password_id": saved_password_id,
    }


@router.post("/versions/{vid}/preview")
def preview(vid: int,
            fmt: str = Query("pdf", pattern="^(docx|pdf)$"),
            force_draft: bool = Query(
                False,
                description=(
                    "When True, the preview is stamped with a DRAFT "
                    "watermark even if the version is approved / "
                    "published. Lets the consultant preview what the "
                    "deliverable WOULD look like with a watermark on "
                    "(e.g. for client expectation-setting) without "
                    "having to reopen the version as a draft. Defaults "
                    "to False — approved / published versions render "
                    "clean."
                ),
            ),
            db: Session = Depends(get_db),
            user: User = Depends(get_current_user)):
    """Render a transient DOCX for in-browser preview WITHOUT persisting it.

    Defaults to `fmt=pdf` so the browser renders the same pixels users will
    see in the final delivered file. PDF conversion goes through the same
    LibreOffice pipeline as Generate, which handles every DOCX feature
    (tables, headers/footers, embedded images, complex layouts) that the
    client-side docx-preview library struggles with.

    `fmt=docx` is retained for older callers and for clients that want to
    do their own rendering. Same pipeline either way:
      - never bumps the version
      - never writes to rv.generated_docx_path
      - always applies the DRAFT watermark
      - writes under REPORT_DIR/{rid}/.preview/{stem}.{docx|pdf}

    Requires `view` access — read-only operation from the user's perspective.
    """
    import tempfile

    rv = _require_version_with_access(db, vid, user, need=AccessLevel.view)

    from ..services.template_resolver import resolve_template_path
    try:
        template_path = resolve_template_path(db, rv.report)
    except FileNotFoundError as e:
        import logging as _log_r
        _log_r.getLogger(__name__).error("Template not found for preview of version %s: %s", vid, e)
        raise HTTPException(500, "Report template not available. Contact an administrator.")
    if not template_path.exists():
        import logging as _log_r
        _log_r.getLogger(__name__).error("Template file missing on disk for preview: %s", template_path)
        raise HTTPException(500, "Report template not available. Contact an administrator.")

    context = _build_context(rv, db)

    # Preview area is per-user so two people previewing don't overwrite each
    # other's file in flight. Keep it in REPORT_DIR (already volume-mounted in
    # docker-compose) so the cleanup path is bounded.
    preview_dir = Path(settings.REPORT_DIR) / str(rv.report_id) / ".preview"
    preview_dir.mkdir(parents=True, exist_ok=True)
    stem = f"preview_v{rv.version}_u{user.id}"
    docx_out = preview_dir / f"{stem}.docx"

    # Severity chart (best-effort, same as generate)
    from ..services.severity_chart import render_severity_chart
    chart_path = preview_dir / f"{stem}_severity_chart.png"
    try:
        render_severity_chart(context["severity_counts"], chart_path)
        context["severity_chart_path"] = str(chart_path)
    except Exception:
        context["severity_chart_path"] = None

    # Preview's DRAFT watermark mirrors the same rules Generate uses,
    # so what the consultant SEES in the preview matches what they'd
    # ship from a real generate. Specifically:
    #   * approved / published → no watermark (sign-off was given,
    #     the preview is now a "look at the final" preview).
    #   * everything else      → watermark (work in progress).
    #   * `?force_draft=true`  → admin override that stamps DRAFT
    #     regardless of state, for the case where a consultant wants
    #     to see what a watermarked version looks like AFTER
    #     approval (e.g. to show the client what they'd ship if it
    #     hadn't been signed off yet).
    # Earlier this was always-watermarked, which surprised consultants
    # who'd approved a report and then expected the preview to flip
    # to a clean view — the only way to verify the clean output was
    # to run Generate.
    approved = rv.review_status in (
        ReportReviewStatus.approved, ReportReviewStatus.published,
    )
    preview_is_draft = (not approved) or force_draft
    # See the matching capture in `generate()` — render_report pops
    # `_embed_attachments` from the context, so we have to grab the
    # list before the call to use it for the PDF post-pass below.
    preview_attachments = list(context.get("_embed_attachments") or []) \
        if isinstance(context, dict) else []
    try:
        render_report(
            template_path=template_path,
            output_path=docx_out,
            context=context,
            is_draft=preview_is_draft,
        )
    except Exception as e:
        _logger.exception("Preview render failed for version %s (template=%s)", vid, template_path.name)
        # Provide template authoring hints derived from pattern-matching only —
        # never expose the raw exception class or message in the HTTP response.
        emsg = str(e)
        hint = ""
        low = emsg.lower()
        if "raw directive" in low:
            hint = (" — Your Word template has an unmatched '{% raw %}' tag. "
                    "If you copied placeholder examples from the docs page, "
                    "delete the '{% raw %}' / '{% endraw %}' wrappers (those "
                    "are only for the web display) and keep the bare "
                    "'{{ placeholder }}' text.")
        elif "unknown tag" in low or "expected token" in low:
            hint = (" — Your Word template likely has a malformed Jinja "
                    "tag. Open the template in Word, check every "
                    "'{% … %}' / '{{ … }}' for typos or stray formatting.")
        elif "undefinederror" in low or "is undefined" in low:
            hint = (" — Your template references a placeholder we don't "
                    "fill. See the Template Instructions modal for the "
                    "exact set of supported placeholders.")
        raise HTTPException(
            500,
            f"Preview render failed: template error{hint}",
        )

    # Convert to PDF via LibreOffice when requested (default). This is the
    # only path that reliably renders every DOCX feature — client-side
    # libraries miss tables, headers/footers, and image positioning.
    # `draft_watermark=True` stamps a DRAFT overlay on every page after
    # conversion; the in-DOCX VML watermark isn't reliably rendered by
    # LibreOffice so we belt-and-braces it on the PDF side.
    if fmt == "pdf":
        try:
            # Mirror the docx render: an approved/published preview
            # exports a clean PDF (no overlay); everything else gets
            # the DRAFT belt-and-braces. `convert_to_pdf` already
            # skips the overlay when the docx contains the VML
            # watermark, so a draft preview produces exactly one
            # DRAFT — not two stacked.
            pdf_out = convert_to_pdf(
                docx_out, preview_dir, draft_watermark=preview_is_draft,
            )
        except Exception as e:
            _logger.exception("Preview PDF conversion failed for version %s", vid)
            raise HTTPException(500, "PDF conversion failed. Please try again or contact an administrator.")
        # Same PDF attachment post-pass as Generate. Non-fatal — a
        # failed attachment shouldn't block the preview from rendering.
        if preview_attachments:
            try:
                from ..services.docx_attachments import embed_pdf_attachments
                embed_pdf_attachments(pdf_out, preview_attachments)
            except Exception as e:
                import logging
                logging.getLogger(__name__).warning(
                    "Preview PDF attachment post-pass failed (non-fatal): %s", e
                )
        _audit(db, user, "report.preview", "report_version", rv.id,
               {"version": rv.version, "fmt": "pdf"})
        db.commit()
        return FileResponse(
            pdf_out,
            media_type="application/pdf",
            filename=pdf_out.name,
            content_disposition_type="inline",
        )

    # Audit log entry (helps spot abuse: someone repeatedly previewing without ever generating)
    _audit(db, user, "report.preview", "report_version", rv.id,
           {"version": rv.version, "fmt": "docx"})
    db.commit()

    return FileResponse(
        docx_out,
        media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        filename=docx_out.name,
    )


@router.get("/versions/{vid}/download")
def download(vid: int, fmt: str = Query("docx", pattern="^(docx|pdf|zip)$"),
             db: Session = Depends(get_db),
             user: User = Depends(get_current_user)):
    rv = _require_version_with_access(db, vid, user, need=AccessLevel.view)

    if fmt == "zip":
        # Encrypted ZIPs live on Report.details (no per-version column).
        zips = (rv.report.details or {}).get("encrypted_zips") or {}
        rec = zips.get(str(rv.id))
        if not rec or not rec.get("path"):
            raise HTTPException(404, "No encrypted ZIP exists for this version")
        p = Path(rec["path"])
        if not p.exists():
            raise HTTPException(410, "Encrypted ZIP is missing on disk")
        return FileResponse(p, media_type="application/zip", filename=p.name)

    path_str = rv.generated_docx_path if fmt == "docx" else rv.generated_pdf_path
    if not path_str:
        raise HTTPException(404, f"No {fmt} generated for this version")
    p = Path(path_str)
    if not p.exists():
        raise HTTPException(410, "Generated file is missing on disk")
    media = (
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        if fmt == "docx" else "application/pdf"
    )
    return FileResponse(p, media_type=media, filename=p.name)


# ============================================================
# Free Edit — out-of-template DOCX adjustments
# ============================================================
#
# Two flows:
#   1. "Edit in browser" — server converts the generated DOCX to HTML
#      (services.free_edit_docx.docx_to_html), the user edits it in a
#      contenteditable, the server converts it back to DOCX
#      (services.free_edit_docx.html_to_docx) and replaces the version's
#      generated_docx_path.
#   2. "Edit in Word" — user downloads the existing generated DOCX,
#      edits it locally, and re-uploads it via the multipart endpoint
#      below. The new file replaces generated_docx_path.
#
# Either flow stamps `details.free_edited_at` on the report so the audit
# trail records that the deliverable was hand-finished. Regenerate-from-
# template ("Generate" button) wipes this back, which is intentional —
# regeneration recovers the canonical template output.


def _free_edit_target_path(rv: ReportVersion) -> Path:
    """Output path for a free-edit DOCX. Lives alongside the version's
    other generated artefacts so existing cleanup / download logic stays
    intact. We do NOT reuse the original generated_docx_path so that an
    in-flight render isn't trampled mid-write."""
    out_dir = Path(settings.REPORT_DIR) / str(rv.report_id)
    out_dir.mkdir(parents=True, exist_ok=True)
    return out_dir / f"v{rv.version}_freeedit_{uuid.uuid4().hex[:8]}.docx"


@router.get("/versions/{vid}/freedit/html")
def freedit_get_html(vid: int,
                     db: Session = Depends(get_db),
                     user: User = Depends(get_current_user)):
    """Return the version's current generated DOCX rendered as editable
    HTML. 404 if no DOCX has been generated yet — the UI surfaces this
    as "Generate the report first".
    """
    rv = _require_version_with_access(db, vid, user, need=AccessLevel.edit)
    if not rv.generated_docx_path:
        raise HTTPException(404, "Generate the report first — there's no DOCX to edit yet.")
    src = Path(rv.generated_docx_path)
    if not src.exists():
        raise HTTPException(410, "Generated DOCX is missing on disk. Re-run Generate.")
    from ..services.free_edit_docx import docx_to_html
    try:
        html_str = docx_to_html(src)
    except Exception as e:                          # pragma: no cover
        _logger.exception("DOCX-to-HTML conversion failed for version %s", vid)
        raise HTTPException(500, "Could not convert DOCX to HTML. Please try again or contact an administrator.")
    from fastapi.responses import Response
    return Response(content=html_str, media_type="text/html; charset=utf-8")


class _FreeEditHtmlPayload(BaseModel):
    html: str
    notes: Optional[str] = None


@router.post("/versions/{vid}/freedit/html")
def freedit_save_html(vid: int,
                      payload: _FreeEditHtmlPayload,
                      db: Session = Depends(get_db),
                      user: User = Depends(get_current_user)):
    """Convert the submitted HTML back into a fresh .docx and store it
    as the version's generated_docx_path. The old generated docx is
    left in place under its previous name; future "Generate" calls will
    overwrite generated_docx_path with the template-rendered output."""
    rv = _require_version_with_access(db, vid, user, need=AccessLevel.edit)
    from ..services.free_edit_docx import html_to_docx
    out_path = _free_edit_target_path(rv)
    try:
        html_to_docx(payload.html or "", out_path)
    except Exception as e:                          # pragma: no cover
        _logger.exception("HTML-to-DOCX conversion failed for version %s", vid)
        raise HTTPException(500, "Could not save the edited DOCX. Please try again or contact an administrator.")
    rv.generated_docx_path = str(out_path)
    # Invalidate any cached PDF — it was rendered from the previous DOCX.
    rv.generated_pdf_path = None
    # Stamp the report so reviewers / future maintainers can see the
    # deliverable was hand-finished outside the template renderer.
    rep_details = dict(rv.report.details or {})
    rep_details["free_edited_at"] = datetime.utcnow().isoformat()
    rep_details["free_edited_by_id"] = user.id
    rep_details["free_edited_version"] = rv.version
    rv.report.details = rep_details
    flag_modified(rv.report, "details")
    _audit(db, user, "report.version.freedit_html", "report_version", rv.id,
           {"notes": payload.notes or ""})
    db.commit()
    return {"ok": True, "docx_path": str(out_path),
            "report_id": rv.report_id, "version_id": rv.id}


@router.post("/versions/{vid}/freedit/upload")
def freedit_upload_docx(vid: int,
                        file: UploadFile = File(...),
                        notes: Optional[str] = Form(None),
                        db: Session = Depends(get_db),
                        user: User = Depends(get_current_user)):
    """Replace the version's generated DOCX with an externally-edited one
    (user downloaded the DOCX, edited it in Word, and re-uploaded). The
    uploaded file must be a .docx — we don't try to convert .doc /
    other formats here because the user always downloaded a .docx in
    the first place."""
    rv = _require_version_with_access(db, vid, user, need=AccessLevel.edit)
    if not (file.filename or "").lower().endswith(".docx"):
        raise HTTPException(400, "Free-edit re-upload must be a .docx file.")
    out_path = _free_edit_target_path(rv)
    size = _stream_save(file.file, out_path, max_bytes=_MAX_FREEDIT_DOCX_BYTES)
    rv.generated_docx_path = str(out_path)
    rv.generated_pdf_path = None
    rep_details = dict(rv.report.details or {})
    rep_details["free_edited_at"] = datetime.utcnow().isoformat()
    rep_details["free_edited_by_id"] = user.id
    rep_details["free_edited_version"] = rv.version
    rep_details["free_edited_mode"] = "word_upload"
    rv.report.details = rep_details
    flag_modified(rv.report, "details")
    _audit(db, user, "report.version.freedit_upload", "report_version", rv.id,
           {"size": size, "notes": notes or ""})
    db.commit()
    return {"ok": True, "docx_path": str(out_path),
            "report_id": rv.report_id, "version_id": rv.id,
            "size": size}


# ============================================================
# Project-scoped stored ZIP passwords
# ============================================================
# Reuse across sibling reports of the same engagement. The plaintext is
# Fernet-encrypted with a key derived from settings.SECRET_KEY; only the
# *label* and *metadata* are returned to the browser.

# ============================================================
# Review workflow
# ============================================================
# Lifecycle: draft -> in_review -> (approved | rejected) -> draft/published
# (See ReportReviewStatus in models.py for full semantics.) The DRAFT
# watermark in the generated DOCX is forced ON whenever a version is
# in_review, regardless of the consultant's `is_draft` choice.

class SubmitReviewBody(BaseModel):
    reviewer_id: int
    notes: Optional[str] = None
    # Allow the consultant to override the placeholder-token gate (e.g. a
    # finding intentionally references a bracketed term). Defaults False so
    # the gate is on for every honest submission.
    bypass_placeholder_gate: bool = False


class ReviewDecisionBody(BaseModel):
    decision: str    # "approve" | "reject"
    notes: Optional[str] = None
    publish: bool = False   # if approving, optionally lock as published
    bypass_placeholder_gate: bool = False  # reviewer escape hatch (audited)


@router.get("/review-queue")
def list_review_queue(db: Session = Depends(get_db),
                      user: User = Depends(get_current_user)):
    """Reports awaiting review.

    Every authenticated user calls this from the Reviews page —
    consultants and admins alike. The response is split into:

      * ``assigned`` — versions where ``reviewer_id == user.id`` and
        status is ``in_review``. The user is the named reviewer and
        can approve / reject directly.
      * ``all`` — admin/senior only: every other version in
        ``in_review`` so the team lead can see the full queue and
        cover for a reviewer who's out. Empty for plain consultants.

    Each entry carries enough metadata for the page to render a row
    without a second round-trip — report name, version, submitter,
    submitted-at, and the link target.
    """
    def _serialise(rv: ReportVersion) -> dict:
        r = rv.report
        submitter_user = db.get(User, r.created_by_id) if r and r.created_by_id else None
        return {
            "version_id": rv.id,
            "report_id":  rv.report_id,
            "report_name": r.name if r else "(unknown)",
            "version":    rv.version,
            "review_status": rv.review_status,
            "submitted_at": rv.submitted_for_review_at.isoformat() + "Z"
                            if rv.submitted_for_review_at else None,
            "reviewer_id":   rv.reviewer_id,
            "reviewer_username": (db.get(User, rv.reviewer_id).username
                                  if rv.reviewer_id else None),
            "submitter_username": submitter_user.username if submitter_user else None,
            "notes": rv.review_notes or "",
        }

    in_review_q = db.query(ReportVersion).filter(
        ReportVersion.review_status == ReportReviewStatus.in_review.value
    ).order_by(ReportVersion.submitted_for_review_at.desc().nullslast())

    assigned = [_serialise(rv) for rv in in_review_q
                if rv.reviewer_id == user.id]

    is_admin_or_senior = user.role in (Role.admin, Role.senior)
    all_pending: list[dict] = []
    if is_admin_or_senior:
        all_pending = [_serialise(rv) for rv in in_review_q
                       if rv.reviewer_id != user.id]

    return {
        "assigned": assigned,
        "all":       all_pending,
        "is_admin_or_senior": is_admin_or_senior,
    }


@router.post("/versions/{vid}/submit-review")
def submit_for_review(vid: int, body: SubmitReviewBody,
                       db: Session = Depends(get_db),
                       user: User = Depends(get_current_user)):
    """Consultant submits this version for senior review.

    The version's review_status flips to `in_review` and any subsequent
    Generate calls inject the DRAFT watermark even if the consultant
    untiqued `is_draft`. The reviewer can approve (status -> approved)
    or reject (status -> rejected, sends it back).
    """
    rv = _require_version_with_access(db, vid, user, need=AccessLevel.edit)
    if rv.review_status == ReportReviewStatus.in_review:
        raise HTTPException(400, "Already under review")
    reviewer = db.get(User, body.reviewer_id)
    if not reviewer or not reviewer.is_active:
        raise HTTPException(404, "Reviewer not found")
    if reviewer.id == user.id:
        raise HTTPException(400, "Pick someone other than yourself as the reviewer")
    # Peer review is allowed — any active user can be picked as a
    # reviewer. We used to limit this to admin/senior, but the team
    # wanted consultants to be able to sign off on each other's
    # reports too. The reviewer's role is recorded in the audit log,
    # so a peer-approved report is still traceable.

    # Placeholder gate: refuse to submit if any finding still contains
    # unresolved template tokens (e.g. "[DESCRIBE HOW THIS WAS PERFORMED]").
    # The consultant has to either fix them or set bypass_placeholder_gate=True
    # — which is recorded in the audit log so a reviewer can hold them to it.
    if not body.bypass_placeholder_gate:
        ph = _ph_check.summarise_unresolved(rv.findings)
        if not ph["all_ok"]:
            raise HTTPException(400, detail={
                "error": "unresolved_placeholders",
                "message": (f"{ph['blocker_count']} finding(s) still contain unresolved "
                            "template tokens. Resolve them or pass bypass_placeholder_gate=true "
                            "to submit anyway."),
                "blocker_titles": ph["blocker_titles"],
                "findings": ph["findings"],
            })

    rv.review_status = ReportReviewStatus.in_review.value
    rv.reviewer_id = reviewer.id
    rv.submitted_for_review_at = datetime.utcnow()
    rv.review_decision_at = None
    if body.notes is not None:
        rv.review_notes = body.notes

    _audit(db, user, "report.review.submitted", "report_version", rv.id,
           {"reviewer_id": reviewer.id, "version": rv.version})
    db.commit()
    return {
        "ok": True,
        "review_status": rv.review_status,
        "reviewer_id": reviewer.id,
        "reviewer_username": reviewer.username,
        "submitted_for_review_at": rv.submitted_for_review_at.isoformat() + "Z",
    }


@router.post("/versions/{vid}/review-decision")
def review_decision(vid: int, body: ReviewDecisionBody,
                     db: Session = Depends(get_db),
                     user: User = Depends(get_current_user)):
    """Reviewer signs off on (or rejects) a version that was submitted to
    them. Only the assigned reviewer, an admin, or a senior can act on
    behalf of the assigned reviewer if needed.
    """
    rv = _require_version_with_access(db, vid, user, need=AccessLevel.view)
    if rv.review_status != ReportReviewStatus.in_review:
        raise HTTPException(400, "Version is not currently in review")
    # Peer review: the assigned reviewer can decide regardless of role.
    # Admins can also override on behalf of any reviewer (useful when
    # the assigned reviewer is unavailable). Seniors retain the
    # historical "act-for" capability for backward compatibility.
    is_assigned = (rv.reviewer_id == user.id)
    if not is_assigned and user.role not in (Role.admin, Role.senior):
        raise HTTPException(403, "Only the assigned reviewer (or admin/senior) can decide")

    decision = (body.decision or "").lower()
    # Approval/publish path is the last line of defence — refuse unless the
    # findings are clean (or the reviewer explicitly bypasses, which we audit).
    if decision == "approve" and not body.bypass_placeholder_gate:
        ph = _ph_check.summarise_unresolved(rv.findings)
        if not ph["all_ok"]:
            raise HTTPException(400, detail={
                "error": "unresolved_placeholders",
                "message": (f"Cannot approve — {ph['blocker_count']} finding(s) still "
                            "contain unresolved template tokens."),
                "blocker_titles": ph["blocker_titles"],
                "findings": ph["findings"],
            })
    if decision == "approve":
        rv.review_status = (ReportReviewStatus.published.value if body.publish
                            else ReportReviewStatus.approved.value)
        # Approved + not published => back to a workable state; the
        # consultant can keep editing the version or bump to a new one.
        # Published => watermark suppressed on next Generate.
    elif decision == "reject":
        rv.review_status = ReportReviewStatus.rejected.value
    else:
        raise HTTPException(400, "decision must be 'approve' or 'reject'")
    rv.review_decision_at = datetime.utcnow()
    if body.notes is not None:
        # Append rather than overwrite so the consultant's submit-notes
        # stay visible alongside the reviewer's response.
        prefix = (rv.review_notes + "\n\n") if rv.review_notes else ""
        rv.review_notes = prefix + f"[reviewer @ {user.username}] " + body.notes

    _audit(db, user, "report.review.decision", "report_version", rv.id,
           {"decision": decision,
            "new_status": rv.review_status,
            "version": rv.version})
    db.commit()

    # Best-effort approval notification to the report owner. Only fires
    # on approve/publish; rejection notices stay in-app (the consultant
    # is going to see the rejected state next time they open the report
    # and reviewer comments live in `rv.review_notes`). Routed through
    # `notify_user` so the owner's email-opt-out preference applies.
    if decision == "approve":
        from ..services.notifier import notify_user
        from ..services.url_helpers import absolute_url
        report = db.get(Report, rv.report_id)
        owner = db.get(User, report.created_by_id) if report else None
        notify_user(
            db, owner, "report_version_approved", {
                "user": owner,
                "reviewer_username": user.username,
                "report_name": report.name if report else "",
                "version": rv.version,
                "review_notes": rv.review_notes or "",
                "published": (rv.review_status
                               == ReportReviewStatus.published.value),
                "report_url": absolute_url(
                    f"/reports/{report.id}" if report else "/reports"),
            },
            actor_user_id=user.id,
        )

    return {
        "ok": True,
        "review_status": rv.review_status,
        "review_decision_at": rv.review_decision_at.isoformat() + "Z",
    }


@router.post("/versions/{vid}/reopen-draft")
def reopen_draft(vid: int,
                  confirm_unpublish: bool = Query(
                      False,
                      description=(
                          "Required when reopening a PUBLISHED version. "
                          "Forces the caller to acknowledge they're "
                          "unlocking an immutable-final artefact. The "
                          "transition is audited as `was_published=true`."
                      ),
                  ),
                  db: Session = Depends(get_db),
                  user: User = Depends(get_current_user)):
    """Revert a version back to draft so the consultant can keep working.

    Behaviour by current state:
      * draft           → no-op (already a draft)
      * in_review       → reset to draft (cancels the pending review)
      * approved        → reset to draft (lifts the watermark suppression)
      * rejected        → reset to draft (so the consultant can iterate)
      * published       → ONLY when `?confirm_unpublish=true` is passed.
                          Published was previously locked, but the team
                          needs an explicit escape hatch (e.g. delete an
                          old published version, fix a typo on an already-
                          delivered report). Every published-→-draft
                          transition is recorded in the audit log with
                          `was_published=true` so the lineage is preserved.

    Edit access on the parent report is required for every transition.
    Unpublishing carries the same gate — there is no separate
    admin-only path because deletion (which is the usual reason to
    unpublish) is already edit-gated. The `confirm_unpublish` param is
    the safety belt against accidental clicks, not a role check.
    """
    rv = _require_version_with_access(db, vid, user, need=AccessLevel.edit)
    was_published = (rv.review_status == ReportReviewStatus.published.value)
    if was_published and not confirm_unpublish:
        raise HTTPException(
            400,
            "Version is PUBLISHED. Pass `?confirm_unpublish=true` to "
            "explicitly unlock the immutable-final artefact (the "
            "transition is audited).",
        )
    rv.review_status = ReportReviewStatus.draft.value
    _audit(db, user, "report.review.reopened", "report_version", rv.id,
           {"version": rv.version, "was_published": was_published})
    db.commit()
    return {
        "ok": True,
        "review_status": rv.review_status,
        "was_published": was_published,
    }


# Lives under /api/reports/projects/{pid}/passwords to stay within this
# router's prefix without colliding with /api/projects/{pid}/... in the
# projects router. The frontend treats the prefix opaquely.

@router.get("/projects/{pid}/passwords")
def list_report_passwords(pid: int, db: Session = Depends(get_db),
                           user: User = Depends(get_current_user)):
    """List the saved ZIP passwords for a project. Ciphertext NOT returned."""
    project = db.get(Project, pid)
    if not project:
        raise HTTPException(404, "Project not found")
    # Anyone with visibility on any report in the project may list. Cheap check:
    # user must either be admin/senior, project lead, or have a report grant in
    # the project. (We use the same effective_access logic via the project's
    # first report if there is one, else fall back to lead/admin.)
    if user.role not in (Role.admin, Role.senior) and project.lead_id != user.id:
        # Look for any report in the project the user can see
        from .permissions import effective_access as _ea
        visible = False
        for r in (project.reports or []):
            if _ea(db, user, r) is not None:
                visible = True
                break
        if not visible:
            raise HTTPException(403, "Not a member of this project")
    return {"project_id": pid, "items": _enc.list_project_passwords(project)}


@router.delete("/projects/{pid}/passwords/{password_id}")
def delete_report_password(pid: int, password_id: str,
                            db: Session = Depends(get_db),
                            user: User = Depends(get_current_user)):
    """Remove a stored password. Lead/senior/admin only."""
    project = db.get(Project, pid)
    if not project:
        raise HTTPException(404, "Project not found")
    if user.role not in (Role.admin, Role.senior) and project.lead_id != user.id:
        raise HTTPException(403, "Only project lead or senior+ can delete passwords")
    removed = _enc.delete_project_password(project, password_id)
    if not removed:
        raise HTTPException(404, "Password id not found")
    flag_modified(project, "details")
    _audit(db, user, "project.report_password.delete", "project", pid,
           {"password_id": password_id})
    db.commit()
    return {"ok": True, "deleted_id": password_id}
