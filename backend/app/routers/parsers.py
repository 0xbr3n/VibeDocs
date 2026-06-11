"""
Scan import endpoints (Nessus CSV, Nmap XML/greppable).

Nessus flow:
  1. Tester uploads a CSV.
  2. We parse + group findings.
  3. We diff against existing Nessus-sourced findings already attached to the target version.
       - Things still present: kept (left untouched)
       - Things gone: status auto-set to 'Closed' on existing findings
       - Things new: created as ReportFinding rows
  4. We also offer to update the project scope to the IPs we observed.
     The choice ('keep' / 'update' / 'merge') is supplied by the caller.

Nmap flow:
  1. Tester uploads XML or greppable file.
  2. We parse a flat ports table.
  3. We store it on the ScanImport row. When the report is generated, the docx_generator
     looks for the latest nmap ScanImport for the project and injects it into the template.
"""
from pathlib import Path
import uuid
import logging as _log_parsers

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form
from sqlalchemy.orm import Session

_logger = _log_parsers.getLogger(__name__)

from ..database import get_db
from ..config import settings
from ..models import (
    Project, ReportVersion, ReportFinding, ScanImport,
    Severity, FindingStatus, User, Role,
)
from ..auth import get_current_user
from ..services import nessus_parser, nmap_parser
from ..services import cloud_parsers as _cloud_parsers
from ..services import cloud_pipeline as _cloud_pipeline
from .permissions import require_access, AccessLevel

router = APIRouter(prefix="/api/scans", tags=["scans"])

# Nessus exports can have verbose plugin output — 50 MB is generous.
# Nmap files are plain text; 10 MB covers even very large scans.
_MAX_NESSUS_BYTES = 50 * 1024 * 1024
_MAX_NMAP_BYTES   = 10 * 1024 * 1024
_CHUNK = 64 * 1024

_NMAP_ALLOWED_EXT = {".xml", ".txt", ".nmap", ".gnmap", ".log"}


def _save_upload(upload: UploadFile, subdir: str, max_bytes: int | None = None) -> Path:
    target = Path(settings.UPLOAD_DIR) / subdir
    target.mkdir(parents=True, exist_ok=True)
    # Strip any directory components from the uploaded filename so a
    # path like "../../etc/passwd" can't traverse outside the target dir.
    safe = f"{uuid.uuid4().hex}__{Path(upload.filename or 'upload').name}"
    dest = target / safe
    total = 0
    try:
        with dest.open("wb") as out:
            while True:
                chunk = upload.file.read(_CHUNK)
                if not chunk:
                    break
                total += len(chunk)
                if max_bytes and total > max_bytes:
                    dest.unlink(missing_ok=True)
                    raise HTTPException(
                        413,
                        f"Upload exceeds the {max_bytes // (1024 * 1024)} MB limit.",
                    )
                out.write(chunk)
    except HTTPException:
        raise
    except Exception as exc:
        dest.unlink(missing_ok=True)
        _logger.exception("Failed to save upload to %s", dest)
        raise HTTPException(500, "Failed to save the uploaded file. Please try again.") from exc
    return dest


@router.post("/nessus")
def import_nessus(
    project_id: int = Form(...),
    report_version_id: int = Form(...),
    scope_action: str = Form("keep"),  # keep | update | merge
    # Multi-file upload. Each file is a separate Nessus CSV (typical
    # use case: internal + external scans of the same engagement, or
    # per-segment exports split into multiple files). The endpoint
    # parses each, takes the UNION of every row, then runs the diff
    # against existing findings ONCE. Backwards-compatible: a single
    # file still works because `files` accepts a list-of-one.
    files: list[UploadFile] = File(...),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    project = db.get(Project, project_id)
    rv = db.get(ReportVersion, report_version_id)
    if not project or not rv:
        raise HTTPException(404, "Project or report version not found")
    if rv.report.project_id != project.id:
        raise HTTPException(400, "Report version does not belong to this project")
    require_access(db, user, rv.report, need=AccessLevel.edit)
    if not files:
        raise HTTPException(400, "Upload at least one Nessus CSV file")
    _NESSUS_ALLOWED_EXT = {".csv", ".xlsx", ".xls"}
    for f in files:
        ext = Path(f.filename or "upload").suffix.lower()
        if ext not in _NESSUS_ALLOWED_EXT:
            raise HTTPException(
                400,
                f"Nessus import requires CSV or Excel files — {f.filename!r} is not allowed.",
            )

    # Parse every uploaded file and concatenate their rows. Each file
    # is stored separately on disk so the audit trail keeps every
    # upload identifiable. The first stored path is recorded on the
    # `ScanImport.stored_path` column (legacy single-path field);
    # every path is also listed under `summary.uploaded_files` so
    # multi-file imports remain inspectable later.
    all_rows: list = []
    per_file: list[dict] = []
    stored_paths: list[Path] = []
    for f in files:
        stored = _save_upload(f, subdir=f"nessus/{project_id}", max_bytes=_MAX_NESSUS_BYTES)
        stored_paths.append(stored)
        try:
            rows_one = nessus_parser.parse_nessus_csv(stored)
        except Exception as exc:
            _logger.warning("Nessus parse failed for file %r: %s", f.filename, exc)
            raise HTTPException(400, f"Could not parse {f.filename!r}. Please ensure it is a valid Nessus CSV or Excel export.") from exc
        all_rows.extend(rows_one)
        per_file.append({
            "filename": f.filename,
            "stored_path": str(stored),
            "rows": len(rows_one),
            "hosts": len({r.host for r in rows_one if r.host}),
        })

    rows = all_rows
    groups = nessus_parser.group_findings(rows)

    # Diff vs existing — works against the UNION so a finding seen in
    # ANY uploaded file counts as "still present".
    to_create, to_auto_close, kept = nessus_parser.diff_against_existing(
        groups, rv.findings
    )

    # Auto-close findings no longer present
    auto_closed_titles = []
    for ef in to_auto_close:
        ef.status = FindingStatus.closed
        ef.retest_notes = (
            (ef.retest_notes or "")
            + "\nAuto-closed: not present in latest Nessus scan."
        ).strip()
        auto_closed_titles.append(ef.title)

    # Create new ones
    created_titles = []
    for g in to_create:
        payload = g.to_report_finding_payload()
        f = ReportFinding(
            report_version_id=rv.id,
            title=payload["title"],
            description=payload["description"],
            impact=payload["impact"],
            remediation=payload["remediation"],
            references=payload["references"],
            affected_asset=payload["affected_asset"],
            severity=Severity(payload["severity"]),
            cvss_score=payload["cvss_score"],
            status=FindingStatus.open,
            added_by_id=user.id,
            source="nessus",
            source_ref=payload["source_ref"],
        )
        db.add(f)
        created_titles.append(payload["title"])

    # Scope handling — observed_hosts is the union across all uploads.
    observed_hosts = sorted({r.host for r in rows if r.host})
    scope_change = {"action": scope_action, "observed_hosts": observed_hosts}
    if scope_action == "update":
        project.scope_targets = observed_hosts
    elif scope_action == "merge":
        merged = sorted(set((project.scope_targets or []) + observed_hosts))
        project.scope_targets = merged
    # 'keep' = no-op

    summary = {
        "files": len(files),
        "rows": len(rows),
        "hosts": len(observed_hosts),
        "groups_in_scan": len(groups),
        "created": len(created_titles),
        "auto_closed": len(auto_closed_titles),
        "kept": len(kept),
        "uploaded_files": per_file,
    }

    # Use a `+`-joined filename when multiple files come in so the
    # audit row still shows what was uploaded at a glance. Cap at
    # ~500 chars (the column's width) to stay safe.
    combined_name = " + ".join(f.filename or "(unnamed)" for f in files)
    if len(combined_name) > 480:
        combined_name = (
            (files[0].filename or "(unnamed)") + f" (+{len(files) - 1} more)"
        )

    si = ScanImport(
        project_id=project.id,
        report_version_id=rv.id,
        scan_type="nessus",
        original_filename=combined_name,
        stored_path=str(stored_paths[0]) if stored_paths else None,
        uploaded_by_id=user.id,
        summary=summary,
        parsed_data={"scope_change": scope_change,
                      "stored_paths": [str(p) for p in stored_paths]},
    )
    db.add(si); db.commit(); db.refresh(si)

    return {
        "scan_import_id": si.id,
        "summary": summary,
        "scope_change": scope_change,
        "created_titles": created_titles,
        "auto_closed_titles": auto_closed_titles,
        "kept_titles": list(kept.values()),
    }


@router.post("/nmap")
def import_nmap(
    project_id: int = Form(...),
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    project = db.get(Project, project_id)
    if not project:
        raise HTTPException(404, "Project not found")
    if user.role not in (Role.admin, Role.senior) and project.lead_id != user.id:
        # Nmap imports are project-level (no report version scoping). Require
        # at least project-lead status or admin/senior to import scan data.
        from ..models import Report as _Report
        accessible = (
            db.query(_Report.id)
              .filter(_Report.project_id == project.id,
                      _Report.created_by_id == user.id)
              .limit(1).scalar()
        )
        if not accessible:
            raise HTTPException(403, "You do not have access to this project")

    ext = Path(file.filename or "upload").suffix.lower()
    if ext not in _NMAP_ALLOWED_EXT:
        raise HTTPException(
            400,
            f"Nmap import requires an XML, txt, .nmap, or .gnmap file — {file.filename!r} is not allowed.",
        )

    stored = _save_upload(file, subdir=f"nmap/{project_id}", max_bytes=_MAX_NMAP_BYTES)
    try:
        entries = nmap_parser.parse_nmap(stored)
    except Exception as exc:
        _logger.warning("Nmap parse failed for file %r: %s", file.filename, exc)
        raise HTTPException(400, "Could not parse the Nmap file. Please ensure it is a valid XML, txt, .nmap, or .gnmap output.") from exc
    summary = nmap_parser.summarise(entries)

    si = ScanImport(
        project_id=project.id,
        scan_type="nmap",
        original_filename=file.filename,
        stored_path=str(stored),
        uploaded_by_id=user.id,
        summary=summary,
        parsed_data={"ports": [e.to_dict() for e in entries]},
    )
    db.add(si); db.commit(); db.refresh(si)
    return {"scan_import_id": si.id, "summary": summary}


# ─────────────────────────────────────────────────────────────────────────────
# Cloud VA/VAPT import  (Prowler v3 CSV + Steampipe CIS benchmark CSV)
# ─────────────────────────────────────────────────────────────────────────────

_MAX_CLOUD_BYTES = 50 * 1024 * 1024   # 50 MB
_CLOUD_ALLOWED_EXT = {".csv", ".txt"}


@router.post("/cloud")
def import_cloud(
    project_id: int = Form(...),
    report_version_id: int = Form(...),
    files: list[UploadFile] = File(...),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Parse Prowler and/or Steampipe CIS CSV exports, group by AWS/Azure
    service, and upsert one ReportFinding per service onto the report version.

    Accepts multiple files in one call (e.g. Prowler L1 + Steampipe L2).
    Only FAIL/ALARM rows are imported; PASS/SKIP rows are discarded.
    Re-running this endpoint on the same report version is idempotent — existing
    cloud_pipeline findings for a service are updated in-place.

    Returns:
        {
          "scan_import_id": int,
          "summary": {
              "files": int, "total_findings": int, "services_found": [str],
              "groups_created": int, "groups_updated": int,
              "per_file": [{filename, rows, format}]
          },
          "pipeline": {
              "ok": True, "total_findings": int, "services": [...], ...
          }
        }
    """
    project = db.get(Project, project_id)
    rv      = db.get(ReportVersion, report_version_id)
    if not project or not rv:
        raise HTTPException(404, "Project or report version not found")
    if rv.report.project_id != project.id:
        raise HTTPException(400, "Report version does not belong to this project")
    require_access(db, user, rv.report, need=AccessLevel.edit)
    if not files:
        raise HTTPException(400, "Upload at least one cloud CSV file")

    for f in files:
        ext = Path(f.filename or "upload").suffix.lower()
        if ext not in _CLOUD_ALLOWED_EXT:
            raise HTTPException(
                400,
                f"Cloud import requires CSV files — {f.filename!r} is not allowed.",
            )

    all_findings: list = []
    per_file: list[dict] = []
    stored_paths: list[Path] = []

    for f in files:
        stored = _save_upload(
            f,
            subdir=f"cloud/{project_id}",
            max_bytes=_MAX_CLOUD_BYTES,
        )
        stored_paths.append(stored)
        content = stored.read_bytes()
        try:
            rows = _cloud_parsers.parse_cloud_csv(content, filename=f.filename or "")
        except Exception as exc:
            _logger.warning("Cloud parse failed for %r: %s", f.filename, exc)
            raise HTTPException(
                400,
                f"Could not parse {f.filename!r}. "
                "Please ensure it is a valid Prowler v3 CSV or Steampipe CIS benchmark CSV.",
            ) from exc
        fmt = rows[0].source if rows else "unknown"
        all_findings.extend(rows)
        per_file.append({
            "filename": f.filename,
            "stored_path": str(stored),
            "rows": len(rows),
            "format": fmt,
        })

    # Run the pipeline: group by service → upsert ReportFindings
    pipeline_result = _cloud_pipeline.run_cloud_pipeline(
        db, rv, user, all_findings
    )

    services_found = [s["service"] for s in pipeline_result.get("services", [])]

    summary = {
        "files":           len(files),
        "total_findings":  len(all_findings),
        "services_found":  services_found,
        "groups_created":  pipeline_result["groups_created"],
        "groups_updated":  pipeline_result["groups_updated"],
        "per_file":        per_file,
    }

    combined_name = " + ".join(f.filename or "(unnamed)" for f in files)
    if len(combined_name) > 480:
        combined_name = (files[0].filename or "(unnamed)") + f" (+{len(files) - 1} more)"

    si = ScanImport(
        project_id        = project.id,
        report_version_id = rv.id,
        scan_type         = "cloud",
        original_filename = combined_name,
        stored_path       = str(stored_paths[0]) if stored_paths else None,
        uploaded_by_id    = user.id,
        summary           = summary,
        parsed_data       = {
            "stored_paths": [str(p) for p in stored_paths],
            # Store individual findings so the cloud tracker export can
            # build per-service sheets without re-reading files from disk.
            "findings": [f.to_dict() for f in all_findings],
        },
    )
    db.add(si)
    db.commit()
    db.refresh(si)

    return {
        "scan_import_id": si.id,
        "summary":        summary,
        "pipeline":       pipeline_result,
    }


@router.post("/cloud/iam")
def import_cloud_iam(
    project_id: int = Form(...),
    report_version_id: int = Form(...),
    files: list[UploadFile] = File(...),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Store IAMActionHunter privilege-escalation CSV export(s) for a Cloud
    VA/VAPT report version.

    Unlike the Steampipe/Prowler scanner import, these CSVs are NOT parsed into
    findings — the cloud tracker export pastes each one verbatim into its own new
    worksheet (see services/tracker_iam.py). Re-uploading replaces the previous
    set (the export uses the most recent ``cloud_iam`` import for the version).

    Returns: {"scan_import_id": int, "summary": {files, per_file:[{filename, path, rows}]}}
    """
    import csv as _csv

    project = db.get(Project, project_id)
    rv      = db.get(ReportVersion, report_version_id)
    if not project or not rv:
        raise HTTPException(404, "Project or report version not found")
    if rv.report.project_id != project.id:
        raise HTTPException(400, "Report version does not belong to this project")
    require_access(db, user, rv.report, need=AccessLevel.edit)
    if not files:
        raise HTTPException(400, "Upload at least one IAMActionHunter CSV file")

    for f in files:
        ext = Path(f.filename or "upload").suffix.lower()
        if ext not in _CLOUD_ALLOWED_EXT:           # .csv / .txt
            raise HTTPException(
                400,
                f"IAMActionHunter import requires CSV files — {f.filename!r} is not allowed.",
            )

    csv_entries: list[dict] = []
    for f in files:
        stored = _save_upload(
            f, subdir=f"cloud/{project_id}/iam", max_bytes=_MAX_CLOUD_BYTES,
        )
        # Best-effort data-row count (excludes the header) for the UI summary.
        rows = 0
        try:
            text = stored.read_bytes().decode("utf-8-sig", errors="replace")
            rows = max(0, sum(1 for _ in _csv.reader(text.splitlines())) - 1)
        except Exception:
            rows = 0
        csv_entries.append(
            {"filename": f.filename or stored.name, "path": str(stored), "rows": rows}
        )

    combined = " + ".join(c["filename"] for c in csv_entries)
    if len(combined) > 480:
        combined = (csv_entries[0]["filename"]) + f" (+{len(csv_entries) - 1} more)"

    si = ScanImport(
        project_id        = project.id,
        report_version_id = rv.id,
        scan_type         = "cloud_iam",
        original_filename = combined,
        stored_path       = csv_entries[0]["path"] if csv_entries else None,
        uploaded_by_id    = user.id,
        summary           = {"files": len(csv_entries), "per_file": csv_entries},
        parsed_data       = {"csvs": csv_entries},
    )
    db.add(si)
    db.commit()
    db.refresh(si)

    return {"scan_import_id": si.id, "summary": si.summary}
