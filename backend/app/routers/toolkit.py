"""
Consultant toolkit — JSON-only endpoints backing the /toolkit pages.

This router is intentionally small and additive: each tool is one
endpoint that takes the consultant's inputs (typically a file upload)
and returns either a ready-to-download artifact OR a JSON preview the
UI renders before the download is committed. Adding a new tool means
adding one endpoint + one tool entry in the toolkit landing page —
nothing about the existing tools needs to change.

First tool: Nessus Compliance → Excel
-------------------------------------
The consultant drags one or more .nessus / .xml CIS Host Configuration
Review files onto the page; the server parses every Policy Compliance
report-item, builds a styled .xlsx (Summary + All Compliance + Host
Summary + per-policy sheets) and streams it back.

Behaviour mirrors the standalone CLI tool
``nessus_compliance_to_excel.py`` — same column layout, same
worksheet structure, same formula-escape on values that begin with
``=``. The CLI is preserved untouched; this is just an in-app
equivalent so consultants don't have to leave the browser.
"""
from __future__ import annotations

import io
import logging
import re
from datetime import datetime
from typing import List

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File
from fastapi.responses import StreamingResponse

from ..auth import get_current_user
from ..models import User, AuditLog
from ..database import get_db
from sqlalchemy.orm import Session
from ..services.tools import nessus_compliance as nc

router = APIRouter(prefix="/api/toolkit", tags=["toolkit"])
log = logging.getLogger(__name__)


# Per-upload hard cap. A typical CIS HCR .nessus runs ~2-10 MB; 50 MB
# is generous enough for "I scanned 30 hosts" and small enough that an
# accidental "uploaded the full Nessus DB" can't blow up memory.
_MAX_UPLOAD_BYTES = 50 * 1024 * 1024
# Number of files per request — keeps a misbehaving client from
# DoS-ing the worker by streaming hundreds of files at once.
_MAX_FILES_PER_REQUEST = 25


def _safe_filename_stem(name: str) -> str:
    """Sanitise an upload's filename for use in the download stem.
    Drops the extension, strips path separators, falls back to a
    timestamp if there's nothing usable left."""
    stem = name.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
    stem = stem.rsplit(".", 1)[0]
    stem = re.sub(r"[^A-Za-z0-9._-]", "_", stem).strip("._-")
    return stem or datetime.utcnow().strftime("nessus_%Y%m%d_%H%M%S")


async def _read_upload_capped(f: UploadFile) -> bytes:
    """Stream an upload in 64 KB chunks, rejecting it with HTTP 413 before the
    full contents land in memory when the size cap is exceeded.

    All toolkit endpoints pass uploads through this helper so the size
    enforcement happens at read time rather than after the entire file
    has already been buffered — the original `await f.read()` + `len()`
    pattern loaded the whole file first and only then checked the size.
    """
    _MB = _MAX_UPLOAD_BYTES // 1024 // 1024
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = await f.read(65536)
        if not chunk:
            break
        total += len(chunk)
        if total > _MAX_UPLOAD_BYTES:
            raise HTTPException(
                413,
                f"{f.filename or 'upload'}: file exceeds the {_MB} MB upload limit.",
            )
        chunks.append(chunk)
    return b"".join(chunks)


@router.post("/nessus-compliance/preview")
async def nessus_compliance_preview(
    files: List[UploadFile] = File(...),
    user: User = Depends(get_current_user),
):
    """Parse the uploaded .nessus / .xml files and return a JSON
    summary the UI uses to populate the post-upload preview pane.
    Doesn't build the workbook — that's a separate call so a
    consultant can sanity-check what was parsed before downloading.
    """
    if not files:
        raise HTTPException(400, "Upload at least one .nessus file.")
    if len(files) > _MAX_FILES_PER_REQUEST:
        raise HTTPException(
            400, f"Too many files in one request (max {_MAX_FILES_PER_REQUEST}).",
        )

    uploads: list[tuple[str, bytes]] = []
    for f in files:
        data = await _read_upload_capped(f)
        uploads.append((f.filename or "scan.nessus", data))

    try:
        rows = nc.parse_uploads(uploads)
    except ValueError as e:
        raise HTTPException(400, str(e))
    except Exception as e:                                  # pragma: no cover
        log.exception("nessus-compliance preview failed")
        raise HTTPException(500, "Failed to parse uploads. Please ensure the files are valid .nessus scan outputs.")

    if not rows:
        raise HTTPException(
            422,
            "No Policy Compliance / CIS HCR items were found in the uploaded "
            "file(s). Make sure the scan policy includes a Host Configuration "
            "Review compliance check.",
        )

    summary = nc.summary_stats(rows)
    summary["file_count"] = len(files)
    summary["files"] = [f.filename for f in files]
    return summary


@router.post("/nessus-compliance/convert")
async def nessus_compliance_convert(
    files: List[UploadFile] = File(...),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Parse the uploaded .nessus / .xml files and stream back the
    generated .xlsx workbook. Same input contract as ``/preview`` —
    the only difference is the response body is the workbook bytes
    instead of a summary JSON.
    """
    if not files:
        raise HTTPException(400, "Upload at least one .nessus file.")
    if len(files) > _MAX_FILES_PER_REQUEST:
        raise HTTPException(
            400, f"Too many files in one request (max {_MAX_FILES_PER_REQUEST}).",
        )

    uploads: list[tuple[str, bytes]] = []
    for f in files:
        data = await _read_upload_capped(f)
        uploads.append((f.filename or "scan.nessus", data))

    try:
        rows = nc.parse_uploads(uploads)
    except ValueError as e:
        raise HTTPException(400, str(e))
    except Exception as e:                                  # pragma: no cover
        log.exception("nessus-compliance convert failed at parse")
        raise HTTPException(500, "Failed to parse uploads. Please ensure the files are valid .nessus scan outputs.")

    if not rows:
        raise HTTPException(
            422,
            "No Policy Compliance / CIS HCR items were found in the uploaded "
            "file(s). Make sure the scan policy includes a Host Configuration "
            "Review compliance check.",
        )

    try:
        xlsx_bytes = nc.build_workbook_bytes(rows)
    except Exception as e:                                  # pragma: no cover
        log.exception("nessus-compliance workbook build failed")
        raise HTTPException(500, "Failed to build the output workbook. Please try again or contact an administrator.")

    # Audit so we can see which consultant ran the tool against what
    # — useful when a client question lands and we need to find the
    # source .nessus that produced a given xlsx. We do NOT store the
    # uploaded file contents; only filenames + row counts.
    try:
        db.add(AuditLog(
            actor_id=user.id,
            action="toolkit.nessus_compliance.convert",
            object_type="upload",
            object_id=None,
            detail={
                "files": [f.filename for f in files],
                "row_count": len(rows),
                "unique_hosts": len({(r.ip_address or r.host_name) for r in rows}),
            },
        ))
        db.commit()
    except Exception:                                       # pragma: no cover
        db.rollback()

    # Filename for the download. With a single upload we use that
    # stem; with multiple, fall back to a timestamped name.
    if len(files) == 1:
        stem = _safe_filename_stem(files[0].filename or "scan")
    else:
        stem = datetime.utcnow().strftime("nessus_compliance_%Y%m%d_%H%M%S")
    out_name = f"{stem}_compliance.xlsx"

    return StreamingResponse(
        io.BytesIO(xlsx_bytes),
        media_type=(
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        ),
        headers={
            "Content-Disposition": f'attachment; filename="{out_name}"',
            "X-Compliance-Row-Count": str(len(rows)),
        },
    )


# ============================================================
# Tool: HCR custom-benchmark → CIS-benchmark mapping
# Single file upload (.docx / .pdf). Returns either a JSON preview
# (/preview) or the streamed .xlsx mapping workbook (/convert).
# ============================================================
from ..services.tools import cis_benchmark_mapper as cbm


@router.post("/cis-benchmark-map/preview")
async def cis_benchmark_map_preview(
    files: List[UploadFile] = File(...),
    user: User = Depends(get_current_user),
):
    """Parse ONE uploaded hardening-standard / HCR document
    (.docx or .pdf) and return the auto-extracted CIS mapping as a
    JSON preview so the consultant can sanity-check before downloading
    the workbook."""
    if not files:
        raise HTTPException(400, "Upload a .docx or .pdf document.")
    f = files[0]
    data = await _read_upload_capped(f)
    try:
        segments = cbm.extract_text(f.filename or "doc", data)
        result = cbm.find_cis_references(segments)
    except ValueError as e:
        raise HTTPException(400, str(e))
    except Exception as e:                                  # pragma: no cover
        log.exception("cis-benchmark-map preview failed")
        raise HTTPException(500, "Failed to parse the document. Please ensure it is a valid .docx or .pdf file.")
    out = result.as_preview()
    out["filename"] = f.filename
    return out


@router.post("/cis-benchmark-map/convert")
async def cis_benchmark_map_convert(
    files: List[UploadFile] = File(...),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Parse the uploaded hardening-standard / HCR document and stream
    back the generated CIS-mapping .xlsx workbook."""
    if not files:
        raise HTTPException(400, "Upload a .docx or .pdf document.")
    f = files[0]
    data = await _read_upload_capped(f)
    try:
        segments = cbm.extract_text(f.filename or "doc", data)
        result = cbm.find_cis_references(segments)
        xlsx_bytes = cbm.build_xlsx(result)
    except ValueError as e:
        raise HTTPException(400, str(e))
    except Exception as e:                                  # pragma: no cover
        log.exception("cis-benchmark-map convert failed")
        raise HTTPException(500, "Failed to build the CIS mapping workbook. Please try again or contact an administrator.")

    try:
        db.add(AuditLog(
            actor_id=user.id,
            action="toolkit.cis_benchmark_map.convert",
            object_type="upload", object_id=None,
            detail={
                "filename": f.filename,
                "mapping_rows": len(result.rows),
                "benchmarks": result.benchmark_titles[:10],
            },
        ))
        db.commit()
    except Exception:                                       # pragma: no cover
        db.rollback()

    stem = _safe_filename_stem(f.filename or "hcr")
    out_name = f"{stem}_cis_mapping.xlsx"
    return StreamingResponse(
        io.BytesIO(xlsx_bytes),
        media_type=(
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        ),
        headers={
            "Content-Disposition": f'attachment; filename="{out_name}"',
            "X-CIS-Mapping-Rows": str(len(result.rows)),
        },
    )


# ============================================================
# Tool: VA-Recurring scan pipeline
# Multipart input:
#   current_csvs[]    — one or more Nessus CSV exports (REQUIRED)
#   risk_accept       — optional management risk-accept doc
#                       (.xlsx/.xls/.csv/.pdf)
#   prev_tracker      — optional previous quarter's tracker (.xlsx/.xls)
#   custom_comment_col — optional text (e.g. "VibeDocs Comments")
#   group_ips_in_by_category — checkbox, defaults false
# Returns: streamed ZIP of every output file the library wrote
# (remaining_findings.xlsx + risk_accepted_removed.xlsx + by_category/*.xlsx +
# summary.txt + audit / preview xlsx files as applicable).
# ============================================================

from fastapi import Form
from typing import Optional


async def _collect_va_uploads(
    current_csvs: List[UploadFile],
    risk_accept: List[UploadFile],
    prev_tracker: List[UploadFile],
) -> tuple:
    """Read every upload into memory and tuple-ify them in the shape
    `va_recurring.run_pipeline` expects. Pulled out so preview + run
    don't drift. Risk-accept and prev-tracker are NOW lists — the
    library's folder-mode loader fans out across every uploaded file
    so the consultant can hand us a quarter's worth of risk-accept
    PDFs / xlsxes in one shot."""
    def _meaningful(f: UploadFile) -> bool:
        # FastAPI populates the form field even when the user didn't
        # pick a file — the empty placeholder shows up with an empty
        # filename. Skip those so we don't try to validate "0 bytes".
        return bool((f.filename or "").strip())

    _MB = _MAX_UPLOAD_BYTES // 1024 // 1024

    csv_tuples: list[tuple[str, bytes]] = []
    for f in current_csvs or []:
        if not _meaningful(f):
            continue
        data = await _read_upload_capped(f)
        csv_tuples.append((f.filename or "scan.csv", data))

    ra_tuples: list[tuple[str, bytes]] = []
    for f in risk_accept or []:
        if not _meaningful(f):
            continue
        data = await _read_upload_capped(f)
        ra_tuples.append((f.filename or "risk_accept.xlsx", data))

    tr_tuples: list[tuple[str, bytes]] = []
    for f in prev_tracker or []:
        if not _meaningful(f):
            continue
        data = await _read_upload_capped(f)
        tr_tuples.append((f.filename or "prev_tracker.xlsx", data))

    return csv_tuples, ra_tuples, tr_tuples


@router.post("/va-recurring/run")
async def va_recurring_run(
    current_csvs: List[UploadFile] = File(..., description="Nessus CSV exports"),
    risk_accept: List[UploadFile] = File(
        default=[], description="Risk-accept docs (multi)",
    ),
    prev_tracker: List[UploadFile] = File(
        default=[], description="Previous tracker xlsxes (multi)",
    ),
    custom_comment_col: str = Form(""),
    custom_comment_default: str = Form(""),
    group_ips_in_by_category: bool = Form(False),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Run the full Recurring-VA scan pipeline against the uploads and
    stream back a ZIP of every output xlsx + summary.txt.
    """
    from ..services.tools import va_recurring as vr

    meaningful_csvs = [f for f in (current_csvs or []) if (f.filename or "").strip()]
    if not meaningful_csvs:
        raise HTTPException(400, "Upload at least one Nessus CSV.")
    if len(meaningful_csvs) > _MAX_FILES_PER_REQUEST:
        raise HTTPException(400, f"Too many CSV files (max {_MAX_FILES_PER_REQUEST}).")

    csvs, ra_list, tr_list = await _collect_va_uploads(
        current_csvs, risk_accept, prev_tracker,
    )

    try:
        result = vr.run_pipeline(
            current_csvs=csvs,
            risk_accept=ra_list or None,
            prev_tracker=tr_list or None,
            custom_comment_col=custom_comment_col,
            custom_comment_default=custom_comment_default,
            group_ips_in_by_category=group_ips_in_by_category,
        )
    except ValueError as e:
        raise HTTPException(400, str(e))
    except Exception as e:                                  # pragma: no cover
        log.exception("va-recurring run failed")
        raise HTTPException(500, "Pipeline failed. Please try again or contact an administrator.")

    # Audit — record what was processed. Like the Nessus → Excel tool
    # we record metadata only (filenames + counts), NOT the file
    # contents.
    try:
        db.add(AuditLog(
            actor_id=user.id,
            action="toolkit.va_recurring.run",
            object_type="upload",
            object_id=None,
            detail={
                "csv_files":          [name for name, _ in csvs],
                "risk_accept_files":  [name for name, _ in ra_list],
                "prev_tracker_files": [name for name, _ in tr_list],
                "custom_comment_col": custom_comment_col or None,
                "custom_comment_default_set": bool(custom_comment_default),
                "total_current":  result["summary"].get("total_current"),
                "total_after_subtract": result["summary"].get("total_after_subtract"),
                "category_counts": result["summary"].get("category_counts"),
            },
        ))
        db.commit()
    except Exception:                                       # pragma: no cover
        db.rollback()

    # Pack the summary into a response header so the page can pop a
    # toast with "X findings remaining after subtract" without needing
    # a second request.
    s = result["summary"]
    headers = {
        "Content-Disposition": f'attachment; filename="{result["zip_name"]}"',
        "X-Total-Current":         str(s.get("total_current", 0)),
        "X-Total-After-Subtract":  str(s.get("total_after_subtract", 0)),
        "X-Removed":               str(s.get("n_removed_riskaccepted", 0)),
        "X-Output-Files":          str(len(s.get("output_files", []))),
    }
    return StreamingResponse(
        io.BytesIO(result["zip_bytes"]),
        media_type="application/zip",
        headers=headers,
    )


# ============================================================
# Tool: VA-Retest tracker update
# Distinct from VA-Recurring because there's no risk-accept pass —
# the rescan is just "client remediated some findings, refresh the
# tracker". Form inputs:
#   current_csvs[]       — fresh rescan CSV exports (REQUIRED)
#   original_tracker     — last tracker xlsx (REQUIRED, single file —
#                          image-preserving openpyxl edit)
#   sheet_index          — which sheet (default 0)
#   custom_comment_col   — optional ("VibeDocs Comments" etc.)
#   custom_comment_default — text written into the custom column on
#                          every row this pass closes
#   new_ip_action        — include | exclude | list_only
#   enable_version_check — checkbox (default on); flips
#                          plugin-output-based auto-closure on/off
# Returns: streamed ZIP with updated_tracker.xlsx + side files +
# summary.txt. Image-safe — embedded screenshots in the original
# tracker survive the round-trip.
# ============================================================

@router.post("/va-retest/run")
async def va_retest_run(
    current_csvs: List[UploadFile] = File(..., description="Rescan CSVs"),
    original_tracker: UploadFile = File(..., description="Original tracker xlsx"),
    sheet_index: int = Form(0),
    custom_comment_col: str = Form(""),
    custom_comment_default: str = Form(""),
    new_ip_action: str = Form("include"),
    enable_version_check: bool = Form(True),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Run the retest tracker-update pipeline and stream back the ZIP."""
    from ..services.tools import va_retest as vr

    # Validate and collect CSV uploads
    meaningful_csvs = [f for f in (current_csvs or []) if (f.filename or "").strip()]
    if not meaningful_csvs:
        raise HTTPException(400, "Upload at least one rescan CSV.")
    if len(meaningful_csvs) > _MAX_FILES_PER_REQUEST:
        raise HTTPException(400, f"Too many CSV files (max {_MAX_FILES_PER_REQUEST}).")

    csv_tuples: list[tuple[str, bytes]] = []
    for f in current_csvs or []:
        if not (f.filename or "").strip():
            continue
        data = await _read_upload_capped(f)
        csv_tuples.append((f.filename or "scan.csv", data))

    if not original_tracker or not (original_tracker.filename or "").strip():
        raise HTTPException(400, "Original tracker .xlsx upload is required.")
    tracker_data = await _read_upload_capped(original_tracker)
    tracker_tuple = (
        original_tracker.filename or "original_tracker.xlsx",
        tracker_data,
    )

    try:
        result = vr.run_retest(
            current_csvs=csv_tuples,
            original_tracker=tracker_tuple,
            sheet_index=sheet_index,
            custom_comment_col=custom_comment_col,
            custom_comment_default=custom_comment_default,
            new_ip_action=new_ip_action,
            enable_version_check=enable_version_check,
        )
    except ValueError as e:
        raise HTTPException(400, str(e))
    except Exception as e:                                  # pragma: no cover
        log.exception("va-retest run failed")
        raise HTTPException(500, "Retest pipeline failed. Please try again or contact an administrator.")

    # Audit — metadata only.
    s = result["summary"]
    try:
        db.add(AuditLog(
            actor_id=user.id,
            action="toolkit.va_retest.run",
            object_type="upload",
            object_id=None,
            detail={
                "csv_files":          [name for name, _ in csv_tuples],
                "tracker_file":       tracker_tuple[0],
                "custom_comment_col": custom_comment_col or None,
                "custom_comment_default_set": bool(custom_comment_default),
                "new_ip_action":      new_ip_action,
                "enable_version_check": bool(enable_version_check),
                "closed_missing":     s.get("closed_missing"),
                "closed_version":     s.get("closed_version"),
                "still_open":         s.get("still_open"),
                "rows_appended":      s.get("rows_appended"),
                "new_ips_count":      len(s.get("new_ips") or []),
            },
        ))
        db.commit()
    except Exception:                                       # pragma: no cover
        db.rollback()

    headers = {
        "Content-Disposition": f'attachment; filename="{result["zip_name"]}"',
        "X-Closed-Missing":   str(s.get("closed_missing", 0)),
        "X-Closed-Version":   str(s.get("closed_version", 0)),
        "X-Still-Open":       str(s.get("still_open", 0)),
        "X-New-IPs":          str(len(s.get("new_ips") or [])),
        "X-Rows-Appended":    str(s.get("rows_appended", 0)),
    }
    return StreamingResponse(
        io.BytesIO(result["zip_bytes"]),
        media_type="application/zip",
        headers=headers,
    )
