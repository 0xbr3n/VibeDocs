"""
Resolve which Word template file to render a report from.

Priority (highest wins):
  1. Per-report override         (report.details["custom_template_path"])
  2. Per-project override        (project.details["custom_template_path"])
  3. Master template default     (ReportTemplate.docx_filename)

Custom client templates uploaded by consultants land under
UPLOAD_DIR/custom_templates/ and the path is stored in the relevant
JSON details column. We never overwrite the master template files in
TEMPLATE_DIR -- those stay pristine across uploads.
"""
from pathlib import Path
from typing import Optional

from sqlalchemy.orm import Session
from ..models import Report, Project, ReportTemplate
from ..config import settings


def _safe_custom_path(raw: str) -> Optional[Path]:
    """Resolve a stored custom_template_path and verify it is within one of
    the permitted base directories (UPLOAD_DIR or TEMPLATE_DIR).  Returns
    the resolved Path if it exists and is safe, otherwise None.

    This prevents a compromised DB value from pointing at arbitrary filesystem
    paths (e.g. /etc/passwd) when the generator opens the template.
    """
    try:
        p = Path(raw).resolve()
    except (TypeError, ValueError):
        return None
    allowed_roots = (
        Path(settings.UPLOAD_DIR).resolve(),
        Path(settings.TEMPLATE_DIR).resolve(),
    )
    # Use proper parent-directory containment rather than string startswith —
    # startswith("/data/uploads") would wrongly allow "/data/uploads_evil/...".
    if not any(p == root or str(p).startswith(str(root) + "/") for root in allowed_roots):
        import logging
        logging.getLogger(__name__).warning(
            "Blocked custom_template_path outside allowed roots: %s", raw
        )
        return None
    return p if p.exists() else None


def resolve_template_path(db: Session, report: Report) -> Path:
    """Return the .docx path the generator should render against."""
    # Per-report override
    details = report.details or {}
    if details.get("custom_template_path"):
        p = _safe_custom_path(details["custom_template_path"])
        if p:
            return p

    # Per-project override
    project = db.get(Project, report.project_id)
    p_details = (getattr(project, "details", None) or {}) if project else {}
    if p_details.get("custom_template_path"):
        p = _safe_custom_path(p_details["custom_template_path"])
        if p:
            return p

    # Master template default
    template = db.get(ReportTemplate, report.template_id)
    if template and template.docx_filename:
        return Path(settings.TEMPLATE_DIR) / template.docx_filename

    raise FileNotFoundError(
        f"No template resolvable for report {report.id} "
        f"(template_id={report.template_id})"
    )


def validate_custom_template(docx_path: Path) -> dict:
    """Inspect an uploaded client template and report which expected
    placeholders are present/missing.

    Returns:
        {
          "valid": bool,
          "warnings": list[str],   # missing nice-to-have placeholders
          "errors": list[str],     # missing critical placeholders
          "placeholders_found": set[str],
        }

    Critical placeholders: {{ project.client_name }}, {{ findings ... }} loop
    Nice-to-have: severity_counts, sections.executive_summary, severity_chart
    """
    import zipfile, re

    REQUIRED = [
        r"\{\{\s*project\.client_name",
        r"\{%p?\s*for\s+f\s+in\s+findings",
    ]
    NICE = [
        r"\{\{\s*severity_counts",
        r"\{\{\s*sections\.executive_summary",
        r"\{\{\s*severity_chart",
        r"\{\{\s*report\.version",
        r"\{\{\s*project\.name",
    ]

    errors: list[str] = []
    warnings: list[str] = []
    found: set[str] = set()

    try:
        with zipfile.ZipFile(docx_path) as zf:
            xml_blob = "\n".join(
                zf.read(name).decode("utf-8", errors="ignore")
                for name in zf.namelist()
                if name.startswith("word/") and name.endswith(".xml")
            )
    except (zipfile.BadZipFile, FileNotFoundError, OSError):
        # JSON column can't store a Python `set` — keep this a list so the
        # dict stays serialisable when it lands in Project/Report.details.
        return {"valid": False, "errors": ["Not a valid .docx file"], "warnings": [],
                "placeholders_found": []}

    # Word XML can split a placeholder across multiple <w:t> runs;
    # strip XML tags first so we read the literal text.
    text = re.sub(r"<[^>]+>", "", xml_blob)
    text = re.sub(r"\s+", " ", text)

    for pat in REQUIRED:
        if re.search(pat, text):
            found.add(pat)
        else:
            errors.append(f"Required placeholder missing: matches /{pat}/")

    for pat in NICE:
        if re.search(pat, text):
            found.add(pat)
        else:
            warnings.append(f"Optional placeholder missing: matches /{pat}/ -- that section will fall back to defaults")

    return {
        "valid": not errors,
        "errors": errors,
        "warnings": warnings,
        "placeholders_found": [p for p in found],
    }


def save_custom_template_upload(
    file_bytes: bytes,
    *,
    scope: str,                 # "project" / "report"
    scope_id: int,
    original_filename: str,
) -> Path:
    """Save the uploaded .docx under UPLOAD_DIR/custom_templates/ and
    return the stored path. Caller is responsible for stashing this
    path in the project or report's details JSON.

    Strips any DRAFT watermark from the file's headers as a
    best-effort cleanup pass — the renderer adds its own DRAFT stamp
    on every page when `is_draft=True`, and consultants routinely
    upload templates whose source already contains a baked-in
    "DRAFT" wordart. Leaving both in place produces visibly stacked
    watermarks in the rendered PDF.
    """
    import uuid
    safe_name = "".join(c if c.isalnum() or c in "._-" else "_" for c in original_filename)[:120]
    out_dir = Path(settings.UPLOAD_DIR) / "custom_templates" / scope / str(scope_id)
    out_dir.mkdir(parents=True, exist_ok=True)
    dest = out_dir / f"{uuid.uuid4().hex[:8]}__{safe_name}"
    dest.write_bytes(file_bytes)
    try:
        from .watermark import strip_draft_watermarks
        strip_draft_watermarks(dest)
    except Exception as e:                                  # pragma: no cover
        import logging
        logging.getLogger(__name__).warning(
            "watermark strip failed on custom template upload: %s", e,
        )
    # Inject Jinja2 expressions into the template so report-details values
    # (client name, app name, tester names, etc.) are rendered at report
    # generation time.  Without this, custom templates uploaded by consultants
    # keep their static placeholder text regardless of what the user enters in
    # the Report Details form.
    try:
        from ..tools.inject_jinja2_into_templates import process_template
        process_template(dest)
    except Exception as e:                                  # pragma: no cover
        import logging
        logging.getLogger(__name__).warning(
            "Jinja2 injection failed on custom template upload (%s): %s",
            dest.name, e,
        )
    return dest
