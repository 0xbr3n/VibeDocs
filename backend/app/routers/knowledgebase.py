"""
XML knowledge-base upload endpoint.

The seed flow loads the bundled Knowledgebase.xml on first container start.
When the team adds new findings to their XML file they can either:
  (a) rebuild and redeploy the container (the new XML ships baked in), OR
  (b) upload the updated XML through this endpoint without redeploying.

The uploader runs the same idempotent merge as the seeder: existing
(title + template_id) pairs are skipped, only new entries get added.

Endpoint:
  POST /api/knowledgebase/upload     (admin / senior)
  GET  /api/knowledgebase/stats      (anyone) -- summarises what's in the DB
"""
from pathlib import Path
import tempfile
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import User, Role, FindingLibrary, AuditLog
from ..auth import get_current_user, require_roles
from ..services.xml_findings_parser import parse_xml_knowledgebase, summarize
import logging as _log_kb

_logger = _log_kb.getLogger(__name__)


router = APIRouter(prefix="/api/knowledgebase", tags=["knowledgebase"])


@router.post("/upload")
async def upload_knowledgebase(
    file: UploadFile = File(..., description="Updated Knowledgebase.xml"),
    dry_run: bool = False,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(Role.admin, Role.senior)),
):
    """Upload the team's XML knowledge base. New entries are added; existing
    entries (matched by title+template) are skipped. Set dry_run=true to
    just see what *would* be added without writing anything.
    """
    if not file.filename or not file.filename.lower().endswith(".xml"):
        raise HTTPException(400, "Upload an .xml file")

    _MAX_XML_BYTES = 50 * 1024 * 1024   # 50 MB
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = await file.read(65536)
        if not chunk:
            break
        total += len(chunk)
        if total > _MAX_XML_BYTES:
            raise HTTPException(413, "XML file exceeds the 50 MB upload limit.")
        chunks.append(chunk)
    contents = b"".join(chunks)

    import os as _os
    fd, tmp_path_str = tempfile.mkstemp(suffix=".xml")
    tmp_path = Path(tmp_path_str)
    try:
        with _os.fdopen(fd, "wb") as tf:
            tf.write(contents)
    except Exception:
        tmp_path.unlink(missing_ok=True)
        raise

    try:
        records = parse_xml_knowledgebase(tmp_path)
    except Exception as e:
        _logger.warning("Knowledgebase XML parse failed: %s", e)
        raise HTTPException(400, "Could not parse the uploaded file. Please ensure it is a valid XML knowledge base export.")
    finally:
        try:
            tmp_path.unlink()
        except Exception:
            pass

    summary = summarize(records)

    if dry_run:
        return {
            "ok": True,
            "dry_run": True,
            "would_process": summary,
            "note": "No changes made. Re-submit without dry_run to commit.",
        }

    # Persist using the shared seeder
    from ..seed_xml_knowledgebase import seed_xml_knowledgebase
    # The seeder expects the XML at a path; write again
    with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as tf:
        tf.write(contents)
        tmp_path = Path(tf.name)
    try:
        stats = seed_xml_knowledgebase(db, user, xml_path=tmp_path)
    finally:
        try:
            tmp_path.unlink()
        except Exception:
            pass

    db.add(AuditLog(actor_id=user.id, action="knowledgebase.upload",
                    object_type="finding_library",
                    detail={"added": stats["added"], "skipped": stats["skipped"],
                            "filename": file.filename}))
    db.commit()
    return {"ok": True, "dry_run": False, **stats}


@router.get("/stats")
def stats(db: Session = Depends(get_db),
          _: User = Depends(get_current_user)):
    """Quick summary of the library: counts by template, by severity, sources."""
    from sqlalchemy import func
    from ..models import ReportTemplate, Severity, LibraryStatus

    total = db.query(func.count(FindingLibrary.id)).scalar()
    by_template = dict(
        db.query(ReportTemplate.code, func.count(FindingLibrary.id))
          .join(FindingLibrary, FindingLibrary.template_id == ReportTemplate.id)
          .group_by(ReportTemplate.code)
          .all()
    )
    by_severity = dict(
        db.query(FindingLibrary.default_severity, func.count(FindingLibrary.id))
          .group_by(FindingLibrary.default_severity)
          .all()
    )
    by_severity = {k.value if hasattr(k, "value") else str(k): v for k, v in by_severity.items()}
    by_status = dict(
        db.query(FindingLibrary.status, func.count(FindingLibrary.id))
          .group_by(FindingLibrary.status)
          .all()
    )
    by_status = {k.value if hasattr(k, "value") else str(k): v for k, v in by_status.items()}
    with_cwe = (db.query(func.count(FindingLibrary.id))
                  .filter(FindingLibrary.cwe.isnot(None)).scalar())
    with_owasp = (db.query(func.count(FindingLibrary.id))
                    .filter(FindingLibrary.owasp_category.isnot(None)).scalar())
    return {
        "total": total,
        "by_template": by_template,
        "by_severity": by_severity,
        "by_status": by_status,
        "with_cwe": with_cwe,
        "with_owasp": with_owasp,
    }
