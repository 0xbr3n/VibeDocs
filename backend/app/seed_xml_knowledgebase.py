"""
Seed FindingLibrary from the bundled XML knowledge base.

Called from seed.py after templates exist. Idempotent: skips records that
already exist (matched by title + template_id). Re-running after the XML
file is updated will insert only new findings.

The bundled XML lives at app/seed_data/Knowledgebase.xml and ships in the
Docker image, so on first `docker compose up` the team's full library is
loaded automatically — no manual import needed.
"""
from pathlib import Path
from sqlalchemy.orm import Session

from .models import FindingLibrary, ReportTemplate, Severity, LibraryStatus, User
from .services.xml_findings_parser import parse_xml_knowledgebase, summarize


XML_PATH = Path(__file__).parent / "seed_data" / "Knowledgebase.xml"


_SEVERITY_MAP = {
    "Critical":      Severity.critical,
    "High":          Severity.high,
    "Medium":        Severity.medium,
    "Low":           Severity.low,
    "Informational": Severity.informational,
}


def seed_xml_knowledgebase(db: Session, admin: User, *, xml_path: Path = XML_PATH) -> dict:
    """Load the XML knowledge base into FindingLibrary.

    Returns a stats dict for logging:
      {"added": int, "skipped": int, "by_template": {...}}
    """
    if not xml_path.exists():
        return {"added": 0, "skipped": 0, "error": f"XML not found at {xml_path}"}

    records = parse_xml_knowledgebase(xml_path)
    summary = summarize(records)

    # Build a code → ReportTemplate lookup
    templates = {t.code: t for t in db.query(ReportTemplate).all()}

    added = 0
    skipped = 0
    by_template_added: dict[str, int] = {}

    for rec in records:
        tcode = rec["template_code"]
        template = templates.get(tcode)
        if not template:
            # Fall back to web_vapt if the inferred template doesn't exist yet
            template = templates.get("web_vapt")
            if not template:
                continue

        # Idempotency check
        existing = (db.query(FindingLibrary)
                      .filter(FindingLibrary.template_id == template.id,
                              FindingLibrary.title == rec["title"])
                      .first())
        if existing:
            skipped += 1
            continue

        sev = _SEVERITY_MAP.get(rec["default_severity"], Severity.medium)
        item = FindingLibrary(
            template_id=template.id,
            title=rec["title"],
            description=rec["description"],
            impact=rec["impact"],
            remediation=rec["remediation"],
            references=rec["references"],
            default_severity=sev,
            default_cvss_vector=rec["default_cvss_vector"],
            default_cvss_score=rec["default_cvss_score"],
            tags=rec["tags"],
            cwe=rec["cwe"],
            owasp_category=rec["owasp_category"],
            status=LibraryStatus.approved,   # bundled DB ships approved
            created_by_id=admin.id,
            reviewed_by_id=admin.id,
        )
        db.add(item)
        added += 1
        by_template_added[tcode] = by_template_added.get(tcode, 0) + 1

    db.commit()

    return {
        "added": added,
        "skipped": skipped,
        "total_in_xml": summary["total"],
        "by_template_added": by_template_added,
        "with_cwe": summary["with_cwe"],
        "with_owasp": summary["with_owasp"],
    }
