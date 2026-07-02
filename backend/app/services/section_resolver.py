"""
Resolve the prose to show in each templated section.

A report's executive summary, methodology, and other long-form sections live
in three layers (highest priority wins):

    1. ReportSectionOverride          (per-report consultant edit)
    2. TemplateSection                (master prose, admin-editable)
    3. Fallback default               (hardcoded sensible default)

Used during DOCX generation to build the `sections` dict that gets passed
to docxtpl. The Word template references {{ sections.executive_summary }},
{{ sections.methodology }}, {{ sections.scope_disclaimer }}, etc.
"""
from sqlalchemy.orm import Session
from ..models import TemplateSection, ReportSectionOverride


# Sections we expect every template to define. The Word template can
# reference any of these via {{ sections.<key> }}. Missing entries get
# a fallback string so the document never breaks.
DEFAULT_SECTION_KEYS = [
    "executive_summary",
    "methodology",
    "scope_disclaimer",
    "limitations",
    "risk_rating_explanation",
    "report_distribution",
]

FALLBACKS = {
    "executive_summary": "This report presents the findings of the security assessment.",
    "methodology": "The assessment followed industry-standard methodologies including OWASP Testing Guide, NIST SP 800-115, and PTES.",
    "scope_disclaimer": "Testing was limited to the agreed scope. Out-of-scope assets were not assessed.",
    "limitations": "Testing was performed within a defined time window and may not exhaustively identify every issue.",
    "risk_rating_explanation": "Findings are rated Critical, High, Medium, Low, or Informational based on CVSS 4.0 base scores.",
    "report_distribution": "This report is confidential and intended only for the named recipient.",
}


def resolve_sections(db: Session, *, template_id: int, report_id: int) -> dict[str, str]:
    """Build the final section dict: override > master > fallback."""
    out = dict(FALLBACKS)

    # Layer 2: master template sections
    masters = (db.query(TemplateSection)
                 .filter(TemplateSection.template_id == template_id)
                 .all())
    for s in masters:
        if s.body and s.body.strip():
            out[s.key] = s.body

    # Layer 1: per-report overrides
    overrides = (db.query(ReportSectionOverride)
                   .filter(ReportSectionOverride.report_id == report_id)
                   .all())
    for o in overrides:
        if o.body and o.body.strip():
            out[o.key] = o.body

    return out


def list_section_definitions(db: Session, template_id: int) -> list[dict]:
    """Return ordered list of section definitions for the editor UI.
    Includes any master sections defined for the template, plus the
    DEFAULT_SECTION_KEYS that haven't been customised yet.
    """
    masters = {s.key: s for s in db.query(TemplateSection)
                                     .filter(TemplateSection.template_id == template_id)
                                     .order_by(TemplateSection.order, TemplateSection.id)
                                     .all()}
    seen = set()
    out = []
    # First the master-defined sections (in admin-set order)
    for s in masters.values():
        seen.add(s.key)
        out.append({
            "key": s.key,
            "title": s.title or s.key.replace("_", " ").title(),
            "body": s.body,
            "is_master_defined": True,
            "updated_at": s.updated_at.isoformat() if s.updated_at else None,
        })
    # Then any DEFAULT keys that haven't been customised
    for key in DEFAULT_SECTION_KEYS:
        if key not in seen:
            out.append({
                "key": key,
                "title": key.replace("_", " ").title(),
                "body": FALLBACKS.get(key, ""),
                "is_master_defined": False,
                "updated_at": None,
            })
    return out
