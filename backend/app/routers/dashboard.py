"""
Dashboard infographics endpoint.

`GET /api/dashboard/stats` returns the JSON payload the dashboard page
uses to draw its KPI counters + donuts + sparkline. Scope rules mirror
`/api/reports/accessible`:

  admin           -> sees everything
  senior          -> sees everything (matches their workflow)
  consultant etc. -> sees reports they own + project-led + explicit grants

We aggregate in-process rather than via SQL `GROUP BY` because:
  * the result sets are small (tens-to-hundreds of rows per user); and
  * SQLAlchemy enums need normalising and that's cleaner in Python.

Keys are intentionally short — they ride in a small JSON payload that
the dashboard polls on load. Per-user, no caching: numbers should be
fresh after a report state change.
"""
from __future__ import annotations
from collections import Counter, defaultdict
from datetime import datetime, timedelta, date

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import (
    User, Role, Project, Report, ReportVersion, ReportFinding,
    ReportAccess, Severity,
)
from ..auth import get_current_user
router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])


def _accessible_reports(db: Session, user: User) -> list[Report]:
    """All reports the current user can see. Mirrors /api/reports/accessible."""
    if user.role == Role.admin or user.role == Role.senior:
        return db.query(Report).all()
    owned = {r.id for r in db.query(Report.id)
                             .filter(Report.created_by_id == user.id).all()}
    led   = {r.id for r in db.query(Report.id).join(Project)
                             .filter(Project.lead_id == user.id).all()}
    shared = {g.report_id for g in db.query(ReportAccess.report_id)
                                       .filter(ReportAccess.user_id == user.id).all()}
    ids = owned | led | shared
    return db.query(Report).filter(Report.id.in_(ids)).all() if ids else []


def _latest_version(report: Report) -> ReportVersion | None:
    return report.versions[-1] if report.versions else None


@router.get("/stats")
def dashboard_stats(db: Session = Depends(get_db),
                     user: User = Depends(get_current_user)):
    reports = _accessible_reports(db, user)
    report_ids = [r.id for r in reports]

    # --- KPI counters --------------------------------------------------
    # Total reports the user can see.
    total_reports = len(reports)
    # Total active projects (= projects that have at least one report we can see).
    active_projects = len({r.project_id for r in reports})

    # Findings + severities across ALL accessible reports — only on the
    # latest version per report so we don't double-count history.
    sev_counts: Counter[str] = Counter()
    open_findings = 0
    for r in reports:
        lv = _latest_version(r)
        if not lv:
            continue
        for f in lv.findings:
            sev = (f.severity.value if f.severity else "Informational")
            sev_counts[sev] += 1
            # Treat anything not explicitly Closed / Risk-accepted / N-A as "open"
            status_v = (f.status.value if f.status else "Open").lower()
            if status_v in ("open", "in remediation"):
                open_findings += 1

    # Status of the latest version per report.
    status_counts: Counter[str] = Counter()
    awaiting_my_review = 0
    for r in reports:
        lv = _latest_version(r)
        st = (lv.review_status if lv and lv.review_status else "draft")
        # Stored as VARCHAR now; normalise to lowercase.
        st = str(st).lower()
        status_counts[st] += 1
        if (lv and st == "in_review" and lv.reviewer_id == user.id):
            awaiting_my_review += 1

    # Project-by-sector for projects that show up among the visible reports.
    sector_counts: Counter[str] = Counter()
    for pid in {r.project_id for r in reports}:
        p = db.get(Project, pid)
        if not p:
            continue
        sector_counts[(p.sector or "Unspecified").strip() or "Unspecified"] += 1

    # 30-day report-creation activity (day buckets, UTC).
    today = date.today()
    horizon = today - timedelta(days=29)         # include both endpoints -> 30 buckets
    by_day: dict[str, int] = defaultdict(int)
    for r in reports:
        if not r.created_at:
            continue
        d = r.created_at.date()
        if d < horizon:
            continue
        by_day[d.isoformat()] += 1
    activity = [
        {"date": (horizon + timedelta(days=i)).isoformat(),
         "count": by_day.get((horizon + timedelta(days=i)).isoformat(), 0)}
        for i in range(30)
    ]

    return {
        "scope": (
            "admin (all)" if user.role == Role.admin
            else "senior (all)" if user.role == Role.senior
            else "owned + shared + project-led"
        ),
        "kpi": {
            "total_reports":     total_reports,
            "active_projects":   active_projects,
            "open_findings":     open_findings,
            "awaiting_review":   awaiting_my_review,
        },
        "findings_by_severity": [
            {"key": sev, "count": sev_counts.get(sev, 0)}
            for sev in ("Critical", "High", "Medium", "Low", "Informational")
        ],
        "reports_by_status": [
            {"key": k,
             "count": status_counts.get(k, 0)}
            for k in ("draft", "in_review", "approved", "rejected", "published")
        ],
        "projects_by_sector": sorted(
            ({"key": k, "count": v} for k, v in sector_counts.items()),
            key=lambda x: -x["count"],
        ),
        "activity_30d": activity,
    }
