"""
Report access management.

Endpoints:
  GET    /api/users                            list all users (for the share picker)
  GET    /api/reports/{rid}/access             list who currently has access
  POST   /api/reports/{rid}/access             grant a user access to this report
  PUT    /api/reports/{rid}/access/{user_id}   change a user's access level
  DELETE /api/reports/{rid}/access/{user_id}   revoke access
  GET    /api/reports/mine                     reports I own
  GET    /api/reports/shared-with-me           reports others have shared with me
  GET    /api/reports/accessible               union of both, for "all my reports" feed

Authorization rules:
  - Owners (Report.created_by_id) always have implicit `admin` access; cannot be revoked.
  - System admins (User.role == admin) always have implicit `admin` access on every report.
  - Project leads have implicit `admin` access on every report in their project.
  - Anyone with `admin` access on a report can grant/change/revoke for that report.
  - Anyone with `edit` access can edit content but not change permissions.
  - Anyone with `view` access can read but not modify.
  - You cannot revoke the owner's access. You can leave a report yourself (revoke own grant).
"""
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import or_, func
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import (
    Report, ReportAccess, AccessLevel, User, Role, Project, AuditLog
)
from ..auth import get_current_user


router = APIRouter(tags=["permissions"])


# ---------- Authorization helpers (exported for use in other routers) ----------

def effective_access(db: Session, user: User, report: Report) -> Optional[AccessLevel]:
    """Return the access level this user has on this report, or None if no access.

    Resolution order (highest wins):
      1. user.role == admin                     -> admin
      2. user.id == report.created_by_id        -> admin
      3. project lead                           -> admin
      4. explicit ReportAccess row              -> grant.access_level
      5. otherwise                              -> None
    """
    if user.role == Role.admin:
        return AccessLevel.admin
    if report.created_by_id == user.id:
        return AccessLevel.admin
    project = db.get(Project, report.project_id)
    if project and project.lead_id == user.id:
        return AccessLevel.admin

    grant = (db.query(ReportAccess)
               .filter(ReportAccess.report_id == report.id,
                       ReportAccess.user_id == user.id)
               .first())
    if grant:
        return grant.access_level

    # Users assigned to the parent project (via project.details["assigned_user_ids"])
    # get edit access on all reports in that project. This lets an admin assign
    # a consultant to a project without needing to manually grant per-report access.
    if project:
        assigned_ids = (getattr(project, "details", None) or {}).get("assigned_user_ids") or []
        if user.id in assigned_ids:
            return AccessLevel.edit

    # "Open by default" fallback — mirrors the frontend's CAN_EDIT logic:
    #   CAN_EDIT = (MY_ACCESS == null) ? true : (MY_ACCESS === "edit" || …)
    # If no explicit ReportAccess grants exist for this report it is
    # "unlocked", and any authenticated user gets edit access. Once an admin
    # adds at least one explicit grant the report is "locked down" and only
    # those grantees (plus the owner / lead / admins above) have access.
    # This lets a newly-created consultant navigate to any unshared report
    # and contribute findings without requiring per-user setup.
    explicit_grant_count = (
        db.query(ReportAccess.id)
          .filter(ReportAccess.report_id == report.id)
          .limit(1)
          .count()
    )
    if explicit_grant_count == 0:
        return AccessLevel.edit

    return None


def require_access(db: Session, user: User, report: Report, *,
                   need: AccessLevel = AccessLevel.view) -> AccessLevel:
    """Raise 403 if the user doesn't have `need` access (or higher) on this report.
    Returns the effective level when it passes.
    """
    have = effective_access(db, user, report)
    if have is None:
        raise HTTPException(403, "You do not have access to this report")
    levels = {AccessLevel.view: 0, AccessLevel.edit: 1, AccessLevel.admin: 2}
    if levels[have] < levels[need]:
        raise HTTPException(403, f"This action requires {need.value} access (you have {have.value})")
    return have


# ---- Project-level visibility ---------------------------------------------
# There is no per-project ACL table in the schema. Project visibility is
# derived: admins/seniors see everything, the project lead sees their own
# project, an assigned ProjectMember sees it, and anyone with a report-level
# grant in the project gets project visibility too (otherwise they couldn't
# navigate to their own shared report from the project page).

def user_can_see_project(db: Session, user: User, project: Project) -> bool:
    """True if the user is allowed to view this project at all (any page,
    any API). Used to plug the IDOR where unrelated users could open
    /projects/{pid} by URL.
    """
    if user.role in (Role.admin, Role.senior):
        return True
    if project.lead_id == user.id:
        return True
    # Assigned team members. Membership is stored as a list of user ids on
    # `project.details["assigned_user_ids"]` — see assign_user_to_project
    # in projects.py. This used to also try a `ProjectMember` SQLAlchemy
    # model that doesn't exist in the schema, so the import always failed
    # and assignments were invisible everywhere.
    assigned_ids = (getattr(project, "details", None) or {}).get("assigned_user_ids") or []
    if user.id in assigned_ids:
        return True
    # Any report in the project the user owns, leads, or has a grant on.
    owned_report = (db.query(Report.id)
                      .filter(Report.project_id == project.id,
                              Report.created_by_id == user.id)
                      .first()) is not None
    if owned_report:
        return True
    granted_report = (db.query(ReportAccess.id)
                        .join(Report, Report.id == ReportAccess.report_id)
                        .filter(Report.project_id == project.id,
                                ReportAccess.user_id == user.id)
                        .first()) is not None
    if granted_report:
        return True

    # "Open by default": if the project has any report with no explicit
    # ReportAccess grants it is "unlocked" — any authenticated user may
    # view the project so they can navigate to those open reports.
    # Mirrors the effective_access() "open by default" fallback.
    open_report = (
        db.query(Report.id)
          .filter(Report.project_id == project.id)
          .outerjoin(ReportAccess, ReportAccess.report_id == Report.id)
          .group_by(Report.id)
          .having(func.count(ReportAccess.id) == 0)
          .limit(1)
          .first()
    ) is not None
    return open_report


def require_project_visibility(db: Session, user: User, project: Project) -> None:
    """Raise 403 if the user has no business looking at this project."""
    if not user_can_see_project(db, user, project):
        raise HTTPException(403, "You do not have access to this project")


# ---------- DTOs ----------

class UserPickerOut(BaseModel):
    """Minimal user info for the share picker. No password, no auth bits."""
    id: int
    username: str
    full_name: Optional[str] = None
    email: str
    role: Role
    is_active: bool

    class Config:
        from_attributes = True


class GrantAccessRequest(BaseModel):
    user_id: int
    access_level: AccessLevel = AccessLevel.edit
    note: Optional[str] = None


class UpdateAccessRequest(BaseModel):
    access_level: AccessLevel
    note: Optional[str] = None


class AccessGrantOut(BaseModel):
    id: int
    user: UserPickerOut
    access_level: AccessLevel
    granted_by_id: Optional[int] = None
    granted_at: str
    note: Optional[str] = None
    is_owner: bool = False
    is_implicit: bool = False  # true for admins / project leads (no row in report_access)

    class Config:
        from_attributes = True


class ReportFeedItem(BaseModel):
    """An entry in the 'my reports' / 'shared with me' feeds."""
    id: int
    name: str
    project_id: int
    project_name: str
    client_name: str
    template_id: int
    current_version: str
    created_at: str
    created_by_id: Optional[int] = None
    my_access: AccessLevel
    is_owner: bool
    shared_by: Optional[str] = None  # username of granter (for shared-with-me feed)


# ---------- User picker ----------

@router.get("/api/users", response_model=list[UserPickerOut])
def list_users_for_picker(
    q: Optional[str] = Query(None, description="Free-text search across username / full_name / email"),
    active_only: bool = True,
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
):
    """Every authenticated user can list registered users -- this powers the share picker.
    Sensitive fields (password hash) are excluded by the schema.
    """
    query = db.query(User)
    if active_only:
        query = query.filter(User.is_active == True)  # noqa
    if q:
        pat = f"%{q}%"
        query = query.filter(or_(
            User.username.ilike(pat),
            User.full_name.ilike(pat),
            User.email.ilike(pat),
        ))
    return query.order_by(User.username).limit(200).all()


# ---------- Access management ----------

def _serialize_grant(grant: ReportAccess) -> dict:
    return {
        "id": grant.id,
        "user": UserPickerOut.model_validate(grant.user).model_dump(),
        "access_level": grant.access_level,
        "granted_by_id": grant.granted_by_id,
        "granted_at": grant.granted_at.isoformat() if grant.granted_at else None,
        "note": grant.note,
        "is_owner": False,
        "is_implicit": False,
    }


@router.get("/api/reports/{rid}/access")
def list_access(rid: int,
                db: Session = Depends(get_db),
                user: User = Depends(get_current_user)):
    report = db.get(Report, rid)
    if not report:
        raise HTTPException(404, "Report not found")
    require_access(db, user, report, need=AccessLevel.view)

    items: list[dict] = []

    # Owner (always present, immutable)
    if report.created_by_id:
        owner = db.get(User, report.created_by_id)
        if owner:
            items.append({
                "id": None,
                "user": UserPickerOut.model_validate(owner).model_dump(),
                "access_level": AccessLevel.admin,
                "granted_by_id": None,
                "granted_at": report.created_at.isoformat() if report.created_at else None,
                "note": "Report owner",
                "is_owner": True,
                "is_implicit": False,
            })

    # Project lead (if different from owner -- implicit admin)
    project = db.get(Project, report.project_id)
    if project and project.lead_id and project.lead_id != report.created_by_id:
        lead = db.get(User, project.lead_id)
        if lead:
            items.append({
                "id": None,
                "user": UserPickerOut.model_validate(lead).model_dump(),
                "access_level": AccessLevel.admin,
                "granted_by_id": None,
                "granted_at": None,
                "note": "Project lead (implicit)",
                "is_owner": False,
                "is_implicit": True,
            })

    # Explicit grants
    for grant in report.access_grants:
        if grant.user_id == report.created_by_id:
            continue  # owner already shown
        items.append(_serialize_grant(grant))

    return {"report_id": rid, "items": items}


@router.post("/api/reports/{rid}/access")
def grant_access(rid: int,
                 payload: GrantAccessRequest,
                 db: Session = Depends(get_db),
                 user: User = Depends(get_current_user)):
    report = db.get(Report, rid)
    if not report:
        raise HTTPException(404, "Report not found")
    require_access(db, user, report, need=AccessLevel.admin)

    target = db.get(User, payload.user_id)
    if not target:
        raise HTTPException(404, "Target user not found")
    if not target.is_active:
        raise HTTPException(400, "Target user is disabled")
    if target.id == report.created_by_id:
        raise HTTPException(400, "Cannot grant access -- target is already the report owner")

    existing = (db.query(ReportAccess)
                  .filter(ReportAccess.report_id == rid,
                          ReportAccess.user_id == target.id)
                  .first())
    if existing:
        existing.access_level = payload.access_level
        existing.granted_by_id = user.id
        existing.note = payload.note
        grant = existing
        action = "report.access.update"
    else:
        grant = ReportAccess(
            report_id=rid,
            user_id=target.id,
            access_level=payload.access_level,
            granted_by_id=user.id,
            note=payload.note,
        )
        db.add(grant)
        action = "report.access.grant"

    db.add(AuditLog(
        actor_id=user.id, action=action, object_type="report", object_id=rid,
        detail={"target_user_id": target.id, "access_level": payload.access_level.value},
    ))
    db.commit()
    db.refresh(grant)

    # Best-effort email notification — routed through `notify_user`
    # so the recipient's email-opt-out preference is honoured.
    from ..services.notifier import notify_user
    from ..services.url_helpers import absolute_url
    project = db.get(Project, report.project_id)
    notify_user(
        db, target, "report_access_granted", {
            "user": target,
            "actor_username": user.username,
            "report_name": report.name,
            "project_name": project.name if project else "",
            "client_name": project.client_name if project else "",
            "access_level": payload.access_level.value,
            "report_url": absolute_url(f"/reports/{rid}"),
        },
        actor_user_id=user.id,
    )

    return _serialize_grant(grant)


@router.put("/api/reports/{rid}/access/{user_id}")
def update_access(rid: int, user_id: int,
                  payload: UpdateAccessRequest,
                  db: Session = Depends(get_db),
                  user: User = Depends(get_current_user)):
    report = db.get(Report, rid)
    if not report:
        raise HTTPException(404, "Report not found")
    require_access(db, user, report, need=AccessLevel.admin)
    if user_id == report.created_by_id:
        raise HTTPException(400, "Cannot modify owner's access")

    grant = (db.query(ReportAccess)
               .filter(ReportAccess.report_id == rid,
                       ReportAccess.user_id == user_id)
               .first())
    if not grant:
        raise HTTPException(404, "No access grant exists for this user")
    grant.access_level = payload.access_level
    grant.granted_by_id = user.id
    if payload.note is not None:
        grant.note = payload.note
    db.add(AuditLog(
        actor_id=user.id, action="report.access.update",
        object_type="report", object_id=rid,
        detail={"target_user_id": user_id, "access_level": payload.access_level.value},
    ))
    db.commit()
    db.refresh(grant)
    return _serialize_grant(grant)


@router.delete("/api/reports/{rid}/access/{user_id}")
def revoke_access(rid: int, user_id: int,
                  db: Session = Depends(get_db),
                  user: User = Depends(get_current_user)):
    report = db.get(Report, rid)
    if not report:
        raise HTTPException(404, "Report not found")

    # Two valid cases: (1) admin revoking someone else, (2) anyone removing themselves
    if user.id == user_id:
        # self-removal allowed for anyone with a grant
        pass
    else:
        require_access(db, user, report, need=AccessLevel.admin)
    if user_id == report.created_by_id:
        raise HTTPException(400, "Cannot revoke the report owner's access")

    grant = (db.query(ReportAccess)
               .filter(ReportAccess.report_id == rid,
                       ReportAccess.user_id == user_id)
               .first())
    if not grant:
        raise HTTPException(404, "No grant to revoke")
    db.delete(grant)
    db.add(AuditLog(
        actor_id=user.id, action="report.access.revoke",
        object_type="report", object_id=rid,
        detail={"target_user_id": user_id},
    ))
    db.commit()
    return {"ok": True, "revoked_user_id": user_id}


# ---------- Personalised report feeds ----------

def _feed_item(db: Session, report: Report, user: User,
               shared_by: Optional[str] = None) -> dict:
    project = db.get(Project, report.project_id)
    level = effective_access(db, user, report) or AccessLevel.view
    return {
        "id": report.id,
        "name": report.name,
        "project_id": report.project_id,
        "project_name": project.name if project else "",
        "client_name": project.client_name if project else "",
        "template_id": report.template_id,
        "current_version": report.current_version,
        "created_at": report.created_at.isoformat() if report.created_at else None,
        "created_by_id": report.created_by_id,
        "my_access": level.value if level else "view",
        "is_owner": (report.created_by_id == user.id),
        "shared_by": shared_by,
    }


@router.get("/api/reports/mine")
def my_reports(db: Session = Depends(get_db),
               user: User = Depends(get_current_user)):
    """Reports I own (i.e. I created)."""
    rows = (db.query(Report)
              .filter(Report.created_by_id == user.id)
              .order_by(Report.created_at.desc())
              .all())
    return {"items": [_feed_item(db, r, user) for r in rows]}


@router.get("/api/reports/shared-with-me")
def shared_with_me(db: Session = Depends(get_db),
                   user: User = Depends(get_current_user)):
    """Reports another user has granted me access to (explicit ReportAccess rows)."""
    grants = (db.query(ReportAccess)
                .filter(ReportAccess.user_id == user.id)
                .order_by(ReportAccess.granted_at.desc())
                .all())
    items = []
    for g in grants:
        report = db.get(Report, g.report_id)
        if not report:
            continue
        # Exclude reports I happen to own (shouldn't happen but defensive)
        if report.created_by_id == user.id:
            continue
        granter = db.get(User, g.granted_by_id) if g.granted_by_id else None
        items.append(_feed_item(db, report, user,
                                shared_by=granter.username if granter else None))
    return {"items": items}


@router.get("/api/reports/accessible")
def accessible_reports(db: Session = Depends(get_db),
                       user: User = Depends(get_current_user)):
    """Union: owned + shared. For the unified 'my work' feed.

    Admins see everything; sees-everything is intentional for the admin role.
    """
    if user.role == Role.admin:
        rows = db.query(Report).order_by(Report.created_at.desc()).limit(500).all()
        return {"items": [_feed_item(db, r, user) for r in rows], "admin_view": True}

    owned_ids = {r.id for r in db.query(Report.id)
                                  .filter(Report.created_by_id == user.id).all()}
    led_ids = {r.id for r in db.query(Report.id).join(Project)
                                 .filter(Project.lead_id == user.id).all()}
    shared_ids = {g.report_id for g in db.query(ReportAccess.report_id)
                                          .filter(ReportAccess.user_id == user.id).all()}
    all_ids = owned_ids | led_ids | shared_ids
    if not all_ids:
        return {"items": [], "admin_view": False}

    rows = (db.query(Report)
              .filter(Report.id.in_(all_ids))
              .order_by(Report.created_at.desc())
              .all())
    return {"items": [_feed_item(db, r, user) for r in rows], "admin_view": False}
