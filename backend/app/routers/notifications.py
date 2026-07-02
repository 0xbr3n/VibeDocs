"""
In-app notification bell.

The bell icon in the top-right of every page (see templates/base.html)
fetches its content from this router. Notifications are derived from
existing `audit_log` rows — we deliberately don't have a separate
`notifications` table because every event that should notify a user
(report shared with me, added to a project team, project I had access
to deleted, my access revoked) is already persisted as an AuditLog
row by the action that caused it.

Unread tracking
---------------
We add a single column `users.notifications_read_at` (NULL = never
opened the bell). The badge count = number of notifications whose
`AuditLog.at` is newer than that timestamp. POSTing /mark-all-read
sets the timestamp to now() and zeroes the count.

We never notify a user about their own action, so `actor_id != user.id`
is enforced for every selector. The same user cannot receive a
notification triggered by themselves (e.g. an admin who shares a report
with themselves wouldn't get a self-notification).

Endpoints
---------
  GET  /api/notifications             list recent notifications + unread count
  POST /api/notifications/mark-all-read   mark all currently-visible as read
"""
from __future__ import annotations

from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends
from sqlalchemy import or_
from sqlalchemy.orm import Session
from sqlalchemy.orm.attributes import flag_modified

from ..database import get_db
from ..models import AuditLog, User, Report, Project, Role
from ..auth import get_current_user


router = APIRouter(prefix="/api/notifications", tags=["notifications"])


# How many recent notifications to surface in the dropdown. The full
# audit trail still lives in `audit_log`; this is just what the bell
# shows. Kept small so the dropdown stays snappy and bounded.
MAX_NOTIFICATIONS = 30


def _build_message(db: Session, log: AuditLog) -> Optional[dict]:
    """Translate an AuditLog row into a UI-friendly notification dict.

    Returns None for actions we don't want to surface in the bell
    (e.g. self-revocations, or rows where we can't resolve the target).
    """
    actor = db.get(User, log.actor_id) if log.actor_id else None
    actor_name = (actor.full_name or actor.username) if actor else "Someone"
    detail = log.detail or {}

    if log.action in ("report.access.grant", "report.access.update"):
        report = db.get(Report, log.object_id) if log.object_id else None
        level = (detail.get("access_level") or "view").lower()
        verb = "shared" if log.action == "report.access.grant" else "updated your access on"
        if report:
            project = db.get(Project, report.project_id) if report.project_id else None
            client = f" ({project.client_name})" if project and project.client_name else ""
            title = f"{actor_name} {verb} report “{report.name}”{client}"
        else:
            title = f"{actor_name} {verb} a report"
        return {
            "id": log.id,
            "type": log.action,
            "message": title,
            "detail": f"Access level: {level}",
            "link": f"/reports/{log.object_id}" if log.object_id else "/reports",
            "icon": "\U0001F4E5",  # inbox tray
            "created_at": log.at.isoformat() if log.at else None,
        }

    if log.action == "report.access.revoke":
        report = db.get(Report, log.object_id) if log.object_id else None
        name = report.name if report else "a report"
        return {
            "id": log.id,
            "type": log.action,
            "message": f"{actor_name} removed your access to “{name}”",
            "detail": None,
            "link": "/reports",
            "icon": "\U0001F6AB",  # no-entry
            "created_at": log.at.isoformat() if log.at else None,
        }

    if log.action == "project.member.assigned":
        project = db.get(Project, log.object_id) if log.object_id else None
        if project:
            client = f" ({project.client_name})" if project.client_name else ""
            title = f"{actor_name} added you to project “{project.name}”{client}"
        else:
            name = detail.get("project_name") or "a project"
            title = f"{actor_name} added you to project “{name}”"
        return {
            "id": log.id,
            "type": log.action,
            "message": title,
            "detail": None,
            "link": f"/projects/{log.object_id}" if log.object_id else "/projects",
            "icon": "\U0001F465",  # busts in silhouette
            "created_at": log.at.isoformat() if log.at else None,
        }

    if log.action == "project.member.removed":
        name = detail.get("project_name") or "a project"
        return {
            "id": log.id,
            "type": log.action,
            "message": f"{actor_name} removed you from project “{name}”",
            "detail": None,
            "link": "/projects",
            "icon": "\U0001F6AB",
            "created_at": log.at.isoformat() if log.at else None,
        }

    if log.action == "project.delete":
        name = detail.get("name") or "a project"
        client = detail.get("client")
        suffix = f" ({client})" if client else ""
        return {
            "id": log.id,
            "type": log.action,
            "message": f"{actor_name} deleted project “{name}”{suffix}",
            "detail": "All reports under this project have been removed.",
            "link": "/projects",
            "icon": "\U0001F5D1",  # wastebasket
            "created_at": log.at.isoformat() if log.at else None,
        }

    if log.action == "template.review.requested":
        name = detail.get("template_name") or "a template"
        ttype = detail.get("template_type") or ""
        suffix = f" ({ttype})" if ttype else ""
        return {
            "id": log.id,
            "type": log.action,
            "message": f"{actor_name} submitted template “{name}”{suffix} for review",
            "detail": "Open the Reviews page to approve or reject.",
            "link": "/reviews",
            "icon": "\U0001F4DD",  # memo
            "created_at": log.at.isoformat() if log.at else None,
        }

    if log.action == "template.review.decided":
        name = detail.get("template_name") or "your template"
        dec  = (detail.get("decision") or "").lower()
        verb = "approved" if dec == "approved" else "rejected"
        return {
            "id": log.id,
            "type": log.action,
            "message": f"{actor_name} {verb} your template “{name}”",
            "detail": (detail.get("notes") or "")[:160] or None,
            "link": f"/templates/edit/{log.object_id}" if log.object_id else "/templates",
            "icon": "✅" if dec == "approved" else "❌",
            "created_at": log.at.isoformat() if log.at else None,
        }

    if log.action == "finding.review.requested":
        name = detail.get("finding_title") or "a finding"
        return {
            "id": log.id,
            "type": log.action,
            "message": f"{actor_name} submitted finding “{name}” for review",
            "detail": "Open the Reviews page to approve or reject.",
            "link": "/reviews",
            "icon": "\U0001F50D",  # magnifying glass
            "created_at": log.at.isoformat() if log.at else None,
        }

    if log.action == "finding.review.decided":
        name = detail.get("finding_title") or "your finding"
        dec  = (detail.get("decision") or "").lower()
        verb = "approved" if dec == "approved" else "rejected"
        suffix = ""
        if dec == "rejected" and detail.get("notes"):
            suffix = " — see Findings library for reviewer notes"
        return {
            "id": log.id,
            "type": log.action,
            "message": f"{actor_name} {verb} your finding “{name}”{suffix}",
            "detail": (detail.get("notes") or "")[:160] or None,
            "link": "/library",
            "icon": "✅" if dec == "approved" else "❌",
            "created_at": log.at.isoformat() if log.at else None,
        }

    return None


RELEVANT_ACTIONS = (
    "report.access.grant",
    "report.access.update",
    "report.access.revoke",
    "project.member.assigned",
    "project.member.removed",
    "project.delete",
    "template.review.requested",
    "template.review.decided",
    "finding.review.requested",
    "finding.review.decided",
)


# Actions that fan out to every reviewer (admin + senior). The audit
# row doesn't name a specific recipient — instead, every user with
# review authority sees it in their bell + on the Reviews page.
_REVIEW_FANOUT_ACTIONS = (
    "template.review.requested",
    "finding.review.requested",
)


def _row_targets_user(log: AuditLog, uid: int, role: Optional[Role] = None) -> bool:
    """In-Python predicate for whether a given AuditLog row should appear
    in this user's notification feed.

    `role` is the caller's role; only consulted for review-fanout rows
    (those go to every admin / senior, not to a single named target).

    We do the action-prefilter at the DB layer (cheap, indexed) and the
    per-row JSON inspection here. The audit log is bounded by the number
    of permission / membership / review events, not by general user
    activity, so this stays fast in practice. Moving the JSON match
    into the DB layer would require dialect-specific operators
    (`detail->>` for JSONB vs `json_extract` for SQLite); doing it in
    Python keeps the router portable across both supported databases.
    """
    detail = log.detail or {}
    if log.action in ("report.access.grant",
                      "report.access.update",
                      "report.access.revoke"):
        return detail.get("target_user_id") == uid
    if log.action == "project.member.assigned":
        return detail.get("assigned_user_id") == uid
    if log.action == "project.member.removed":
        return detail.get("removed_user_id") == uid
    if log.action == "project.delete":
        notified = detail.get("notified_user_ids") or []
        return uid in notified
    if log.action in _REVIEW_FANOUT_ACTIONS:
        # Reviewers (admin + senior) are notified of every new pending
        # item. We don't fan out to the submitter — the actor_id check
        # in _fetch_candidate_rows already excludes their own action.
        return role in (Role.admin, Role.senior)
    if log.action in ("template.review.decided", "finding.review.decided"):
        return detail.get("submitter_id") == uid
    return False


def _fetch_candidate_rows(db: Session, user: User, limit: int) -> list[AuditLog]:
    """Pull recent rows matching the relevant action set, then filter in
    Python. Over-fetches by 4x to leave headroom for rows that don't
    target this user (e.g. permission changes affecting other people),
    capped to avoid unbounded scans on noisy logs.
    """
    uid = user.id
    fetch_window = max(limit * 4, 200)
    rows = (
        db.query(AuditLog)
          .filter(
              AuditLog.action.in_(RELEVANT_ACTIONS),
              # Never notify the user about their own actions
              or_(AuditLog.actor_id == None,  # noqa: E711
                  AuditLog.actor_id != uid),
          )
          .order_by(AuditLog.at.desc())
          .limit(fetch_window)
          .all()
    )
    return [r for r in rows if _row_targets_user(r, uid, user.role)]


def _dismissed_ids(user: User) -> set[int]:
    """Return the set of AuditLog ids the user has individually dismissed.

    Tolerates the column being missing on old deployments and gracefully
    coerces stored strings/numbers to int so list comparisons stay sane
    even if the JSON column was hand-edited.
    """
    raw = getattr(user, "dismissed_notifications", None) or []
    out: set[int] = set()
    for v in raw:
        try:
            out.add(int(v))
        except (TypeError, ValueError):
            continue
    return out


@router.get("")
def list_notifications(
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Return the current user's notifications + unread count.

    A notification is unread iff:
      • its `AuditLog.at` is newer than `users.notifications_read_at`
        (or that watermark is NULL), AND
      • its id is NOT in `users.dismissed_notifications`.

    The dismissed-id list handles per-row reads — clicking a single
    notification dismisses only that row, decrementing the badge by one
    instead of forcing "Mark all read".
    """
    read_at = getattr(user, "notifications_read_at", None)
    dismissed = _dismissed_ids(user)

    rows = _fetch_candidate_rows(db, user, MAX_NOTIFICATIONS)[:MAX_NOTIFICATIONS]

    items = []
    unread = 0
    for log in rows:
        item = _build_message(db, log)
        if not item:
            continue
        is_unread = (read_at is None) or (log.at is not None and log.at > read_at)
        if log.id in dismissed:
            is_unread = False
        item["is_unread"] = is_unread
        if is_unread:
            unread += 1
        items.append(item)

    return {
        "unread_count": unread,
        "items": items,
        "read_at": read_at.isoformat() if read_at else None,
    }


@router.post("/mark-all-read")
def mark_all_read(
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Set the user's `notifications_read_at` to now, zeroing the badge.

    Also empties `dismissed_notifications` since the new watermark
    supersedes every per-row dismissal — keeps that column from growing
    indefinitely. Idempotent.
    """
    now = datetime.utcnow()
    target = db.get(User, user.id)
    if target is not None:
        if hasattr(target, "notifications_read_at"):
            target.notifications_read_at = now
        if hasattr(target, "dismissed_notifications"):
            target.dismissed_notifications = []
            flag_modified(target, "dismissed_notifications")
        db.commit()
    return {"ok": True, "read_at": now.isoformat()}


@router.post("/{notif_id}/mark-read")
def mark_one_read(
    notif_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Dismiss a single notification (by its AuditLog id) for the caller.

    Only useful when the notification is post-`notifications_read_at` —
    anything older is already considered read via the watermark. The
    endpoint stays idempotent: re-dismissing a row is a no-op.

    Security note: we don't 404 when the AuditLog row doesn't belong to
    this user. The dismissal is keyed on the caller's user id only, so
    the worst a malicious caller can do is litter their OWN dismissed
    list with arbitrary ids — no cross-user effect.
    """
    target = db.get(User, user.id)
    if target is None or not hasattr(target, "dismissed_notifications"):
        return {"ok": True, "dismissed": []}
    current = list(target.dismissed_notifications or [])
    # Coerce to int for stable comparisons; keep the list canonical.
    norm = []
    seen: set[int] = set()
    for v in current:
        try:
            i = int(v)
            if i not in seen:
                seen.add(i); norm.append(i)
        except (TypeError, ValueError):
            continue
    if notif_id not in seen:
        norm.append(int(notif_id))
        target.dismissed_notifications = norm
        flag_modified(target, "dismissed_notifications")
        db.commit()
    return {"ok": True, "dismissed_count": len(norm)}
