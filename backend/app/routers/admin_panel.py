"""Admin Panel — user / role / permission management.

The classic role system (admin / senior / consultant / viewer) is the
baseline. This panel lets an admin layer per-user permission overrides
on top, without forcing role escalation — a consultant who needs to
approve library findings gets `library.approve` granted explicitly
instead of being promoted to senior.

Endpoints
---------
    Catalog (read-only — drives the UI checkbox matrix)
        GET  /api/admin/panel/permissions/catalog

    User management
        GET  /api/admin/panel/users
        POST /api/admin/panel/users
        PATCH /api/admin/panel/users/{uid}                 role / full_name / email / is_active
        DELETE /api/admin/panel/users/{uid}                 soft-disable (sets is_active=False)
        POST /api/admin/panel/users/{uid}/reset-password    generate + send reset email

    Per-user permission overrides
        GET  /api/admin/panel/users/{uid}/permissions
        PUT  /api/admin/panel/users/{uid}/permissions       bulk replace (list of grants)
        POST /api/admin/panel/users/{uid}/permissions       grant or revoke one
        DELETE /api/admin/panel/users/{uid}/permissions/{perm}    drop the override (back to role default)

    Role default overrides
        GET  /api/admin/panel/roles/{role}/permissions
        PUT  /api/admin/panel/roles/{role}/permissions      bulk replace
        DELETE /api/admin/panel/roles/{role}/permissions/{perm}

    Audit (recent changes for the admin log tab)
        GET  /api/admin/panel/audit?limit=200

Authorisation
-------------
Every endpoint is gated on `Permission.PERMISSION_GRANT`. The admin
role implicitly has this permission (the `has_permission` resolver
short-circuits for admins) so a fresh deploy works without any
seeded overrides. A senior user can be granted
`permission.grant` explicitly by an admin to become a co-admin
without taking the full `admin` role.
"""
from __future__ import annotations
import logging
import secrets
from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, UploadFile, File
from fastapi.responses import Response
from pydantic import BaseModel, EmailStr
from sqlalchemy import or_
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import (
    User, Role, AuditLog,
    UserPermissionOverride, RolePermissionOverride,
    AccountUnlockToken,
)
from ..auth import get_current_user, hash_password
from ..services.permissions_service import (
    Permission, PERMISSION_LABELS, PERMISSION_GROUPS,
    ROLE_DEFAULT_PERMISSIONS, has_permission, effective_permissions,
    require_permission,
)


router = APIRouter(prefix="/api/admin/panel", tags=["admin-panel"])

logger = logging.getLogger(__name__)


# ============================================================
# Catalog (read-only)
# ============================================================

@router.get("/permissions/catalog")
def get_permissions_catalog(
    _: User = Depends(require_permission(Permission.PERMISSION_GRANT)),
):
    """Return the catalog the admin Panel UI uses to render the
    permission checkbox matrix. Includes:

      * `groups` — ordered list of (label, [perm strings]) used as
        the row grouping in the UI. Adding a new permission to the
        backend automatically shows up here.
      * `labels` — perm string → human-readable label.
      * `roles` — list of role names + their default permission set.
    """
    return {
        "groups": [
            {"label": label,
             "permissions": [p.value for p in perms]}
            for label, perms in PERMISSION_GROUPS
        ],
        "labels": {p.value: PERMISSION_LABELS[p] for p in Permission},
        "roles": [
            {
                "name": role.value,
                "default_permissions": sorted(
                    p.value for p in ROLE_DEFAULT_PERMISSIONS.get(role, set())
                ),
            }
            for role in Role
        ],
    }


# ============================================================
# Users
# ============================================================

class _UserOut(BaseModel):
    id: int
    username: str
    email: str
    full_name: Optional[str] = None
    role: Role
    is_active: bool
    created_at: Optional[datetime] = None
    has_2fa: bool = False
    effective_permission_count: int = 0
    override_count: int = 0

    class Config:
        from_attributes = True


@router.get("/users")
def list_users(
    db: Session = Depends(get_db),
    _: User = Depends(require_permission(Permission.PERMISSION_GRANT)),
):
    """List every user with their effective permission count + any
    overrides. The Panel UI groups this by role and renders the
    override-count badge next to each row so the admin sees at a
    glance who has been customised away from their role default.

    Previously queried UserPermissionOverride and RolePermissionOverride
    once per user (N+1). Now pre-fetches all overrides in 2 queries,
    then computes effective permissions in Python for each user.
    """
    from collections import defaultdict

    rows = db.query(User).order_by(User.username).all()

    # Bulk-fetch all overrides in 2 queries regardless of user count
    user_ovs: dict[int, list] = defaultdict(list)
    for ov in db.query(UserPermissionOverride).all():
        user_ovs[ov.user_id].append(ov)

    role_ovs: dict[str, list] = defaultdict(list)
    for ov in db.query(RolePermissionOverride).all():
        role_ovs[ov.role if isinstance(ov.role, str) else ov.role.value].append(ov)

    def _eff_perms_bulk(u: User) -> set[str]:
        if u.role == Role.admin:
            return {p.value for p in Permission}
        role_str = u.role.value if hasattr(u.role, "value") else str(u.role)
        base = {p.value for p in ROLE_DEFAULT_PERMISSIONS.get(u.role, set())}
        for ov in role_ovs.get(role_str, []):
            if ov.granted:
                base.add(ov.permission)
            else:
                base.discard(ov.permission)
        for ov in user_ovs.get(u.id, []):
            if ov.granted:
                base.add(ov.permission)
            else:
                base.discard(ov.permission)
        return base

    out: list[dict] = []
    for u in rows:
        eff = _eff_perms_bulk(u)
        out.append({
            "id": u.id,
            "username": u.username,
            "email": u.email,
            "full_name": u.full_name,
            "role": u.role.value if hasattr(u.role, "value") else u.role,
            "is_active": u.is_active,
            "created_at": u.created_at.isoformat() if u.created_at else None,
            "has_2fa": bool(u.totp_enabled),
            "mfa_enforced": bool(getattr(u, "totp_required", False)),
            "effective_permission_count": len(eff),
            "override_count": len(user_ovs.get(u.id, [])),
            # Account lockout fields
            "locked_at": u.locked_at.isoformat() if getattr(u, "locked_at", None) else None,
            "lock_reason": getattr(u, "lock_reason", None),
            "failed_login_attempts": getattr(u, "failed_login_attempts", 0) or 0,
        })
    return {"users": out}


class _UserCreatePayload(BaseModel):
    username: str
    email: EmailStr
    full_name: Optional[str] = None
    password: str
    role: Role = Role.consultant
    # Admin can flip "you must set up 2FA at next login" at create
    # time so a freshly-provisioned user never gets to use the app
    # without an authenticator. The forced-enrollment gate in
    # `auth.get_current_user` only lets these users reach the MFA
    # setup endpoints until they finish enrollment.
    enforce_mfa: bool = False


@router.post("/users")
def create_user(
    payload: _UserCreatePayload,
    db: Session = Depends(get_db),
    actor: User = Depends(require_permission(Permission.USER_CREATE)),
):
    if len(payload.password) < 8 or len(payload.password) > 256:
        raise HTTPException(400, "Password must be 8–256 characters.")
    if db.query(User).filter(User.username == payload.username).first():
        raise HTTPException(400, "Username already exists")
    if db.query(User).filter(User.email == payload.email).first():
        raise HTTPException(400, "Email already exists")
    u = User(
        username=payload.username,
        email=payload.email,
        full_name=payload.full_name,
        role=payload.role,
        hashed_password=hash_password(payload.password),
        is_active=True,
        totp_required=bool(payload.enforce_mfa),
        totp_required_by_id=actor.id if payload.enforce_mfa else None,
        totp_required_at=datetime.utcnow() if payload.enforce_mfa else None,
    )
    db.add(u)
    db.commit()
    db.refresh(u)
    db.add(AuditLog(
        actor_id=actor.id, action="user.create", object_type="user",
        object_id=u.id,
        detail={"username": u.username, "role": payload.role.value,
                "enforce_mfa": bool(payload.enforce_mfa)},
    ))
    db.commit()
    return {"ok": True, "id": u.id}


class _AdminSetPasswordPayload(BaseModel):
    new_password: str


class _MfaEnforcePayload(BaseModel):
    enforce: bool


@router.post("/users/{uid}/set-password")
def admin_set_password(
    uid: int,
    payload: _AdminSetPasswordPayload,
    db: Session = Depends(get_db),
    actor: User = Depends(require_permission(Permission.USER_RESET_PASSWORD)),
):
    """Admin force-sets a user's password to a value of the admin's
    choosing. Used when a user is locked out and the team wants to
    hand them a temporary password directly rather than have them go
    through the email-reset loop.

    Audit-logged with `admin_id` + `target_user_id` so the action is
    traceable. The plaintext password is NEVER logged. Any existing
    password-reset tokens on the user are invalidated (so an
    in-flight reset link can't outlive the admin's intervention).
    """
    target = db.get(User, uid)
    if not target:
        raise HTTPException(404, "User not found")
    new_pw = (payload.new_password or "").strip()
    if len(new_pw) < 8 or len(new_pw) > 256:
        raise HTTPException(400, "Password must be 8–256 characters.")
    # Don't allow admins to force-set THEIR own password through this
    # endpoint — they'd bypass the current-password check that the
    # legitimate self-service `change-password` route enforces.
    if target.id == actor.id:
        raise HTTPException(
            400,
            "Use /api/auth/change-password to change your own password "
            "(requires your current password).",
        )

    target.hashed_password = hash_password(new_pw)
    db.commit()

    # Invalidate any pending password-reset tokens — if the admin
    # has just handed the user a new password the in-flight email
    # link shouldn't keep working.
    try:
        from ..models import PasswordResetToken
        (db.query(PasswordResetToken)
           .filter(PasswordResetToken.user_id == target.id,
                   PasswordResetToken.used_at.is_(None))
           .update({"used_at": datetime.utcnow()}))
        db.commit()
    except Exception:                                       # pragma: no cover
        db.rollback()

    db.add(AuditLog(
        actor_id=actor.id, action="admin.user.password_force_set",
        object_type="user", object_id=target.id,
        detail={"target_username": target.username},
    ))
    db.commit()

    # Send a confirmation email so the USER notices the change in
    # case they didn't ask for it. Bypasses the per-user opt-out
    # because this is a security event.
    if target.email:
        try:
            from ..services import email_templates as _email_tmpls
            from ..services.email_send import send_mail
            subject, body_text, body_html = _email_tmpls.render_template(
                db, "password_changed", {
                    "user": target,
                    "actor_username": actor.username,
                },
            )
            send_mail(target.email, subject,
                      body_text=body_text, body_html=body_html)
        except Exception:                                   # pragma: no cover
            pass

    return {"ok": True, "target_username": target.username,
            "tokens_invalidated": True}


class _AdminSendResetPayload(BaseModel):
    pass


@router.post("/users/{uid}/send-reset-link")
def admin_send_reset_link(
    uid: int,
    request: Request,
    db: Session = Depends(get_db),
    actor: User = Depends(require_permission(Permission.USER_RESET_PASSWORD)),
):
    """Admin triggers a password-reset email to the user. Mints a
    fresh token (invalidates any prior ones), stores the bcrypt hash
    on a PasswordResetToken row, and emails the plaintext link.

    Same TTL + same email template as the user-initiated `forgot
    password` flow — the only difference is the audit row records
    `admin.user.password_reset_sent` rather than
    `auth.forgot_requested`, so the security team can tell the two
    apart in the log.
    """
    from ..models import PasswordResetToken

    target = db.get(User, uid)
    if not target:
        raise HTTPException(404, "User not found")
    if not target.email:
        raise HTTPException(
            400,
            f"User {target.username!r} has no email address on file — "
            "use Set password instead.",
        )
    if not target.is_active:
        raise HTTPException(400, "Cannot reset password for a disabled user.")

    # Invalidate any prior unused tokens — only one live token at a
    # time, same invariant as the user-initiated path.
    (db.query(PasswordResetToken)
       .filter(PasswordResetToken.user_id == target.id,
               PasswordResetToken.used_at.is_(None))
       .update({"used_at": datetime.utcnow()}))

    # Mint a fresh token via the password-reset router's helpers so
    # the format / TTL stay in lockstep with the user-initiated flow.
    from ..routers.password_reset import _mint_token, TOKEN_TTL_MINUTES
    plain, token_hash = _mint_token()
    row = PasswordResetToken(
        user_id=target.id,
        token_hash=token_hash,
        expires_at=datetime.utcnow() + timedelta(minutes=TOKEN_TTL_MINUTES),
        requested_ip=None,
        user_agent="admin-panel",
    )
    db.add(row)
    db.add(AuditLog(
        actor_id=actor.id, action="admin.user.password_reset_sent",
        object_type="user", object_id=target.id,
        detail={"target_username": target.username,
                "ttl_minutes": TOKEN_TTL_MINUTES},
    ))
    db.commit()

    # Send the email. Bypasses the user's email-opt-out preference
    # because this is a security event triggered by an admin.
    try:
        from ..services import email_templates as _email_tmpls
        from ..services.email_send import send_mail
        from ..services.url_helpers import absolute_url
        reset_url = absolute_url(f"/reset-password?token={plain}", request=request)
        subject, body_text, body_html = _email_tmpls.render_template(
            db, "password_reset", {
                "user": target,
                "reset_url": reset_url,
                "ttl_minutes": TOKEN_TTL_MINUTES,
            },
        )
        send_mail(target.email, subject,
                  body_text=body_text, body_html=body_html)
    except Exception as e:                                  # pragma: no cover
        # Token already minted + audit-logged. We still surface a
        # 200 so the admin knows the token exists, but include a
        # warning so they can resort to copy-pasting the link if
        # SMTP is broken.
        return {"ok": True, "email_sent": False, "warning": str(e),
                "target_email": target.email,
                "ttl_minutes": TOKEN_TTL_MINUTES}

    return {"ok": True, "email_sent": True,
            "target_email": target.email,
            "ttl_minutes": TOKEN_TTL_MINUTES}


@router.post("/users/{uid}/enforce-mfa")
def enforce_mfa(
    uid: int,
    payload: _MfaEnforcePayload,
    db: Session = Depends(get_db),
    actor: User = Depends(require_permission(Permission.USER_EDIT)),
):
    """Toggle whether the user is forced into 2FA enrollment.

    enforce=True
        Sets `totp_required=True`. If the user already has
        `totp_enabled=True` this is effectively a no-op for them
        until the day they ever disable 2FA — the column is the
        admin's intent, not the user's current state.
    enforce=False
        Clears `totp_required`. Does NOT auto-disable an
        already-enrolled second factor — a user who has 2FA on stays
        on it. To actually disable a user's 2FA, use the existing
        `/api/twofa/disable` route (which they need to do themselves
        with their own password).
    """
    u = db.get(User, uid)
    if not u:
        raise HTTPException(404, "User not found")
    if u.id == actor.id and not payload.enforce:
        raise HTTPException(
            400,
            "Can't disable MFA enforcement on yourself. Have another "
            "admin do it.",
        )
    if u.totp_required == payload.enforce:
        return {"ok": True, "no_change": True,
                "totp_required": u.totp_required,
                "totp_enabled": u.totp_enabled}
    u.totp_required = payload.enforce
    u.totp_required_by_id = actor.id if payload.enforce else None
    u.totp_required_at = datetime.utcnow() if payload.enforce else None
    db.commit()
    db.add(AuditLog(
        actor_id=actor.id,
        action="user.mfa.enforce" if payload.enforce else "user.mfa.unenforce",
        object_type="user", object_id=u.id,
        detail={"totp_enabled": u.totp_enabled},
    ))
    db.commit()
    return {"ok": True, "totp_required": u.totp_required,
            "totp_enabled": u.totp_enabled}


class _UserPatchPayload(BaseModel):
    full_name: Optional[str] = None
    email: Optional[EmailStr] = None
    role: Optional[Role] = None
    is_active: Optional[bool] = None


@router.patch("/users/{uid}")
def patch_user(
    uid: int,
    payload: _UserPatchPayload,
    db: Session = Depends(get_db),
    actor: User = Depends(require_permission(Permission.USER_EDIT)),
):
    u = db.get(User, uid)
    if not u:
        raise HTTPException(404, "User not found")
    # Block self-demotion from admin → consultant; the admin can hand
    # the role to another user first, then have them edit this one.
    if actor.id == u.id and payload.role and payload.role != u.role:
        raise HTTPException(
            400,
            "Cannot change your own role. Have another admin do it.",
        )
    if actor.id == u.id and payload.is_active is False:
        raise HTTPException(400, "Cannot deactivate yourself.")
    changes: dict = {}
    if payload.full_name is not None and payload.full_name != u.full_name:
        changes["full_name"] = [u.full_name, payload.full_name]
        u.full_name = payload.full_name
    if payload.email is not None and payload.email != u.email:
        # Uniqueness check
        if db.query(User).filter(User.email == payload.email,
                                  User.id != uid).first():
            raise HTTPException(400, "Email already in use")
        changes["email"] = [u.email, payload.email]
        u.email = payload.email
    if payload.role is not None and payload.role != u.role:
        # Demoting the last admin is dangerous — count first.
        if u.role == Role.admin and payload.role != Role.admin:
            remaining = (db.query(User)
                           .filter(User.role == Role.admin,
                                   User.is_active == True,        # noqa
                                   User.id != uid).count())
            if remaining == 0:
                raise HTTPException(
                    400,
                    "Cannot demote the last active admin. Promote another "
                    "user to admin first.",
                )
        changes["role"] = [u.role.value if hasattr(u.role, 'value') else u.role,
                            payload.role.value]
        u.role = payload.role
    if payload.is_active is not None and payload.is_active != u.is_active:
        if (u.is_active and not payload.is_active
                and u.role == Role.admin):
            remaining = (db.query(User)
                           .filter(User.role == Role.admin,
                                   User.is_active == True,        # noqa
                                   User.id != uid).count())
            if remaining == 0:
                raise HTTPException(
                    400, "Cannot deactivate the last active admin.")
        changes["is_active"] = [u.is_active, payload.is_active]
        u.is_active = payload.is_active

    db.commit()
    if changes:
        db.add(AuditLog(
            actor_id=actor.id, action="user.edit", object_type="user",
            object_id=u.id, detail={"changes": changes},
        ))
        db.commit()
    return {"ok": True, "changes": list(changes.keys())}


# ============================================================
# Per-user permission overrides
# ============================================================

class _PermissionOverridePayload(BaseModel):
    permission: str
    granted: bool
    note: Optional[str] = None


@router.get("/users/{uid}/permissions")
def get_user_permissions(
    uid: int,
    db: Session = Depends(get_db),
    _: User = Depends(require_permission(Permission.PERMISSION_GRANT)),
):
    u = db.get(User, uid)
    if not u:
        raise HTTPException(404, "User not found")
    overrides = (db.query(UserPermissionOverride)
                   .filter(UserPermissionOverride.user_id == uid)
                   .all())
    role_defaults = {p.value for p in ROLE_DEFAULT_PERMISSIONS.get(u.role, set())}
    effective = effective_permissions(db, u)
    return {
        "user_id": uid,
        "username": u.username,
        "role": u.role.value if hasattr(u.role, "value") else u.role,
        "is_admin": u.role == Role.admin,
        "role_default_permissions": sorted(role_defaults),
        "effective_permissions": sorted(effective),
        "overrides": [
            {
                "permission": ov.permission,
                "granted": ov.granted,
                "note": ov.note,
                "granted_by_id": ov.granted_by_id,
                "granted_at": ov.granted_at.isoformat() if ov.granted_at else None,
            } for ov in overrides
        ],
    }


@router.post("/users/{uid}/permissions")
def set_user_permission(
    uid: int,
    payload: _PermissionOverridePayload,
    db: Session = Depends(get_db),
    actor: User = Depends(require_permission(Permission.PERMISSION_GRANT)),
):
    """Add or update a single permission override on a user."""
    u = db.get(User, uid)
    if not u:
        raise HTTPException(404, "User not found")
    # Validate the permission code against the catalog so we don't
    # accumulate typos in the DB. Storing arbitrary strings would
    # mean `has_permission()` silently never matches.
    try:
        Permission(payload.permission)
    except ValueError:
        raise HTTPException(
            400,
            f"Unknown permission code: {payload.permission!r}. "
            "See /api/admin/panel/permissions/catalog for the catalog.",
        )

    row = (db.query(UserPermissionOverride)
             .filter(UserPermissionOverride.user_id == uid,
                     UserPermissionOverride.permission == payload.permission)
             .first())
    if row:
        row.granted = payload.granted
        row.granted_by_id = actor.id
        row.granted_at = datetime.utcnow()
        if payload.note is not None:
            row.note = payload.note
        action = "permission.user.update"
    else:
        row = UserPermissionOverride(
            user_id=uid,
            permission=payload.permission,
            granted=payload.granted,
            granted_by_id=actor.id,
            note=payload.note,
        )
        db.add(row)
        action = "permission.user.grant"
    db.commit()
    db.add(AuditLog(
        actor_id=actor.id, action=action, object_type="user",
        object_id=uid,
        detail={
            "permission": payload.permission,
            "granted": payload.granted,
            "note": payload.note,
        },
    ))
    db.commit()
    return {"ok": True}


@router.delete("/users/{uid}/permissions/{perm:path}")
def remove_user_permission_override(
    uid: int,
    perm: str,
    db: Session = Depends(get_db),
    actor: User = Depends(require_permission(Permission.PERMISSION_GRANT)),
):
    """Drop the override row entirely — the user reverts to whatever
    their role defaults grant. Use :path so dot-separated permission
    codes ("project.create") survive URL routing.
    """
    u = db.get(User, uid)
    if not u:
        raise HTTPException(404, "User not found")
    row = (db.query(UserPermissionOverride)
             .filter(UserPermissionOverride.user_id == uid,
                     UserPermissionOverride.permission == perm)
             .first())
    if not row:
        raise HTTPException(404, "No override for that permission")
    db.delete(row)
    db.add(AuditLog(
        actor_id=actor.id, action="permission.user.revoke",
        object_type="user", object_id=uid,
        detail={"permission": perm},
    ))
    db.commit()
    return {"ok": True}


# ============================================================
# Role default overrides
# ============================================================

class _RolePermissionPayload(BaseModel):
    permission: str
    granted: bool


@router.get("/roles/{role}/permissions")
def get_role_permissions(
    role: Role,
    db: Session = Depends(get_db),
    _: User = Depends(require_permission(Permission.PERMISSION_GRANT)),
):
    defaults = {p.value for p in ROLE_DEFAULT_PERMISSIONS.get(role, set())}
    overrides = (db.query(RolePermissionOverride)
                   .filter(RolePermissionOverride.role == role.value)
                   .all())
    effective = set(defaults)
    for ov in overrides:
        if ov.granted:
            effective.add(ov.permission)
        else:
            effective.discard(ov.permission)
    return {
        "role": role.value,
        "default_permissions": sorted(defaults),
        "effective_permissions": sorted(effective),
        "overrides": [
            {"permission": ov.permission, "granted": ov.granted}
            for ov in overrides
        ],
    }


@router.post("/roles/{role}/permissions")
def set_role_permission(
    role: Role,
    payload: _RolePermissionPayload,
    db: Session = Depends(get_db),
    actor: User = Depends(require_permission(Permission.ROLE_EDIT_DEFAULTS)),
):
    try:
        Permission(payload.permission)
    except ValueError:
        raise HTTPException(400, f"Unknown permission: {payload.permission!r}")
    # Block edits to the admin role — admin always has every permission
    # by design (resolver short-circuits). Letting an admin "revoke"
    # one would create a dangerously inconsistent state where the row
    # claims revoke but the resolver still grants.
    if role == Role.admin:
        raise HTTPException(
            400,
            "Admin role permissions are immutable — admin always has every "
            "permission. Grant overrides to non-admin users instead.",
        )
    row = (db.query(RolePermissionOverride)
             .filter(RolePermissionOverride.role == role.value,
                     RolePermissionOverride.permission == payload.permission)
             .first())
    if row:
        row.granted = payload.granted
        row.updated_by_id = actor.id
        action = "permission.role.update"
    else:
        row = RolePermissionOverride(
            role=role.value, permission=payload.permission,
            granted=payload.granted, updated_by_id=actor.id,
        )
        db.add(row)
        action = "permission.role.grant"
    db.commit()
    db.add(AuditLog(
        actor_id=actor.id, action=action, object_type="role",
        object_id=None,
        detail={"role": role.value, "permission": payload.permission,
                "granted": payload.granted},
    ))
    db.commit()
    return {"ok": True}


@router.delete("/roles/{role}/permissions/{perm:path}")
def remove_role_permission_override(
    role: Role,
    perm: str,
    db: Session = Depends(get_db),
    actor: User = Depends(require_permission(Permission.ROLE_EDIT_DEFAULTS)),
):
    if role == Role.admin:
        raise HTTPException(400, "Admin role permissions are immutable.")
    row = (db.query(RolePermissionOverride)
             .filter(RolePermissionOverride.role == role.value,
                     RolePermissionOverride.permission == perm)
             .first())
    if not row:
        raise HTTPException(404, "No override for that role+permission")
    db.delete(row)
    db.add(AuditLog(
        actor_id=actor.id, action="permission.role.revoke",
        object_type="role", object_id=None,
        detail={"role": role.value, "permission": perm},
    ))
    db.commit()
    return {"ok": True}


# ============================================================
# Audit feed (for the panel's Activity tab)
# ============================================================

@router.get("/audit")
def get_audit_feed(
    limit: int = 200,
    db: Session = Depends(get_db),
    _: User = Depends(require_permission(Permission.AUDIT_READ)),
):
    """Return the most recent admin-relevant audit entries — user
    edits, permission grants, template replacements, etc. Filtered
    by action prefix so the panel only shows admin work, not every
    finding-edit / report-create row.
    """
    relevant_prefixes = (
        "user.", "permission.", "role.", "template.",
        "tracker_template.", "report.access.",
        "auth.account_",    # auto-lock / unlock events
        "admin.user.",      # admin-initiated user actions
    )
    rows = (
        db.query(AuditLog)
          .filter(or_(*(AuditLog.action.like(p + "%") for p in relevant_prefixes)))
          .order_by(AuditLog.at.desc())
          .limit(min(max(limit, 1), 500))
          .all()
    )
    # Bulk-fetch all referenced actor IDs in one query to avoid N+1.
    actor_ids = {r.actor_id for r in rows if r.actor_id}
    actor_map: dict[int, str] = {}
    if actor_ids:
        for u in db.query(User.id, User.username).filter(User.id.in_(actor_ids)).all():
            actor_map[u.id] = u.username

    out: list[dict] = []
    for r in rows:
        actor_name = None
        if r.actor_id:
            actor_name = actor_map.get(r.actor_id) or f"#{r.actor_id}"
        out.append({
            "id": r.id,
            "at": r.at.isoformat() if r.at else None,
            "actor": actor_name,
            "action": r.action,
            "object_type": r.object_type,
            "object_id": r.object_id,
            "detail": r.detail,
        })
    return {"items": out}


# ============================================================
# Account lockout management
# ============================================================

_UNLOCK_TOKEN_TTL_MINUTES = 30


@router.post("/users/{uid}/lock")
def lock_user(
    uid: int,
    db: Session = Depends(get_db),
    actor: User = Depends(require_permission(Permission.USER_EDIT)),
):
    """Manually lock a user account, immediately preventing login."""
    target = db.get(User, uid)
    if not target:
        raise HTTPException(404, "User not found")
    if target.id == actor.id:
        raise HTTPException(400, "Cannot lock your own account.")
    if target.role == Role.admin:
        remaining = (db.query(User)
                       .filter(User.role == Role.admin,
                               User.is_active == True,     # noqa
                               User.id != uid,
                               User.locked_at.is_(None))
                       .count())
        if remaining == 0:
            raise HTTPException(
                400,
                "Cannot lock the last active unlocked admin. "
                "Promote or unlock another admin first.",
            )
    if getattr(target, 'locked_at', None) is not None:
        return {"ok": True, "no_change": True, "already_locked": True}

    target.locked_at = datetime.utcnow()
    target.lock_reason = "admin"
    db.add(AuditLog(
        actor_id=actor.id, action="admin.user.locked",
        object_type="user", object_id=target.id,
        detail={"target_username": target.username},
    ))
    db.commit()
    return {"ok": True, "locked_at": target.locked_at.isoformat()}


@router.post("/users/{uid}/unlock")
def unlock_user(
    uid: int,
    db: Session = Depends(get_db),
    actor: User = Depends(require_permission(Permission.USER_EDIT)),
):
    """Manually unlock a user account and reset the failed-attempt counter."""
    target = db.get(User, uid)
    if not target:
        raise HTTPException(404, "User not found")
    if getattr(target, 'locked_at', None) is None and (getattr(target, 'failed_login_attempts', 0) or 0) == 0:
        return {"ok": True, "no_change": True, "already_unlocked": True}

    target.locked_at = None
    target.lock_reason = None
    target.failed_login_attempts = 0
    db.add(AuditLog(
        actor_id=actor.id, action="admin.user.unlocked",
        object_type="user", object_id=target.id,
        detail={"target_username": target.username},
    ))
    db.commit()
    return {"ok": True}


@router.post("/users/{uid}/send-unlock-link")
def send_unlock_link(
    uid: int,
    request: Request,
    db: Session = Depends(get_db),
    actor: User = Depends(require_permission(Permission.USER_EDIT)),
):
    """Mint a single-use unlock token and email it to the user.

    The user clicks the link in the email → POST /api/auth/unlock?token=<...>
    which clears the lock without requiring admin involvement after the send.
    Useful when the admin is not available to manually unlock — the user can
    self-serve after they verify their email identity via the link.
    """
    target = db.get(User, uid)
    if not target:
        raise HTTPException(404, "User not found")
    if not target.email:
        raise HTTPException(
            400,
            f"User {target.username!r} has no email address on file — "
            "use the manual Unlock button instead.",
        )
    if not target.is_active:
        raise HTTPException(400, "Cannot unlock a disabled user via link — re-enable the account first.")

    # Invalidate any prior unused unlock tokens for this user.
    (db.query(AccountUnlockToken)
       .filter(AccountUnlockToken.user_id == target.id,
               AccountUnlockToken.used_at.is_(None))
       .update({"used_at": datetime.utcnow()}))

    # Mint a fresh token (reuse the password-reset mint helper).
    from ..routers.password_reset import _mint_token
    ttl = _UNLOCK_TOKEN_TTL_MINUTES
    plain, token_hash = _mint_token()
    row = AccountUnlockToken(
        user_id=target.id,
        token_hash=token_hash,
        expires_at=datetime.utcnow() + timedelta(minutes=ttl),
        created_by_id=actor.id,
    )
    db.add(row)
    db.add(AuditLog(
        actor_id=actor.id, action="admin.user.unlock_link_sent",
        object_type="user", object_id=target.id,
        detail={"target_username": target.username, "ttl_minutes": ttl},
    ))
    db.commit()

    try:
        from ..services import email_templates as _email_tmpls
        from ..services.email_send import send_mail
        from ..services.url_helpers import absolute_url
        unlock_url = absolute_url(f"/unlock-account?token={plain}", request=request)
        subject, body_text, body_html = _email_tmpls.render_template(
            db, "account_unlock", {
                "user": target,
                "unlock_url": unlock_url,
                "ttl_minutes": ttl,
                "admin_username": actor.username,
            },
        )
        send_mail(target.email, subject, body_text=body_text, body_html=body_html)
    except Exception as e:                                  # pragma: no cover
        return {"ok": True, "email_sent": False, "warning": str(e),
                "target_email": target.email, "ttl_minutes": ttl}

    return {"ok": True, "email_sent": True,
            "target_email": target.email, "ttl_minutes": ttl}


class _AnonymizePayload(BaseModel):
    confirm: str  # must equal the target user's username to prevent accidents


@router.post("/users/{uid}/anonymize")
def anonymize_user(
    uid: int,
    payload: _AnonymizePayload,
    db: Session = Depends(get_db),
    actor: User = Depends(require_permission(Permission.USER_EDIT)),
):
    """Irreversibly anonymise a user record (GDPR right-to-erasure).

    Replaces all PII (username, email, full_name) with opaque placeholders,
    deactivates the account, and invalidates all tokens / sessions.  The
    user's AuditLog rows are preserved (as `actor_id` FK) but the username
    is replaced so the log no longer names the individual — the integer ID
    remains for relational queries.

    This action is PERMANENT and cannot be undone by the application.
    The caller must pass `confirm` = the target's current username to
    prevent accidental anonymisation.
    """
    target = db.get(User, uid)
    if not target:
        raise HTTPException(404, "User not found")
    if target.id == actor.id:
        raise HTTPException(400, "Cannot anonymise your own account.")
    if target.role == Role.admin:
        remaining = (db.query(User)
                       .filter(User.role == Role.admin,
                               User.is_active == True,     # noqa
                               User.id != uid).count())
        if remaining == 0:
            raise HTTPException(
                400,
                "Cannot anonymise the last active admin. Promote or enable another admin first.",
            )
    if payload.confirm != target.username:
        raise HTTPException(
            400,
            "confirm value does not match the user's current username. "
            "Pass the exact username to confirm irreversible anonymisation.",
        )

    old_username = target.username
    placeholder_id = f"deleted_{target.id}"

    target.username           = placeholder_id
    target.email              = f"{placeholder_id}@deleted.invalid"
    target.full_name          = None
    target.hashed_password    = "*"
    target.is_active          = False
    target.totp_secret        = None
    target.totp_enabled       = False
    target.locked_at          = None
    target.lock_reason        = None
    target.failed_login_attempts = 0
    target.background_path    = None

    # Invalidate all outstanding tokens.
    try:
        from ..models import PasswordResetToken
        (db.query(PasswordResetToken)
           .filter(PasswordResetToken.user_id == target.id,
                   PasswordResetToken.used_at.is_(None))
           .update({"used_at": datetime.utcnow()}))
    except Exception:                                       # pragma: no cover
        pass

    (db.query(AccountUnlockToken)
       .filter(AccountUnlockToken.user_id == target.id,
               AccountUnlockToken.used_at.is_(None))
       .update({"used_at": datetime.utcnow()}))

    db.add(AuditLog(
        actor_id=actor.id, action="admin.user.anonymized",
        object_type="user", object_id=target.id,
        detail={"old_username": old_username,
                "placeholder": placeholder_id},
    ))
    db.commit()


# ============================================================
# Company aliases — list of entity names selectable per project
# ============================================================

from ..services.company_aliases import get_aliases, set_aliases as _save_aliases
from pydantic import BaseModel as _BM


class _CompanyAliasesPayload(_BM):
    aliases: list[str]


@router.get("/company-aliases")
def list_company_aliases(
    _: User = Depends(require_permission(Permission.PERMISSION_GRANT)),
):
    """Return the current company alias list."""
    return {"aliases": get_aliases()}


@router.put("/company-aliases")
def update_company_aliases(
    payload: _CompanyAliasesPayload,
    actor: User = Depends(require_permission(Permission.PERMISSION_GRANT)),
    db: Session = Depends(get_db),
):
    """Replace the company alias list. Persists to /data/config/company_aliases.json."""
    saved = _save_aliases(payload.aliases)
    db.add(AuditLog(
        actor_id=actor.id,
        action="admin.company_aliases.updated",
        object_type="config",
        detail={"count": len(saved)},
    ))
    db.commit()
    return {"aliases": saved}
    return {"ok": True, "placeholder_username": placeholder_id}


# ============================================================
# Full DB export / import — for the monthly Kali VM image swap
# ============================================================

@router.get("/export")
def export_database(
    db: Session = Depends(get_db),
    user: User = Depends(require_permission(Permission.SYSTEM_CONFIGURE)),
):
    """Download a single ZIP bundle containing the entire VibeDocs dataset
    (projects, reports, versions, findings, library, templates, users,
    notes) plus every uploaded screenshot / evidence file and generated
    report. Import it into a fresh VibeDocs image to carry all work across a
    monthly Kali VM swap.
    """
    from ..services.db_portability import export_bundle
    now = datetime.utcnow()
    blob = export_bundle(db, now_iso=now.isoformat())
    fname = now.strftime("vibedocs_export_%Y%m%d_%H%M%S.zip")
    db.add(AuditLog(
        actor_id=user.id, action="admin.db.export",
        object_type="system", object_id=0, detail={"bytes": len(blob)},
    ))
    db.commit()
    return Response(
        content=blob, media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{fname}"'},
    )


@router.post("/import")
def import_database(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    user: User = Depends(require_permission(Permission.SYSTEM_CONFIGURE)),
):
    """Restore a bundle produced by ``/export`` into THIS image.

    DESTRUCTIVE: this wipes-and-restores the dataset. Intended for a fresh
    VM image whose DB only holds seed data. Encrypted report passwords are
    dropped (they can't decrypt under the new image's key) — the consultant
    re-enters any needed passwords.
    """
    from ..services.db_portability import import_bundle
    if not (file.filename or "").lower().endswith(".zip"):
        raise HTTPException(400, "Upload a VibeDocs export .zip bundle.")
    uid = user.id
    data = file.file.read()
    try:
        summary = import_bundle(db, data)
    except ValueError as e:
        raise HTTPException(400, str(e))
    except Exception as e:
        logger.exception("VibeDocs import failed")
        raise HTTPException(500, f"Import failed: {e}")
    try:
        db.add(AuditLog(
            actor_id=uid, action="admin.db.import",
            object_type="system", object_id=0,
            detail={"rows": summary.get("rows_restored"),
                    "files": summary.get("files_restored")},
        ))
        db.commit()
    except Exception:
        db.rollback()
    return summary
