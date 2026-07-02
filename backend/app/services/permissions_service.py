"""System-wide permission catalog + resolver.

The legacy auth layer in `..auth` only knows about three roles
(admin / senior / consultant / viewer) and gates routes via
`require_roles(Role.admin, …)`. That worked for the initial scope
but the team has outgrown it — Brendon wants admins to be able to
grant specific abilities (create projects, approve library
findings, etc.) to individual users without escalating them to a
full senior / admin.

Design
------
1. **Permission catalog** (this file). A flat list of stable,
   string-keyed permissions. The string IS the wire format — it
   appears in DB rows, audit logs, and the admin UI. Adding a new
   one is an enum-extension; renaming an existing one is a
   migration.
2. **Role defaults** (this file). A hardcoded mapping
   `Role → set[Permission]` that ships with the deployment. The
   admin can override these via the `role_permission_overrides`
   table without a code change.
3. **Per-user overrides** (`UserPermissionOverride` table). Lets
   admins grant or revoke specific permissions on a per-user basis.
4. **Resolver** (`has_permission`). For a given (user, permission)
   it returns True if:
   - `user.role == admin`, OR
   - the user has a `UserPermissionOverride` with `granted=True`, OR
   - there is no such override with `granted=False`, AND the
     effective role defaults grant the permission.
   This precedence means an explicit per-user revoke can take a
   permission away even from a role that defaults to having it.

`admin` is always all-powerful — it can never be locked out by
overrides. That's the safety net: if every other user loses
`permission.grant`, the admin can still re-grant it.

How to roll out gradually
-------------------------
Routes today use `require_roles(...)`. New routes should use
`require_permission(...)` instead. Existing routes can be migrated
one at a time; until then `has_permission()` is callable inline so
authors can add a permission gate alongside a role check without
forcing a global cutover.
"""
from __future__ import annotations
import enum
import logging
from typing import Optional

from fastapi import Depends, HTTPException
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import Role, User
from ..auth import get_current_user


logger = logging.getLogger(__name__)


# ============================================================
# 1. Permission catalog
# ============================================================
# Naming convention: <object>.<verb>[.<scope>]
#   verb   : create / read / write / delete / approve / grant / use ...
#   scope  : all / any / own — only for the read/write/delete verbs to
#            distinguish broad-access permissions ("read every project")
#            from owner-scoped ("read your own projects").
# Keep these strings stable across releases — they appear in DB rows
# (`user_permission_overrides.permission`) and audit logs. Renaming is
# a migration.

class Permission(str, enum.Enum):
    # ---- Projects ----
    PROJECT_CREATE          = "project.create"
    PROJECT_READ_ALL        = "project.read.all"
    PROJECT_WRITE_ANY       = "project.write.any"
    PROJECT_CLOSE           = "project.close"
    PROJECT_REOPEN          = "project.reopen"
    PROJECT_DELETE          = "project.delete"
    PROJECT_ASSIGN_MEMBERS  = "project.assign_members"

    # ---- Reports ----
    REPORT_CREATE           = "report.create"
    REPORT_READ_ALL         = "report.read.all"
    REPORT_WRITE_ANY        = "report.write.any"
    REPORT_DELETE           = "report.delete"
    REPORT_GENERATE         = "report.generate"
    REPORT_APPROVE          = "report.approve"
    REPORT_PUBLISH          = "report.publish"
    REPORT_SHARE            = "report.share"

    # ---- Per-finding edits inside a report ----
    FINDING_CREATE          = "finding.create"
    FINDING_EDIT            = "finding.edit"
    FINDING_DELETE          = "finding.delete"

    # ---- Findings library (canonical reusable findings) ----
    LIBRARY_USE             = "library.use"
    LIBRARY_ADD             = "library.add"
    LIBRARY_EDIT            = "library.edit"
    LIBRARY_DELETE          = "library.delete"
    LIBRARY_APPROVE         = "library.approve"

    # ---- Word report templates ----
    TEMPLATE_READ           = "template.read"
    TEMPLATE_UPLOAD         = "template.upload"
    TEMPLATE_REPLACE        = "template.replace"
    TEMPLATE_DELETE         = "template.delete"
    TEMPLATE_TOGGLE_ACTIVE  = "template.toggle_active"
    TEMPLATE_TRANSFORM      = "template.transform"
    TEMPLATE_REGENERATE     = "template.regenerate"
    TEMPLATE_APPROVE_CUSTOM = "template.approve_custom"

    # ---- Excel tracker templates ----
    TRACKER_READ            = "tracker.read"
    TRACKER_UPLOAD          = "tracker.upload"
    TRACKER_REPLACE         = "tracker.replace"
    TRACKER_DELETE          = "tracker.delete"
    TRACKER_EXPORT          = "tracker.export"
    TRACKER_IMPORT          = "tracker.import"

    # ---- Toolkit utilities ----
    TOOLKIT_USE             = "toolkit.use"
    TOOLKIT_NESSUS_COMPLIANCE = "toolkit.nessus_compliance"
    TOOLKIT_VA_RECURRING    = "toolkit.va_recurring"
    TOOLKIT_VA_RETEST       = "toolkit.va_retest"

    # ---- User / account management ----
    USER_LIST               = "user.list"
    USER_CREATE             = "user.create"
    USER_EDIT               = "user.edit"
    USER_DISABLE            = "user.disable"
    USER_RESET_PASSWORD     = "user.reset_password"

    # ---- Permission / role management (the "admin of admin") ----
    PERMISSION_GRANT        = "permission.grant"
    ROLE_EDIT_DEFAULTS      = "role.edit_defaults"

    # ---- System surfaces ----
    AUDIT_READ              = "audit.read"
    EMAIL_TEMPLATE_EDIT     = "email_template.edit"
    SYSTEM_CONFIGURE        = "system.configure"


# Human-readable descriptions surfaced in the admin Panel checkbox UI.
# Kept here rather than co-located on the enum so the enum stays a
# plain string mapping (cheap to compare against DB strings).
PERMISSION_LABELS: dict[Permission, str] = {
    Permission.PROJECT_CREATE:           "Create projects",
    Permission.PROJECT_READ_ALL:         "Read every project (not just own/assigned)",
    Permission.PROJECT_WRITE_ANY:        "Edit any project",
    Permission.PROJECT_CLOSE:            "Close projects",
    Permission.PROJECT_REOPEN:           "Re-open closed projects",
    Permission.PROJECT_DELETE:           "Delete projects (and all their reports)",
    Permission.PROJECT_ASSIGN_MEMBERS:   "Assign team members to projects",

    Permission.REPORT_CREATE:            "Create reports inside accessible projects",
    Permission.REPORT_READ_ALL:          "Read every report (cross-project)",
    Permission.REPORT_WRITE_ANY:         "Edit any report regardless of access grant",
    Permission.REPORT_DELETE:            "Delete reports",
    Permission.REPORT_GENERATE:          "Render the Word/PDF deliverable for a report",
    Permission.REPORT_APPROVE:           "Approve / reject reports submitted for review",
    Permission.REPORT_PUBLISH:           "Publish approved report versions (lock as final)",
    Permission.REPORT_SHARE:             "Grant per-report access to other users",

    Permission.FINDING_CREATE:           "Add findings to reports",
    Permission.FINDING_EDIT:             "Edit existing findings",
    Permission.FINDING_DELETE:           "Delete findings",

    Permission.LIBRARY_USE:              "Pull canonical findings out of the library into a report",
    Permission.LIBRARY_ADD:              "Submit new findings to the team library",
    Permission.LIBRARY_EDIT:             "Edit existing library entries",
    Permission.LIBRARY_DELETE:           "Delete library entries",
    Permission.LIBRARY_APPROVE:          "Approve library submissions for team-wide visibility",

    Permission.TEMPLATE_READ:            "View Word report-template list + metadata",
    Permission.TEMPLATE_UPLOAD:          "Upload brand-new master templates",
    Permission.TEMPLATE_REPLACE:         "Replace .docx for existing templates (system-wide swap)",
    Permission.TEMPLATE_DELETE:          "Delete master templates",
    Permission.TEMPLATE_TOGGLE_ACTIVE:   "Enable/disable templates in the consultant picker",
    Permission.TEMPLATE_TRANSFORM:       "Re-run the VibeDocs→docxtpl transformer on existing templates",
    Permission.TEMPLATE_REGENERATE:      "Regenerate every canonical template from VibeDocs sources",
    Permission.TEMPLATE_APPROVE_CUSTOM:  "Approve consultant-uploaded custom templates",

    Permission.TRACKER_READ:             "View bundled Excel tracker templates list",
    Permission.TRACKER_UPLOAD:           "Upload brand-new tracker .xlsx files",
    Permission.TRACKER_REPLACE:          "Replace existing tracker templates (system-wide swap)",
    Permission.TRACKER_DELETE:           "Delete tracker templates",
    Permission.TRACKER_EXPORT:           "Export a report as an Excel tracker",
    Permission.TRACKER_IMPORT:           "Import findings from a tracker into a report",

    Permission.TOOLKIT_USE:              "Access the Toolkit page at all",
    Permission.TOOLKIT_NESSUS_COMPLIANCE: "Run the Nessus Compliance → Excel converter",
    Permission.TOOLKIT_VA_RECURRING:     "Run the VA-Recurring scan pipeline",
    Permission.TOOLKIT_VA_RETEST:        "Run the VA-Retest tracker updater",

    Permission.USER_LIST:                "List registered users",
    Permission.USER_CREATE:              "Create new user accounts",
    Permission.USER_EDIT:                "Edit user details (name, email, role)",
    Permission.USER_DISABLE:             "Activate / deactivate user accounts",
    Permission.USER_RESET_PASSWORD:      "Issue password resets for other users",

    Permission.PERMISSION_GRANT:         "Grant or revoke individual permissions for users",
    Permission.ROLE_EDIT_DEFAULTS:       "Edit the default permissions a role gets at signup",

    Permission.AUDIT_READ:               "Read the system audit log",
    Permission.EMAIL_TEMPLATE_EDIT:      "Edit the outbound email templates",
    Permission.SYSTEM_CONFIGURE:         "Edit system-wide configuration (auth provider, SMTP, etc.)",
}


# Functional grouping for the admin Panel — controls how the
# permission matrix is rendered. Order within a group matches the
# enum order above. Adding a new permission means adding it to both
# `Permission` and the appropriate group below; the UI then picks it
# up automatically.
PERMISSION_GROUPS: list[tuple[str, list[Permission]]] = [
    ("Projects", [
        Permission.PROJECT_CREATE, Permission.PROJECT_READ_ALL,
        Permission.PROJECT_WRITE_ANY, Permission.PROJECT_CLOSE,
        Permission.PROJECT_REOPEN, Permission.PROJECT_DELETE,
        Permission.PROJECT_ASSIGN_MEMBERS,
    ]),
    ("Reports", [
        Permission.REPORT_CREATE, Permission.REPORT_READ_ALL,
        Permission.REPORT_WRITE_ANY, Permission.REPORT_DELETE,
        Permission.REPORT_GENERATE, Permission.REPORT_APPROVE,
        Permission.REPORT_PUBLISH, Permission.REPORT_SHARE,
    ]),
    ("Findings (per-report)", [
        Permission.FINDING_CREATE, Permission.FINDING_EDIT,
        Permission.FINDING_DELETE,
    ]),
    ("Findings Library", [
        Permission.LIBRARY_USE, Permission.LIBRARY_ADD,
        Permission.LIBRARY_EDIT, Permission.LIBRARY_DELETE,
        Permission.LIBRARY_APPROVE,
    ]),
    ("Word Templates", [
        Permission.TEMPLATE_READ, Permission.TEMPLATE_UPLOAD,
        Permission.TEMPLATE_REPLACE, Permission.TEMPLATE_DELETE,
        Permission.TEMPLATE_TOGGLE_ACTIVE, Permission.TEMPLATE_TRANSFORM,
        Permission.TEMPLATE_REGENERATE, Permission.TEMPLATE_APPROVE_CUSTOM,
    ]),
    ("Tracker Templates", [
        Permission.TRACKER_READ, Permission.TRACKER_UPLOAD,
        Permission.TRACKER_REPLACE, Permission.TRACKER_DELETE,
        Permission.TRACKER_EXPORT, Permission.TRACKER_IMPORT,
    ]),
    ("Toolkit", [
        Permission.TOOLKIT_USE, Permission.TOOLKIT_NESSUS_COMPLIANCE,
        Permission.TOOLKIT_VA_RECURRING, Permission.TOOLKIT_VA_RETEST,
    ]),
    ("User management", [
        Permission.USER_LIST, Permission.USER_CREATE,
        Permission.USER_EDIT, Permission.USER_DISABLE,
        Permission.USER_RESET_PASSWORD,
    ]),
    ("Permissions & roles", [
        Permission.PERMISSION_GRANT, Permission.ROLE_EDIT_DEFAULTS,
    ]),
    ("System", [
        Permission.AUDIT_READ, Permission.EMAIL_TEMPLATE_EDIT,
        Permission.SYSTEM_CONFIGURE,
    ]),
]


# ============================================================
# 2. Hardcoded role defaults
# ============================================================
# Sets a sensible baseline. Admin gets ALL permissions — that's
# enforced in `has_permission` so it survives admin-of-admin
# misconfiguration. The other roles below are starting points the
# admin can refine per-installation via the role-overrides table.

_ALL: set[Permission] = set(Permission)

_SENIOR_DEFAULTS: set[Permission] = {
    # Projects — sees + edits everything, can close but not delete
    Permission.PROJECT_CREATE, Permission.PROJECT_READ_ALL,
    Permission.PROJECT_WRITE_ANY, Permission.PROJECT_CLOSE,
    Permission.PROJECT_REOPEN, Permission.PROJECT_ASSIGN_MEMBERS,

    # Reports — full operational power minus delete
    Permission.REPORT_CREATE, Permission.REPORT_READ_ALL,
    Permission.REPORT_WRITE_ANY, Permission.REPORT_GENERATE,
    Permission.REPORT_APPROVE, Permission.REPORT_PUBLISH,
    Permission.REPORT_SHARE,

    Permission.FINDING_CREATE, Permission.FINDING_EDIT,
    Permission.FINDING_DELETE,

    # Library — full curatorial power
    Permission.LIBRARY_USE, Permission.LIBRARY_ADD,
    Permission.LIBRARY_EDIT, Permission.LIBRARY_APPROVE,

    # Templates — view + custom-template approval; not the
    # system-wide replace (kept admin-only by default)
    Permission.TEMPLATE_READ, Permission.TEMPLATE_APPROVE_CUSTOM,

    Permission.TRACKER_READ, Permission.TRACKER_EXPORT,
    Permission.TRACKER_IMPORT,

    Permission.TOOLKIT_USE, Permission.TOOLKIT_NESSUS_COMPLIANCE,
    Permission.TOOLKIT_VA_RECURRING, Permission.TOOLKIT_VA_RETEST,

    Permission.USER_LIST, Permission.AUDIT_READ,
}

_CONSULTANT_DEFAULTS: set[Permission] = {
    # Projects — can create, can see+edit ones they own or are
    # assigned to. No write/read.all, no close, no delete.
    Permission.PROJECT_CREATE,

    # Reports — operate on own/shared reports
    Permission.REPORT_CREATE, Permission.REPORT_GENERATE,
    Permission.REPORT_SHARE,

    Permission.FINDING_CREATE, Permission.FINDING_EDIT,
    Permission.FINDING_DELETE,

    # Library — use everything, propose additions
    Permission.LIBRARY_USE, Permission.LIBRARY_ADD,

    Permission.TEMPLATE_READ, Permission.TRACKER_READ,
    Permission.TRACKER_EXPORT, Permission.TRACKER_IMPORT,

    Permission.TOOLKIT_USE, Permission.TOOLKIT_NESSUS_COMPLIANCE,
    Permission.TOOLKIT_VA_RECURRING, Permission.TOOLKIT_VA_RETEST,

    Permission.USER_LIST,
}

_VIEWER_DEFAULTS: set[Permission] = {
    # Read-only. Sees the things they've been shared into; can't
    # create or modify anything. Library is browsable so they can
    # learn the team's canonical phrasing.
    Permission.LIBRARY_USE,
    Permission.TEMPLATE_READ, Permission.TRACKER_READ,
    Permission.USER_LIST,
}

ROLE_DEFAULT_PERMISSIONS: dict[Role, set[Permission]] = {
    Role.admin:      _ALL,
    Role.senior:     _SENIOR_DEFAULTS,
    Role.consultant: _CONSULTANT_DEFAULTS,
    Role.viewer:     _VIEWER_DEFAULTS,
}


# ============================================================
# 3. Resolver
# ============================================================

def _role_default_set(role: Role) -> set[Permission]:
    return ROLE_DEFAULT_PERMISSIONS.get(role, set())


def _effective_role_set(db: Session, role: Role) -> set[str]:
    """Apply DB-stored role overrides on top of the hardcoded
    defaults. Returns a set of permission strings (not enum values)
    because that's what `UserPermissionOverride.permission` stores
    and what the resolver compares against.
    """
    # Late import — keeps this module importable from `models.py`
    # transitively without a circular cycle.
    from ..models import RolePermissionOverride

    defaults = {p.value for p in _role_default_set(role)}
    rows = (db.query(RolePermissionOverride)
              .filter(RolePermissionOverride.role == role.value)
              .all())
    for row in rows:
        if row.granted:
            defaults.add(row.permission)
        else:
            defaults.discard(row.permission)
    return defaults


def has_permission(db: Session, user: User, perm: Permission | str) -> bool:
    """Return True iff `user` is allowed to perform `perm`.

    Resolution order:
      1. Admin role short-circuits to True (lockout safety).
      2. Per-user override with `granted=False` denies.
      3. Per-user override with `granted=True`  allows.
      4. Effective role set (defaults + role overrides) is consulted.
      5. Otherwise denied.

    `perm` may be a `Permission` enum value OR the string code — the
    latter lets callers reference permissions by their wire string
    without importing the enum (handy for migrations / scripts).
    """
    if user.role == Role.admin:
        return True
    perm_str = perm.value if isinstance(perm, Permission) else str(perm)

    # Late import for the same circular-dep reason as above.
    from ..models import UserPermissionOverride

    override = (db.query(UserPermissionOverride)
                  .filter(UserPermissionOverride.user_id == user.id,
                          UserPermissionOverride.permission == perm_str)
                  .first())
    if override is not None:
        return bool(override.granted)
    return perm_str in _effective_role_set(db, user.role)


def effective_permissions(db: Session, user: User) -> set[str]:
    """All permissions this user currently holds — the union of the
    resolver above across every catalog entry. Used by the admin
    Panel UI to render the "current grants" column.
    """
    if user.role == Role.admin:
        return {p.value for p in Permission}

    from ..models import UserPermissionOverride

    base = set(_effective_role_set(db, user.role))
    overrides = (db.query(UserPermissionOverride)
                   .filter(UserPermissionOverride.user_id == user.id)
                   .all())
    for ov in overrides:
        if ov.granted:
            base.add(ov.permission)
        else:
            base.discard(ov.permission)
    return base


def require_permission(perm: Permission):
    """FastAPI dependency — passes through if the current user has
    `perm`, raises 403 otherwise. Drop in alongside (or replacing) a
    `require_roles(...)` dependency.

    Usage:
        @router.post("/some-action")
        def some_action(_: User = Depends(require_permission(
                                              Permission.PROJECT_CREATE))):
            ...
    """
    def _checker(db: Session = Depends(get_db),
                 user: User = Depends(get_current_user)) -> User:
        if not has_permission(db, user, perm):
            raise HTTPException(
                403,
                f"You do not have the required permission: {perm.value}",
            )
        return user
    return _checker
