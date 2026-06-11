"""
Server-rendered HTML pages (HTMX + Jinja2). Plays alongside the JSON API.
This keeps the system 'plug and play' with no separate frontend build step.
"""
from pathlib import Path
from typing import Optional
from fastapi import APIRouter, Depends, Request, HTTPException, Form, Response, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import (
    Project, Report, ReportVersion, ReportTemplate, FindingLibrary, User, Role,
    ReportReviewStatus,
)
from ..auth import get_current_user, require_admin
from ..config import settings as _settings

_secure_cookie = ((_settings.SITE_URL or "").lower().startswith("https://"))

# Jinja for HTML UI (NOT to be confused with docxtpl which is for Word)
templates = Jinja2Templates(
    directory=str(Path(__file__).parent.parent / "templates"),
    auto_reload=True,
)

router = APIRouter(tags=["ui"])


def _safe_user(request: Request, db: Session) -> User | None:
    """Soft auth - returns None instead of raising, so login redirects work cleanly."""
    from jose import jwt, JWTError
    from ..config import settings
    token = request.cookies.get("access_token")
    if not token:
        auth_h = request.headers.get("authorization", "")
        if auth_h.lower().startswith("bearer "):
            parts = auth_h.split(None, 1)
            token = parts[1] if len(parts) == 2 else None
    if not token:
        return None
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        username = payload.get("sub")
    except JWTError:
        return None
    if not username:
        return None
    return db.query(User).filter(User.username == username, User.is_active == True).first()  # noqa


@router.get("/", response_class=HTMLResponse)
def root(request: Request, db: Session = Depends(get_db)):
    # Already signed in (any mode) → dashboard.
    user = _safe_user(request, db)
    if user:
        return RedirectResponse("/dashboard", status_code=302)

    local = _settings.LOCAL_MODE_ENABLED
    sso = _settings.SSO_ENABLED
    # When local mode is on, ALWAYS show the selector so the consultant
    # consciously picks a workflow (Local → /local/enter, or the VibeDocs
    # Login card → /login). Only when local mode is OFF do we skip the
    # selector and go straight to the password/SSO login page.
    if not local:
        return RedirectResponse("/login", status_code=302)
    return templates.TemplateResponse(request, "welcome.html", {
        "local_mode_enabled": True,
        "sso_enabled": sso,
    })


def _get_or_create_local_user(db: Session) -> User:
    """Return the singleton local-mode user, creating it on first access.

    role=admin so EVERY approval gate (require_roles / require_admin /
    has_permission / report effective_access) auto-passes — the local
    consultant creates projects, reports, custom templates and library
    findings with zero review. is_local=True marks it as the no-login
    account so the UI can hide Admin / Reviews nav. The password is random
    bytes it can never authenticate with via the username/password form.
    """
    from ..auth import hash_password
    import secrets as _secrets
    uname = _settings.LOCAL_MODE_USERNAME
    user = db.query(User).filter(User.username == uname).first()
    if user is None:
        user = User(
            username=uname,
            email=f"{uname}@standalone.local",
            full_name="Local Standalone User",
            hashed_password=hash_password(_secrets.token_hex(32)),
            role=Role.admin,            # bypasses every approval gate
            is_active=True,
            is_local=True,
            sso_provider=None,
            sso_subject=None,
            totp_required=False,        # never force the local user into MFA enrollment
        )
        db.add(user)
        db.commit()
        db.refresh(user)
    else:
        # Self-heal: an operator could have flipped these. The local user
        # must always be active, admin, MFA-not-forced, and flagged local.
        changed = False
        if not user.is_active:
            user.is_active = True; changed = True
        if user.role != Role.admin:
            user.role = Role.admin; changed = True
        if getattr(user, "totp_required", False):
            user.totp_required = False; changed = True
        if not getattr(user, "is_local", False):
            user.is_local = True; changed = True
        if changed:
            db.commit()
            db.refresh(user)
    return user


@router.get("/local/enter")
def local_mode_enter(request: Request, db: Session = Depends(get_db)):
    """No-login entry point: mint a session for the singleton local user
    and land on /dashboard. Returns 404 when local mode is disabled so it
    can't be reached by URL-paste on an SSO-only deployment."""
    from ..auth import create_access_token
    if not _settings.LOCAL_MODE_ENABLED:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Local mode is disabled")
    user = _get_or_create_local_user(db)
    token = create_access_token(user.username, uid=user.id)
    redirect = RedirectResponse("/dashboard", status_code=302)
    redirect.set_cookie(
        "access_token", token,
        httponly=True, samesite="lax", max_age=60 * 60 * 8, secure=_secure_cookie,
    )
    return redirect


@router.get("/login", response_class=HTMLResponse)
def login_page(request: Request, error: str = "", local: str = ""):
    from ..config import settings as _s
    return templates.TemplateResponse(request, "login.html", {
        "error": error,
        "sso_enabled": _s.SSO_ENABLED,
        # Hide local form only when SSO_DISABLE_LOCAL_LOGIN=true AND the
        # user hasn't explicitly requested it via ?local=1 (break-glass).
        "show_local_login": not _s.SSO_DISABLE_LOCAL_LOGIN or local == "1",
    })


# ============================================
# NEW: Registration Page Route
# ============================================
@router.get("/register", response_class=HTMLResponse)
def register_page(request: Request):
    """User registration page"""
    return templates.TemplateResponse(request, "register.html", {})
# ============================================


@router.post("/login")
def login_form(
    request: Request,
    response: Response,
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db),
):
    """Browser-friendly login. Sets the auth cookie and 302-redirects to
    /dashboard. If the user has 2FA enabled, instead 302-redirects to
    /login/challenge with a short-lived challenge token cookie so the second
    step can read it.
    """
    from ..auth import verify_password, create_access_token
    from ..services import twofa_challenge
    from ..services import rate_limit as rl
    from ..database import engine

    # IP-level brute-force throttle — 20 attempts per 5 minutes (DB-backed,
    # shared across all uvicorn worker processes).
    ip = rl.client_ip_from_request(request)
    allowed, retry_after, _ = rl.hit_db(engine, "login_ip", ip,
                                         max_attempts=20, window_seconds=300)
    if not allowed:
        return templates.TemplateResponse(
            request, "login.html",
            {"error": f"Too many login attempts from your network. Try again in {retry_after}s."},
            status_code=429,
        )

    user = db.query(User).filter(User.username == username).first()
    password_ok = user is not None and verify_password(password, user.hashed_password)

    if not password_ok or not (user and user.is_active):
        # Track failed attempts per-user for auto-lock (mirrors auth.py logic).
        if user is not None and user.is_active and not password_ok:
            from datetime import datetime as _dt
            fa = (getattr(user, 'failed_login_attempts', 0) or 0) + 1
            user.failed_login_attempts = fa
            if fa >= 5 and not getattr(user, 'locked_at', None):
                user.locked_at = _dt.utcnow()
                user.lock_reason = "auto"
                from ..models import AuditLog
                db.add(AuditLog(
                    actor_id=user.id, action="auth.account_auto_locked",
                    object_type="user", object_id=user.id,
                    detail={"failed_attempts": fa},
                ))
            db.commit()
        return templates.TemplateResponse(
            request, "login.html",
            {"error": "Invalid username or password."},
            status_code=401,
        )

    # Correct password — check account lock before issuing any session.
    if getattr(user, 'locked_at', None) is not None:
        from ..models import AuditLog
        db.add(AuditLog(
            actor_id=user.id, action="auth.login_blocked_locked",
            object_type="user", object_id=user.id,
            detail={"username": user.username},
        ))
        db.commit()
        return templates.TemplateResponse(
            request, "login.html",
            {"error": (
                "Your account is locked due to too many failed login attempts. "
                "Contact your administrator or use the unlock link sent to your email."
            )},
            status_code=403,
        )

    # Success — reset failed-attempt counter.
    user.failed_login_attempts = 0

    if user.totp_enabled:
        challenge_token, ttl = twofa_challenge.issue(user.id)
        db.commit()  # persist failed_login_attempts reset before redirecting
        redirect = RedirectResponse("/login/challenge", status_code=302)
        # Short-lived cookie carries ONLY the opaque challenge token — never
        # the username/password, never a JWT. Same SameSite/HttpOnly settings
        # as the real access cookie. Cleared on success or restart.
        redirect.set_cookie(
            "mfa_challenge", challenge_token,
            httponly=True, samesite="lax", max_age=ttl, secure=_secure_cookie,
        )
        return redirect

    token = create_access_token(user.username, uid=user.id)
    redirect = RedirectResponse("/dashboard", status_code=302)
    redirect.set_cookie(
        "access_token", token,
        httponly=True, samesite="lax", max_age=60 * 60 * 8, secure=_secure_cookie,
    )
    db.commit()  # persist failed_login_attempts reset
    return redirect


@router.get("/login/challenge", response_class=HTMLResponse)
def login_challenge_page(request: Request):
    """Render the 2FA code entry page. Bounces back to /login if there is no
    in-flight challenge cookie (e.g. user opens the URL directly)."""
    if not request.cookies.get("mfa_challenge"):
        return RedirectResponse("/login", status_code=302)
    return templates.TemplateResponse(request, "login_challenge.html", {})


@router.post("/login/challenge")
def login_challenge_submit(
    request: Request,
    code: str = Form(...),
    db: Session = Depends(get_db),
):
    """Second step of the browser login. Consumes the mfa_challenge cookie +
    the user-supplied TOTP/backup code. On success: clear the challenge cookie,
    set the real access_token cookie, redirect to /dashboard.

    Shares the same rate limiter bucket as the JSON API so a brute-forcer
    can't bypass the cap by alternating between /api/auth/twofa/challenge and
    /login/challenge.
    """
    from ..auth import create_access_token
    from ..services import twofa_challenge
    from ..services import totp as totp_svc
    from ..services import rate_limit as rl
    from ..database import engine
    from ..models import AuditLog

    # ---- IP-level throttle (DB-backed, shared across uvicorn workers) ----------
    ip = rl.client_ip_from_request(request)
    allowed, retry_after, _ = rl.hit_db(engine, "mfa_login_ip", ip,
                                         max_attempts=30, window_seconds=300)
    if not allowed:
        resp = templates.TemplateResponse(
            request, "login.html",
            {"error": f"Too many attempts from your network. Try again in {retry_after}s."},
            status_code=429,
        )
        resp.delete_cookie("mfa_challenge")
        return resp

    challenge_token = request.cookies.get("mfa_challenge")
    if not challenge_token:
        return RedirectResponse("/login", status_code=302)

    user_id = twofa_challenge.consume(challenge_token)
    if not user_id:
        # Token expired/invalid: discard the stale cookie and force re-auth.
        resp = templates.TemplateResponse(
            request, "login.html",
            {"error": "2FA challenge expired. Please sign in again."},
            status_code=401,
        )
        resp.delete_cookie("mfa_challenge")
        return resp

    user = db.get(User, user_id)
    if not user or not user.is_active:
        resp = RedirectResponse("/login", status_code=302)
        resp.delete_cookie("mfa_challenge")
        return resp

    # ---- Per-user lockout gate -----------------------------------------------
    user_key = f"u{user.id}"
    locked, retry_after = rl.is_locked("mfa_login", user_key)
    if locked:
        db.add(AuditLog(actor_id=user.id, action="auth.twofa_locked",
                        object_type="user", object_id=user.id,
                        detail={"retry_after": retry_after, "ip": ip,
                                "channel": "browser"}))
        db.commit()
        resp = templates.TemplateResponse(
            request, "login.html",
            {"error": f"Account locked after repeated failed 2FA codes. "
                       f"Try again in {retry_after // 60}m {retry_after % 60}s."},
            status_code=429,
        )
        resp.delete_cookie("mfa_challenge")
        return resp

    if not totp_svc.verify_code(user, code, db):
        now_locked, lockout_for = rl.record_failure(
            "mfa_login", user_key,
            max_failures=5, window_seconds=300, lockout_seconds=900,
        )
        db.add(AuditLog(actor_id=user.id, action="auth.twofa_failed",
                        object_type="user", object_id=user.id,
                        detail={"locked": now_locked, "ip": ip,
                                "channel": "browser"}))
        db.commit()
        if now_locked:
            # Force the user back to /login — no fresh challenge while locked.
            resp = templates.TemplateResponse(
                request, "login.html",
                {"error": f"Too many failed 2FA codes. Account locked for {lockout_for // 60} minutes."},
                status_code=429,
            )
            resp.delete_cookie("mfa_challenge")
            return resp
        # Reissue so the user can retry without re-entering their password.
        new_token, ttl = twofa_challenge.issue(user.id)
        resp = templates.TemplateResponse(
            request, "login_challenge.html",
            {"error": "Invalid code. Try again."},
            status_code=401,
        )
        resp.set_cookie("mfa_challenge", new_token,
                        httponly=True, samesite="lax", max_age=ttl, secure=_secure_cookie)
        return resp

    # All good — mint the access token cookie, drop the challenge cookie.
    rl.clear("mfa_login", user_key)
    token = create_access_token(user.username, uid=user.id)
    db.add(AuditLog(actor_id=user.id, action="auth.login_ok",
                    object_type="user", object_id=user.id,
                    detail={"twofa_required": True}))
    db.commit()
    redirect = RedirectResponse("/dashboard", status_code=302)
    redirect.set_cookie(
        "access_token", token,
        httponly=True, samesite="lax", max_age=60 * 60 * 8, secure=_secure_cookie,
    )
    redirect.delete_cookie("mfa_challenge")
    return redirect


@router.post("/logout")
def logout_form(request: Request, db: Session = Depends(get_db)):
    """Browser-friendly logout. Clears the cookie and redirects.

    Local-mode accounts have no real login to return to, so sending them to
    the SSO/password login screen is confusing. They go to the home / welcome
    page (where they can re-enter local mode) instead. SSO / password users
    keep going to /login.
    """
    user = _safe_user(request, db)
    dest = "/" if (user is not None and getattr(user, "is_local", False)) else "/login"
    redirect = RedirectResponse(dest, status_code=302)
    redirect.delete_cookie("access_token")
    return redirect


@router.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request, user: User = Depends(get_current_user),
              db: Session = Depends(get_db)):
    # IDOR fix: the dashboard previously listed the 20 most-recent projects
    # and 10 most-recent reports system-wide, regardless of the viewer's
    # membership. Filter to what they can actually see.
    from .permissions import user_can_see_project, effective_access
    all_projects = db.query(Project).order_by(Project.created_at.desc()).all()
    visible_projects = [p for p in all_projects if user_can_see_project(db, user, p)]
    projects = visible_projects[:20]
    all_reports = db.query(Report).order_by(Report.created_at.desc()).limit(200).all()
    visible_reports = [r for r in all_reports if effective_access(db, user, r) is not None]
    reports = visible_reports[:10]

    # ============================================================
    # Personal stats — feed the dashboard infographic. Computed from
    # the same access-filtered lists so a user only ever sees counts
    # for the engagements they're entitled to.
    # ============================================================
    # Report status breakdown across the user's visible reports. We use
    # the latest version's review_status as the report-level status,
    # falling back to "draft" when there's no version yet.
    status_buckets = {"draft": 0, "in_review": 0, "approved": 0,
                      "rejected": 0, "published": 0}
    for r in visible_reports:
        latest = (db.query(ReportVersion)
                    .filter(ReportVersion.report_id == r.id)
                    .order_by(ReportVersion.created_at.desc())
                    .first())
        s = (latest.review_status if latest and latest.review_status else "draft")
        if s in status_buckets:
            status_buckets[s] += 1
        else:
            status_buckets["draft"] += 1

    # Reports I personally own (created the row). Owners drive most of
    # the in-flight work; this is the "what's on my desk" number.
    my_reports = [r for r in visible_reports if r.created_by_id == user.id]

    # Findings authored in the team library — captures the user's
    # content contribution beyond the deliverables themselves.
    findings_authored = (db.query(FindingLibrary)
                           .filter(FindingLibrary.created_by_id == user.id)
                           .count())

    # Unique clients across visible projects. `client_name` is plain
    # text, so de-dupe case-insensitively to avoid "ACME" and "Acme"
    # double-counting.
    seen_clients: set[str] = set()
    for p in visible_projects:
        if p.client_name:
            seen_clients.add(p.client_name.strip().lower())

    completed = status_buckets["approved"] + status_buckets["published"]
    in_flight = status_buckets["draft"] + status_buckets["in_review"]

    # ---- Review-queue counts (so the user doesn't have to open the
    # Reviews page just to know if anything is waiting on them) ----
    #   * pending_reviews    — versions in_review where THIS user is the
    #     named reviewer (their action queue).
    #   * reports_assigned   — distinct reports where this user is the
    #     assigned reviewer on ANY version (their review workload, all
    #     statuses).
    in_review_val = ReportReviewStatus.in_review.value
    pending_reviews = (
        db.query(ReportVersion)
          .filter(ReportVersion.reviewer_id == user.id,
                  ReportVersion.review_status == in_review_val)
          .count()
    )
    reports_assigned = (
        db.query(ReportVersion.report_id)
          .filter(ReportVersion.reviewer_id == user.id)
          .distinct()
          .count()
    )
    # Admins / seniors also cover the team-wide queue — surface the
    # full in_review count so the tile is useful for leads too.
    team_pending_reviews = 0
    if user.role in (Role.admin, Role.senior):
        team_pending_reviews = (
            db.query(ReportVersion)
              .filter(ReportVersion.review_status == in_review_val)
              .count()
        )

    stats = {
        "projects_visible":   len(visible_projects),
        "unique_clients":     len(seen_clients),
        "reports_visible":    len(visible_reports),
        "reports_owned":      len(my_reports),
        "reports_completed":  completed,
        "reports_in_flight":  in_flight,
        "findings_authored":  findings_authored,
        "pending_reviews":    pending_reviews,
        "reports_assigned":   reports_assigned,
        "team_pending_reviews": team_pending_reviews,
        "is_reviewer_role":   user.role in (Role.admin, Role.senior),
        "status_breakdown":   status_buckets,
    }

    # Per-user widget selection. `dashboard_widgets` is a JSON list of
    # widget keys; NULL/empty => the default-all set. The template
    # renders only the enabled tiles + a Customize panel that PATCHes
    # /api/auth/me/preferences. Order here is the canonical display
    # order; the catalog drives the customise checkboxes.
    WIDGET_CATALOG = [
        ("reports_owned",     "Reports you own"),
        ("reports_completed", "Reports completed"),
        ("reports_assigned",  "Reports assigned to you"),
        ("pending_reviews",   "Pending reviews"),
        ("findings_authored", "Findings you authored"),
        ("projects_visible",  "Projects"),
        ("unique_clients",    "Unique clients"),
        ("status_breakdown",  "Report status breakdown chart"),
    ]
    saved = getattr(user, "dashboard_widgets", None)
    if saved is None:
        enabled_widgets = [k for k, _ in WIDGET_CATALOG]   # default: all
    else:
        enabled_widgets = [k for k in saved if k in dict(WIDGET_CATALOG)]

    return templates.TemplateResponse(request, "dashboard.html", {
        "user": user, "projects": projects, "reports": reports,
        "stats": stats,
        "widget_catalog": WIDGET_CATALOG,
        "enabled_widgets": enabled_widgets,
    })


@router.get("/projects", response_class=HTMLResponse)
def projects_list(request: Request, user: User = Depends(get_current_user),
                  db: Session = Depends(get_db)):
    # IDOR fix: previously this returned every project to every authenticated
    # user. Filter to projects the current user has any visibility on so the
    # listing doesn't leak client names + scope of engagements the user
    # wasn't staffed on.
    from .permissions import user_can_see_project
    all_projects = db.query(Project).order_by(Project.created_at.desc()).all()
    projects = [p for p in all_projects if user_can_see_project(db, user, p)]
    return templates.TemplateResponse(request, "projects/list.html", {
        "user": user, "projects": projects,
    })


@router.get("/projects/new", response_class=HTMLResponse)
def projects_new(request: Request, user: User = Depends(get_current_user)):
    return templates.TemplateResponse(request, "projects/new.html", {"user": user})


@router.get("/projects/{pid}", response_class=HTMLResponse)
def project_detail(pid: int, request: Request, user: User = Depends(get_current_user),
                   db: Session = Depends(get_db)):
    from .permissions import require_project_visibility, effective_access
    project = db.get(Project, pid)
    if not project:
        raise HTTPException(404, "Project not found")
    # IDOR fix: a user who has no relationship to this project (not lead,
    # not assigned, no report grant, not admin/senior) must not be able to
    # open the project page by URL — previously this route only checked
    # authentication, exposing the entire project's metadata + report list.
    require_project_visibility(db, user, project)
    # Filter the report list to only those the current user can actually see.
    # Admins/seniors/leads see all; everyone else sees only reports they
    # own or have an explicit grant on — so the page can't leak the
    # existence of reports the user wasn't shared on.
    all_reports = (db.query(Report).filter(Report.project_id == pid)
                   .order_by(Report.created_at.desc()).all())
    reports = [r for r in all_reports if effective_access(db, user, r) is not None]
    templates_list = db.query(ReportTemplate).filter(
        ReportTemplate.is_active == True  # noqa
    ).all()
    # Enrich each report with owner + access-grant count for the listing.
    # Done in Python rather than the template so the relationship traversals
    # are explicit and N+1 stays small (we batch over the report list only).
    from ..models import ReportAccess
    enriched = []
    for r in reports:
        owner = db.get(User, r.created_by_id) if r.created_by_id else None
        access_count = (db.query(ReportAccess)
                          .filter(ReportAccess.report_id == r.id)
                          .count())
        enriched.append({
            "id": r.id,
            "name": r.name,
            "current_version": r.current_version,
            "template_name": r.template.name if r.template else "",
            "template_code": r.template.code if r.template else "",
            "created_at": r.created_at,
            "owner_username": owner.username if owner else None,
            "owner_full_name": owner.full_name if owner else None,
            "is_mine": (owner.id == user.id) if owner else False,
            "access_count": access_count,
        })
    return templates.TemplateResponse(request, "projects/detail.html", {
        "user": user, "project": project,
        "reports": reports,           # legacy iterator (unused by new UI but kept for compat)
        "report_rows": enriched,
        "templates_list": templates_list,
    })


# ============================================
# REPORTS ROUTES - CORRECT ORDER
# Static routes MUST come BEFORE dynamic routes
# ============================================

@router.get("/reports/new", response_class=HTMLResponse)
def new_report_page(
    request: Request,
    project_id: Optional[int] = None,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user)
):
    """Create new report page"""
    from .permissions import user_can_see_project
    all_projects = db.query(Project).order_by(Project.created_at.desc()).all()
    projects = [p for p in all_projects if user_can_see_project(db, user, p)]

    selected_project = None
    if project_id:
        selected_project = db.get(Project, project_id)
    
    return templates.TemplateResponse(
        request,
        "reports/new.html",
        {
            "request": request,
            "user": user,
            "projects": projects,
            "selected_project": selected_project
        }
    )


@router.get("/reports/{rid}", response_class=HTMLResponse)
def report_detail(rid: int, request: Request, user: User = Depends(get_current_user),
                  db: Session = Depends(get_db)):
    from .permissions import require_access, AccessLevel
    report = db.get(Report, rid)
    if not report:
        raise HTTPException(404, "Report not found")
    # IDOR fix: the report-detail page was reachable by any authenticated
    # user via /reports/{rid}, even though every JSON API gated correctly.
    # Enforce the same view-or-higher check at the HTML route so the page
    # itself refuses to render for users without a grant.
    require_access(db, user, report, need=AccessLevel.view)
    return templates.TemplateResponse(request, "reports/detail.html", {
        "user": user, "report": report,
    })


@router.get("/reports/versions/{vid}/edit", response_class=HTMLResponse)
def report_version_edit(vid: int, request: Request,
                        user: User = Depends(get_current_user),
                        db: Session = Depends(get_db)):
    from .permissions import require_access, effective_access, AccessLevel
    rv = db.get(ReportVersion, vid)
    if not rv:
        raise HTTPException(404, "Version not found")
    # IDOR fix: same problem one level down. Editing the version requires
    # at least view access on the parent report (the API enforces edit on
    # mutations; we don't need edit just to render the page, but anything
    # less than view should be refused).
    require_access(db, user, rv.report, need=AccessLevel.view)
    # Resolve the caller's effective level so the template can render
    # read-only when they only have `view`. We don't restrict access here
    # (the page is still useful as a read-only view) — we just expose the
    # level to the page so the UI can disable edit/save controls. Backend
    # mutations are independently gated, but the UI needs this too so a
    # view-only user isn't presented with controls that look functional.
    my_level = effective_access(db, user, rv.report) or AccessLevel.view
    return templates.TemplateResponse(request, "reports/edit.html", {
        "user": user, "version": rv, "report": rv.report,
        "project": rv.report.project, "template": rv.report.template,
        "my_access": my_level.value,
        "details": rv.report.details or {},
    })


@router.get("/reports", response_class=HTMLResponse)
def reports_index(request: Request, user: User = Depends(get_current_user),
                  db: Session = Depends(get_db)):
    """My-reports landing page. Shows everything the current user can see
    (owned + project-led + explicit grants + admin-sees-all) with the
    metadata that matters: client, owner, version, permission level,
    review status.
    """
    from ..models import ReportAccess, Project
    from .permissions import effective_access

    if user.role == Role.admin:
        rows = (db.query(Report)
                  .order_by(Report.created_at.desc())
                  .limit(500).all())
    else:
        owned = {r.id for r in db.query(Report.id)
                                 .filter(Report.created_by_id == user.id).all()}
        led = {r.id for r in db.query(Report.id).join(Project)
                                .filter(Project.lead_id == user.id).all()}
        shared = {g.report_id for g in db.query(ReportAccess.report_id)
                                          .filter(ReportAccess.user_id == user.id).all()}
        ids = owned | led | shared
        rows = (db.query(Report)
                  .filter(Report.id.in_(ids))
                  .order_by(Report.created_at.desc()).all()) if ids else []

    items = []
    for r in rows:
        project = r.project
        owner = db.get(User, r.created_by_id) if r.created_by_id else None
        level = effective_access(db, user, r)
        # Latest version's review status (defaults to draft if NULL).
        # The column is plain VARCHAR now, so it's already a string.
        latest = r.versions[-1] if r.versions else None
        rs = (latest.review_status if latest and latest.review_status else "draft")
        items.append({
            "id": r.id,
            "name": r.name,
            "current_version": r.current_version,
            "project_id": r.project_id,
            "project_name": project.name if project else "",
            "client_name": project.client_name if project else "",
            "template_id": r.template_id,
            "template_name": r.template.name if r.template else "",
            "template_code": r.template.code if r.template else "",
            "custom_template_id": (r.details or {}).get("custom_template_id"),
            "owner_username": owner.username if owner else None,
            "owner_full_name": owner.full_name if owner else None,
            "is_mine": (owner.id == user.id) if owner else False,
            "my_access": (level.value if level else "view"),
            "review_status": rs,
            "review_status_at": (latest.review_decision_at or
                                  latest.submitted_for_review_at)
                                  .isoformat() if (latest and
                                  (latest.review_decision_at or latest.submitted_for_review_at)) else None,
            "created_at": r.created_at,
        })

    # Picker payload: every master ReportTemplate that's active, plus
    # every approved CustomTemplate. The /reports page renders these
    # in an inline dropdown next to each row so a user with edit/admin
    # access can re-bind a report's template without leaving the list.
    from ..models import CustomTemplate, TemplateStatus
    master_templates = [
        {"id": t.id, "code": t.code, "name": t.name,
         "kind": "master", "template_type": t.code}
        for t in db.query(ReportTemplate)
                    .filter(ReportTemplate.is_active == True)  # noqa
                    .order_by(ReportTemplate.name).all()
    ]
    approved_customs = [
        {"id": c.id, "name": c.name,
         "kind": "custom",
         "template_type": c.template_type,
         "uploaded_by": c.uploaded_by.username if c.uploaded_by else None}
        for c in db.query(CustomTemplate)
                    .filter(CustomTemplate.status == TemplateStatus.approved,
                            CustomTemplate.is_public == True)  # noqa
                    .order_by(CustomTemplate.name).all()
    ]
    return templates.TemplateResponse(request, "reports/list.html", {
        "user": user,
        "items": items,
        "master_templates": master_templates,
        "approved_customs": approved_customs,
    })


@router.get("/library", response_class=HTMLResponse)
def library_page(request: Request, user: User = Depends(get_current_user),
                 db: Session = Depends(get_db)):
    templates_list = db.query(ReportTemplate).filter(
        ReportTemplate.is_active == True  # noqa
    ).all()
    return templates.TemplateResponse(request, "findings/library.html", {
        "user": user, "templates_list": templates_list,
    })


@router.get("/library/new", response_class=HTMLResponse)
def new_finding_page(request: Request, user: User = Depends(get_current_user)):
    """Create new finding page"""
    return templates.TemplateResponse(request, "findings/new.html", {"user": user})


@router.get("/cvss", response_class=HTMLResponse)
def cvss_calc(request: Request, user: User = Depends(get_current_user)):
    return templates.TemplateResponse(request, "partials/cvss_calc.html", {"user": user})


# ============================================================
# Toolkit — landing page + per-tool pages.
# Every consultant has access; each tool below is its own page so we
# can grow the toolkit without bloating one mega-template.
# ============================================================

@router.get("/toolkit", response_class=HTMLResponse)
def toolkit_index(request: Request, user: User = Depends(get_current_user)):
    """Toolkit landing page — lists every available consultant tool as
    its own card. Adding a new tool is as simple as appending an entry
    to ``tools`` here and dropping a new page route + template."""
    tools = [
        {
            "slug":  "nessus-compliance",
            "title": "Nessus Compliance → Excel",
            "blurb": ("Drag in one or more .nessus / .xml CIS Host Configuration "
                      "Review scans and get a styled Excel workbook back — "
                      "Summary, All Compliance, Host Summary, and one sheet "
                      "per benchmark policy. Detects L1 / L2 levels and "
                      "preserves Excel-unsafe values (leading `=`)."),
            "icon":  "📊",
            "tag":   "Compliance",
        },
        {
            "slug":  "va-recurring",
            "title": "Recurring VA scan pipeline",
            "blurb": ("Drop this quarter's Nessus CSV exports — optionally with "
                      "last quarter's risk-accept doc and tracker — and get a "
                      "ZIP of categorised xlsx files (Outdated Software, SSL "
                      "Misconfig, Information Disclosure, etc.), removed-vs-"
                      "remaining audits, and a summary.txt. Categorisation "
                      "learns over time via a shared plugin-ID map."),
            "icon":  "🛡️",
            "tag":   "Recurring VA",
        },
        {
            "slug":  "va-retest",
            "title": "Retest tracker update",
            "blurb": ("Drop the original tracker + this quarter's rescan CSVs. "
                      "Findings no longer in the rescan get auto-marked Closed, "
                      "still-open rows get a version-remediation pass, and net-"
                      "new IPs are listed (with an option to append them as fresh "
                      "rows). Embedded screenshots in the tracker (e.g. client "
                      "Screenshots column) are preserved end-to-end."),
            "icon":  "🔁",
            "tag":   "Retest",
        },
        {
            "slug":  "cis-benchmark-map",
            "title": "HCR → CIS Benchmark mapping",
            "blurb": ("Drop the client's custom hardening standard / HCR "
                      "document (.docx or .pdf). The tool auto-extracts every "
                      "CIS Benchmark title + control id it references and "
                      "builds a cross-reference workbook — each client "
                      "control mapped to its CIS control id(s), with the "
                      "source context preserved for audit."),
            "icon":  "🗺️",
            "tag":   "HCR",
        },
        # Future tools land here. Keep slugs URL-safe — they map 1:1
        # onto `/toolkit/{slug}` routes below.
    ]
    return templates.TemplateResponse(request, "toolkit/index.html", {
        "user": user, "tools": tools,
    })


@router.get("/toolkit/nessus-compliance", response_class=HTMLResponse)
def toolkit_nessus_compliance(request: Request,
                              user: User = Depends(get_current_user)):
    """The Nessus → Excel tool's interactive page."""
    return templates.TemplateResponse(request,
        "toolkit/nessus_compliance.html", {"user": user})


@router.get("/toolkit/va-recurring", response_class=HTMLResponse)
def toolkit_va_recurring(request: Request,
                          user: User = Depends(get_current_user)):
    """The Recurring VA scan tool's interactive page."""
    return templates.TemplateResponse(request,
        "toolkit/va_recurring.html", {"user": user})


@router.get("/toolkit/va-retest", response_class=HTMLResponse)
def toolkit_va_retest(request: Request,
                       user: User = Depends(get_current_user)):
    """The Retest tracker-update tool's interactive page."""
    return templates.TemplateResponse(request,
        "toolkit/va_retest.html", {"user": user})


@router.get("/toolkit/cis-benchmark-map", response_class=HTMLResponse)
def toolkit_cis_benchmark_map(request: Request,
                              user: User = Depends(get_current_user)):
    """The HCR → CIS Benchmark mapping tool's interactive page."""
    return templates.TemplateResponse(request,
        "toolkit/cis_benchmark_map.html", {"user": user})


@router.get("/templates", response_class=HTMLResponse)
def templates_list(request: Request, user: User = Depends(get_current_user),
                   db: Session = Depends(get_db)):
    """Template management page - list all templates, upload new, pending reviews."""
    from ..models import CustomTemplate, TemplateStatus
    
    # User's own templates
    my_templates = db.query(CustomTemplate).filter(
        CustomTemplate.uploaded_by_id == user.id
    ).order_by(CustomTemplate.created_at.desc()).all()
    
    # Approved public templates
    public_templates = db.query(CustomTemplate).filter(
        CustomTemplate.status == TemplateStatus.approved,
        CustomTemplate.is_public == True
    ).order_by(CustomTemplate.created_at.desc()).all()
    
    # Pending reviews (admin only)
    pending_templates = []
    if user.role.value == "admin":
        pending_templates = db.query(CustomTemplate).filter(
            CustomTemplate.status == TemplateStatus.pending_review
        ).order_by(CustomTemplate.created_at.desc()).all()
    
    # `is_admin` gates the admin section of the unified Templates page.
    # When false, the Jinja template renders only the Custom Templates
    # content — no outer tab strip, no admin section, no admin-only
    # JS. The underlying admin API endpoints
    # (`PATCH /api/templates/{id}/active`, `replace-docx`,
    # `regenerate-defaults`, `diagnose-defaults`) are independently
    # gated server-side, so a non-admin can't sneak in via direct
    # API calls either.
    return templates.TemplateResponse(request, "templates/list.html", {
        "user": user,
        "is_admin": user.role.value == "admin",
        "my_templates": my_templates,
        "public_templates": public_templates,
        "pending_templates": pending_templates
    })


@router.get("/templates/edit/{template_id}", response_class=HTMLResponse)
def template_editor(template_id: int, request: Request,
                    user: User = Depends(get_current_user),
                    db: Session = Depends(get_db)):
    """Visual template editor - mark placeholders."""
    from ..models import CustomTemplate
    
    template = db.query(CustomTemplate).filter(CustomTemplate.id == template_id).first()
    if not template:
        raise HTTPException(404, "Template not found")
    
    # Check access
    if template.uploaded_by_id != user.id and user.role.value != "admin":
        raise HTTPException(403, "Access denied")
    
    # Convert to dict for JSON serialization. `file_missing` lets the editor
    # show a re-upload prompt instead of a dead-end 404 when the underlying
    # .docx was wiped by a redeploy (older builds wrote to an unmounted dir).
    from .custom_template_editor import _resolve_docx_path
    template_dict = {
        "id": template.id,
        "name": template.name,
        "description": template.description,
        "template_type": template.template_type,
        "docx_filename": template.docx_filename,
        "placeholder_map": template.placeholder_map or {},
        "status": template.status.value,
        "created_at": template.created_at.isoformat() if template.created_at else None,
        "file_missing": _resolve_docx_path(template) is None,
    }
    
    return templates.TemplateResponse(request, "templates/editor.html", {
        "user": user,
        "template": template_dict,
        "template_id": template.id
    })


@router.get("/templates/review/{template_id}", response_class=HTMLResponse)
def template_review(template_id: int, request: Request,
                    user: User = Depends(require_admin),
                    db: Session = Depends(get_db)):
    """Admin review page for approving/rejecting templates."""
    from ..models import CustomTemplate
    
    template = db.query(CustomTemplate).filter(CustomTemplate.id == template_id).first()
    if not template:
        raise HTTPException(404)
    
    return templates.TemplateResponse(request, "templates/review.html", {
        "user": user,
        "template": template
    })


@router.get("/profile", response_class=HTMLResponse)
def user_profile(request: Request, user: User = Depends(get_current_user)):
    """User profile page"""
    return templates.TemplateResponse(request, "profile.html", {
        "user": user,
        "page_title": "My Profile"
    })


@router.get("/profile/tester-name", response_class=HTMLResponse)
def tester_name_page(request: Request, user: User = Depends(get_current_user)):
    """Minimal local-mode page to edit the tester (full) name. The saved
    name auto-fills the tester field on every report. Saves via the existing
    PATCH /api/auth/me/profile endpoint."""
    return templates.TemplateResponse(request, "profile_tester_name.html", {
        "user": user,
        "page_title": "Tester Name",
    })


@router.get("/profile/password", response_class=HTMLResponse)
def change_password_page(request: Request, user: User = Depends(get_current_user)):
    """Change password page"""
    return templates.TemplateResponse(request, "profile_password.html", {
        "user": user,
        "page_title": "Change Password"
    })


@router.get("/profile/mfa", response_class=HTMLResponse)
def mfa_settings_page(request: Request, user: User = Depends(get_current_user)):
    """MFA settings page"""
    return templates.TemplateResponse(request, "profile_mfa.html", {
        "user": user,
        "page_title": "MFA Settings"
    })


@router.get("/admin/email-templates", response_class=HTMLResponse)
def admin_email_templates_page(request: Request,
                                user: User = Depends(require_admin)):
    """Admin-only — edit outbound email templates."""
    return templates.TemplateResponse(request, "admin/email_templates.html", {
        "user": user,
    })


@router.get("/admin/panel", response_class=HTMLResponse)
def admin_panel_page(request: Request,
                     user: User = Depends(require_admin)):
    """Admin Panel — user / role / permission management.

    Tabs:
      * Users — list every account, edit role / activate / disable,
        click into a user to grant or revoke individual permissions
        on top of their role defaults.
      * Roles — view + customise the default permissions each role
        ships with. Admin row is immutable (always has every
        permission as a safety net).
      * Activity — recent admin-relevant audit entries (user edits,
        permission grants, template / tracker replacements).
    """
    return templates.TemplateResponse(request, "admin/panel.html", {
        "user": user,
        "page_title": "Admin Panel",
    })


@router.get("/admin/templates", response_class=HTMLResponse)
def admin_templates_page(request: Request,
                         user: User = Depends(require_admin)):
    """Admin-only — consolidated templates landing page.

    Two tabs:
      * Report Templates — list every master VAPT type, show whether
        it currently resolves to a VibeDocs source or the simple
        fallback, allow toggling `is_active` (hide / show in the
        consultant picker) and replacing the system-wide .docx.
      * Email Templates — compact summary that links into the
        dedicated `/admin/email-templates` editor for each row.

    Third tab is a placeholder guide so the admin can see which
    Jinja tokens land where in the rendered VibeDocs report without
    having to read the source.
    """
    return templates.TemplateResponse(request, "admin/templates.html", {
        "user": user,
        "page_title": "Admin — Templates",
    })


@router.get("/reviews", response_class=HTMLResponse)
def reviews_page(request: Request,
                 user: User = Depends(get_current_user),
                 db: Session = Depends(get_db)):
    """Reviews queue — visible to every authenticated user.

    The page composes three role-gated sections:

      • **Reports awaiting your review** — versions where the current
        user is the assigned ``reviewer_id`` and status is
        ``in_review``. Always visible; this is the whole reason a
        plain consultant has access to the page (peer review).
      • **Custom report templates** — admin-only. Pending custom
        templates that need an admin sign-off.
      • **Findings library** — admin-only. Pending library finding
        contributions.

    Earlier this route was admin/senior-only and a peer-reviewer with
    an in-flight reports queue couldn't see anything actionable.
    """
    from ..models import CustomTemplate, TemplateStatus, ReportVersion, ReportReviewStatus

    is_admin = (user.role == Role.admin)
    is_admin_or_senior = user.role in (Role.admin, Role.senior)

    # Reports awaiting review — always present, but the "all queue"
    # section only renders for admin/senior. Use the same data shape
    # the JSON `/api/reports/review-queue` endpoint returns so the
    # template can drive both server-side and client-side rendering
    # off the same vocabulary.
    in_review_q = db.query(ReportVersion).filter(
        ReportVersion.review_status == ReportReviewStatus.in_review.value
    ).order_by(ReportVersion.submitted_for_review_at.desc().nullslast()).all()

    def _serialise(rv):
        r = rv.report
        return {
            "version_id":  rv.id,
            "report_id":   rv.report_id,
            "report_name": r.name if r else "(unknown)",
            "version":     rv.version,
            "submitted_at": rv.submitted_for_review_at,
            "reviewer_id":   rv.reviewer_id,
            "reviewer_username": (
                rv.reviewer.username if rv.reviewer else None),
            "submitter_username": (
                r.created_by.username if r and r.created_by else None),
            "review_notes": (rv.review_notes or ""),
        }

    assigned_reports = [_serialise(rv) for rv in in_review_q
                        if rv.reviewer_id == user.id]
    all_in_review_reports = [_serialise(rv) for rv in in_review_q
                              if rv.reviewer_id != user.id] \
                            if is_admin_or_senior else []

    # Templates / findings sections are admin-only. We still pass empty
    # lists to the template when the user isn't admin so the Jinja
    # markup can rely on the variables existing without an `is defined`
    # check.
    pending_templates = []
    pending_findings = []
    if is_admin:
        pending_templates = db.query(CustomTemplate).filter(
            CustomTemplate.status == TemplateStatus.pending_review
        ).order_by(CustomTemplate.updated_at.desc()).all()
        pending_findings = db.query(FindingLibrary).filter(
            FindingLibrary.status == "pending_review"
        ).order_by(FindingLibrary.updated_at.desc()).all()

    return templates.TemplateResponse(request, "reviews/index.html", {
        "user": user,
        "is_reviewer": True,
        "is_admin":            is_admin,
        "is_admin_or_senior":  is_admin_or_senior,
        "assigned_reports":    assigned_reports,
        "all_in_review_reports": all_in_review_reports,
        "pending_templates":   pending_templates,
        "pending_findings":    pending_findings,
    })
