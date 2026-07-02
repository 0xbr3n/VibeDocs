"""Authentication endpoints. The /login route sets an HTTP-only cookie AND returns
the bearer token, so both the server-rendered UI and API clients work."""
from fastapi import APIRouter, Depends, HTTPException, status, Response, Request, Body
from fastapi.responses import JSONResponse
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from typing import Optional
from ..database import get_db
from ..models import User, Role, AuditLog
from ..schemas import Token, UserCreate, UserOut
from ..auth import (
    hash_password, verify_password, create_access_token,
    get_current_user, require_roles,
)
from ..services import twofa_challenge

router = APIRouter(prefix="/api/auth", tags=["auth"])

@router.post("/login")
def login(
    request: Request,
    response: Response,
    form: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db),
):
    """Step 1 of login. Username + password.

    If the user has 2FA enabled, this returns a `challenge_token` instead of an
    access token; the client must POST that token + the 6-digit TOTP code to
    /api/auth/twofa/challenge to get the access token.

    Response shape:
      - 2FA off:  200 {"access_token": "...", "token_type": "bearer", "totp_required": false}
      - 2FA on:   200 {"totp_required": true, "challenge_token": "...", "expires_in": 300}
    """
    from ..services import rate_limit as rl
    from ..database import engine
    ip = rl.client_ip_from_request(request)
    allowed, retry_after, _ = rl.hit_db(engine, "login_ip", ip,
                                         max_attempts=20, window_seconds=300)
    if not allowed:
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            f"Too many login attempts. Try again in {retry_after}s.",
            headers={"Retry-After": str(retry_after)},
        )

    user = db.query(User).filter(User.username == form.username).first()
    password_ok = user is not None and verify_password(form.password, user.hashed_password)

    if not password_ok:
        # Track failed attempts per-user for auto-lock.  Must happen BEFORE
        # returning the error so the counter is persisted even if the caller
        # doesn't retry — this protects against slow-drip attacks that never
        # hit the IP rate-limiter window.
        if user is not None:
            fa = (getattr(user, 'failed_login_attempts', 0) or 0) + 1
            user.failed_login_attempts = fa
            if fa >= 5 and not getattr(user, 'locked_at', None):
                from datetime import datetime as _dt
                user.locked_at = _dt.utcnow()
                user.lock_reason = "auto"
                db.add(AuditLog(
                    actor_id=user.id, action="auth.account_auto_locked",
                    object_type="user", object_id=user.id,
                    detail={"failed_attempts": fa},
                ))
        db.add(AuditLog(actor_id=None, action="auth.login_failed",
                        detail={"username": form.username, "reason": "bad_credentials"}))
        db.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Bad credentials")

    if not user.is_active:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "User is disabled")

    # Correct password — now check account lock.  We reveal the lock status
    # only after the credential check so a wrong-password attempt on a locked
    # account still returns "Bad credentials" (no username enumeration leak).
    if getattr(user, 'locked_at', None) is not None:
        db.add(AuditLog(
            actor_id=user.id, action="auth.login_blocked_locked",
            object_type="user", object_id=user.id,
            detail={"username": user.username},
        ))
        db.commit()
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "Account is locked due to too many failed login attempts. "
            "Contact your administrator or use the unlock link sent to your email.",
        )

    # Successful password auth — reset the failed-attempt counter.
    user.failed_login_attempts = 0

    if user.totp_enabled:
        token, ttl = twofa_challenge.issue(user.id)
        db.add(AuditLog(actor_id=user.id, action="auth.login_step1_ok",
                        object_type="user", object_id=user.id,
                        detail={"twofa_required": True}))
        db.commit()
        # Do NOT set the access_token cookie yet — 2FA challenge must complete first.
        return {"totp_required": True, "challenge_token": token, "expires_in": ttl}

    # No `role` claim — authorisation is DB-driven on every request.
    access = create_access_token(user.username, uid=user.id)
    _secure = (settings.SITE_URL or "").lower().startswith("https://")
    response.set_cookie(
        "access_token", access,
        httponly=True, samesite="lax", max_age=60 * 60 * 8,
        secure=_secure,
    )
    db.add(AuditLog(actor_id=user.id, action="auth.login_ok",
                    object_type="user", object_id=user.id,
                    detail={"twofa_required": False}))
    db.commit()
    return {"access_token": access, "token_type": "bearer", "totp_required": False}

@router.post("/logout")
def logout(response: Response):
    response.delete_cookie("access_token")
    return {"ok": True}

# ============================================================
# Public self-registration
# ============================================================
#
# SECURITY: this endpoint accepts NO `role` parameter. The previous
# version trusted a `role` field from the request body — anyone could
# `POST /api/auth/register` with `role=admin` and instantly own the
# system. Self-registered accounts are now ALWAYS created as
# `consultant`. To grant elevated privileges, an admin uses the
# admin-only `POST /api/auth/users` endpoint below.
@router.post("/register")
def register_user(
    request: Request,
    username: str = Body(...),
    password: str = Body(...),
    email: Optional[str] = Body(None),
    full_name: Optional[str] = Body(None),
    db: Session = Depends(get_db),
):
    """Public self-registration. New accounts are always `consultant`."""
    if not username or not password:
        raise HTTPException(400, "Username and password are required.")
    if len(password) < 8 or len(password) > 256:
        raise HTTPException(400, "Password must be 8–256 characters.")
    if db.query(User).filter(User.username == username).first():
        raise HTTPException(400, "Username already exists")
    # Email is optional in the UI, but the column is NOT NULL + unique. When
    # left blank, synthesise a stable placeholder so the insert succeeds; when
    # supplied, reject duplicates with a clean 400 instead of a 500.
    email = (email or "").strip() or None
    if email and db.query(User).filter(User.email == email).first():
        raise HTTPException(400, "That email is already registered.")
    if not email:
        email = f"{username}@vibedocs.local"

    user = User(
        username=username,
        email=email,
        full_name=full_name,
        hashed_password=hash_password(password),
        role=Role.consultant,    # HARDCODED — never trust client-supplied role
        is_active=True,
    )
    db.add(user)
    try:
        db.commit()
    except Exception:
        db.rollback()
        raise HTTPException(400, "That username or email is already in use.")
    db.refresh(user)

    db.add(AuditLog(actor_id=user.id, action="auth.self_register",
                    object_type="user", object_id=user.id,
                    detail={"username": user.username}))
    db.commit()

    return {
        "id": user.id,
        "username": user.username,
        "role": user.role.value,    # always "consultant"
        "message": "User registered successfully",
    }

@router.get("/me", response_model=UserOut)
def me(user: User = Depends(get_current_user)):
    return user


# ============================================================
# Profile self-edit: username + full_name + email
# ============================================================
#
# These are the only three identity fields a user can change about
# themselves. Role + is_active stay admin-only via the
# `/api/admin/panel/users/{uid}` endpoint. Password changes go
# through `/api/auth/change-password` (current-password check) and
# 2FA enrollment is its own flow under `/api/twofa`.
#
# Username uniqueness is enforced server-side. Email uniqueness too
# — the password-reset flow looks up users by email so a duplicate
# would break recovery for both accounts.


@router.patch("/me/profile")
def patch_my_profile(
    payload: dict = Body(...),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Update the current user's username / email / full_name.

    Accepts any subset of `{username, email, full_name}`. Unknown
    fields are ignored. Returns the updated `UserOut`.
    """
    changes: dict = {}

    new_username = payload.get("username")
    if isinstance(new_username, str):
        new_username = new_username.strip()
        if new_username and new_username != user.username:
            if len(new_username) < 3 or len(new_username) > 64:
                raise HTTPException(400, "Username must be 3-64 characters.")
            # Block whitespace / weird chars — usernames are used in
            # audit logs + URLs + email-from prefixes.
            import re as _re
            if not _re.match(r"^[A-Za-z0-9._\-]+$", new_username):
                raise HTTPException(
                    400,
                    "Username may contain letters, digits, dot, dash, "
                    "and underscore only.",
                )
            existing = (db.query(User)
                          .filter(User.username == new_username,
                                  User.id != user.id)
                          .first())
            if existing:
                raise HTTPException(400, "Username already taken.")
            changes["username"] = [user.username, new_username]
            user.username = new_username

    new_email = payload.get("email")
    if isinstance(new_email, str):
        new_email = new_email.strip()
        if new_email and new_email != (user.email or ""):
            # Light email-shape check. Pydantic's EmailStr would be
            # stricter but the existing UserCreate path already uses
            # EmailStr — duplicating that here would force callers
            # through pydantic, which complicates the partial-update
            # payload. The DB still enforces uniqueness.
            if "@" not in new_email or "." not in new_email.split("@")[-1]:
                raise HTTPException(400, "Email looks invalid.")
            existing = (db.query(User)
                          .filter(User.email == new_email,
                                  User.id != user.id)
                          .first())
            if existing:
                raise HTTPException(400, "Email already in use by another account.")
            changes["email"] = [user.email, new_email]
            user.email = new_email

    new_full = payload.get("full_name")
    if isinstance(new_full, str):
        new_full = new_full.strip() or None
        if new_full != user.full_name:
            if new_full and len(new_full) > 255:
                raise HTTPException(400, "Full name too long (max 255).")
            changes["full_name"] = [user.full_name, new_full]
            user.full_name = new_full

    new_phone = payload.get("phone")
    if isinstance(new_phone, str):
        new_phone = new_phone.strip() or None
        if new_phone != getattr(user, "phone", None):
            if new_phone and len(new_phone) > 64:
                raise HTTPException(400, "Phone number too long (max 64).")
            changes["phone"] = [getattr(user, "phone", None), new_phone]
            user.phone = new_phone

    if changes:
        db.commit()
        try:
            db.add(AuditLog(
                actor_id=user.id, action="user.profile.update",
                object_type="user", object_id=user.id,
                detail={"changes": changes},
            ))
            db.commit()
        except Exception:                                   # pragma: no cover
            db.rollback()
    return {
        "ok": True,
        "changes": list(changes.keys()),
        "user": {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "full_name": user.full_name,
            "phone": getattr(user, "phone", None),
            "role": user.role.value if hasattr(user.role, "value") else user.role,
        },
    }


# ============================================================
# User-level notification preferences
# ============================================================
#
# A single master switch today (`notifications_email_enabled`). Kept as
# its own endpoint so adding more granular per-channel toggles later
# (e.g. opt out of project assignment but keep approval emails) is a
# schema + UI change without touching the route shape.


@router.get("/me/preferences")
def get_my_preferences(user: User = Depends(get_current_user)):
    """Read the current user's preferences."""
    return {
        "notifications_email_enabled": bool(
            getattr(user, "notifications_email_enabled", True)
        ),
        "notes_widget_enabled": bool(
            getattr(user, "notes_widget_enabled", True)
        ),
    }


@router.patch("/me/preferences")
def patch_my_preferences(
    payload: dict = Body(...),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Update user preferences. Accepts any subset of:
        - `notifications_email_enabled: bool`
        - `notes_widget_enabled: bool`
    Unknown fields are silently ignored so a stale client doesn't 400.
    """
    changes: dict = {}
    if "notifications_email_enabled" in payload:
        v = payload["notifications_email_enabled"]
        if not isinstance(v, bool):
            raise HTTPException(
                400, "notifications_email_enabled must be true or false")
        if user.notifications_email_enabled != v:
            user.notifications_email_enabled = v
            changes["notifications_email_enabled"] = v

    if "notes_widget_enabled" in payload:
        v = payload["notes_widget_enabled"]
        if not isinstance(v, bool):
            raise HTTPException(
                400, "notes_widget_enabled must be true or false")
        if getattr(user, "notes_widget_enabled", True) != v:
            user.notes_widget_enabled = v
            changes["notes_widget_enabled"] = v

    # Dashboard widget selection. Accepts a list of widget-key strings;
    # only keys in the known set are kept (a stale/tampered client can't
    # inject arbitrary values). Empty list => user explicitly hid every
    # widget (valid); None/absent => leave unchanged. Sending the
    # sentinel "__default__" resets to the default-all behaviour
    # (stored as NULL).
    if "dashboard_widgets" in payload:
        v = payload["dashboard_widgets"]
        _KNOWN = {
            "reports_owned", "reports_completed", "reports_assigned",
            "pending_reviews", "findings_authored", "projects_visible",
            "unique_clients", "status_breakdown",
        }
        if v == "__default__" or v is None:
            if getattr(user, "dashboard_widgets", None) is not None:
                user.dashboard_widgets = None
                changes["dashboard_widgets"] = None
        elif isinstance(v, list) and all(isinstance(x, str) for x in v):
            cleaned = [x for x in v if x in _KNOWN]
            if getattr(user, "dashboard_widgets", None) != cleaned:
                user.dashboard_widgets = cleaned
                changes["dashboard_widgets"] = cleaned
        else:
            raise HTTPException(
                400,
                "dashboard_widgets must be a list of widget-key strings "
                "or the sentinel '__default__'")

    if changes:
        db.commit()
        try:
            db.add(AuditLog(
                actor_id=user.id,
                action="user.preferences.update",
                object_type="user", object_id=user.id,
                detail=changes,
            ))
            db.commit()
        except Exception:                                   # pragma: no cover
            db.rollback()
    return {
        "ok": True,
        "notifications_email_enabled": bool(
            getattr(user, "notifications_email_enabled", True)
        ),
        "notes_widget_enabled": bool(
            getattr(user, "notes_widget_enabled", True)
        ),
    }


@router.post("/change-password")
def change_password(
    request: Request,
    payload: dict = Body(...),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Update the current user's password. Verifies the existing one first
    so a stolen session cookie alone can't take over the account. Returns
    a structured 400 with a clear `detail` string so the UI can surface
    'Current password is incorrect' instead of the generic 'Not Found'
    that the missing route used to produce.
    """
    from ..services import rate_limit as _rl
    from ..database import engine as _engine
    _ip = _rl.client_ip_from_request(request)
    _ok_ip, _retry_ip, _ = _rl.hit_db(_engine, "change_pw_ip", _ip,
                                       max_attempts=10, window_seconds=600)
    if not _ok_ip:
        raise HTTPException(429, f"Too many password-change attempts. Try again in {_retry_ip}s.")
    _ok_uid, _retry_uid, _ = _rl.hit_db(_engine, "change_pw_uid", str(user.id),
                                         max_attempts=5, window_seconds=600)
    if not _ok_uid:
        raise HTTPException(429, f"Too many password-change attempts for this account. Try again in {_retry_uid}s.")

    current = (payload or {}).get("current_password") or ""
    new_pw  = (payload or {}).get("new_password") or ""
    if not current or not new_pw:
        raise HTTPException(400, "Both current_password and new_password are required")
    if not verify_password(current, user.hashed_password):
        # Audited because repeated wrong-current-password attempts are a
        # signal of session hijacking; we want oncall to be able to spot them.
        db.add(AuditLog(actor_id=user.id, action="user.password.change_failed",
                        object_type="user", object_id=user.id,
                        detail={"reason": "wrong_current_password"}))
        db.commit()
        raise HTTPException(400, "Current password is incorrect")
    if len(new_pw) < 8 or len(new_pw) > 256:
        raise HTTPException(400, "New password must be 8–256 characters")
    if new_pw == current:
        raise HTTPException(400, "New password must be different from the current one")
    user.hashed_password = hash_password(new_pw)
    db.add(AuditLog(actor_id=user.id, action="user.password.changed",
                    object_type="user", object_id=user.id, detail={}))
    db.commit()
    return {"ok": True, "message": "Password updated."}


# ============================================================
# Profile: user-customised background image
# ============================================================

from fastapi import UploadFile, File   # noqa: E402
from fastapi.responses import FileResponse  # noqa: E402
from pathlib import Path  # noqa: E402
import uuid as _uuid  # noqa: E402
from ..config import settings  # noqa: E402


ALLOWED_BG_EXT = {".png", ".jpg", ".jpeg", ".webp", ".gif"}
MAX_BG_BYTES = 6 * 1024 * 1024   # 6 MB — generous for a desktop wallpaper


@router.post("/me/background-upload")
def upload_background_multipart(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Upload a custom background image for the current user. The previous
    file (if any) is deleted on success."""
    suffix = Path(file.filename or "").suffix.lower()
    if suffix not in ALLOWED_BG_EXT:
        raise HTTPException(400, f"Unsupported image type: {suffix or '(none)'}. "
                                  f"Allowed: {sorted(ALLOWED_BG_EXT)}")
    out_dir = Path(settings.UPLOAD_DIR) / "backgrounds" / str(user.id)
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"{_uuid.uuid4().hex}{suffix}"

    written = 0
    with out_path.open("wb") as fh:
        while True:
            chunk = file.file.read(64 * 1024)
            if not chunk: break
            written += len(chunk)
            if written > MAX_BG_BYTES:
                fh.close(); out_path.unlink(missing_ok=True)
                raise HTTPException(413, f"File too large (limit {MAX_BG_BYTES // (1024*1024)} MB)")
            fh.write(chunk)

    # Best-effort clean up of the prior file
    if user.background_path:
        try: Path(user.background_path).unlink(missing_ok=True)
        except Exception: pass

    user.background_path = str(out_path)
    db.commit()
    return {"ok": True, "path": str(out_path)}


@router.delete("/me/background")
def delete_background(
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    if user.background_path:
        try: Path(user.background_path).unlink(missing_ok=True)
        except Exception: pass
        user.background_path = None
        db.commit()
    return {"ok": True}


@router.get("/me/background")
def serve_background(user: User = Depends(get_current_user)):
    """Stream the current user's uploaded background image (or 404 if none)."""
    if not user.background_path:
        raise HTTPException(404, "No background set")
    p = Path(user.background_path).resolve()
    allowed_root = Path(settings.UPLOAD_DIR).resolve()
    if not str(p).startswith(str(allowed_root)):
        raise HTTPException(404, "No background set")
    if not p.exists():
        raise HTTPException(410, "Background file missing on disk")
    _mime = {"jpg": "jpeg", "jpeg": "jpeg", "png": "png",
             "webp": "webp", "gif": "gif"}.get(p.suffix.lstrip(".").lower(), "octet-stream")
    return FileResponse(p, media_type=f"image/{_mime}")

@router.post("/users", response_model=UserOut)
def create_user(
    payload: UserCreate,
    db: Session = Depends(get_db),
    _: User = Depends(require_roles(Role.admin)),
):
    if db.query(User).filter(User.username == payload.username).first():
        raise HTTPException(400, "Username already exists")
    u = User(
        username=payload.username,
        email=payload.email,
        full_name=payload.full_name,
        hashed_password=hash_password(payload.password),
        role=payload.role,
    )
    db.add(u); db.commit(); db.refresh(u)
    return u

@router.post("/unlock")
def unlock_account(
    request: Request,
    token: str,
    db: Session = Depends(get_db),
):
    """Public (no auth required) endpoint consumed by the unlock-link email.

    Accepts the plaintext token from the query string / POST body, verifies
    it against the stored bcrypt hash, and clears the lock on the user's
    account if valid and unexpired.  Returns a generic 400 for any failure
    (expired / already-used / not-found) so the caller can redirect to a
    friendly "Your account has been unlocked" or "Invalid link" page.
    """
    from datetime import datetime as _dt
    from passlib.hash import bcrypt
    from ..models import AccountUnlockToken
    from ..services import rate_limit as rl
    from ..database import engine as _engine

    # Rate-limit by IP — each call does N bcrypt verifies so unchecked
    # flooding would exhaust CPU (bcrypt is intentionally expensive).
    ip = rl.client_ip_from_request(request)
    ok_ip, retry_after, _ = rl.hit_db(_engine, "unlock_ip", ip,
                                       max_attempts=10, window_seconds=600)
    if not ok_ip:
        raise HTTPException(429, f"Too many unlock attempts. Try again in {retry_after}s.")

    if not token or len(token) > 256:
        raise HTTPException(400, "Invalid unlock link.")

    # Fetch all unexpired, unused tokens to find the matching one via
    # constant-time bcrypt verify (we can't look up by plaintext).
    now = _dt.utcnow()
    candidates = (db.query(AccountUnlockToken)
                    .filter(AccountUnlockToken.used_at.is_(None),
                            AccountUnlockToken.expires_at > now)
                    .all())

    matched = None
    for row in candidates:
        try:
            if bcrypt.verify(token, row.token_hash):
                matched = row
                break
        except Exception:
            continue

    if matched is None:
        raise HTTPException(400, "Unlock link is invalid or has expired.")

    user = db.get(User, matched.user_id)
    if user is None or not user.is_active:
        raise HTTPException(400, "User account is no longer active.")

    # Clear the lock
    user.locked_at = None
    user.lock_reason = None
    user.failed_login_attempts = 0
    matched.used_at = now

    db.add(AuditLog(
        actor_id=user.id, action="auth.account_unlocked_via_link",
        object_type="user", object_id=user.id,
        detail={"token_id": matched.id},
    ))
    db.commit()
    return {"ok": True, "message": "Account unlocked. You can now log in."}


@router.get("/users", response_model=list[UserOut])
def list_users(
    db: Session = Depends(get_db),
    _: User = Depends(require_roles(Role.admin, Role.senior)),
):
    return db.query(User).order_by(User.username).all()