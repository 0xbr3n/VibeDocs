"""
Forgot-password / reset-password flow.

Threat model + mitigations:
  * **Token theft** - Only a bcrypt hash of the random URL token is stored;
    the plaintext lives only in the email body. Tokens are 32 bytes of
    `secrets.token_urlsafe`, single-use, and expire in 30 minutes.
  * **CSRF on the reset POST** - The GET /reset-password page mints a CSRF
    token, stores its hash on the PasswordResetToken row, and includes the
    plaintext in a hidden form field. The POST must include the matching
    plaintext CSRF token; otherwise we 400. (SameSite=Lax cookies on the
    rest of the app don't help here because the reset flow doesn't carry
    the access_token cookie at all.)
  * **Account enumeration** - /api/auth/forgot always returns the same
    response (`200 {"ok": true, "message": "..."}`) whether the email
    exists or not. No timing leak because we always run the
    bcrypt+token operation, even on a miss.
  * **Brute force on token guessing** - Both the URL token (32 random bytes,
    ~256 bits) and the CSRF token (32 bytes) are effectively unguessable.
    Plus we rate-limit POST /api/auth/forgot per-IP and per-email.
"""
from __future__ import annotations
import secrets
from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, Form, Request, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from passlib.hash import bcrypt
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session
from pathlib import Path

from ..database import get_db
from ..models import User, PasswordResetToken, AuditLog
from ..auth import hash_password
from ..config import settings
from ..services import rate_limit
from ..services.email_send import send_mail
from ..services import email_templates as _email_tmpls


router = APIRouter(tags=["password-reset"])

templates = Jinja2Templates(
    directory=str(Path(__file__).parent.parent / "templates")
)

TOKEN_TTL_MINUTES = 30
MAX_PASSWORD_LEN = 256          # bcrypt has its own 72-byte cap; this guards memory
MIN_PASSWORD_LEN = 8


# ============================================================
# Helpers
# ============================================================

def _mint_token() -> tuple[str, str]:
    """Return (plaintext, hash). Plaintext is short enough to fit in a URL
    and long enough to be infeasible to guess (32 bytes / ~43 chars)."""
    plain = secrets.token_urlsafe(32)
    h = bcrypt.hash(plain)
    return plain, h


def _find_active_token(db: Session, plain: str) -> Optional[PasswordResetToken]:
    """Look up a reset token by hash compare. We index by token_hash but it's
    a bcrypt hash, so an exact lookup is impossible — we must scan candidates.
    Practically the table has at most a few hundred rows (cleanup below), and
    we filter by "unused + unexpired" first.
    """
    if not plain:
        return None
    now = datetime.utcnow()
    rows = (db.query(PasswordResetToken)
              .filter(PasswordResetToken.used_at.is_(None),
                      PasswordResetToken.expires_at > now)
              .order_by(PasswordResetToken.requested_at.desc())
              .limit(50)
              .all())
    for r in rows:
        try:
            if bcrypt.verify(plain, r.token_hash):
                return r
        except Exception:
            continue
    return None


def _public_base_url(request: Request) -> str:
    """Return the canonical base URL for password-reset / unlock links.

    Priority:
      1. `settings.SITE_URL` — explicitly configured, immune to header injection.
      2. X-Forwarded-Proto + X-Forwarded-Host from a trusted reverse proxy.
      3. The request URL components (scheme + netloc from the Host header).

    In production, always set SITE_URL in the environment to prevent an
    attacker from spoofing the Host header and redirecting reset emails.
    """
    from ..config import settings
    configured = (settings.SITE_URL or "").strip().rstrip("/")
    if configured:
        return configured
    proto = request.headers.get("x-forwarded-proto") or request.url.scheme
    host = request.headers.get("x-forwarded-host") or request.headers.get("host") or request.url.netloc
    return f"{proto}://{host}".rstrip("/")


# ============================================================
# 1. Request a reset link
# ============================================================

class ForgotRequest(BaseModel):
    email: EmailStr


@router.post("/api/auth/forgot")
def forgot_password_api(payload: ForgotRequest, request: Request,
                        db: Session = Depends(get_db)):
    """POST {"email": "..."}. Always 200 to avoid email-enumeration oracles.

    Rate-limited two ways: per-IP and per-email. A flood from one address
    can't burn through reset emails to every account.
    """
    from ..database import engine
    ip = rate_limit.client_ip_from_request(request)
    ok_ip, retry_ip, _ = rate_limit.hit_db(engine, "pw_forgot_ip", ip,
                                            max_attempts=10, window_seconds=600)
    if not ok_ip:
        raise HTTPException(429, f"Too many requests. Try again in {retry_ip}s.")

    email_key = payload.email.lower().strip()
    ok_email, _, _ = rate_limit.hit_db(engine, "pw_forgot_email", email_key,
                                        max_attempts=5, window_seconds=3600)

    # Always reply with the same body — no enumeration.
    generic_response = {
        "ok": True,
        "message": "If an account exists for that email, a reset link is on the way.",
    }

    if not ok_email:
        # Same generic body, but we audit-log internally so admins can spot abuse.
        db.add(AuditLog(actor_id=None, action="auth.forgot_email_rate_limited",
                        detail={"email": email_key, "ip": ip}))
        db.commit()
        return generic_response

    user = db.query(User).filter(User.email == payload.email,
                                  User.is_active == True).first()  # noqa: E712

    if not user:
        # Burn time anyway so timing doesn't leak existence
        bcrypt.hash("dummy")
        db.add(AuditLog(actor_id=None, action="auth.forgot_unknown_email",
                        detail={"email": email_key, "ip": ip}))
        db.commit()
        return generic_response

    # Invalidate any prior unused tokens for this user — only one live at a time.
    (db.query(PasswordResetToken)
       .filter(PasswordResetToken.user_id == user.id,
               PasswordResetToken.used_at.is_(None))
       .update({"used_at": datetime.utcnow()}))

    plain, token_hash = _mint_token()
    row = PasswordResetToken(
        user_id=user.id,
        token_hash=token_hash,
        expires_at=datetime.utcnow() + timedelta(minutes=TOKEN_TTL_MINUTES),
        requested_ip=ip,
        user_agent=(request.headers.get("user-agent") or "")[:255],
    )
    db.add(row)
    db.add(AuditLog(actor_id=user.id, action="auth.forgot_requested",
                    object_type="user", object_id=user.id,
                    detail={"ip": ip}))
    db.commit()

    reset_url = f"{_public_base_url(request)}/reset-password?token={plain}"
    subject, body_text, body_html = _email_tmpls.render_template(
        db, "password_reset",
        {"user": user, "reset_url": reset_url, "ttl_minutes": TOKEN_TTL_MINUTES},
    )
    send_mail(user.email, subject, body_text=body_text, body_html=body_html)
    return generic_response


# ============================================================
# 2. Show the reset form (mints the CSRF token)
# ============================================================

@router.get("/forgot-password", response_class=HTMLResponse)
def forgot_password_page(request: Request):
    return templates.TemplateResponse(request, "forgot_password.html", {})


@router.get("/reset-password", response_class=HTMLResponse)
def reset_password_page(request: Request, token: str = "",
                         db: Session = Depends(get_db)):
    """Show the reset form. Mints a fresh CSRF token bound to this reset token
    so the subsequent POST can prove "this submission originated from a real
    page render"."""
    row = _find_active_token(db, token)
    if not row:
        return templates.TemplateResponse(
            request, "reset_password.html",
            {"error": "This reset link is invalid or has expired. Request a new one."},
            status_code=400,
        )
    csrf_plain = secrets.token_urlsafe(32)
    row.csrf_token_hash = bcrypt.hash(csrf_plain)
    db.commit()
    return templates.TemplateResponse(request, "reset_password.html", {
        "token": token,
        "csrf_token": csrf_plain,
        "username": row.user.username,
    })


# ============================================================
# 3. Apply the reset
# ============================================================

@router.post("/reset-password")
def reset_password_submit(request: Request,
                          token: str = Form(...),
                          csrf_token: str = Form(...),
                          password: str = Form(...),
                          password_confirm: str = Form(...),
                          db: Session = Depends(get_db)):
    from ..database import engine
    ip = rate_limit.client_ip_from_request(request)
    ok_ip, retry_ip, _ = rate_limit.hit_db(engine, "pw_reset_ip", ip,
                                            max_attempts=20, window_seconds=600)
    if not ok_ip:
        return templates.TemplateResponse(
            request, "reset_password.html",
            {"error": f"Too many attempts. Try again in {retry_ip}s.",
             "token": token, "csrf_token": csrf_token},
            status_code=429,
        )

    if password != password_confirm:
        return templates.TemplateResponse(
            request, "reset_password.html",
            {"error": "Passwords don't match.", "token": token, "csrf_token": csrf_token},
            status_code=400,
        )
    if not (MIN_PASSWORD_LEN <= len(password) <= MAX_PASSWORD_LEN):
        return templates.TemplateResponse(
            request, "reset_password.html",
            {"error": f"Password must be {MIN_PASSWORD_LEN}-{MAX_PASSWORD_LEN} characters.",
             "token": token, "csrf_token": csrf_token},
            status_code=400,
        )

    row = _find_active_token(db, token)
    if not row:
        return templates.TemplateResponse(
            request, "reset_password.html",
            {"error": "This reset link is invalid or has expired."},
            status_code=400,
        )

    # CSRF check — must match the hash minted on the GET render.
    if not row.csrf_token_hash or not csrf_token:
        return templates.TemplateResponse(
            request, "reset_password.html",
            {"error": "Security check failed. Please reopen the link from your email."},
            status_code=400,
        )
    try:
        csrf_ok = bcrypt.verify(csrf_token, row.csrf_token_hash)
    except Exception:
        csrf_ok = False
    if not csrf_ok:
        db.add(AuditLog(actor_id=row.user_id, action="auth.reset_csrf_fail",
                        object_type="user", object_id=row.user_id,
                        detail={"ip": ip}))
        db.commit()
        return templates.TemplateResponse(
            request, "reset_password.html",
            {"error": "Security check failed. Please reopen the link from your email."},
            status_code=400,
        )

    # All good — set new password, burn token, audit.
    user = db.get(User, row.user_id)
    if not user or not user.is_active:
        return templates.TemplateResponse(
            request, "reset_password.html",
            {"error": "Account is no longer active."},
            status_code=400,
        )
    user.hashed_password = hash_password(password)
    row.used_at = datetime.utcnow()
    db.add(AuditLog(actor_id=user.id, action="auth.password_reset_completed",
                    object_type="user", object_id=user.id,
                    detail={"ip": ip}))
    db.commit()

    # Best-effort notify the account holder that password changed
    try:
        subject, body_text, body_html = _email_tmpls.render_template(
            db, "password_changed",
            {"user": user, "actor_username": user.username},
        )
        send_mail(user.email, subject, body_text=body_text, body_html=body_html)
    except Exception:
        pass

    return templates.TemplateResponse(request, "reset_password.html",
        {"success": "Password updated. You can now sign in with the new password."})


# ============================================================
# Account unlock — landing page for the email unlock link
# ============================================================

@router.get("/unlock-account", response_class=HTMLResponse)
def unlock_account_page(request: Request, token: str = ""):
    """Landing page consumed from the 'Unlock my account' email link.

    Passes the plaintext token to the template; JS auto-POSTs it to
    /api/auth/unlock and shows the result without a full page reload.
    """
    return templates.TemplateResponse(request, "unlock_account.html", {
        "token": token,
    })
