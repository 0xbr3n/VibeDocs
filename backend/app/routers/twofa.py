"""
Two-Factor Authentication endpoints.

Enrollment is self-service from Settings:
  POST   /api/twofa/enroll                              start, returns QR
  POST   /api/twofa/enroll/verify        code           confirm, returns backup codes
  DELETE /api/twofa/                                    self-disable (or admin disable other)
  GET    /api/twofa/status                              is enabled? backup-codes status?

Step 2 of login (challenge redemption) lives here:
  POST /api/auth/twofa/challenge          challenge_token + code -> access_token

Step 1 (username/password) is served by routers/auth.py and shares the same
challenge-token store via services/twofa_challenge.py.
"""
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import User, Role, AuditLog
from ..auth import get_current_user, create_access_token
from ..services import totp as totp_svc
from ..services import twofa_challenge
from ..services import rate_limit


router = APIRouter(tags=["2fa"])


# Rate-limit policy for MFA verification. Tuned for an internal pentest tool:
# - per-user code failures: 5 in 5min -> lock account out of 2FA for 15min
# - per-IP attempts:        30 in 5min (broad backstop against credential stuffers)
_USER_MAX_FAILURES   = 5
_USER_FAILURE_WINDOW = 300       # 5 minutes
_USER_LOCKOUT_SECS   = 900       # 15 minutes
_IP_MAX_ATTEMPTS     = 30
_IP_WINDOW           = 300       # 5 minutes


# ============================================================
# Enrollment (self-service from settings)
# ============================================================

@router.post("/api/twofa/enroll")
def enroll_start(db: Session = Depends(get_db),
                 user: User = Depends(get_current_user)):
    """Start enrollment. Generates a fresh TOTP secret, returns the QR code
    and otpauth URI for the authenticator app. 2FA is NOT yet enforced --
    the user must verify a code first.
    """
    payload = totp_svc.begin_enrollment(user, db)
    db.add(AuditLog(actor_id=user.id, action="twofa.enroll_start",
                    object_type="user", object_id=user.id, detail={}))
    db.commit()
    return payload


class TwoFAVerifyEnroll(BaseModel):
    code: str


@router.post("/api/twofa/enroll/verify")
def enroll_verify(payload: TwoFAVerifyEnroll,
                  request: Request,
                  db: Session = Depends(get_db),
                  user: User = Depends(get_current_user)):
    """Verify the first TOTP code. On success, flips totp_enabled=True and
    returns backup codes (shown ONCE -- user is responsible for saving them).
    Rate limited the same way as the login challenge.
    """
    user_key = f"u{user.id}"
    ip = rate_limit.client_ip_from_request(request)
    locked, retry_after = rate_limit.is_locked("mfa_enroll", user_key)
    if locked:
        raise HTTPException(429, f"Too many failed attempts. Try again in {retry_after}s.")
    from ..database import engine
    allowed, retry_after, _ = rate_limit.hit_db(engine, "mfa_enroll_ip", ip,
                                                 max_attempts=_IP_MAX_ATTEMPTS,
                                                 window_seconds=_IP_WINDOW)
    if not allowed:
        raise HTTPException(429, f"Too many attempts from your network. Try again in {retry_after}s.")

    ok, backup_codes = totp_svc.verify_enrollment(user, payload.code, db)
    if not ok:
        now_locked, lockout_for = rate_limit.record_failure(
            "mfa_enroll", user_key,
            max_failures=_USER_MAX_FAILURES,
            window_seconds=_USER_FAILURE_WINDOW,
            lockout_seconds=_USER_LOCKOUT_SECS,
        )
        db.add(AuditLog(actor_id=user.id, action="twofa.enroll_verify_failed",
                        object_type="user", object_id=user.id,
                        detail={"locked": now_locked, "ip": ip}))
        db.commit()
        if now_locked:
            raise HTTPException(429,
                f"Too many failed verifications. Enrollment locked for {lockout_for // 60} minutes.")
        raise HTTPException(400, "Invalid code -- check the authenticator app and try again.")
    rate_limit.clear("mfa_enroll", user_key)
    db.add(AuditLog(actor_id=user.id, action="twofa.enrolled",
                    object_type="user", object_id=user.id, detail={}))
    db.commit()
    return {
        "ok": True,
        "totp_enabled": True,
        "backup_codes": backup_codes,
        "note": "Save these backup codes somewhere safe. They are shown only once and let you log in if you lose your authenticator.",
    }


# ============================================================
# Disable
# ============================================================

@router.delete("/api/twofa")
def disable_self(db: Session = Depends(get_db),
                 user: User = Depends(get_current_user)):
    """Self-service disable. Requires the user is currently logged in
    (which already meant passing 2FA if enabled).
    """
    totp_svc.disable(user, db)
    db.add(AuditLog(actor_id=user.id, action="twofa.disabled",
                    object_type="user", object_id=user.id, detail={"by": "self"}))
    db.commit()
    return {"ok": True, "totp_enabled": False}


@router.delete("/api/twofa/{user_id}")
def disable_other(user_id: int,
                  db: Session = Depends(get_db),
                  actor: User = Depends(get_current_user)):
    """Admin-only: turn off 2FA for another user (e.g. lost their phone).
    Audit-logged so the team can review who reset whose 2FA.
    """
    if actor.role != Role.admin:
        raise HTTPException(403, "Only admins can disable 2FA for other users")
    target = db.get(User, user_id)
    if not target:
        raise HTTPException(404, "User not found")
    totp_svc.disable(target, db)
    db.add(AuditLog(actor_id=actor.id, action="twofa.disabled",
                    object_type="user", object_id=user_id,
                    detail={"by": "admin", "admin_username": actor.username}))
    db.commit()
    return {"ok": True, "user_id": user_id, "totp_enabled": False}


# ============================================================
# Status
# ============================================================

@router.get("/api/twofa/status")
def status(db: Session = Depends(get_db),
           user: User = Depends(get_current_user)):
    bc = totp_svc.list_backup_codes_status(user, db)
    return {
        "totp_enabled": user.totp_enabled,
        "totp_enabled_at": user.totp_enabled_at.isoformat() if user.totp_enabled_at else None,
        "backup_codes": bc,
    }


# ============================================================
# Login challenge (step 2 of two-step login)
# Step 1 lives in routers/auth.py; both share services/twofa_challenge.py.
# ============================================================


class ChallengeRequest(BaseModel):
    challenge_token: str
    code: str


@router.post("/api/auth/twofa/challenge")
def challenge(payload: ChallengeRequest, request: Request,
              db: Session = Depends(get_db)):
    """Step 2 of the two-step login. Submit the challenge_token from step 1
    plus the 6-digit TOTP code (or a backup code).

    Rate-limited two ways:
      * per-user: max 5 failures in 5 minutes -> 15 minute lockout. After a
        lockout, even a correct code is rejected with 429 until the lockout
        expires. This is the brute-force defence for the TOTP code itself.
      * per-IP:   max 30 attempts in 5 minutes (challenge token submissions).
        Stops a distributed bot from spreading attempts across user_ids.

    On success returns {"access_token", "token_type": "bearer"}; the JSON API
    expects the client to use this token as a Bearer header. The browser flow
    goes through /login/challenge in routers/ui.py, which sets the cookie.
    """
    ip = rate_limit.client_ip_from_request(request)
    # Broad IP throttle BEFORE we touch the challenge token, so noise can't
    # consume valid challenges.
    from ..database import engine
    allowed, retry_after, _ = rate_limit.hit_db(
        engine, "mfa_login_ip", ip,
        max_attempts=_IP_MAX_ATTEMPTS, window_seconds=_IP_WINDOW,
    )
    if not allowed:
        raise HTTPException(429, f"Too many attempts from your network. Try again in {retry_after}s.")

    user_id = twofa_challenge.consume(payload.challenge_token)
    if not user_id:
        raise HTTPException(401, "Challenge expired or invalid. Please log in again.")
    user = db.get(User, user_id)
    if not user or not user.is_active:
        raise HTTPException(401, "User not found")

    user_key = f"u{user.id}"
    locked, retry_after = rate_limit.is_locked("mfa_login", user_key)
    if locked:
        db.add(AuditLog(actor_id=user.id, action="auth.twofa_locked",
                        object_type="user", object_id=user.id,
                        detail={"retry_after": retry_after, "ip": ip}))
        db.commit()
        raise HTTPException(429,
            f"Account temporarily locked after repeated failed 2FA attempts. "
            f"Try again in {retry_after // 60}m {retry_after % 60}s.")

    if not totp_svc.verify_code(user, payload.code, db):
        now_locked, lockout_for = rate_limit.record_failure(
            "mfa_login", user_key,
            max_failures=_USER_MAX_FAILURES,
            window_seconds=_USER_FAILURE_WINDOW,
            lockout_seconds=_USER_LOCKOUT_SECS,
        )
        db.add(AuditLog(actor_id=user.id, action="auth.twofa_failed",
                        object_type="user", object_id=user.id,
                        detail={"locked": now_locked, "ip": ip}))
        db.commit()
        if now_locked:
            # Do NOT reissue a challenge token while locked — force user to
            # start the flow from /login again after the lockout window.
            raise HTTPException(429,
                f"Too many failed 2FA codes. Account locked for {lockout_for // 60} minutes.")
        # Reissue a fresh challenge so the user can try again without
        # re-submitting their password.
        token, ttl = twofa_challenge.issue(user.id)
        raise HTTPException(401, detail={
            "error": "Invalid 2FA code",
            "challenge_token": token,
            "expires_in": ttl,
        })

    rate_limit.clear("mfa_login", user_key)
    # Role is NOT included in the token — every server-side
    # authorisation check reads `user.role` from the DB on each
    # request (see auth.get_current_user). A client tampering with a
    # `role` claim achieves nothing.
    access = create_access_token(subject=user.username, uid=user.id)
    db.add(AuditLog(actor_id=user.id, action="auth.login_ok",
                    object_type="user", object_id=user.id,
                    detail={"twofa_required": True}))
    db.commit()
    return {"access_token": access, "token_type": "bearer"}
