"""
TOTP (Time-based One-Time Password) service.

Powers 2FA for the VAPT Reporter login. Works with Google Authenticator,
Microsoft Authenticator, Authy, 1Password, FreeOTP -- anything RFC 6238.

Backed by `pyotp` for the TOTP math and `segno` for QR code generation
(pure-python, no Pillow / libqrencode native deps).

Workflow:
  1. enroll(user)         -> (secret, qr_svg_uri, otpauth_uri)
  2. verify_enrollment(user, code, secret)  -> bool
  3. generate_backup_codes(user, count=10)  -> [str]   (shown once)
  4. verify_code(user, code) -> bool   (used at login)
"""
from __future__ import annotations
import secrets
import string
from io import BytesIO

import pyotp
import segno

from passlib.hash import bcrypt
from sqlalchemy.orm import Session

from ..models import User, TOTPBackupCode
from ..config import settings


# How long a TOTP code remains valid in seconds (default 30 = standard).
TOTP_PERIOD = 30
# Number of past/future windows we accept (1 = allow ±30s clock drift).
TOTP_VALID_WINDOW = 1
# Format of backup codes: 5 groups of 4 chars, e.g. "x7k2-3qf9-..."
BACKUP_CODE_LENGTH = 10           # 10 chars (hex-like)
BACKUP_CODES_DEFAULT_COUNT = 10
ISSUER = "VAPT Reporter"


def generate_secret() -> str:
    """Fresh base32 TOTP secret (160 bits, 32 chars). RFC 6238 compliant."""
    return pyotp.random_base32()


def otpauth_uri(user: User, secret: str, issuer: str = ISSUER) -> str:
    """Build the otpauth:// URI that authenticator apps consume."""
    return pyotp.totp.TOTP(secret, interval=TOTP_PERIOD).provisioning_uri(
        name=user.email or user.username,
        issuer_name=issuer,
    )


def qr_svg(otpauth: str) -> str:
    """Render the otpauth URI as an inline SVG string.

    SVG (vs PNG) keeps the file small, scales crisply, and inlines into the
    enrollment HTML page directly via a data: URL with no extra round-trip.
    """
    qr = segno.make(otpauth, error="m")
    buf = BytesIO()
    qr.save(buf, kind="svg", scale=5, dark="#0a0c10", light=None,
            xmldecl=False, omitsize=True)
    return buf.getvalue().decode("utf-8")


def begin_enrollment(user: User, db: Session) -> dict:
    """Generate (or re-generate) a TOTP secret and return enrollment payload.

    Note: the secret is stored on the User row immediately but `totp_enabled`
    stays False until the user proves they can read codes from the app
    (via verify_enrollment). Until that proves out, 2FA is NOT enforced.
    """
    secret = generate_secret()
    user.totp_secret = secret
    user.totp_enabled = False
    user.totp_enabled_at = None
    db.commit()

    uri = otpauth_uri(user, secret)
    return {
        "secret": secret,
        "otpauth_uri": uri,
        "qr_svg": qr_svg(uri),
        "issuer": ISSUER,
        "account": user.email or user.username,
        "period": TOTP_PERIOD,
        "digits": 6,
    }


def verify_enrollment(user: User, code: str, db: Session) -> tuple[bool, list[str]]:
    """Verify the first code from the authenticator. On success:
       - flip totp_enabled = True
       - generate backup codes (returned plain text just this once)
    Returns (success, backup_codes). Backup codes empty on failure.
    """
    if not user.totp_secret:
        return False, []
    if not _verify_totp(user.totp_secret, code):
        return False, []

    from datetime import datetime
    user.totp_enabled = True
    user.totp_enabled_at = datetime.utcnow()

    # Generate backup codes
    codes = _generate_backup_codes(BACKUP_CODES_DEFAULT_COUNT)
    # Remove any existing backup codes (re-enrollment clears old)
    db.query(TOTPBackupCode).filter(TOTPBackupCode.user_id == user.id).delete()
    for c in codes:
        db.add(TOTPBackupCode(user_id=user.id, code_hash=bcrypt.hash(c)))
    db.commit()
    return True, codes


def disable(user: User, db: Session) -> None:
    """Turn off 2FA. Admin or self-service action; the caller is responsible
    for authorisation checks. Wipes the secret and any backup codes.
    """
    user.totp_secret = None
    user.totp_enabled = False
    user.totp_enabled_at = None
    db.query(TOTPBackupCode).filter(TOTPBackupCode.user_id == user.id).delete()
    db.commit()


def verify_code(user: User, code: str, db: Session) -> bool:
    """Check the code at login. Accepts a 6-digit TOTP OR an unused backup code.
    Backup codes are single-use -- marked used on success.
    """
    if not user.totp_enabled or not user.totp_secret:
        return False
    code = (code or "").strip().replace(" ", "").replace("-", "")

    # First: try TOTP (6 digits)
    if code.isdigit() and len(code) == 6 and _verify_totp(user.totp_secret, code):
        return True

    # Otherwise: try backup codes (case-insensitive match against hashes)
    candidates = (db.query(TOTPBackupCode)
                    .filter(TOTPBackupCode.user_id == user.id,
                            TOTPBackupCode.used_at.is_(None))
                    .all())
    for bc in candidates:
        if bcrypt.verify(code.lower(), bc.code_hash):
            from datetime import datetime
            bc.used_at = datetime.utcnow()
            db.commit()
            return True
    return False


def list_backup_codes_status(user: User, db: Session) -> dict:
    """Show how many backup codes are used / unused (NOT the codes themselves --
    those are shown exactly once at enrollment).
    """
    rows = (db.query(TOTPBackupCode)
              .filter(TOTPBackupCode.user_id == user.id)
              .all())
    return {
        "total": len(rows),
        "unused": sum(1 for r in rows if r.used_at is None),
        "used": sum(1 for r in rows if r.used_at is not None),
    }


# ---- internals ----

def _verify_totp(secret: str, code: str) -> bool:
    """Validate a TOTP code against the secret with ±TOTP_VALID_WINDOW drift."""
    if not (code and code.isdigit() and len(code) == 6):
        return False
    return pyotp.TOTP(secret, interval=TOTP_PERIOD).verify(
        code, valid_window=TOTP_VALID_WINDOW
    )


def _generate_backup_codes(n: int) -> list[str]:
    """Random readable codes: 'xxxxx-xxxxx' lowercase alphanumeric."""
    out = []
    alphabet = string.ascii_lowercase + string.digits
    for _ in range(n):
        raw = "".join(secrets.choice(alphabet) for _ in range(BACKUP_CODE_LENGTH))
        out.append(f"{raw[:5]}-{raw[5:]}")
    return out
