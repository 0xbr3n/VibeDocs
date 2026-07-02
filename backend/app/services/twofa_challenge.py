"""
TOTP challenge-token issuing + consumption.

Step 1 of the two-step login issues a short-lived signed token that carries
a user id. Step 2 redeems the token + a TOTP/backup code to obtain a JWT.

The same primitives back both the JSON API
(/api/auth/login -> /api/auth/twofa/challenge) and the browser flow
(/login -> /login/challenge). Keeping issue/consume in one module avoids
two divergent implementations.

**Stateless by design.** The token is an `itsdangerous.URLSafeTimedSerializer`
payload signed with SECRET_KEY — issue() and consume() don't share any
in-process state, so the flow works correctly under multiple uvicorn
workers, across restarts, and across replicas. Previously this module
held an in-memory dict, which caused "2FA challenge expired" right after
typing a valid code when step-1 and step-2 happened to land on different
workers.

Replay protection: the TOTP code itself is single-use against the
authenticator's 30s clock window, and the per-user MFA rate-limit caps
failed attempts at 5/5min -> 15min lockout (see services/rate_limit.py),
so a stolen-but-not-yet-used challenge token can't be brute-forced into
a session.
"""
from __future__ import annotations
from typing import Optional

from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

from ..config import settings


CHALLENGE_TTL_SECONDS = 300       # 5 minutes
_SALT = "vapt-reporter:mfa-challenge:v1"


def _signer() -> URLSafeTimedSerializer:
    # Lazy each call — cheap, and lets the signing key reflect any future
    # SECRET_KEY rotation without restart.
    return URLSafeTimedSerializer(settings.SECRET_KEY, salt=_SALT)


def issue(user_id: int) -> tuple[str, int]:
    """Mint a fresh challenge token tied to a user id.

    The token is self-contained: it carries `{user_id}` signed with
    SECRET_KEY + a timestamp. Returns (token, ttl_seconds).
    """
    token = _signer().dumps({"uid": int(user_id)})
    return token, CHALLENGE_TTL_SECONDS


def consume(token: str) -> Optional[int]:
    """Verify and decode the token. Returns the user id, or None if the
    token is missing / tampered / expired.

    NOT single-use — see module docstring on why that's safe in our setup.
    """
    if not token:
        return None
    try:
        payload = _signer().loads(token, max_age=CHALLENGE_TTL_SECONDS)
    except SignatureExpired:
        return None
    except BadSignature:
        return None
    except Exception:
        return None
    uid = payload.get("uid") if isinstance(payload, dict) else None
    try:
        return int(uid) if uid is not None else None
    except (TypeError, ValueError):
        return None
