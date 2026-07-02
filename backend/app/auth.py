"""Auth helpers — JWT tokens, password hashing, current-user dependency.

JWT hardening (against the usual class of attacks):

1. **Algorithm allow-list** — `jwt.decode` is called with
   `algorithms=[_ACCEPTED_ALG]`. python-jose rejects any token whose
   `alg` header isn't in that list. A token with `alg: none`, `alg:
   HS256` while we expect `RS256`, or vice-versa is rejected before
   any signature check.

2. **Pre-decode header inspection** — we read the unverified header
   first and refuse to even invoke `decode()` if:
     - `alg` is missing, `"none"`, or not in our allow-list
     - the header carries `jwk`, `jku`, `x5u`, or `x5c` — these are
       "fetch the key from an attacker-controlled location" vectors
       that python-jose doesn't honour, but rejecting them
       explicitly is defence-in-depth.

3. **No key fallback** — `get_current_user` uses ONE key (the secret
   for HS256 or the public key for RS256). There's no kid-keyed
   lookup table the attacker could mis-direct.

4. **Strict claim validation** — `decode` is called with
   `require=["exp", "iat", "sub", "uid", "iss"]` and
   `issuer=settings.JWT_ISSUER`, so a token missing any of those —
   or with a wrong `iss` — is rejected.

5. **DB-authoritative identity / role** — the token's `sub`
   (username) is matched against the DB row, AND the `uid` claim
   must match `User.id`. Roles are read from the User row, never
   from the token payload. A client that tampers with the response
   role display ("role: admin" in JSON) achieves nothing — the
   server never trusts JSON sent from the client for authorisation.

6. **Bounded lifetime** — `exp` is enforced server-side by python-jose;
   the token also carries `iat` so the audit log can record token
   freshness. Default 8 hours (`ACCESS_TOKEN_EXPIRE_MINUTES`).

RS256 mode: set `ALGORITHM=RS256` and point
`RS256_PRIVATE_KEY_PATH` / `RS256_PUBLIC_KEY_PATH` at PEM files.
The private key signs; the public key verifies. Both must exist on
the verifying process for now — split deployments would need their
own copy of the public key in `RS256_PUBLIC_KEY_PATH`.
"""
from __future__ import annotations
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

from fastapi import Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy.orm import Session

from .config import settings
from .database import get_db
from .models import User, Role

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login", auto_error=False)


# ============================================================
# Algorithm lock-down
# ============================================================
#
# We support exactly two algorithms — HS256 (default) and RS256
# (asymmetric, opt-in). Anything else, in particular the dangerous
# `none` algorithm, is refused at every layer.
_ACCEPTED_ALG = (settings.ALGORITHM or "HS256").upper()
if _ACCEPTED_ALG not in ("HS256", "RS256"):
    raise RuntimeError(
        f"settings.ALGORITHM must be HS256 or RS256 (got {_ACCEPTED_ALG!r}). "
        "Algorithms outside this allow-list are rejected for security."
    )

# Header fields that, if present, would normally cause a JWT library
# to fetch a key from somewhere the attacker controls. python-jose
# doesn't dereference these, but we still refuse tokens that carry
# them so future library swaps stay safe and so any monitoring picks
# up a clear signal.
_FORBIDDEN_HEADER_FIELDS = ("jwk", "jku", "x5u", "x5c")


def _load_rs256_keys() -> tuple[Optional[str], Optional[str]]:
    """Read the private / public PEM bytes when running in RS256 mode.
    Returns (private_pem_or_None, public_pem_or_None). Either may be
    None when the corresponding env path is missing; the call sites
    error if the key they need isn't loaded.
    """
    priv = pub = None
    if settings.RS256_PRIVATE_KEY_PATH:
        p = Path(settings.RS256_PRIVATE_KEY_PATH)
        if p.exists():
            priv = p.read_text()
    if settings.RS256_PUBLIC_KEY_PATH:
        p = Path(settings.RS256_PUBLIC_KEY_PATH)
        if p.exists():
            pub = p.read_text()
    return priv, pub


_RS256_PRIV, _RS256_PUB = _load_rs256_keys() if _ACCEPTED_ALG == "RS256" else (None, None)

if _ACCEPTED_ALG == "RS256":
    if not _RS256_PRIV:
        raise RuntimeError(
            "ALGORITHM=RS256 but RS256_PRIVATE_KEY_PATH is missing / unreadable."
        )
    if not _RS256_PUB:
        raise RuntimeError(
            "ALGORITHM=RS256 but RS256_PUBLIC_KEY_PATH is missing / unreadable."
        )


def _signing_key() -> str:
    """Return the secret bytes used to *sign* a new token."""
    return _RS256_PRIV if _ACCEPTED_ALG == "RS256" else settings.SECRET_KEY


def _verify_key() -> str:
    """Return the secret bytes used to *verify* an incoming token."""
    return _RS256_PUB if _ACCEPTED_ALG == "RS256" else settings.SECRET_KEY


# ============================================================
# Password hashing
# ============================================================

def hash_password(pw: str) -> str:
    return pwd_context.hash(pw)


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


# ============================================================
# JWT mint / verify
# ============================================================

def create_access_token(
    subject: str,
    *,
    uid: int,
    extra: Optional[dict] = None,
) -> str:
    """Mint a fresh access token for `subject` (username) + `uid`
    (DB user id). `extra` is reserved for non-security claims — never
    pass `role` here; the server reads role from the DB on every
    request.

    Implementation note: uses `time.time()` directly rather than
    `datetime.utcnow().timestamp()`. The latter is broken on Windows
    hosts because `utcnow()` returns a naive datetime whose
    `.timestamp()` interprets the value as LOCAL time — tokens end
    up shifted by the local TZ offset and decode-side `exp` checks
    reject them immediately.
    """
    now_ts = int(time.time())
    exp_ts = now_ts + settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
    claims = {
        "sub": subject,        # username
        "uid": int(uid),       # primary identity — survives rename
        "iat": now_ts,
        "exp": exp_ts,
        "iss": settings.JWT_ISSUER,
    }
    if extra:
        # Strip anything that could shadow our security-critical claims.
        for blacklisted in ("sub", "uid", "iat", "exp", "iss", "role"):
            extra.pop(blacklisted, None)
        claims.update(extra)
    return jwt.encode(claims, _signing_key(), algorithm=_ACCEPTED_ALG)


def _decode_token(tok: str) -> dict:
    """Decode + validate a JWT or raise HTTPException(401).

    Performs three layers of defence:
      1. Pre-flight header check — `alg` must equal our exact
         accepted algorithm. Refuses tokens with `jwk`/`jku`/`x5u`/`x5c`.
      2. python-jose decode with `algorithms=[_ACCEPTED_ALG]` and
         strict claim requirements. Rejects `alg: none`, mismatched
         alg, expired or missing-claim tokens.
      3. Issuer check via `issuer=settings.JWT_ISSUER`.
    """
    # Layer 1: parse the unverified header so we can refuse dangerous
    # shapes before the signature check even runs.
    try:
        header = jwt.get_unverified_header(tok)
    except JWTError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Malformed token")
    alg = (header.get("alg") or "").upper()
    if alg in ("", "NONE"):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED,
                            "Invalid token (algorithm)")
    if alg != _ACCEPTED_ALG:
        # Algorithm-confusion blocker: e.g. an attacker tries HS256
        # with the public-key PEM as a "secret" while we expect RS256.
        raise HTTPException(status.HTTP_401_UNAUTHORIZED,
                            "Invalid token (algorithm)")
    for forbidden in _FORBIDDEN_HEADER_FIELDS:
        if forbidden in header:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED,
                                "Invalid token (header)")

    # Layer 2 + 3: full verify.
    try:
        payload = jwt.decode(
            tok,
            _verify_key(),
            algorithms=[_ACCEPTED_ALG],
            issuer=settings.JWT_ISSUER,
            options={
                "require_sub": True,
                "require_exp": True,
                "require_iat": True,
                "require_iss": True,
                # explicit even though python-jose enables these by default
                "verify_signature": True,
                "verify_exp": True,
                "verify_iat": True,
                "verify_iss": True,
            },
        )
    except JWTError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid token")
    if "uid" not in payload or not isinstance(payload.get("uid"), int):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid token (uid)")
    return payload


def _token_from_request(request: Request, token_from_header: Optional[str]) -> Optional[str]:
    """Look for a JWT either in the Authorization header or the access_token cookie."""
    if token_from_header:
        return token_from_header
    return request.cookies.get("access_token")


# ============================================================
# Forced-MFA enrollment allow-list
# ============================================================
#
# When `user.totp_required=True` and `user.totp_enabled=False`, the
# user has been logged in but the admin requires them to set up an
# authenticator before doing anything else. `get_current_user`
# returns the user normally on these paths so the enrollment UI
# itself works (the 2FA setup page needs to know who is logging in
# to mint QR codes etc.), and returns 403 on every other path so a
# half-enrolled user cannot navigate around the gate by typing a URL.
#
# Paths are matched by `request.url.path.startswith(prefix)`. Keep
# the list tight — every entry here is a hole in the gate.
_MFA_ENROLLMENT_PATHS = (
    # The forced-MFA page itself + its assets
    "/profile/mfa",
    # 2FA enrollment / verify / disable endpoints
    "/api/twofa/",
    # Identity self-lookup — UI needs this to render the navbar/banner
    "/api/auth/me",
    # Logout — let the user back out of the forced gate
    "/api/auth/logout",
    # Static assets the forced-MFA page itself depends on
    "/static/",
)


def _is_mfa_enrollment_path(path: str) -> bool:
    for prefix in _MFA_ENROLLMENT_PATHS:
        if path.startswith(prefix):
            return True
    return False


def _is_mfa_enrollment_required(user: User) -> bool:
    """Return True iff the user has been flagged by an admin to set
    up 2FA but hasn't completed enrollment yet. The check is
    deliberately a getattr() so older deploys without the column
    don't crash here.
    """
    return bool(getattr(user, "totp_required", False)) and not bool(
        getattr(user, "totp_enabled", False)
    )


def get_current_user(
    request: Request,
    token: Optional[str] = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
) -> User:
    """Resolve the authenticated user from a JWT or 401.

    Identity is DB-authoritative:
      * `sub` (username) AND `uid` (DB id) from the token must both
        match the same User row. This defeats a "renamed account
        replay" — even if a stale token's `sub` matches a new user
        with that username, the `uid` won't.
      * Role is read from `user.role` on the row, never from the
        token. A token that somehow carried `role: admin` is ignored.

    Forced-MFA enrollment:
      If the user has `totp_required=True` and `totp_enabled=False`,
      every request to a path that isn't in `_MFA_ENROLLMENT_PATHS`
      returns 403 with a structured `mfa_enrollment_required` body.
      The UI uses that body to redirect the user to /profile/mfa.
    """
    tok = _token_from_request(request, token)
    if not tok:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Not authenticated")
    payload = _decode_token(tok)
    username = payload.get("sub")
    uid      = payload.get("uid")
    if not isinstance(username, str) or not username:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid token (sub)")
    user = (db.query(User)
              .filter(User.id == int(uid),
                      User.username == username,
                      User.is_active == True)  # noqa: E712
              .first())
    if not user:
        # Local-standalone resilience: the singleton "local" user's row id
        # changes if the database is reset/recreated, which would 401 an
        # otherwise-valid local session (e.g. file downloads then fail with
        # "User not found or inactive"). It's a single-user, no-login mode, so
        # resolving the local user by username instead of id is safe and
        # auto-heals the session without forcing a re-login.
        from .config import settings as _s
        if username == _s.LOCAL_MODE_USERNAME:
            user = (db.query(User)
                      .filter(User.username == username,
                              User.is_active == True)  # noqa: E712
                      .first())
    if not user:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED,
                            "User not found or inactive")
    # Forced-MFA gate: block every non-enrollment path until the user
    # finishes 2FA setup. We surface a structured 403 body so the
    # global JS fetch wrapper can detect it and redirect to the
    # enrollment page in one place rather than every API caller
    # having to know.
    if _is_mfa_enrollment_required(user):
        if not _is_mfa_enrollment_path(request.url.path):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "code": "mfa_enrollment_required",
                    "message": ("Two-factor authentication is required for "
                                "your account. Finish setup at /profile/mfa "
                                "before continuing."),
                    "redirect": "/profile/mfa?forced=1",
                },
            )
    return user


def require_roles(*roles: Role):
    """FastAPI dependency: enforces that the current user has one of the given roles."""
    def _checker(user: User = Depends(get_current_user)) -> User:
        if user.role not in roles and user.role != Role.admin:
            raise HTTPException(status.HTTP_403_FORBIDDEN,
                                f"Requires one of: {[r.value for r in roles]}")
        return user
    return _checker


def require_admin(user: User = Depends(get_current_user)) -> User:
    """FastAPI dependency: enforces that the current user is an admin."""
    if user.role != Role.admin:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Admin access required")
    return user
