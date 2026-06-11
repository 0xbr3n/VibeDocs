"""
Azure AD SSO routes — Authorization Code Flow.

  GET /auth/sso/login     — start SSO: generate state+nonce, redirect to Azure
  GET /auth/sso/callback  — complete SSO: validate token, provision user, set cookie

Security design
---------------
* State is a random token stored in a **signed, timed cookie** (`sso_state`)
  using itsdangerous.  The cookie is HttpOnly + SameSite=Lax — it cannot be
  read by JavaScript, and CSRF attacks cannot trigger the callback route.
* Nonce is embedded in the signed cookie so id_token replay attacks are
  rejected even if an attacker intercepts a code+state pair.
* Tenant restriction (`SSO_ALLOWED_TENANT` == AZURE_TENANT_ID) prevents a
  token minted by a different tenant from being accepted.
* SSO-provisioned users have a random placeholder password hash — they can
  never authenticate through the local username+password form.
"""
from __future__ import annotations

import json
import logging
import secrets
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import RedirectResponse
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from passlib.context import CryptContext
from sqlalchemy.orm import Session

from ..auth import create_access_token
from ..config import settings
from ..database import get_db
from ..models import Role, User
from ..services.oidc_client import SSOUserInfo, get_oidc_client

log = logging.getLogger(__name__)
router = APIRouter(prefix="/auth/sso", tags=["sso"])

# Used to hash a discarded random value as a placeholder for sso_provider users.
_pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")

# ------------------------------------------------------------------ #
# Helpers                                                              #
# ------------------------------------------------------------------ #

_STATE_SALT = "sso-state-v1"
_STATE_MAX_AGE = 600  # seconds — enough for the Azure redirect round-trip


def _make_signer() -> URLSafeTimedSerializer:
    return URLSafeTimedSerializer(settings.SECRET_KEY, salt=_STATE_SALT)


def _make_state_cookie(state: str, nonce: str) -> str:
    """Sign {"s": state, "n": nonce} into a timed token."""
    return _make_signer().dumps({"s": state, "n": nonce})


def _read_state_cookie(cookie_value: str) -> tuple[str, str]:
    """Unsign and return (state, nonce). Raises ValueError on failure."""
    try:
        payload = _make_signer().loads(cookie_value, max_age=_STATE_MAX_AGE)
        return payload["s"], payload["n"]
    except SignatureExpired:
        raise ValueError("SSO session expired — please try signing in again")
    except (BadSignature, KeyError, Exception) as exc:
        raise ValueError(f"Invalid SSO state cookie: {exc}") from exc


def _redirect_uri() -> str:
    """Compute the OAuth2 redirect URI from settings or request context."""
    uri = settings.SSO_REDIRECT_URI.strip()
    if not uri:
        raise RuntimeError(
            "SSO_REDIRECT_URI is not set — add it to your .env file "
            "and register it in the Azure App Registration."
        )
    return uri


def _resolve_role(groups: list[str]) -> Role:
    """Map Azure group IDs to a VibeDocs role using SSO_GROUP_ROLE_MAP.

    Falls back to SSO_DEFAULT_ROLE when no group matches.
    """
    try:
        group_map: dict[str, str] = json.loads(settings.SSO_GROUP_ROLE_MAP or "{}")
    except (json.JSONDecodeError, Exception):
        group_map = {}

    role_priority = {
        "admin":      0,
        "senior":     1,
        "consultant": 2,
        "viewer":     3,
    }
    best_role: str = settings.SSO_DEFAULT_ROLE or "consultant"

    for gid in groups:
        mapped = group_map.get(gid)
        if mapped and mapped in role_priority:
            if role_priority[mapped] < role_priority.get(best_role, 99):
                best_role = mapped

    try:
        return Role(best_role)
    except ValueError:
        return Role.consultant


def _get_or_create_user(db: Session, info: SSOUserInfo) -> User:
    """JIT-provision an SSO user or link to an existing account.

    Lookup order:
      1. Existing row with matching (sso_provider, sso_subject) — fastest path
         on repeat logins.
      2. Existing row with matching email — links the SSO identity to an
         existing local account (e.g. the admin pre-created the account).
      3. Create a new user with a placeholder password.
    """
    # 1. Repeat SSO login
    user = (
        db.query(User)
        .filter(User.sso_provider == "azure_ad", User.sso_subject == info.subject)
        .first()
    )
    if user:
        # Refresh name/email in case they changed in Azure AD
        user.full_name = info.full_name or user.full_name
        if info.email and user.email != info.email:
            # Only update email if the new one isn't taken by another account
            collision = db.query(User).filter(
                User.email == info.email, User.id != user.id
            ).first()
            if not collision:
                user.email = info.email
        db.commit()
        return user

    # 2. Link to existing account by email
    if info.email:
        user = db.query(User).filter(User.email == info.email).first()
        if user:
            user.sso_provider = "azure_ad"
            user.sso_subject = info.subject
            user.full_name = info.full_name or user.full_name
            db.commit()
            log.info("SSO: linked existing account id=%d email=%s to Azure OID=%s",
                     user.id, info.email, info.subject)
            return user

    # 3. Create new user
    role = _resolve_role(info.groups)
    # Placeholder password — random bytes that are immediately discarded.
    # This prevents the account from ever being authenticated via local login.
    placeholder_hash = _pwd_ctx.hash(secrets.token_hex(32))

    # Generate a unique username — prefer UPN, fall back with suffix on collision
    base_username = info.username or f"sso_{info.subject[:12]}"
    username = base_username
    suffix = 0
    while db.query(User).filter(User.username == username).first():
        suffix += 1
        username = f"{base_username}_{suffix}"

    user = User(
        username=username,
        email=info.email or f"{info.subject}@sso.local",
        full_name=info.full_name or username,
        hashed_password=placeholder_hash,
        role=role,
        is_active=True,
        sso_provider="azure_ad",
        sso_subject=info.subject,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    log.info(
        "SSO: JIT-provisioned new user id=%d username=%s role=%s email=%s",
        user.id, user.username, role.value, info.email,
    )
    return user


def _set_auth_cookie(response: RedirectResponse, user: User) -> None:
    token = create_access_token(user.username, uid=user.id)
    response.set_cookie(
        "access_token",
        token,
        httponly=True,
        samesite="lax",
        max_age=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        secure=settings.SITE_URL.startswith("https"),
    )


# ------------------------------------------------------------------ #
# Routes                                                               #
# ------------------------------------------------------------------ #

@router.get("/login")
async def sso_login(request: Request):
    """Initiate the Azure AD login flow.

    Generates a CSRF state token + nonce, stores them in a signed cookie,
    and redirects the browser to the Microsoft authorization endpoint.
    """
    if not settings.SSO_ENABLED:
        raise HTTPException(404, "SSO is not enabled on this server")

    try:
        client = get_oidc_client()
        redirect_uri = _redirect_uri()
    except RuntimeError as exc:
        log.error("SSO misconfigured: %s", exc)
        return RedirectResponse(
            "/login?error=SSO+is+misconfigured.+Contact+IT+support.", status_code=302
        )

    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)
    signed_cookie = _make_state_cookie(state, nonce)

    try:
        authorize_url = await client.build_authorize_url(redirect_uri, state, nonce)
    except Exception as exc:
        log.error("SSO: could not build authorize URL: %s", exc)
        return RedirectResponse(
            "/login?error=Could+not+reach+Microsoft.+Please+try+again.", status_code=302
        )

    resp = RedirectResponse(authorize_url, status_code=302)
    resp.set_cookie(
        "sso_state",
        signed_cookie,
        httponly=True,
        samesite="lax",
        max_age=_STATE_MAX_AGE,
        secure=settings.SITE_URL.startswith("https"),
    )
    return resp


@router.get("/callback")
async def sso_callback(
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    # Azure appends code + state on success, or error + error_description on failure
    code:              str = Query(default=""),
    state:             str = Query(default=""),
    error:             str = Query(default=""),
    error_description: str = Query(default=""),
):
    """Handle the Azure AD authorization callback.

    On success: validates the id_token, provisions/looks up the user,
    sets the VibeDocs access_token cookie, and redirects to /dashboard.

    On any failure: redirects to /login with a human-readable error message.
    """
    if not settings.SSO_ENABLED:
        raise HTTPException(404, "SSO is not enabled")

    # ── Azure returned an error (e.g. user cancelled) ─────────────────
    if error:
        log.warning("SSO callback: Azure returned error=%s desc=%s", error, error_description)
        msg = _azure_error_to_message(error, error_description)
        return RedirectResponse(f"/login?error={_qenc(msg)}", status_code=302)

    if not code:
        return RedirectResponse("/login?error=No+authorization+code+received.", status_code=302)

    # ── Validate state (CSRF protection) ──────────────────────────────
    cookie_val = request.cookies.get("sso_state", "")
    if not cookie_val:
        log.warning("SSO callback: sso_state cookie missing")
        return RedirectResponse(
            "/login?error=SSO+session+expired.+Please+try+signing+in+again.",
            status_code=302,
        )
    try:
        expected_state, nonce = _read_state_cookie(cookie_val)
    except ValueError as exc:
        log.warning("SSO callback: bad state cookie: %s", exc)
        return RedirectResponse(
            "/login?error=SSO+session+expired.+Please+try+signing+in+again.",
            status_code=302,
        )

    if not secrets.compare_digest(state, expected_state):
        log.warning("SSO callback: state mismatch (possible CSRF)")
        return RedirectResponse(
            "/login?error=Invalid+SSO+state.+Please+try+signing+in+again.",
            status_code=302,
        )

    # ── Exchange code for tokens ───────────────────────────────────────
    try:
        client = get_oidc_client()
        token_response = await client.exchange_code(code, _redirect_uri())
    except Exception as exc:
        log.error("SSO: token exchange error: %s", exc)
        return RedirectResponse(
            "/login?error=Could+not+complete+Microsoft+login.+Please+try+again.",
            status_code=302,
        )

    id_token = token_response.get("id_token")
    if not id_token:
        log.error("SSO: no id_token in token response")
        return RedirectResponse(
            "/login?error=Microsoft+did+not+return+an+identity+token.",
            status_code=302,
        )

    # ── Validate id_token ─────────────────────────────────────────────
    try:
        claims = await client.validate_id_token(
            id_token,
            nonce,
            allowed_tenant=settings.SSO_ALLOWED_TENANT or None,
        )
    except ValueError as exc:
        log.warning("SSO: id_token validation failed: %s", exc)
        if "tenant" in str(exc).lower():
            return RedirectResponse(
                "/login?error=You+must+sign+in+with+your+VibeDocs+corporate+account.",
                status_code=302,
            )
        return RedirectResponse(
            "/login?error=Microsoft+issued+an+invalid+token.+Please+try+again.",
            status_code=302,
        )

    # ── Extract user identity ─────────────────────────────────────────
    try:
        info: SSOUserInfo = client.extract_user_info(claims)
    except ValueError as exc:
        log.error("SSO: could not extract user info from claims: %s", exc)
        return RedirectResponse(
            "/login?error=Could+not+read+your+identity+from+Microsoft.",
            status_code=302,
        )

    log.info("SSO: authenticated subject=%s email=%s tenant=%s",
             info.subject, info.email, info.tenant_id)

    # ── Get or create user ────────────────────────────────────────────
    try:
        user = _get_or_create_user(db, info)
    except Exception as exc:
        log.exception("SSO: user provisioning failed for %s: %s", info.email, exc)
        return RedirectResponse(
            "/login?error=Could+not+create+your+account.+Please+contact+IT+support.",
            status_code=302,
        )

    if not user.is_active:
        log.warning("SSO: disabled account attempted login: id=%d", user.id)
        return RedirectResponse(
            "/login?error=Your+account+has+been+disabled.+Contact+IT+support.",
            status_code=302,
        )

    # ── Mint VibeDocs session token ────────────────────────────────────────
    resp = RedirectResponse("/dashboard", status_code=302)
    _set_auth_cookie(resp, user)
    # Clear the now-consumed state cookie
    resp.delete_cookie("sso_state")
    return resp


# ------------------------------------------------------------------ #
# Helpers                                                              #
# ------------------------------------------------------------------ #

def _azure_error_to_message(error: str, description: str) -> str:
    """Map common Azure error codes to user-friendly messages."""
    _MAP = {
        "access_denied":       "Microsoft login was cancelled or access was denied.",
        "invalid_request":     "Invalid SSO request. Please try again.",
        "temporarily_unavailable": "Microsoft login is temporarily unavailable. Try again later.",
        "server_error":        "Microsoft returned a server error. Please try again.",
        "login_required":      "Sign-in is required. Please try again.",
        "consent_required":    "Consent is required to proceed. Contact your IT admin.",
        "interaction_required": "Additional interaction is required. Please try again.",
    }
    return _MAP.get(error, description or "Microsoft login failed. Please try again.")


def _qenc(s: str) -> str:
    """Simple + encoding for short error messages in query strings."""
    return s.replace(" ", "+")
