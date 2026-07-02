"""
Pluggable authentication backend.

Two providers ship today:
  - LocalAuthProvider: username + password against the User table (default)
  - OIDCAuthProvider:  OpenID Connect (VibeDocs Azure AD when ready)

Switching is config-driven. Set AUTH_PROVIDER=oidc in .env plus the
OIDC_* env vars, restart, done. Local accounts keep working as a fallback
during cutover -- LocalAuthProvider stays mounted on /api/auth/local/login
so service accounts and break-glass admins still work.

The OIDC provider here is a SCAFFOLD. It implements the contract and
documents the env vars + redirect flow, but doesn't talk to a live IDP
yet. When VibeDocs SSO is ready, fill in the `exchange_code()` and
`fetch_userinfo()` methods using httpx + the issuer's well-known config.
"""
from __future__ import annotations
import os
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional

from sqlalchemy.orm import Session

from ..models import User, Role


@dataclass
class AuthResult:
    """Returned by all providers on successful authentication."""
    user: User
    provider: str               # "local" / "oidc" / "saml"
    is_new: bool = False        # provisioned just now via JIT


class AuthProvider(ABC):
    """Interface for an auth backend. New providers (SAML, LDAP) implement this."""
    name: str = "abstract"

    @abstractmethod
    def authenticate(self, db: Session, **kwargs) -> Optional[AuthResult]:
        ...


# ============== LOCAL ==============

class LocalAuthProvider(AuthProvider):
    """Username + password against the User table. Always available."""
    name = "local"

    def authenticate(self, db: Session, *, username: str, password: str) -> Optional[AuthResult]:
        from ..auth import verify_password  # late import to avoid cycle
        u = db.query(User).filter(User.username == username).first()
        if not u or not u.is_active:
            return None
        if not verify_password(password, u.hashed_password):
            return None
        return AuthResult(user=u, provider=self.name, is_new=False)


# ============== OIDC (scaffold) ==============

class OIDCAuthProvider(AuthProvider):
    """OpenID Connect provider scaffold.

    Required env vars when activated:
      OIDC_ISSUER              e.g. https://login.microsoftonline.com/<tenant>/v2.0
      OIDC_CLIENT_ID
      OIDC_CLIENT_SECRET
      OIDC_REDIRECT_URI        e.g. https://vapt.internal/api/auth/oidc/callback
      OIDC_SCOPES              default: "openid email profile"
      OIDC_USERNAME_CLAIM      default: "preferred_username"

    Flow (to be wired up):
      1. GET /api/auth/oidc/login
            -> 302 to <issuer>/authorize?client_id=...&response_type=code&...
      2. IDP redirects back to OIDC_REDIRECT_URI with ?code=...
      3. GET /api/auth/oidc/callback exchanges the code for an id_token
            -> validates signature against issuer JWKS
            -> extracts claims, calls self.authenticate(db, claims=...)
      4. authenticate() does JIT user provisioning if the user doesn't exist
            (creates a User row with role=consultant by default; admins later
             promote via the user management UI).
    """
    name = "oidc"

    def authenticate(self, db: Session, *, claims: dict) -> Optional[AuthResult]:
        """JIT-provision or look up a user from validated OIDC claims."""
        username_claim = os.environ.get("OIDC_USERNAME_CLAIM", "preferred_username")
        username = claims.get(username_claim) or claims.get("sub")
        if not username:
            return None

        email = claims.get("email", f"{username}@unknown.local")
        full_name = claims.get("name") or username

        u = db.query(User).filter(User.username == username).first()
        is_new = False
        if not u:
            u = User(
                username=username,
                email=email,
                full_name=full_name,
                hashed_password="!oidc!",  # marker: cannot login via local
                role=Role.consultant,       # default; admin promotes later
                is_active=True,
            )
            db.add(u)
            db.commit()
            db.refresh(u)
            is_new = True
        else:
            # Keep email/name in sync with IDP
            if u.email != email:
                u.email = email
            if u.full_name != full_name:
                u.full_name = full_name
            if not u.is_active:
                return None  # IDP says yes but admin disabled them
            db.commit()
        return AuthResult(user=u, provider=self.name, is_new=is_new)

    @staticmethod
    def get_authorize_url(state: str) -> str:
        """Build the IDP authorize URL. Wired up when OIDC is activated."""
        from urllib.parse import urlencode
        issuer = os.environ["OIDC_ISSUER"].rstrip("/")
        params = {
            "client_id": os.environ["OIDC_CLIENT_ID"],
            "response_type": "code",
            "redirect_uri": os.environ["OIDC_REDIRECT_URI"],
            "scope": os.environ.get("OIDC_SCOPES", "openid email profile"),
            "state": state,
        }
        return f"{issuer}/authorize?{urlencode(params)}"

    # exchange_code() and fetch_jwks() left intentionally unimplemented
    # until the team has the VibeDocs Azure AD tenant id and is ready to wire it.


# ============== Provider registry ==============

PROVIDERS: dict[str, type[AuthProvider]] = {
    "local": LocalAuthProvider,
    "oidc":  OIDCAuthProvider,
}


def get_active_provider() -> AuthProvider:
    """Return the auth provider configured via AUTH_PROVIDER env (default 'local').
    Falls back to local on misconfiguration -- never leave the app un-loggable.
    """
    name = os.environ.get("AUTH_PROVIDER", "local").lower()
    cls = PROVIDERS.get(name, LocalAuthProvider)
    return cls()


def get_local_provider() -> LocalAuthProvider:
    """Local is always available as a break-glass fallback even when OIDC is active."""
    return LocalAuthProvider()
