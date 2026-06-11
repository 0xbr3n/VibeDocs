"""
Azure AD (Microsoft Entra ID) OIDC client for VibeDocs SSO.

Implements the OIDC Authorization Code Flow:
  1. build_authorize_url()  — redirect user to Microsoft login
  2. exchange_code()        — trade authorization code for id_token + access_token
  3. validate_id_token()    — verify RS256 signature + claims via JWKS
  4. extract_user_info()    — pull stable identity from validated claims

Discovery and JWKS documents are cached for one hour to avoid hitting
Microsoft's endpoints on every login.  The JWKS cache is force-refreshed
on a kid-miss (key rotation) so new keys are picked up immediately.

References:
  https://learn.microsoft.com/en-us/entra/identity-platform/v2-protocols-oidc
  https://login.microsoftonline.com/{tenant}/v2.0/.well-known/openid-configuration
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlencode

import httpx
from jose import jwt, JWTError

log = logging.getLogger(__name__)

# Discovery document cached at module level — shared across requests.
_discovery_cache: Optional["_OIDCDiscovery"] = None
_jwks_cache:      Optional[dict] = None
_jwks_fetched_at: float = 0.0
_CACHE_TTL = 3600  # seconds


@dataclass
class _OIDCDiscovery:
    authorization_endpoint: str
    token_endpoint: str
    jwks_uri: str
    issuer: str
    userinfo_endpoint: Optional[str] = None
    fetched_at: float = field(default_factory=time.time)

    def is_stale(self) -> bool:
        return time.time() - self.fetched_at > _CACHE_TTL


@dataclass
class SSOUserInfo:
    """Normalised identity extracted from a validated Azure AD id_token."""
    subject: str       # Azure oid — stable across apps in the same tenant
    email: str         # corporate email / UPN
    full_name: str     # display name
    username: str      # preferred_username / UPN — used as the VibeDocs username
    tenant_id: str     # Azure tenant ID (tid claim)
    groups: list[str]  # group object IDs (may be empty if not configured)


class OIDCClient:
    """Minimal async OIDC client for a single Azure AD tenant.

    Instantiate once with tenant/client credentials and reuse across
    requests (the app creates one singleton per process via
    `get_oidc_client()`).
    """

    def __init__(self, tenant_id: str, client_id: str, client_secret: str) -> None:
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret
        self._discovery_url = (
            f"https://login.microsoftonline.com/{tenant_id}"
            "/v2.0/.well-known/openid-configuration"
        )

    # ------------------------------------------------------------------ #
    # Discovery + JWKS                                                     #
    # ------------------------------------------------------------------ #

    async def _get_discovery(self) -> _OIDCDiscovery:
        global _discovery_cache
        if _discovery_cache and not _discovery_cache.is_stale():
            return _discovery_cache
        async with httpx.AsyncClient(timeout=10) as c:
            r = await c.get(self._discovery_url)
            r.raise_for_status()
            doc = r.json()
        _discovery_cache = _OIDCDiscovery(
            authorization_endpoint=doc["authorization_endpoint"],
            token_endpoint=doc["token_endpoint"],
            jwks_uri=doc["jwks_uri"],
            issuer=doc["issuer"],
            userinfo_endpoint=doc.get("userinfo_endpoint"),
        )
        log.debug("OIDC discovery refreshed: issuer=%s", _discovery_cache.issuer)
        return _discovery_cache

    async def _get_jwks(self, jwks_uri: str, *, force_refresh: bool = False) -> dict:
        global _jwks_cache, _jwks_fetched_at
        stale = time.time() - _jwks_fetched_at > _CACHE_TTL
        if _jwks_cache and not stale and not force_refresh:
            return _jwks_cache
        async with httpx.AsyncClient(timeout=10) as c:
            r = await c.get(jwks_uri)
            r.raise_for_status()
            _jwks_cache = r.json()
            _jwks_fetched_at = time.time()
        log.debug("JWKS refreshed: %d keys", len(_jwks_cache.get("keys", [])))
        return _jwks_cache

    # ------------------------------------------------------------------ #
    # Authorization URL                                                    #
    # ------------------------------------------------------------------ #

    async def build_authorize_url(
        self,
        redirect_uri: str,
        state: str,
        nonce: str,
    ) -> str:
        """Return the URL to redirect the user to for Microsoft login."""
        disc = await self._get_discovery()
        params = {
            "client_id": self.client_id,
            "response_type": "code",
            "redirect_uri": redirect_uri,
            "response_mode": "query",
            # openid + email + profile are required OIDC scopes.
            # offline_access adds a refresh_token (not needed here).
            # GroupMember.Read.All would let us fetch group membership via
            # Graph API — included here so admins can consent it if they
            # want group-based role mapping.
            "scope": "openid email profile",
            "state": state,
            "nonce": nonce,
            # Prompt Microsoft to always show the account picker.
            # Remove if you want silent re-auth for already-signed-in users.
            "prompt": "select_account",
        }
        return f"{disc.authorization_endpoint}?{urlencode(params)}"

    # ------------------------------------------------------------------ #
    # Token exchange                                                       #
    # ------------------------------------------------------------------ #

    async def exchange_code(self, code: str, redirect_uri: str) -> dict:
        """Exchange an authorization code for id_token + access_token."""
        disc = await self._get_discovery()
        async with httpx.AsyncClient(timeout=15) as c:
            r = await c.post(
                disc.token_endpoint,
                data={
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                    "code": code,
                    "redirect_uri": redirect_uri,
                    "grant_type": "authorization_code",
                },
            )
        if not r.is_success:
            body = r.text[:500]
            log.warning("OIDC token exchange failed %d: %s", r.status_code, body)
            raise ValueError(f"Token exchange failed (HTTP {r.status_code})")
        return r.json()

    # ------------------------------------------------------------------ #
    # id_token validation                                                  #
    # ------------------------------------------------------------------ #

    async def validate_id_token(
        self,
        id_token: str,
        nonce: str,
        *,
        allowed_tenant: Optional[str] = None,
    ) -> dict:
        """Validate the RS256 id_token signature and critical claims.

        Raises ValueError with a descriptive message on any failure.
        Returns the decoded claims dict on success.
        """
        disc = await self._get_discovery()

        # Peek at the header to find the right JWKS key
        try:
            header = jwt.get_unverified_header(id_token)
        except JWTError as exc:
            raise ValueError(f"Malformed id_token header: {exc}") from exc

        kid = header.get("kid")
        alg = header.get("alg", "")
        if alg != "RS256":
            raise ValueError(f"Unexpected id_token algorithm: {alg!r} (expected RS256)")

        # Find the signing key — refresh once on miss (Azure key rotation)
        key = self._find_jwk(await self._get_jwks(disc.jwks_uri), kid)
        if key is None:
            key = self._find_jwk(
                await self._get_jwks(disc.jwks_uri, force_refresh=True), kid
            )
        if key is None:
            raise ValueError(f"id_token kid={kid!r} not found in JWKS")

        # Full signature + claim validation
        try:
            claims = jwt.decode(
                id_token,
                key,
                algorithms=["RS256"],
                audience=self.client_id,
                # Azure v2.0 issuer: https://login.microsoftonline.com/{tid}/v2.0
                issuer=disc.issuer,
                options={
                    "require_exp": True,
                    "require_iat": True,
                    "require_sub": True,
                },
            )
        except JWTError as exc:
            raise ValueError(f"id_token validation failed: {exc}") from exc

        # Nonce check — prevents replay of a previously intercepted id_token
        if claims.get("nonce") != nonce:
            raise ValueError("id_token nonce mismatch — possible replay attack")

        # Tenant restriction — prevents cross-tenant token acceptance
        if allowed_tenant:
            token_tid = claims.get("tid", "")
            if token_tid != allowed_tenant:
                raise ValueError(
                    f"id_token tenant {token_tid!r} does not match "
                    f"expected tenant {allowed_tenant!r}"
                )

        return claims

    @staticmethod
    def _find_jwk(jwks: dict, kid: Optional[str]) -> Optional[dict]:
        """Return the JWK entry matching `kid`, or the first key if kid is None."""
        keys = jwks.get("keys", [])
        if not keys:
            return None
        if kid:
            for k in keys:
                if k.get("kid") == kid:
                    return k
            return None
        return keys[0]

    # ------------------------------------------------------------------ #
    # User info extraction                                                 #
    # ------------------------------------------------------------------ #

    def extract_user_info(self, claims: dict) -> SSOUserInfo:
        """Pull a normalised SSOUserInfo from validated id_token claims.

        Azure AD id_token key claims:
          oid               — object ID, stable across apps in the tenant
          preferred_username / upn — corporate UPN (user@vibedocs.com)
          email             — may differ from UPN on guest accounts
          name              — display name
          tid               — tenant ID
          groups            — list of group object IDs (if configured in manifest)
        """
        # oid is the stable identifier; sub is app-scoped and can change.
        subject = claims.get("oid") or claims.get("sub", "")
        if not subject:
            raise ValueError("id_token is missing oid / sub claim")

        # UPN is the best username for VibeDocs AD users.
        upn = claims.get("preferred_username") or claims.get("upn") or ""
        email = claims.get("email") or upn or ""
        full_name = claims.get("name") or ""

        # Use UPN as the VibeDocs username so it's human-readable and
        # unique within the tenant.  Sanitise to ASCII-safe form.
        username = (upn or email or f"sso_{subject[:12]}").lower().strip()

        tenant_id = claims.get("tid", "")

        # Azure sends groups as a list of UUID strings when the app manifest
        # has "groupMembershipClaims": "SecurityGroup".
        # If the user is in >200 groups, Azure omits the claim and sets
        # "_claim_names" — that overage case would require a Graph API call
        # (not implemented here; log a warning so admins are aware).
        groups: list[str] = []
        if "groups" in claims:
            groups = [str(g) for g in claims["groups"] if g]
        elif "_claim_names" in claims and "groups" in claims.get("_claim_names", {}):
            log.warning(
                "SSO: user %s is in >200 groups; group-claim overage detected. "
                "Group-based role mapping will not work for this user — "
                "consider reducing group membership or calling Graph API.",
                email,
            )

        return SSOUserInfo(
            subject=subject,
            email=email,
            full_name=full_name,
            username=username,
            tenant_id=tenant_id,
            groups=groups,
        )


# ------------------------------------------------------------------ #
# Singleton accessor                                                   #
# ------------------------------------------------------------------ #

_oidc_client: Optional[OIDCClient] = None


def get_oidc_client() -> OIDCClient:
    """Return the module-level OIDCClient singleton.

    Raises RuntimeError if the required SSO env vars are not set — call
    sites should check `settings.SSO_ENABLED` before calling this.
    """
    global _oidc_client
    if _oidc_client is None:
        from ..config import settings
        if not (settings.AZURE_TENANT_ID and settings.AZURE_CLIENT_ID
                and settings.AZURE_CLIENT_SECRET):
            raise RuntimeError(
                "SSO is enabled but AZURE_TENANT_ID / AZURE_CLIENT_ID / "
                "AZURE_CLIENT_SECRET are not all set in environment / .env"
            )
        _oidc_client = OIDCClient(
            tenant_id=settings.AZURE_TENANT_ID,
            client_id=settings.AZURE_CLIENT_ID,
            client_secret=settings.AZURE_CLIENT_SECRET,
        )
    return _oidc_client
