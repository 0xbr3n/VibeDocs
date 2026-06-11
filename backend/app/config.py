"""Application configuration via environment variables."""
import logging as _logging
import secrets as _secrets
from pathlib import Path
from pydantic_settings import BaseSettings


_WEAK_KEYS = frozenset({
    "",
    "change_me",
    "secret",
    "please_set_a_long_random_secret_in_.env",
    "your-secret-key",
    "supersecret",
    "dev",
})


def _require_secret_key() -> str:
    """Return SECRET_KEY from the environment, or a per-process random fallback.

    The fallback is intentionally ephemeral: every restart invalidates all
    existing JWT sessions. That is acceptable because tokens are short-lived
    (8 h) and users will be prompted to log in again.

    For production: always set SECRET_KEY in the environment or .env file to
    a cryptographically random value (e.g. ``openssl rand -hex 32``).
    Setting it ensures sessions survive container restarts without re-login.
    """
    import os
    key = os.environ.get("SECRET_KEY", "").strip()
    if key.lower() in _WEAK_KEYS or len(key) < 32:
        key = _secrets.token_hex(32)
        _logging.getLogger(__name__).warning(
            "SECRET_KEY not set, uses a known placeholder, or is too short (<32 chars). "
            "A random per-process key has been generated. "
            "All sessions will be invalidated on restart. "
            "Set SECRET_KEY to a random hex string (openssl rand -hex 32) for persistent sessions."
        )
    return key


class Settings(BaseSettings):
    # Database
    DATABASE_URL: str = "postgresql+psycopg2://vapt:vapt@localhost:5432/vapt_reporter"

    # Auth — SECRET_KEY must be set via env var for production deployments.
    # See _require_secret_key() for the fallback behaviour.
    SECRET_KEY: str = ""  # populated via validator / env override
    # Symmetric default. The allow-list inside auth.py is locked to
    # exactly this value — alg=none / RS256 / HS-anything-else tokens
    # are rejected even if the header claims them. If you want RS256
    # (asymmetric, public-key verifies / private-key signs), set this
    # to "RS256" AND populate RS256_PRIVATE_KEY_PATH +
    # RS256_PUBLIC_KEY_PATH below.
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 480
    # JWT issuer claim. Tokens missing or mismatching `iss` are
    # rejected on decode — defeats cross-deployment token replay if
    # the same SECRET_KEY ever gets reused.
    JWT_ISSUER: str = "vapt-reporter"
    # Optional RS256 key paths. When ALGORITHM == "RS256" both must
    # point at PEM-encoded keys readable by the app process.
    RS256_PRIVATE_KEY_PATH: str = ""
    RS256_PUBLIC_KEY_PATH:  str = ""

    # Paths
    UPLOAD_DIR: str = "/data/uploads"
    REPORT_DIR: str = "/data/reports"
    TEMPLATE_DIR: str = "/app/word_templates"
    # Folder holding the VibeDocs Excel + Word *tracking-list* templates
    # (one per VAPT type — Web / API / Cloud / Network / Mobile / SCR /
    # Thick Client …). The Risk-Register export uses the matching file
    # as a layout source so colours, sheets, and formulae survive.
    # Default points at the repo-bundled `report-templates/` directory.
    TRACKER_TEMPLATES_DIR: str = str(
        Path(__file__).resolve().parent.parent.parent / "report-templates"
    )

    # Server
    ALLOWED_HOSTS: str = "*"
    ENV: str = "production"
    # Canonical public URL used to build password-reset and unlock links in
    # emails. Set to the actual domain (e.g. https://vapt.example.com) so
    # the reset URL is never derived from the client's Host header (which an
    # attacker can spoof). When blank, the app falls back to the request URL
    # — acceptable on internal-only deployments where every client has the
    # same Host, but set this for any public-facing deploy.
    SITE_URL: str = ""

    # ── Azure AD / OIDC Single Sign-On ──────────────────────────────────────
    # Set SSO_ENABLED=true to show the "Sign in with Microsoft" button on
    # the login page.  All AZURE_* fields must be set when SSO_ENABLED=true.
    SSO_ENABLED: bool = False
    # Azure portal → Microsoft Entra ID → Overview → Tenant ID (UUID)
    AZURE_TENANT_ID: str = ""
    # App Registration → Application (client) ID
    AZURE_CLIENT_ID: str = ""
    # App Registration → Certificates & secrets → Client secret value
    AZURE_CLIENT_SECRET: str = ""
    # Must exactly match a Redirect URI registered in the Azure App Registration.
    # Example: https://vapt.vibedocs.internal/auth/sso/callback
    SSO_REDIRECT_URI: str = ""
    # Restrict sign-in to this tenant only (strongly recommended — set this to
    # your AZURE_TENANT_ID).  Empty = accept any tenant (not safe for prod).
    SSO_ALLOWED_TENANT: str = ""
    # Role assigned to new SSO users when no Azure group matches SSO_GROUP_ROLE_MAP.
    SSO_DEFAULT_ROLE: str = "consultant"
    # JSON mapping of Azure AD Group object-ID strings → VibeDocs role names.
    # Example: '{"aaaa-bbbb-cccc": "admin", "dddd-eeee-ffff": "senior"}'
    SSO_GROUP_ROLE_MAP: str = "{}"
    # When True the local username+password form is hidden on the login page;
    # SSO becomes the primary login path.  Admins can still reach the local form
    # via /login?local=1 for break-glass access.
    SSO_DISABLE_LOCAL_LOGIN: bool = False

    # ── Local / Standalone (no-login) mode ──────────────────────────────────
    # When True, the root "/" landing page offers a "Local / Standalone
    # (no login)" choice that mints a session for a built-in singleton
    # admin user with full, approval-free access. Intended for the Kali
    # VMware image shipped to each consultant — every consultant runs their
    # own copy, so there is no multi-user / approval concept locally.
    #
    # Selector logic (see routers/ui.py root()):
    #   LOCAL_MODE_ENABLED and SSO_ENABLED  -> show the two-choice selector
    #   only LOCAL_MODE_ENABLED             -> go straight into local mode
    #   only SSO_ENABLED                    -> go straight to /login
    # Shipped default is local-only (SSO_ENABLED defaults False), so the
    # Kali image boots straight into the report generator with no login.
    LOCAL_MODE_ENABLED: bool = True
    # Username of the built-in singleton local user. Created on first
    # local-mode entry with role=admin so every approval gate is bypassed.
    LOCAL_MODE_USERNAME: str = "local"

    # Data root (used by services that need write-able scratch space, e.g. dev email outbox)
    DATA_DIR: str = "/data"

    # Outbound email (used by password reset). Leave SMTP_HOST blank in
    # development — emails will be persisted to DATA_DIR/outgoing-mail/ as
    # .eml files so you can see the reset link without a real mail server.
    SMTP_HOST: str = ""
    SMTP_PORT: int = 587
    SMTP_USER: str = ""
    SMTP_PASS: str = ""
    SMTP_FROM: str = "vapt-reporter@localhost"

    class Config:
        env_file = ".env"
        case_sensitive = True

    @property
    def allowed_hosts_list(self) -> list[str]:
        return [h.strip() for h in self.ALLOWED_HOSTS.split(",") if h.strip()]


settings = Settings()

# Resolve SECRET_KEY: use env value if valid, otherwise generate a random one.
# Check the full weak-key set here (not just empty / "change_me") so that any
# placeholder in _WEAK_KEYS triggers the per-process random fallback + warning.
if settings.SECRET_KEY.strip().lower() in _WEAK_KEYS or len(settings.SECRET_KEY.strip()) < 32:
    settings.SECRET_KEY = _require_secret_key()

# Ensure directories exist at import time
for p in (settings.UPLOAD_DIR, settings.REPORT_DIR, settings.TEMPLATE_DIR):
    Path(p).mkdir(parents=True, exist_ok=True)
