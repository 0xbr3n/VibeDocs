"""FastAPI app entry. Wires routers, static, templates, DB init."""
from pathlib import Path
from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from fastapi.exceptions import HTTPException

from .config import settings
from .database import Base, engine
from .routers import (
    auth, templates as templates_router, findings, projects, reports,
    parsers, imports, permissions, ui,
    sections, snippets, standards, custom_templates, cvss,
    twofa, knowledgebase, postman, source_code, custom_template_editor,
    collab, password_reset, engagement_docs, tracker, admin_email,
    notifications, notes, toolkit, admin_trackers, admin_panel, dashboard,
    sso,
)

app = FastAPI(
    title="VAPT Reporter",
    description="Internal VAPT report generator with findings library, "
                "Nessus/Nmap import, CVSS 4.0 scoring, and DOCX/PDF output.",
    version="0.1.0",
)

# CORS - tighten this in production. By default allow same-host.
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_hosts_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security response headers applied to every response. These defend against
# common browser-level attacks: MIME-sniffing (nosniff), clickjacking (DENY),
# and cross-site leaks (no-referrer on navigations out of the app).
#
# CSP nonce approach: a fresh random nonce is generated per request and stored
# on request.state.csp_nonce so Jinja2 templates can include it on every
# <script> block. CSP Level 3 browsers ignore 'unsafe-inline' for <script>
# elements when a nonce is present, giving XSS protection for injected script
# blocks. Inline event handlers (onclick=...) still require 'unsafe-inline';
# migrating those to addEventListener calls is a separate TODO.
import secrets
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # Generate nonce BEFORE call_next so route handlers and Jinja2
        # templates can read request.state.csp_nonce during rendering.
        nonce = secrets.token_urlsafe(16)
        request.state.csp_nonce = nonce
        # Expose deployment-mode flags to every Jinja2 template (base.html
        # reads request.state.* directly, the same way it reads csp_nonce).
        # The authoritative per-session signal for "this is the local user"
        # is still user.is_local in the template context; these flags drive
        # the landing-page selector and pure-config decisions.
        request.state.local_mode_enabled = settings.LOCAL_MODE_ENABLED
        request.state.sso_enabled = settings.SSO_ENABLED
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Permissions-Policy"] = (
            "camera=(), microphone=(), geolocation=(), payment=(), "
            "usb=(), magnetometer=(), accelerometer=(), gyroscope=()"
        )
        if "Content-Security-Policy" not in response.headers:
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; "
                "script-src 'self' 'unsafe-inline' "
                    "https://cdn.quilljs.com "
                    "https://cdn.jsdelivr.net; "
                "style-src 'self' 'unsafe-inline' "
                    "https://cdn.quilljs.com "
                    "https://fonts.googleapis.com; "
                "font-src 'self' data: "
                    "https://fonts.gstatic.com; "
                "img-src 'self' data: blob:; "
                "connect-src 'self' ws: wss:; "
                "frame-src 'self' blob:; "
                "object-src 'self' blob:;"
            )
        return response

app.add_middleware(SecurityHeadersMiddleware)

# IP / VPN whitelist. Driven by env var ALLOWED_IPS (comma-separated
# IPs / CIDRs). Empty disables the check, so this middleware is a no-op
# in the default deployment. See services/ip_whitelist.py for the
# bypass-paths + log-only knobs.
import os as _os
from .services.ip_whitelist import IPWhitelistMiddleware
app.add_middleware(
    IPWhitelistMiddleware,
    allowed=_os.environ.get("ALLOWED_IPS", ""),
    bypass_paths=[p.strip() for p in
                  _os.environ.get("ALLOWED_IPS_BYPASS_PATHS", "/health,/static").split(",")
                  if p.strip()],
    log_only=_os.environ.get("ALLOWED_IPS_LOG_ONLY", "").lower() in ("1","true","yes"),
)

# Auto-create tables on first start. Switch to Alembic for production migrations.
Base.metadata.create_all(bind=engine)


def _light_migrate() -> None:
    """Idempotent column-adds for evolving models on an existing database.

    `Base.metadata.create_all` only creates *missing tables* — it never
    ALTERs existing ones. We deliberately stay schemaless on JSON columns
    where we can, but a few new features (review workflow, per-user
    background image) genuinely need new columns. We add them here at
    startup with `ADD COLUMN IF NOT EXISTS` so users can upgrade in
    place without running migrations manually.
    """
    from sqlalchemy import text
    STMTS = [
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS phone VARCHAR(64)",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS background_path VARCHAR(500)",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS notifications_read_at TIMESTAMP",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS dismissed_notifications JSON DEFAULT '[]'::json",
        "ALTER TABLE report_versions ADD COLUMN IF NOT EXISTS review_status VARCHAR(32) DEFAULT 'draft'",
        # Backfill rows that were added before the default was set.
        "UPDATE report_versions SET review_status = 'draft' WHERE review_status IS NULL",
        "ALTER TABLE report_versions ADD COLUMN IF NOT EXISTS reviewer_id INTEGER REFERENCES users(id)",
        "ALTER TABLE report_versions ADD COLUMN IF NOT EXISTS submitted_for_review_at TIMESTAMP",
        "ALTER TABLE report_versions ADD COLUMN IF NOT EXISTS review_decision_at TIMESTAMP",
        "ALTER TABLE report_versions ADD COLUMN IF NOT EXISTS review_notes TEXT",
        # New CWE column on report findings. Seeded from the library
        # finding on add, but the consultant can override per-report.
        "ALTER TABLE report_findings ADD COLUMN IF NOT EXISTS cwe VARCHAR(255)",
        "ALTER TABLE report_findings ADD COLUMN IF NOT EXISTS client_statement_date VARCHAR(32)",
        "ALTER TABLE report_findings ADD COLUMN IF NOT EXISTS client_statements JSON DEFAULT '[]'::json",
        # Preserve the admin's original filename when they replace a
        # master template's .docx via the admin UI. The hashed
        # `web_vapt__<uuid>.docx` on disk is opaque; this column lets
        # the table show "MyCorpWebVAPT_v3.docx" so the admin can see
        # what they uploaded at a glance.
        "ALTER TABLE report_templates ADD COLUMN IF NOT EXISTS original_filename VARCHAR(500)",
        # Per-tasking Excel tracker override. NULL = legacy hardcoded
        # mapping in `tracker_templates.TRACKER_TYPE_BY_CODE` wins.
        # Editable from the Tasking Assignments admin tab.
        "ALTER TABLE report_templates ADD COLUMN IF NOT EXISTS tracker_filename VARCHAR(500)",
        # Widen `finding_library.cwe` from VARCHAR(64) so the
        # canonicalised "CWE-XXX (Long Human Readable Name)" form
        # fits. Before this, every seed boot logged a
        # `StringDataRightTruncation` warning and the human-name
        # backfill silently no-op'd.
        "ALTER TABLE finding_library ALTER COLUMN cwe TYPE VARCHAR(255)",
        # Admin-controlled forced 2FA. `totp_required=True` means the
        # next login routes the user to mandatory enrollment until
        # they set up an authenticator. Default False on existing
        # rows so the feature is opt-in per user.
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_required BOOLEAN DEFAULT FALSE NOT NULL",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_required_by_id INTEGER REFERENCES users(id)",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_required_at TIMESTAMP",
        # Master switch for collaboration / notification emails. New
        # users default to opted-in. Security emails (password reset,
        # password changed) bypass this flag — see `services.notifier`.
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS notifications_email_enabled BOOLEAN DEFAULT TRUE NOT NULL",
        # Per-finding file attachments (Excel workbooks produced by
        # the Infra Scan Pipeline). NULL → treated as empty list by
        # the SQLAlchemy `default=list` on the column declaration.
        "ALTER TABLE report_findings ADD COLUMN IF NOT EXISTS attachments JSON DEFAULT '[]'::json",
        # Per-user toggle for the floating VibeDocs scratchpad notes
        # widget at bottom-right. New users default to having it on.
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS notes_widget_enabled BOOLEAN DEFAULT TRUE NOT NULL",
        # Per-user dashboard widget selection (JSON list of widget keys).
        # NULL => default set (all widgets). Editable from the
        # dashboard "Customize" panel.
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS dashboard_widgets JSON",
        # Widen `report_findings.affected_asset` from VARCHAR(500)
        # to TEXT. The Infra Scan Pipeline's grouped output ("a
        # comma-joined IP list per finding") routinely exceeds the
        # 500-char limit (60+ hosts on a single ICMP-timestamp /
        # speculative-execution finding). The pipeline's whole
        # value-prop is "one finding per (name, port) with all
        # affected IPs in one cell" — capping the cell defeats it.
        "ALTER TABLE report_findings ALTER COLUMN affected_asset TYPE TEXT",
        # Account lockout — consecutive failed password attempts + lock timestamp.
        # Existing rows get 0 attempts and no lock (NULL) by default.
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS failed_login_attempts INTEGER DEFAULT 0 NOT NULL",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS locked_at TIMESTAMP",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS lock_reason VARCHAR(64)",
        # Azure AD / OIDC SSO identity columns.  NULL on local-auth accounts.
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS sso_provider VARCHAR(32)",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS sso_subject VARCHAR(128)",
        # Composite index for fast JIT-provisioning lookup on SSO callback.
        "CREATE INDEX IF NOT EXISTS ix_users_sso ON users (sso_provider, sso_subject) WHERE sso_provider IS NOT NULL",
        # Local/standalone-mode singleton user marker. TRUE only for the
        # built-in no-login account; FALSE for SSO and password users.
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS is_local BOOLEAN DEFAULT FALSE NOT NULL",
        # Account unlock tokens — emailed by admins to let locked users
        # self-service unlock without a password reset.
        """CREATE TABLE IF NOT EXISTS account_unlock_tokens (
            id SERIAL PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id),
            token_hash VARCHAR(255) NOT NULL,
            expires_at TIMESTAMP NOT NULL,
            used_at TIMESTAMP,
            created_by_id INTEGER REFERENCES users(id),
            created_at TIMESTAMP DEFAULT NOW() NOT NULL
        )""",
    ]
    with engine.begin() as conn:
        for stmt in STMTS:
            try:
                conn.execute(text(stmt))
            except Exception as e:                  # pragma: no cover
                # Log and continue — never block startup on a non-fatal ALTER.
                import logging
                logging.getLogger(__name__).warning(
                    "_light_migrate: %s -> %s", stmt, e
                )


_light_migrate()


def _seed_email_templates() -> None:
    """Make sure every email template key from services.email_templates
    has a row in the DB so admins can edit it via the UI. Idempotent —
    keys already present (likely already edited by an admin) are left
    alone."""
    from .database import SessionLocal
    from .services.email_templates import seed_default_email_templates
    db = SessionLocal()
    try:
        seed_default_email_templates(db)
    except Exception as e:                          # pragma: no cover
        import logging
        logging.getLogger(__name__).warning("email-template seed skipped: %s", e)
    finally:
        db.close()


_seed_email_templates()


def _backfill_library_cwe_names() -> None:
    """Idempotently enrich every FindingLibrary row whose `cwe` is a
    bare "CWE-XXX" id with the matching human name from the central
    [cwe_names.CWE_NAMES](services/cwe_names.py) catalogue. Runs once
    per boot and is a no-op after the first successful pass."""
    from .database import SessionLocal
    from .services.cwe_names import backfill_library_cwes
    db = SessionLocal()
    try:
        n = backfill_library_cwes(db)
        if n:
            import logging
            logging.getLogger(__name__).info(
                "CWE backfill: enriched %d FindingLibrary row(s) with descriptive names", n)
    except Exception as e:                              # pragma: no cover
        import logging
        logging.getLogger(__name__).warning("CWE backfill skipped: %s", e)
    finally:
        db.close()


_backfill_library_cwe_names()


def _seed_catalogue_and_backfill_owasp() -> None:
    """Boot-time idempotent reconcile of the FindingLibrary table:

      1. Insert any catalogue entries from `seed_findings_v2._findings_catalogue()`
         whose title doesn't already exist (covers new web/api/infra
         findings shipped in a release without requiring an admin to
         hit `POST /api/findings/seed-defaults`).
      2. Tag every row with its OWASP Top 10 2025 category. Rows
         already carrying "A0X:2025" are skipped. Rows whose CWE /
         title don't match any inference rule are left untouched so
         the consultant can hand-edit them through the library admin
         UI.

    Both passes are no-ops on the next boot once the DB is in sync.
    """
    from .database import SessionLocal
    from .seed_findings_v2 import seed_default_findings
    db = SessionLocal()
    try:
        summary = seed_default_findings(db)
        import logging
        log = logging.getLogger(__name__)
        if summary.get("created"):
            log.info(
                "Library seed: created %d new finding(s)", summary["created"])
        if summary.get("owasp_2025_backfilled"):
            log.info(
                "OWASP-2025 backfill: tagged %d row(s)",
                summary["owasp_2025_backfilled"],
            )
    except Exception as e:                              # pragma: no cover
        import logging
        logging.getLogger(__name__).warning(
            "Library seed / OWASP backfill skipped: %s", e)
        db.rollback()
    finally:
        db.close()


_seed_catalogue_and_backfill_owasp()


def _reword_library_recommendations() -> None:
    """Boot-time idempotent pass: rephrase every FindingLibrary remediation so
    it opens with "It is recommended to ...". Runs AFTER the catalogue seed so
    freshly-inserted findings are normalised too. No-op on subsequent boots
    (format_recommendation skips text already in the desired form).
    """
    from .database import SessionLocal
    from .models import FindingLibrary
    from .services.recommendation_phrasing import format_recommendation
    db = SessionLocal()
    try:
        rows = db.query(FindingLibrary).all()
        changed = 0
        for r in rows:
            new = format_recommendation(r.remediation or "")
            if new != (r.remediation or ""):
                r.remediation = new
                changed += 1
        if changed:
            db.commit()
            import logging
            logging.getLogger(__name__).info(
                "Recommendation rephrase: updated %d FindingLibrary row(s)", changed)
    except Exception as e:                                  # pragma: no cover
        import logging
        logging.getLogger(__name__).warning(
            "Recommendation rephrase skipped: %s", e)
        db.rollback()
    finally:
        db.close()


_reword_library_recommendations()


def _regenerate_word_templates() -> None:
    """Regenerate every default master Word template from its VibeDocs
    source. Runs once per boot — idempotent and cheap because the
    transformer is deterministic and only processes a handful of
    files.

    Why at boot: when this code first ships, deployments will already
    have `word_templates/*_template.docx` files from the prior simple-
    builder runs. Without this hook, the report generator would keep
    serving the old layout because `gen_word_templates.main()` is a
    one-off CLI step that nobody re-runs. By calling it on every
    start with `force_overwrite_simple=True`, existing deployments
    auto-upgrade the moment they pull this commit.

    Admin-uploaded replacements (via `POST /api/templates/{id}/replace-docx`)
    live under UUID-stamped filenames and are NOT touched by this
    pass — the DB row's `docx_filename` points at the admin copy,
    so the canonical `<code>_template.docx` is unused for that
    template and can be safely regenerated.
    """
    import logging
    log = logging.getLogger(__name__)

    # Cross-process boot lock. The Dockerfile runs `uvicorn ... --workers 2`,
    # so BOTH worker processes import this module and would otherwise run
    # the regeneration concurrently — racing on the shared output files
    # and the watermark-strip temp files. We take a non-blocking flock:
    # the worker that wins regenerates; the worker that loses skips
    # entirely (the winner produces the canonical files for everyone).
    # If flock is unavailable (non-POSIX) we fall back to just running
    # it — the watermark stripper now uses unique temp names so the
    # worst case is duplicated work, not a crash.
    import os
    import tempfile
    lock_path = os.path.join(tempfile.gettempdir(), "vapt_wordtpl_regen.lock")
    lock_fh = None
    try:
        import fcntl
        lock_fh = open(lock_path, "w")
        try:
            fcntl.flock(lock_fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except (BlockingIOError, OSError):
            # Another worker holds the lock and is regenerating. Skip —
            # by the time requests are served the files will be fresh.
            log.info(
                "Word-template regen: another worker holds the boot lock; "
                "skipping in this process")
            lock_fh.close()
            return
    except ImportError:
        # No fcntl (e.g. Windows dev host) — proceed unguarded. Unique
        # temp names in the stripper keep this safe, just not deduped.
        lock_fh = None

    try:
        from .gen_word_templates import main as _regen
        summary = _regen(force_overwrite_simple=True)
        vibedocs = sum(1 for v in summary.values() if v.startswith("vibedocs:"))
        simple   = sum(1 for v in summary.values() if v == "simple")
        log.info(
            "Word-template regen: %d VibeDocs-derived, %d simple-fallback",
            vibedocs, simple,
        )
    except Exception as e:                                  # pragma: no cover
        log.warning("Word-template regen skipped: %s", e)
    finally:
        # Hold the lock until regeneration is fully done, THEN release —
        # so a worker that skipped never serves a request before the
        # files exist (it returned early above; the winner finishes here).
        if lock_fh is not None:
            try:
                import fcntl
                fcntl.flock(lock_fh.fileno(), fcntl.LOCK_UN)
            except Exception:
                pass
            lock_fh.close()


_regenerate_word_templates()


def _ensure_report_template_rows() -> None:
    """Idempotently reconcile the `report_templates` table with the
    bootstrap list in `seed_findings_v2.TEMPLATE_BOOTSTRAP`. Runs once
    per boot.

    Why at boot: when we expand the list of supported VAPT types
    (Wi-Fi / Kiosk / OT / SCR / Cloud), existing DB rows were seeded
    `is_active=False` so they never appear in the template picker.
    This hook flips the active flag on next boot so the dropdown
    immediately shows every supported type — no manual re-seed step
    required. New rows are created for any code that doesn't exist
    yet. Admin-uploaded `docx_filename` overrides are preserved.
    """
    try:
        from .seed_findings_v2 import ensure_templates_at_boot
        ensure_templates_at_boot()
    except Exception as e:                                  # pragma: no cover
        import logging
        logging.getLogger(__name__).warning(
            "Report-template bootstrap skipped: %s", e,
        )


_ensure_report_template_rows()


def _inject_templates_at_boot() -> None:
    """Retroactively apply Jinja2 injection to any .docx in TEMPLATE_DIR
    and UPLOAD_DIR/custom_templates/** that don't yet have {{ expressions }}
    in docProps/custom.xml.

    Why at boot:
    - Admin-uploaded templates from before the per-upload injection was
      introduced (session 2026-05-19 150000) still have static placeholder
      text ("Agency Full Name", "XXX Application") in custom.xml.
    - Custom templates uploaded by consultants via /api/projects/{pid}/custom-template
      or /api/reports/{rid}/custom-template were never run through
      process_template() — they kept whatever static values the uploader
      baked in, so report-details changes had zero effect on generated output.
    - Without Jinja2 in custom.xml, `_inject_custom_xml_values` in the
      docx_generator is a no-op, so LibreOffice resolves those DOCPROPERTY
      fields with the static values during DOCX→PDF conversion.

    Idempotent: templates that already have {{ are skipped. Best-effort:
    failures are logged but never block the server from starting.
    """
    import logging
    log = logging.getLogger(__name__)
    try:
        from pathlib import Path as _Path
        from .config import settings as _settings
        from .tools.inject_jinja2_into_templates import inject_all_in_dir

        total_injected: list[str] = []

        # 1. Canonical / admin-uploaded master templates
        tdir = _Path(_settings.TEMPLATE_DIR)
        summary = inject_all_in_dir(tdir)
        injected = [k for k, v in summary.items() if v == 'injected']
        total_injected.extend(injected)

        # 2. Per-project / per-report consultant custom templates stored
        #    under UPLOAD_DIR/custom_templates/{scope}/{id}/*.docx
        upload_custom_dir = _Path(_settings.UPLOAD_DIR) / "custom_templates"
        if upload_custom_dir.exists():
            for docx in sorted(upload_custom_dir.rglob("*.docx")):
                if docx.name.startswith("~$"):
                    continue
                # inject_all_in_dir works on directories; call per-file here
                from .tools.inject_jinja2_into_templates import (
                    needs_injection, process_template,
                )
                try:
                    if needs_injection(docx):
                        process_template(docx)
                        total_injected.append(str(docx.relative_to(upload_custom_dir)))
                except Exception as _e:
                    log.warning("inject boot: skipping %s: %s", docx.name, _e)

        if total_injected:
            log.info(
                "Word-template inject: applied Jinja2 injection to %d file(s): %s",
                len(total_injected), ", ".join(total_injected),
            )
        else:
            log.info("Word-template inject: all templates already up-to-date")
    except Exception as e:                                  # pragma: no cover
        import logging as _l
        _l.getLogger(__name__).warning("Word-template inject skipped: %s", e)


_inject_templates_at_boot()


# Static files
static_dir = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

# JSON API routers
app.include_router(auth.router)
app.include_router(templates_router.router)
app.include_router(findings.router)
app.include_router(projects.router)
# permissions.router must come BEFORE reports.router. permissions defines
# /api/reports/mine, /api/reports/shared-with-me, /api/reports/accessible.
# reports.router defines /api/reports/{report_id:int}. FastAPI matches in
# registration order, so without this ordering the static paths get
# coerced to int and return HTTP 422 ("accessible" is not a valid int).
app.include_router(permissions.router)
app.include_router(reports.router)
app.include_router(parsers.router)
app.include_router(imports.router)
app.include_router(sections.router)
app.include_router(snippets.router)
app.include_router(standards.router)
app.include_router(custom_templates.router)
app.include_router(custom_template_editor.router)
app.include_router(cvss.router)
app.include_router(twofa.router)
app.include_router(knowledgebase.router)
app.include_router(postman.router)
app.include_router(source_code.router)
app.include_router(collab.router)
app.include_router(password_reset.router)
app.include_router(engagement_docs.router)
app.include_router(tracker.router)
app.include_router(admin_email.router)
app.include_router(toolkit.router)
app.include_router(admin_trackers.router)
app.include_router(admin_panel.router)
app.include_router(dashboard.router)
app.include_router(notifications.router)
app.include_router(notes.router)
app.include_router(sso.router)

# HTML UI routes


# UI router MUST be last (HTML routes can conflict with API routes)
app.include_router(ui.router)

# When an HTML page request hits 401, send the user to /login. API routes still 401 cleanly.
# Also: when ANY request from a forced-MFA-enrollment user hits the
# `mfa_enrollment_required` 403 emitted by `auth.get_current_user`,
# we redirect HTML pageloads to /profile/mfa?forced=1 so the user
# actually sees the enrollment screen instead of a raw JSON 403.
# API calls still get the JSON body so client-side fetch() callers
# can detect the gate and react however they want.
@app.exception_handler(HTTPException)
def handle_http(request: Request, exc: HTTPException):
    is_api = request.url.path.startswith("/api/")
    # Forced-MFA enrollment redirect — browsers go to the setup page,
    # API callers get the structured JSON detail.
    if (exc.status_code == 403
            and isinstance(exc.detail, dict)
            and exc.detail.get("code") == "mfa_enrollment_required"
            and not is_api):
        return RedirectResponse(
            exc.detail.get("redirect") or "/profile/mfa?forced=1",
            status_code=302,
        )
    if exc.status_code == 401 and not is_api:
        # Send browsers to the right entry point for the active deployment
        # mode. Pure-local: straight back into a fresh no-login session.
        # Both modes: the selector. Otherwise (SSO/password only): /login.
        if settings.LOCAL_MODE_ENABLED and not settings.SSO_ENABLED:
            return RedirectResponse("/local/enter", status_code=302)
        if settings.LOCAL_MODE_ENABLED and settings.SSO_ENABLED:
            return RedirectResponse("/", status_code=302)
        return RedirectResponse("/login", status_code=302)
    return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)


@app.get("/health")
def health():
    return {"status": "ok", "version": app.version}


# Idle-presence reaper — drops WebSocket connections whose liveness ping
# has gone silent past PRESENCE_IDLE_SECONDS. The startup hook spawns it
# inside the app's event loop so we don't try to schedule asyncio tasks
# before the loop exists.
@app.on_event("startup")
async def _start_presence_reaper() -> None:
    from .services import presence as _presence_svc
    await _presence_svc.start_reaper(interval_seconds=15)


@app.on_event("startup")
async def _start_rate_limit_purge_reaper() -> None:
    """Periodically delete rate_limit_hits rows older than 24 hours.

    The hit_db() function prunes per-(bucket, key) rows on every call,
    but IPs that only ever get rate-limited once accumulate rows that
    are never swept. This reaper handles that by running a global
    DELETE every 6 hours. 6 hours >> login window (minutes), so no
    live window data is ever lost.
    """
    import asyncio
    from sqlalchemy import text

    async def _loop() -> None:
        while True:
            try:
                from datetime import datetime, timedelta
                cutoff = datetime.utcnow() - timedelta(hours=24)
                with engine.begin() as conn:
                    result = conn.execute(
                        text("DELETE FROM rate_limit_hits WHERE hit_at < :cutoff"),
                        {"cutoff": cutoff},
                    )
                    deleted = result.rowcount
                    if deleted:
                        import logging
                        logging.getLogger(__name__).info(
                            "rate_limit purge: deleted %d stale row(s)", deleted
                        )
            except Exception:
                pass
            await asyncio.sleep(6 * 3600)  # every 6 hours

    asyncio.create_task(_loop(), name="rate-limit-purge-reaper")
