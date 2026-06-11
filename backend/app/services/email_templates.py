"""
Outbound email templates — DB-backed, admin-editable, with hardcoded
fallbacks so the system always renders something even on a fresh deploy.

Two pieces:
  * `DEFAULTS` — the hardcoded subject/text/html for each template `key`.
    These are seeded into the `email_templates` table on first start by
    `seed_default_email_templates(db)`. Admins can then edit them via
    /admin/email-templates without touching code.
  * `render_template(db, key, context)` — looks up the row, renders the
    three fields through a small Jinja2 sandbox with the per-key
    variable allow-list, returns `(subject, text, html)`. Falls back to
    DEFAULTS if the row is missing.

Variables exposed to admins (per template key):

    password_reset      : user, reset_url, ttl_minutes, now
    password_changed    : user, actor_username, now
    project_deleted     : user, actor_username, project_name, client_name, now

`user` is a thin dict {full_name, username, email} so SQLAlchemy session
state doesn't leak into the renderer. The Jinja sandbox uses
`SandboxedEnvironment` which blocks attribute access on dunder names
and any callable that the allow-list hasn't surfaced — admin template
edits can't trigger Python code execution.
"""
from __future__ import annotations
from datetime import datetime
from typing import Any, Optional, Tuple

from jinja2.sandbox import SandboxedEnvironment


# ============================================================
# Hardcoded defaults
# ============================================================

# Common HTML shell used by every default template — kept short so the
# admin can edit it freely. Inline styles only (most email clients strip
# `<style>` blocks).
_HTML_SHELL = """\
<!doctype html>
<html><body style="margin:0;padding:0;background:#f5f7fa;
  font-family:-apple-system,'Segoe UI',Arial,sans-serif;color:#1f2937">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0"
         style="background:#f5f7fa;padding:24px 0"><tr><td align="center">
    <table role="presentation" width="560" cellpadding="0" cellspacing="0"
           border="0" style="max-width:560px;background:#fff;border-radius:12px;
           border:1px solid #e5e7eb;overflow:hidden">
      <tr><td style="background:#0a0c10;padding:20px 24px">
        <span style="color:#fff;font-size:20px;font-weight:800;
                     letter-spacing:-0.02em">VibeDocs<span style="color:#7C5CFC">.</span></span>
        <span style="color:#9ca3af;font-size:12px;margin-left:10px">VAPT Reporter</span>
      </td></tr>
      __BODY__
    </table>
  </td></tr></table>
</body></html>"""


def _shell(body: str) -> str:
    """Wrap a body fragment in the standard branded HTML shell."""
    return _HTML_SHELL.replace("__BODY__", body)


DEFAULTS: dict[str, dict[str, str]] = {
    "password_reset": {
        "description": "Sent when a user requests a password reset link.",
        "subject": "Reset your VAPT Reporter password",
        "body_text": (
            "Hello {{ user.full_name or user.username }},\n\n"
            "Someone (probably you) asked to reset the password on your\n"
            "VAPT Reporter account.\n\n"
            "Click the link below to choose a new password. The link expires\n"
            "in {{ ttl_minutes }} minutes and can only be used once.\n\n"
            "    {{ reset_url }}\n\n"
            "If you didn't request this, you can ignore this email — your\n"
            "current password remains unchanged.\n\n"
            "-- VAPT Reporter"
        ),
        "body_html": _shell("""\
      <tr><td style="padding:28px 28px 8px;font-size:18px;font-weight:600;
                     color:#111827">Reset your password</td></tr>
      <tr><td style="padding:0 28px 14px;font-size:14px;line-height:1.55;color:#374151">
        Hello {{ user.full_name or user.username }},<br><br>
        Someone (probably you) asked to reset the password on your
        VAPT Reporter account. The button below opens a one-time form
        where you can choose a new password.
      </td></tr>
      <tr><td style="padding:8px 28px 16px" align="center">
        <a href="{{ reset_url }}" style="display:inline-block;padding:11px 22px;
           background:#7C5CFC;color:#111827;font-weight:600;font-size:14px;
           border-radius:8px;text-decoration:none;letter-spacing:.01em">
           Choose a new password →
        </a>
      </td></tr>
      <tr><td style="padding:8px 28px 22px;font-size:13px;line-height:1.55;color:#4b5563">
        The link is valid for <strong>{{ ttl_minutes }} minutes</strong> and can only
        be used once.<br><br>
        If you didn't request this, you can safely ignore this email — your
        current password remains unchanged.<br><br>
        If the button doesn't work, paste this URL into your browser:<br>
        <a href="{{ reset_url }}" style="word-break:break-all;color:#5B3FD6">{{ reset_url }}</a>
      </td></tr>
      <tr><td style="padding:14px 28px;border-top:1px solid #e5e7eb;
                     font-size:11.5px;color:#9ca3af;background:#fafafa">
        Sent {{ now }} · VAPT Reporter security mailer · Do not reply to this address.
      </td></tr>"""),
    },

    "password_changed": {
        "description": "Sent after a successful password reset to confirm the change.",
        "subject": "Your VAPT Reporter password was changed",
        "body_text": (
            "Hi {{ user.full_name or user.username }},\n\n"
            "This is a confirmation that your VAPT Reporter password was just\n"
            "reset by {{ actor_username }} on {{ now }}.\n\n"
            "If this wasn't you, contact your administrator immediately.\n\n"
            "-- VAPT Reporter"
        ),
        "body_html": _shell("""\
      <tr><td style="padding:24px 28px 8px;font-size:17px;font-weight:600;color:#111827">
        Password updated
      </td></tr>
      <tr><td style="padding:0 28px 18px;font-size:14px;line-height:1.55;color:#374151">
        Hi {{ user.full_name or user.username }},<br><br>
        This is a confirmation that your VAPT Reporter password was just reset
        by <strong>{{ actor_username }}</strong> on {{ now }}.<br><br>
        If this wasn't you, contact your administrator immediately and rotate
        any other credentials that share this password.
      </td></tr>
      <tr><td style="padding:14px 28px;border-top:1px solid #e5e7eb;
                     font-size:11.5px;color:#9ca3af;background:#fafafa">
        VAPT Reporter security mailer · Do not reply to this address.
      </td></tr>"""),
    },

    "project_deleted": {
        "description": "Sent to every project member when a project is deleted.",
        "subject": "[VAPT Reporter] Project deleted: {{ project_name }}",
        "body_text": (
            "Hi {{ user.full_name or user.username }},\n\n"
            "The VAPT Reporter project \"{{ project_name }}\" "
            "(client: {{ client_name }}) was deleted by {{ actor_username }} on\n"
            "{{ now }}.\n\n"
            "All reports and findings under this project have been removed.\n"
            "If this was unexpected, contact your administrator immediately.\n\n"
            "-- VAPT Reporter"
        ),
        "body_html": _shell("""\
      <tr><td style="padding:24px 28px 6px;font-size:17px;font-weight:600;color:#b91c1c">
        Project deleted
      </td></tr>
      <tr><td style="padding:0 28px 18px;font-size:14px;line-height:1.55;color:#374151">
        Hi {{ user.full_name or user.username }},<br><br>
        The VAPT Reporter project <strong>{{ project_name }}</strong>
        (client: {{ client_name }}) was deleted by <strong>{{ actor_username }}</strong>
        on {{ now }}.<br><br>
        All reports and findings under this project have been removed.
        If this was unexpected, contact your administrator immediately.
      </td></tr>
      <tr><td style="padding:14px 28px;border-top:1px solid #e5e7eb;
                     font-size:11.5px;color:#9ca3af;background:#fafafa">
        VAPT Reporter notifications · Do not reply to this address.
      </td></tr>"""),
    },

    # ============================================================
    # Collaboration notifications — sent to the user on the receiving
    # end of an admin/peer action. Each one tells the recipient what
    # changed and (where appropriate) links them to the resource.
    # ============================================================

    "project_assigned": {
        "description": "Sent to a consultant when they are added to a project's team.",
        "subject": "[VAPT Reporter] You were assigned to project: {{ project_name }}",
        "body_text": (
            "Hi {{ user.full_name or user.username }},\n\n"
            "{{ actor_username }} added you to the VAPT Reporter project\n"
            "\"{{ project_name }}\" (client: {{ client_name }}) on {{ now }}.\n\n"
            "You can now view the project, its reports, and contribute findings.\n\n"
            "Open the project: {{ project_url }}\n\n"
            "-- VAPT Reporter"
        ),
        "body_html": _shell("""\
      <tr><td style="padding:24px 28px 6px;font-size:17px;font-weight:600;color:#111827">
        You were added to a project
      </td></tr>
      <tr><td style="padding:0 28px 18px;font-size:14px;line-height:1.55;color:#374151">
        Hi {{ user.full_name or user.username }},<br><br>
        <strong>{{ actor_username }}</strong> added you to the project
        <strong>{{ project_name }}</strong> (client: {{ client_name }})
        on {{ now }}.<br><br>
        You can now view the project, its reports, and contribute findings.
      </td></tr>
      <tr><td style="padding:6px 28px 22px" align="center">
        <a href="{{ project_url }}" style="display:inline-block;padding:11px 22px;
           background:#7C5CFC;color:#111827;font-weight:600;font-size:14px;
           border-radius:8px;text-decoration:none">Open project →</a>
      </td></tr>
      <tr><td style="padding:14px 28px;border-top:1px solid #e5e7eb;
                     font-size:11.5px;color:#9ca3af;background:#fafafa">
        VAPT Reporter collaboration notice · Do not reply to this address.
      </td></tr>"""),
    },

    "report_access_granted": {
        "description": "Sent to a user when another user grants them access to a specific report.",
        "subject": "[VAPT Reporter] {{ access_level }} access granted: {{ report_name }}",
        "body_text": (
            "Hi {{ user.full_name or user.username }},\n\n"
            "{{ actor_username }} just granted you {{ access_level }} access to the\n"
            "report \"{{ report_name }}\" on the project \"{{ project_name }}\"\n"
            "(client: {{ client_name }}) on {{ now }}.\n\n"
            "Open the report: {{ report_url }}\n\n"
            "-- VAPT Reporter"
        ),
        "body_html": _shell("""\
      <tr><td style="padding:24px 28px 6px;font-size:17px;font-weight:600;color:#111827">
        Report access granted
      </td></tr>
      <tr><td style="padding:0 28px 18px;font-size:14px;line-height:1.55;color:#374151">
        Hi {{ user.full_name or user.username }},<br><br>
        <strong>{{ actor_username }}</strong> granted you
        <strong>{{ access_level }}</strong> access to the report
        <strong>{{ report_name }}</strong> on the project
        <strong>{{ project_name }}</strong> (client: {{ client_name }}) on {{ now }}.
      </td></tr>
      <tr><td style="padding:6px 28px 22px" align="center">
        <a href="{{ report_url }}" style="display:inline-block;padding:11px 22px;
           background:#7C5CFC;color:#111827;font-weight:600;font-size:14px;
           border-radius:8px;text-decoration:none">Open report →</a>
      </td></tr>
      <tr><td style="padding:14px 28px;border-top:1px solid #e5e7eb;
                     font-size:11.5px;color:#9ca3af;background:#fafafa">
        VAPT Reporter sharing notice · Do not reply to this address.
      </td></tr>"""),
    },

    "report_version_approved": {
        "description": "Sent to the report owner when a reviewer approves a version they submitted for review.",
        "subject": "[VAPT Reporter] Report approved: {{ report_name }} v{{ version }}",
        "body_text": (
            "Hi {{ user.full_name or user.username }},\n\n"
            "Good news — {{ reviewer_username }} has APPROVED version\n"
            "{{ version }} of your report \"{{ report_name }}\" on {{ now }}.\n\n"
            "{% if review_notes %}Reviewer comments:\n{{ review_notes }}\n\n{% endif %}"
            "{% if published %}The version is now PUBLISHED — it carries no draft watermark and is ready for delivery.{% else %}The version is approved and editable; submit a new version when you need to lock it as final.{% endif %}\n\n"
            "Open the report: {{ report_url }}\n\n"
            "-- VAPT Reporter"
        ),
        "body_html": _shell("""\
      <tr><td style="padding:24px 28px 6px;font-size:17px;font-weight:600;color:#15803d">
        ✓ Report approved
      </td></tr>
      <tr><td style="padding:0 28px 18px;font-size:14px;line-height:1.55;color:#374151">
        Hi {{ user.full_name or user.username }},<br><br>
        Good news — <strong>{{ reviewer_username }}</strong> approved version
        <strong>{{ version }}</strong> of your report
        <strong>{{ report_name }}</strong> on {{ now }}.<br>
        {% if review_notes %}
        <div style="margin-top:12px;padding:10px 12px;background:#f0fdf4;
                    border-left:3px solid #7C5CFC;border-radius:4px">
          <strong style="font-size:13px;color:#15803d">Reviewer comments</strong><br>
          <span style="font-size:13px;color:#374151;white-space:pre-wrap">{{ review_notes }}</span>
        </div>
        {% endif %}
        <br>
        {% if published %}
        The version is now <strong>published</strong> — it carries no
        draft watermark and is ready for delivery.
        {% else %}
        The version is approved and editable; submit a new version when
        you need to lock it as final.
        {% endif %}
      </td></tr>
      <tr><td style="padding:6px 28px 22px" align="center">
        <a href="{{ report_url }}" style="display:inline-block;padding:11px 22px;
           background:#7C5CFC;color:#111827;font-weight:600;font-size:14px;
           border-radius:8px;text-decoration:none">Open report →</a>
      </td></tr>
      <tr><td style="padding:14px 28px;border-top:1px solid #e5e7eb;
                     font-size:11.5px;color:#9ca3af;background:#fafafa">
        VAPT Reporter review notifications · Do not reply to this address.
      </td></tr>"""),
    },

    "finding_approved": {
        "description": "Sent to the author of a library finding when an admin/senior approves it for team-wide use.",
        "subject": "[VAPT Reporter] Library finding approved: {{ finding_title }}",
        "body_text": (
            "Hi {{ user.full_name or user.username }},\n\n"
            "{{ reviewer_username }} approved your library finding\n"
            "\"{{ finding_title }}\" on {{ now }}. It's now visible to every\n"
            "consultant and can be added to any report.\n\n"
            "Open in the library: {{ finding_url }}\n\n"
            "-- VAPT Reporter"
        ),
        "body_html": _shell("""\
      <tr><td style="padding:24px 28px 6px;font-size:17px;font-weight:600;color:#15803d">
        ✓ Your library finding was approved
      </td></tr>
      <tr><td style="padding:0 28px 18px;font-size:14px;line-height:1.55;color:#374151">
        Hi {{ user.full_name or user.username }},<br><br>
        <strong>{{ reviewer_username }}</strong> approved your library finding
        <strong>{{ finding_title }}</strong> on {{ now }}. It is now visible to
        every consultant and can be added to any report.
      </td></tr>
      <tr><td style="padding:6px 28px 22px" align="center">
        <a href="{{ finding_url }}" style="display:inline-block;padding:11px 22px;
           background:#7C5CFC;color:#111827;font-weight:600;font-size:14px;
           border-radius:8px;text-decoration:none">Open in library →</a>
      </td></tr>
      <tr><td style="padding:14px 28px;border-top:1px solid #e5e7eb;
                     font-size:11.5px;color:#9ca3af;background:#fafafa">
        VAPT Reporter library notifications · Do not reply to this address.
      </td></tr>"""),
    },

    "custom_template_approved": {
        "description": "Sent to the uploader of a custom Word template when an admin approves it for team-wide use.",
        "subject": "[VAPT Reporter] Custom template approved: {{ template_name }}",
        "body_text": (
            "Hi {{ user.full_name or user.username }},\n\n"
            "{{ reviewer_username }} approved your custom Word template\n"
            "\"{{ template_name }}\" on {{ now }}. It is now available to every\n"
            "consultant on the Templates page.\n\n"
            "{% if review_notes %}Reviewer comments:\n{{ review_notes }}\n\n{% endif %}"
            "Open the template: {{ template_url }}\n\n"
            "-- VAPT Reporter"
        ),
        "body_html": _shell("""\
      <tr><td style="padding:24px 28px 6px;font-size:17px;font-weight:600;color:#15803d">
        ✓ Your custom template was approved
      </td></tr>
      <tr><td style="padding:0 28px 18px;font-size:14px;line-height:1.55;color:#374151">
        Hi {{ user.full_name or user.username }},<br><br>
        <strong>{{ reviewer_username }}</strong> approved your custom Word template
        <strong>{{ template_name }}</strong> on {{ now }}. It is now available
        to every consultant on the Templates page.
        {% if review_notes %}
        <div style="margin-top:12px;padding:10px 12px;background:#f0fdf4;
                    border-left:3px solid #7C5CFC;border-radius:4px">
          <strong style="font-size:13px;color:#15803d">Reviewer comments</strong><br>
          <span style="font-size:13px;color:#374151;white-space:pre-wrap">{{ review_notes }}</span>
        </div>
        {% endif %}
      </td></tr>
      <tr><td style="padding:6px 28px 22px" align="center">
        <a href="{{ template_url }}" style="display:inline-block;padding:11px 22px;
           background:#7C5CFC;color:#111827;font-weight:600;font-size:14px;
           border-radius:8px;text-decoration:none">Open template →</a>
      </td></tr>
      <tr><td style="padding:14px 28px;border-top:1px solid #e5e7eb;
                     font-size:11.5px;color:#9ca3af;background:#fafafa">
        VAPT Reporter template notifications · Do not reply to this address.
      </td></tr>"""),
    },

    "account_unlock": {
        "description": "Sent to a locked user so they can self-service unlock their account.",
        "subject": "Unlock your VAPT Reporter account",
        "body_text": (
            "Hi {{ user.full_name or user.username }},\n\n"
            "Your account was locked after too many failed login attempts.\n"
            "{{ admin_username }} has sent you this link to unlock it.\n\n"
            "Click the link below to unlock your account (expires in {{ ttl_minutes }} minutes):\n\n"
            "{{ unlock_url }}\n\n"
            "If you did not request this, please contact your administrator immediately.\n\n"
            "-- VAPT Reporter"
        ),
        "body_html": _shell("""\
      <tr><td style="padding:24px 28px 6px;font-size:17px;font-weight:600;color:#b45309">
        🔒 Your account has been locked
      </td></tr>
      <tr><td style="padding:0 28px 18px;font-size:14px;line-height:1.55;color:#374151">
        Hi {{ user.full_name or user.username }},<br><br>
        Your VAPT Reporter account was locked after too many failed login attempts.
        <strong>{{ admin_username }}</strong> has sent you this link to unlock it.
      </td></tr>
      <tr><td style="padding:6px 28px 22px" align="center">
        <a href="{{ unlock_url }}" style="display:inline-block;padding:11px 22px;
           background:#7C5CFC;color:#111827;font-weight:600;font-size:14px;
           border-radius:8px;text-decoration:none">Unlock my account →</a>
      </td></tr>
      <tr><td style="padding:0 28px 14px;font-size:13px;color:#6b7280">
        This link expires in {{ ttl_minutes }} minutes. If you did not expect this
        email, contact your administrator immediately.
      </td></tr>
      <tr><td style="padding:14px 28px;border-top:1px solid #e5e7eb;
                     font-size:11.5px;color:#9ca3af;background:#fafafa">
        VAPT Reporter account security · Do not reply to this address.
      </td></tr>"""),
    },
}


# Per-key allow-list of variables the admin can reference in the
# template. Anything else is filtered out before the render so a typo
# can't accidentally expose other context fields.
ALLOWED_VARS = {
    "password_reset":   {"user", "reset_url", "ttl_minutes", "now"},
    "password_changed": {"user", "actor_username", "now"},
    "project_deleted":  {"user", "actor_username", "project_name", "client_name", "now"},

    # Collaboration notifications
    "project_assigned": {"user", "actor_username", "project_name",
                          "client_name", "project_url", "now"},
    "report_access_granted": {"user", "actor_username", "report_name",
                               "project_name", "client_name", "access_level",
                               "report_url", "now"},
    "report_version_approved": {"user", "reviewer_username", "report_name",
                                 "version", "review_notes", "published",
                                 "report_url", "now"},
    "finding_approved": {"user", "reviewer_username", "finding_title",
                          "finding_url", "now"},
    "custom_template_approved": {"user", "reviewer_username", "template_name",
                                  "review_notes", "template_url", "now"},
    "account_unlock": {"user", "unlock_url", "ttl_minutes", "admin_username", "now"},
}


# ============================================================
# Render
# ============================================================

_ENV = SandboxedEnvironment(autoescape=False)
_ENV_HTML = SandboxedEnvironment(autoescape=True)


def _user_view(user) -> dict:
    """Project the User row into a small dict that's safe to pass to a
    sandboxed Jinja env. Direct ORM instances aren't a great idea inside
    user-supplied templates."""
    return {
        "full_name": getattr(user, "full_name", None) or "",
        "username":  getattr(user, "username", None) or "",
        "email":     getattr(user, "email", None) or "",
    }


def _build_context(key: str, raw: dict) -> dict:
    """Stamp a `now` value, normalise `user`, and drop any key the
    template isn't allowed to see."""
    allowed = ALLOWED_VARS.get(key, set())
    out: dict = {}
    if "user" in allowed and "user" in raw:
        out["user"] = _user_view(raw["user"])
    for k in allowed:
        if k == "user":
            continue
        if k == "now":
            out["now"] = raw.get("now") or datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
        elif k in raw:
            out[k] = raw[k]
    return out


def render_template(db, key: str, raw_context: dict) -> Tuple[str, str, str]:
    """Resolve, render, return (subject, body_text, body_html).

    Lookup order:
      1. `email_templates` row with matching `key`
      2. `DEFAULTS[key]`
      3. KeyError on unknown key — caller should never request a key we
         don't know about, so this is a programmer error not a config one.
    """
    from ..models import EmailTemplate
    row = db.query(EmailTemplate).filter(EmailTemplate.key == key).first() if db else None

    if row:
        subject_tpl  = row.subject
        text_tpl     = row.body_text
        html_tpl     = row.body_html
    else:
        spec = DEFAULTS.get(key)
        if not spec:
            raise KeyError(f"Unknown email template key: {key}")
        subject_tpl  = spec["subject"]
        text_tpl     = spec["body_text"]
        html_tpl     = spec["body_html"]

    ctx = _build_context(key, raw_context)
    # Subject + plain text render through the non-escaping env (it's text).
    # HTML body renders through the autoescape env so admin-supplied
    # context values can't introduce raw HTML by accident.
    subject = _ENV.from_string(subject_tpl).render(**ctx)
    body_text = _ENV.from_string(text_tpl).render(**ctx)
    body_html = _ENV_HTML.from_string(html_tpl).render(**ctx)
    return subject, body_text, body_html


def render_preview(key: str, subject_tpl: str, text_tpl: str, html_tpl: str,
                   raw_context: dict | None = None) -> dict:
    """Render an unsaved template (used by the admin preview button).
    Builds a synthetic context with sample values so the admin can see
    what an email looks like before saving."""
    sample = _sample_context(key)
    if raw_context:
        sample.update(raw_context)
    ctx = _build_context(key, sample)
    try:
        return {
            "ok": True,
            "subject": _ENV.from_string(subject_tpl).render(**ctx),
            "body_text": _ENV.from_string(text_tpl).render(**ctx),
            "body_html": _ENV_HTML.from_string(html_tpl).render(**ctx),
        }
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}


def _sample_context(key: str) -> dict:
    """Filled-in sample values for the preview button. Realistic enough
    that the admin can eyeball that links / interpolation work."""
    return {
        "user": _SampleUser(),
        "reset_url": "https://vapt.internal/reset-password?token=ZXhhbXBsZS10b2tlbg",
        "ttl_minutes": 30,
        "actor_username": "alice.consultant",
        "reviewer_username": "robin.senior",
        "project_name": "Acme Corp Q2 Pentest",
        "client_name": "Acme Corp",
        "report_name": "Web App External Pentest",
        "version": "0.3",
        "review_notes": "Looks great — punchy executive summary, evidence is clear.",
        "published": True,
        "access_level": "edit",
        "finding_title": "Stored Cross-Site Scripting (XSS) in /profile/bio",
        "template_name": "Acme Corp Custom WAPT Report Template",
        "project_url":  "https://vapt.internal/projects/123",
        "report_url":   "https://vapt.internal/reports/456",
        "finding_url":  "https://vapt.internal/library?finding=789",
        "template_url": "https://vapt.internal/templates/edit/12",
        "now": datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
    }


class _SampleUser:
    full_name = "Jane Recipient"
    username = "jane.recipient"
    email = "jane@example.com"


# ============================================================
# Seed
# ============================================================

def seed_default_email_templates(db) -> dict:
    """Insert any missing template row from DEFAULTS. Idempotent — won't
    overwrite a row an admin has edited (we look up by key first).
    Returns a {seeded: int, skipped: int} summary."""
    from ..models import EmailTemplate
    seeded = 0
    skipped = 0
    for key, spec in DEFAULTS.items():
        existing = db.query(EmailTemplate).filter(EmailTemplate.key == key).first()
        if existing:
            skipped += 1
            continue
        row = EmailTemplate(
            key=key,
            description=spec.get("description") or "",
            subject=spec["subject"],
            body_text=spec["body_text"],
            body_html=spec["body_html"],
        )
        db.add(row)
        seeded += 1
    if seeded:
        db.commit()
    return {"seeded": seeded, "skipped": skipped}
