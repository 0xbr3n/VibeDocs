"""User-targeted email notifications, with a master opt-out per user.

`notify_user(db, user, template_key, context)` is the canonical way
to send a COLLABORATION email — project assignment, report-access
grant, approval notices, etc. It short-circuits and sends nothing
when:

  * `user` is None or has no `email` set, OR
  * `user.notifications_email_enabled` is False (the per-user
    master switch surfaced under /profile → Notifications), OR
  * `user.is_active` is False (disabled accounts get no traffic), OR
  * the recipient is the same person who triggered the action (we
    never email someone about their own button click — checked by
    the caller passing `actor_user_id`).

Every send is wrapped in try/except so notification failure can
NEVER block the underlying write (commit happened before this call,
not after). Failure is logged at WARNING level so the deploy team
can spot smtp drift without it tripping the user.

Security emails (password reset, password changed, MFA enrollment)
are explicitly NOT routed through this helper — they MUST reach the
user regardless of preferences. Those keep using `send_mail` directly
the way they always have.

Available keys (must exist in `services.email_templates.DEFAULTS`):
    project_assigned, report_access_granted, report_version_approved,
    finding_approved, custom_template_approved
"""
from __future__ import annotations
import logging
from typing import Optional

from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)


# The template keys this helper routes. Listed explicitly so a typo in
# a caller's `template_key` arg doesn't silently fail — we'd rather
# log a clear warning than send the wrong email.
COLLAB_TEMPLATE_KEYS = frozenset({
    "project_assigned",
    "report_access_granted",
    "report_version_approved",
    "finding_approved",
    "custom_template_approved",
})


def notify_user(
    db: Session,
    user,
    template_key: str,
    context: dict,
    *,
    actor_user_id: Optional[int] = None,
) -> bool:
    """Render + send a collaboration notification email.

    Returns:
        True  — the email was rendered AND handed off to the mailer
                (delivery itself is still best-effort — SMTP may bounce).
        False — sending was skipped for an expected reason (no email,
                opt-out, self-trigger, unknown key, etc.). Caller can
                ignore the return value; it's surfaced for tests +
                future "notification dashboard" features.

    Never raises — internal errors are logged but propagated as
    `False` so a notification failure cannot roll the caller's
    transaction back.
    """
    if user is None:
        return False
    if not getattr(user, "email", None):
        return False
    if not getattr(user, "is_active", True):
        return False
    # Per-user opt-out. Default-True column; older rows without the
    # value treated as opted-in via getattr fallback.
    if not bool(getattr(user, "notifications_email_enabled", True)):
        logger.debug(
            "notify_user: %r opted out of collab emails — skipping %r",
            user.username, template_key,
        )
        return False
    if actor_user_id is not None and actor_user_id == getattr(user, "id", None):
        # Self-trigger — don't email someone about their own action.
        return False
    if template_key not in COLLAB_TEMPLATE_KEYS:
        logger.warning(
            "notify_user called with unknown template key %r — "
            "expected one of %s",
            template_key, sorted(COLLAB_TEMPLATE_KEYS),
        )
        return False

    try:
        # Late imports — keeps this module cheap to import and avoids a
        # cycle with `services.email_templates`, which imports models.
        from . import email_templates as _email_tmpls
        from .email_send import send_mail
        subject, body_text, body_html = _email_tmpls.render_template(
            db, template_key, context,
        )
        send_mail(user.email, subject=subject,
                   body_text=body_text, body_html=body_html)
        return True
    except Exception as e:                                  # pragma: no cover
        logger.warning(
            "notify_user(%r) failed for user %s: %s",
            template_key, getattr(user, "id", None), e,
        )
        return False
