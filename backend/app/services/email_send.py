"""
Minimal email sender used for password-reset and (in future) notification mail.

Behavior:
  * If `settings.SMTP_HOST` is configured -> send via SMTP (STARTTLS if port 587,
    SSL if port 465, plain otherwise).
  * Otherwise -> write the message to data/outgoing-mail/<timestamp>.eml so a
    developer running locally without an SMTP relay can still see the link
    that would have been sent.

We deliberately *never* raise to the caller on send failure: an unreachable
SMTP server should not give an attacker a 500-vs-200 oracle on the
forgot-password endpoint. We log instead.
"""
from __future__ import annotations
import logging
import smtplib
import ssl
from email.message import EmailMessage
from email.utils import formatdate, make_msgid
from pathlib import Path
from datetime import datetime

from ..config import settings


log = logging.getLogger(__name__)


def send_mail(to: str, subject: str, body_text: str,
              body_html: str | None = None) -> bool:
    """Send an email. Returns True if dispatched (or persisted to disk in
    dev mode); False on hard failure. Never raises."""
    if not to:
        return False

    msg = EmailMessage()
    sender = getattr(settings, "SMTP_FROM", None) or "vapt-reporter@localhost"
    msg["From"] = sender
    msg["To"] = to
    msg["Subject"] = subject
    msg["Date"] = formatdate(localtime=True)
    msg["Message-ID"] = make_msgid()
    msg.set_content(body_text or "(no body)")
    if body_html:
        msg.add_alternative(body_html, subtype="html")

    smtp_host = getattr(settings, "SMTP_HOST", None)
    if not smtp_host:
        # Dev fallback: persist to disk so the developer can grab the link.
        try:
            out_dir = Path(getattr(settings, "DATA_DIR", "/data")) / "outgoing-mail"
            out_dir.mkdir(parents=True, exist_ok=True)
            stamp = datetime.utcnow().strftime("%Y%m%dT%H%M%S%f")
            (out_dir / f"{stamp}.eml").write_bytes(bytes(msg))
            log.info("email persisted to %s/%s.eml (no SMTP_HOST configured)",
                     out_dir, stamp)
            return True
        except Exception as e:
            log.error("could not persist dev email: %s", e)
            return False

    try:
        smtp_port = int(getattr(settings, "SMTP_PORT", 587))
        smtp_user = getattr(settings, "SMTP_USER", None)
        smtp_pass = getattr(settings, "SMTP_PASS", None)
        ctx = ssl.create_default_context()
        if smtp_port == 465:
            with smtplib.SMTP_SSL(smtp_host, smtp_port, context=ctx, timeout=10) as s:
                if smtp_user: s.login(smtp_user, smtp_pass or "")
                s.send_message(msg)
        else:
            with smtplib.SMTP(smtp_host, smtp_port, timeout=10) as s:
                s.ehlo()
                try: s.starttls(context=ctx); s.ehlo()
                except smtplib.SMTPNotSupportedError: pass
                if smtp_user: s.login(smtp_user, smtp_pass or "")
                s.send_message(msg)
        return True
    except Exception as e:
        log.error("email send failed (to=%s, host=%s): %s", to, smtp_host, e)
        return False
