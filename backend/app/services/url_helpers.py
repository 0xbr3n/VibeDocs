"""Shared helper for building absolute-URL links inside outbound
emails / notifications.

Picks a base URL in this order:
  1. Explicit `request` argument — read `x-forwarded-proto` /
     `x-forwarded-host` headers (set by nginx in production) and
     fall back to `request.url.scheme` / `request.url.netloc` for
     dev runs without a reverse proxy. This is the same logic
     `routers/password_reset._public_base_url` already used; we
     re-export it here so the rest of the codebase has one place
     to call.
  2. `settings.PUBLIC_BASE_URL` — admin-configurable env var
     (e.g. `https://vapt.acme.internal`). Useful when an email
     send happens OUTSIDE a request context (background job,
     scheduled reminder, etc.).
  3. Hardcoded `http://localhost:8000` fallback so a fresh dev
     deploy still produces clickable links in Mailpit.

The helpers strip trailing slashes from the base and prepend a
leading slash to the path so concatenation always produces a valid
URL.
"""
from __future__ import annotations
from typing import Optional

from fastapi import Request

from ..config import settings


def public_base_url(request: Optional[Request] = None) -> str:
    """Return the system's external-facing base URL (no trailing slash).

    Priority:
      1. `settings.SITE_URL` — admin-configured, immune to header injection.
      2. X-Forwarded-Proto + X-Forwarded-Host from a trusted reverse proxy
         (only if a `request` is supplied and SITE_URL is not set).
      3. Hardcoded `http://localhost:8000` for fresh dev deployments.

    Set SITE_URL in the environment for any production or staging deploy.
    """
    configured = (getattr(settings, "SITE_URL", None) or "").strip().rstrip("/")
    if configured:
        return configured
    if request is not None:
        proto = (request.headers.get("x-forwarded-proto")
                 or request.url.scheme or "http")
        host = (request.headers.get("x-forwarded-host")
                or request.headers.get("host")
                or request.url.netloc)
        if host:
            return f"{proto}://{host}".rstrip("/")
    return "http://localhost:8000"


def absolute_url(path: str, request: Optional[Request] = None) -> str:
    """Join the base URL with a relative path, normalising slashes."""
    base = public_base_url(request)
    if not path:
        return base
    if not path.startswith("/"):
        path = "/" + path
    return base + path
