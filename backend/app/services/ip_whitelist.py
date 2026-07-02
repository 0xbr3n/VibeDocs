"""
IP / VPN whitelist middleware.

Driven by the `ALLOWED_IPS` env var — a comma-separated list of bare IPv4 /
IPv6 addresses *or* CIDR ranges. Empty / unset disables the check (the app
behaves exactly as before). One concrete example:

    ALLOWED_IPS = 10.0.0.0/8, 192.168.0.0/16, 203.0.113.42

The client IP is read from the standard `X-Forwarded-For` chain when the
app sits behind nginx (which it does by default in our compose), falling
back to the socket peer when the header is absent.

A few additional knobs (also env-driven):

    ALLOWED_IPS_BYPASS_PATHS   /health,/static,...   paths always allowed
                               (defaults to /health + /static, so the
                               docker healthcheck never gets blocked).
    ALLOWED_IPS_LOG_ONLY       1 / true              don't block, just log
                               the rejected IPs. Use during rollout to
                               confirm the whitelist won't lock anyone out.

Blocked requests get a small JSON 403 explaining the policy so an
on-call engineer connecting from a non-VPN address sees a useful error
instead of a generic Forbidden.

Anything that fails to parse in `ALLOWED_IPS` is logged once at startup
and ignored — a typo in env shouldn't ground the app.
"""
from __future__ import annotations
import ipaddress
import logging
import os
from typing import Iterable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse


log = logging.getLogger(__name__)


def _parse_allowlist(raw: str) -> list[ipaddress._BaseNetwork]:
    nets: list[ipaddress._BaseNetwork] = []
    for token in (raw or "").split(","):
        t = token.strip()
        if not t:
            continue
        try:
            nets.append(ipaddress.ip_network(t, strict=False))
        except ValueError as e:
            log.warning("ALLOWED_IPS: ignoring invalid entry %r (%s)", t, e)
    return nets


def _parse_paths(raw: str) -> list[str]:
    return [p.strip() for p in (raw or "").split(",") if p.strip()]


def _client_ip(request) -> str:
    """Return the real client IP, preferring headers set by nginx.

    Priority:
      1. X-Real-IP — nginx sets this to $remote_addr (the actual socket
         peer of the nginx process), which cannot be spoofed by the client.
      2. X-Forwarded-For last entry — nginx appends its own $remote_addr
         to the end of any client-supplied XFF header, so the rightmost
         value is the nearest hop and can't be faked from outside.
      3. Starlette request.client.host — socket peer as seen by the
         FastAPI process (the nginx container in our compose stack).

    The leftmost XFF value is deliberately NOT used here because nginx's
    proxy_add_x_forwarded_for appends rather than replaces, so a client
    can inject a spoofed IP as the leftmost entry to bypass an IP whitelist.
    """
    real_ip = request.headers.get("x-real-ip", "").strip()
    if real_ip:
        return real_ip
    xff = request.headers.get("x-forwarded-for", "")
    if xff:
        # Rightmost entry is nginx's appended $remote_addr — trustworthy.
        return xff.split(",")[-1].strip() or ""
    if request.client and request.client.host:
        return request.client.host
    return ""


class IPWhitelistMiddleware(BaseHTTPMiddleware):
    """Block requests from non-whitelisted sources.

    Built so the whole feature can be turned off with a single env var:
    when `ALLOWED_IPS` is blank, the middleware short-circuits to
    `call_next` for every request, costing essentially nothing.
    """

    def __init__(self, app, *, allowed: Iterable[str] = (),
                 bypass_paths: Iterable[str] = (),
                 log_only: bool = False):
        super().__init__(app)
        if isinstance(allowed, str):
            self._nets = _parse_allowlist(allowed)
        else:
            self._nets = _parse_allowlist(",".join(allowed))
        self._bypass = list(bypass_paths)
        self._log_only = bool(log_only)
        if self._nets:
            log.info("ALLOWED_IPS active: %d range(s); log_only=%s; "
                     "bypass_paths=%s",
                     len(self._nets), self._log_only, self._bypass)
        else:
            log.info("ALLOWED_IPS empty — IP whitelist DISABLED")

    @classmethod
    def from_env(cls, app):
        return cls(
            app,
            allowed=os.environ.get("ALLOWED_IPS", ""),
            bypass_paths=_parse_paths(
                os.environ.get("ALLOWED_IPS_BYPASS_PATHS", "/health,/static")
            ),
            log_only=os.environ.get("ALLOWED_IPS_LOG_ONLY", "").lower()
                in ("1", "true", "yes"),
        )

    def _is_allowed(self, ip_str: str) -> bool:
        if not ip_str:
            return False
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            return False
        return any(ip in net for net in self._nets)

    def _path_bypassed(self, path: str) -> bool:
        for prefix in self._bypass:
            if path == prefix or path.startswith(prefix.rstrip("/") + "/"):
                return True
        return False

    async def dispatch(self, request, call_next):
        # No whitelist configured = pass-through. Cheap path, no parsing.
        if not self._nets:
            return await call_next(request)

        # Bypass paths get a free pass — keeps the docker healthcheck and
        # asset serving alive even if the engineer is debugging the
        # whitelist itself.
        if self._path_bypassed(request.url.path):
            return await call_next(request)

        ip_str = _client_ip(request)
        if self._is_allowed(ip_str):
            return await call_next(request)

        if self._log_only:
            log.warning("IP whitelist (log-only): would block %s %s %s",
                        ip_str or "?", request.method, request.url.path)
            return await call_next(request)

        log.warning("IP whitelist blocked %s %s %s",
                    ip_str or "?", request.method, request.url.path)
        return JSONResponse(
            {"detail": (
                "Access restricted to the configured VPN / trusted-network "
                "ranges. Connect through the corporate VPN and retry. "
                "If you believe this is wrong, ask an admin to check "
                "ALLOWED_IPS in the server environment."
            ),
             "your_ip": ip_str or "unknown"},
            status_code=403,
        )
