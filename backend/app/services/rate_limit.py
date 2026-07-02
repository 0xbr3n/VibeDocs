"""
Sliding-window rate limiter with two backends:

  hit_db(engine, bucket, key, *, max_attempts, window_seconds)
      DB-backed (PostgreSQL). Correct when uvicorn runs --workers > 1
      because all worker processes share the same database. Use this for
      IP-throttling on login endpoints.

  hit(bucket, key, *, max_attempts, window_seconds)
      In-memory per-process fallback. Kept for backward compatibility and
      unit tests. AVOID on multi-worker deployments for security-critical
      throttles — each worker maintains an independent counter.

  record_failure / is_locked / clear
      In-memory MFA lockout gate. Per-user, per-session — the in-memory
      store is acceptable here because MFA challenges are always tied to a
      single user session, which sticks to one worker via the auth cookie.
"""
from __future__ import annotations
import threading
from collections import deque
from datetime import datetime, timedelta
from typing import Optional


_lock = threading.Lock()

# bucket -> key -> deque[datetime]    rolling timestamps
_hits: dict[str, dict[str, deque[datetime]]] = {}
# bucket -> key -> deque[datetime]    failure timestamps (separate stream)
_failures: dict[str, dict[str, deque[datetime]]] = {}
# bucket -> key -> datetime           lockout expiry
_lockouts: dict[str, dict[str, datetime]] = {}


def _now() -> datetime:
    return datetime.utcnow()


def _trim(d: deque[datetime], cutoff: datetime) -> None:
    while d and d[0] < cutoff:
        d.popleft()


def hit(bucket: str, key: str, *,
        max_attempts: int, window_seconds: int) -> tuple[bool, int, int]:
    """Record one attempt against (bucket, key). Returns:
        (allowed, retry_after_seconds, remaining_in_window)
    Where `allowed=False` means the caller should reject with 429.
    """
    now = _now()
    cutoff = now - timedelta(seconds=window_seconds)
    with _lock:
        b = _hits.setdefault(bucket, {})
        q = b.setdefault(key, deque())
        _trim(q, cutoff)
        if len(q) >= max_attempts:
            retry_after = max(1, int((q[0] + timedelta(seconds=window_seconds) - now).total_seconds()))
            return False, retry_after, 0
        q.append(now)
        return True, 0, max(0, max_attempts - len(q))


def record_failure(bucket: str, key: str, *,
                    max_failures: int, window_seconds: int,
                    lockout_seconds: int) -> tuple[bool, int]:
    """Mark a failed attempt. If the failure count within `window_seconds`
    reaches `max_failures`, lock the key for `lockout_seconds`. Returns
    (now_locked, retry_after_seconds).
    """
    now = _now()
    cutoff = now - timedelta(seconds=window_seconds)
    with _lock:
        b = _failures.setdefault(bucket, {})
        q = b.setdefault(key, deque())
        _trim(q, cutoff)
        q.append(now)
        if len(q) >= max_failures:
            lockout_until = now + timedelta(seconds=lockout_seconds)
            _lockouts.setdefault(bucket, {})[key] = lockout_until
            q.clear()  # reset so the user gets a fresh streak after the lockout
            return True, lockout_seconds
    return False, 0


def is_locked(bucket: str, key: str) -> tuple[bool, int]:
    """Return (locked, retry_after_s). Locked entries past their expiry are
    swept lazily on read."""
    now = _now()
    with _lock:
        b = _lockouts.get(bucket)
        if not b:
            return False, 0
        until = b.get(key)
        if not until:
            return False, 0
        if until <= now:
            b.pop(key, None)
            return False, 0
        return True, max(1, int((until - now).total_seconds()))


def clear(bucket: str, key: str) -> None:
    """Reset failure history + lockout for (bucket, key). Call on success."""
    with _lock:
        if bucket in _failures:
            _failures[bucket].pop(key, None)
        if bucket in _lockouts:
            _lockouts[bucket].pop(key, None)


def hit_db(engine, bucket: str, key: str, *,
           max_attempts: int, window_seconds: int) -> tuple[bool, int, int]:
    """PostgreSQL-backed sliding-window rate limiter.

    Correct with --workers N because all uvicorn processes share the same DB.
    Uses a single transaction per call:
      1. DELETE expired rows for (bucket, key)
      2. COUNT current rows
      3. If count >= max_attempts: block (no insert)
      4. Otherwise: INSERT the new hit

    Returns (allowed, retry_after_seconds, remaining_in_window).
    Falls back silently to allow=True on any DB error so a rate-limiter
    outage does not take down the login endpoint.
    """
    from datetime import datetime, timedelta
    from sqlalchemy import text

    now = datetime.utcnow()
    cutoff = now - timedelta(seconds=window_seconds)
    try:
        with engine.begin() as conn:
            # Prune expired entries for this (bucket, key)
            conn.execute(
                text("DELETE FROM rate_limit_hits "
                     "WHERE bucket = :b AND key = :k AND hit_at < :cutoff"),
                {"b": bucket, "k": key, "cutoff": cutoff},
            )
            # Count hits still in the window
            count = conn.execute(
                text("SELECT COUNT(*) FROM rate_limit_hits "
                     "WHERE bucket = :b AND key = :k"),
                {"b": bucket, "k": key},
            ).scalar() or 0

            if count >= max_attempts:
                # Find the oldest in-window hit to calculate retry_after
                oldest = conn.execute(
                    text("SELECT MIN(hit_at) FROM rate_limit_hits "
                         "WHERE bucket = :b AND key = :k"),
                    {"b": bucket, "k": key},
                ).scalar()
                if oldest:
                    retry_after = max(
                        1,
                        int((oldest + timedelta(seconds=window_seconds) - now)
                            .total_seconds()),
                    )
                else:
                    retry_after = window_seconds
                return False, retry_after, 0

            # Record this attempt
            conn.execute(
                text("INSERT INTO rate_limit_hits (bucket, key, hit_at) "
                     "VALUES (:b, :k, :now)"),
                {"b": bucket, "k": key, "now": now},
            )
            return True, 0, max(0, max_attempts - count - 1)
    except Exception:
        # DB unreachable or table missing — fail open so login still works.
        import logging
        logging.getLogger(__name__).warning(
            "rate_limit.hit_db failed — allowing request", exc_info=True
        )
        return True, 0, max_attempts


def client_ip_from_request(request) -> str:
    """Best-effort source IP. Honors X-Forwarded-For (first hop) because we
    sit behind nginx, then falls back to the socket peer. Used as a rate
    limiter key for unauthenticated endpoints."""
    xff = request.headers.get("x-forwarded-for", "")
    if xff:
        return xff.split(",")[0].strip() or "unknown"
    if request.client and request.client.host:
        return request.client.host
    return "unknown"
