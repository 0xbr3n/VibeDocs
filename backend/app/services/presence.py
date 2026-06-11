"""
Live-collaboration backend: presence + soft locks.

Two concerns, one module so the WebSocket broadcasts can include both:

* Presence — who is currently viewing a given report. Tracks WebSocket
  connections per report_id and lets clients see each other.
* Soft locks — advisory locks on individual resources (findings, sections).
  Held for LOCK_TTL_SECONDS and refreshed by a keepalive. Soft means the
  server won't *reject* writes from non-holders (existing endpoints still
  work) — it just *advertises* who's editing what so the UI can warn.

In-memory, single-process. Acceptable for the existing single-replica
uvicorn deployment. Swap to Redis pub/sub + Redis TTLs if scaled out.
"""
from __future__ import annotations
import asyncio
import secrets
from datetime import datetime, timedelta
from typing import Optional

from fastapi import WebSocket


LOCK_TTL_SECONDS = 120              # auto-release if no refresh in this window
PRESENCE_IDLE_SECONDS = 60          # presence falls off after this without ping
PALETTE = [                         # cycle through stable colours per user
    "#7C5CFC", "#2563eb", "#a855f7", "#ec4899", "#f97316",
    "#0ea5e9", "#10b981", "#eab308", "#ef4444", "#14b8a6",
]


# ============================================================
# Presence registry — connections per report
# ============================================================

class _Connection:
    """One open WebSocket plus the user metadata advertised to peers."""

    def __init__(self, ws: WebSocket, user_id: int, username: str,
                 full_name: Optional[str], report_id: int):
        self.ws = ws
        self.user_id = user_id
        self.username = username
        self.full_name = full_name or username
        self.report_id = report_id
        self.color = PALETTE[user_id % len(PALETTE)]
        self.joined_at = datetime.utcnow()
        self.last_seen = datetime.utcnow()
        # client may advertise "I'm looking at finding 42" via a focus message
        self.focus: Optional[dict] = None

    def info(self) -> dict:
        return {
            "user_id": self.user_id,
            "username": self.username,
            "full_name": self.full_name,
            "color": self.color,
            "joined_at": self.joined_at.isoformat(),
            "focus": self.focus,
        }


# report_id -> set of _Connection
_rooms: dict[int, set[_Connection]] = {}
_rooms_lock = asyncio.Lock()


async def connect(ws: WebSocket, user_id: int, username: str,
                  full_name: Optional[str], report_id: int) -> _Connection:
    conn = _Connection(ws, user_id, username, full_name, report_id)
    async with _rooms_lock:
        _rooms.setdefault(report_id, set()).add(conn)
    await _broadcast_presence(report_id)
    return conn


async def disconnect(conn: _Connection) -> None:
    async with _rooms_lock:
        room = _rooms.get(conn.report_id)
        if room and conn in room:
            room.discard(conn)
        if room is not None and not room:
            _rooms.pop(conn.report_id, None)
    # Releasing any locks this connection was holding is the caller's job
    # (the WS handler does it after disconnect).
    await _broadcast_presence(conn.report_id)


def presence_snapshot(report_id: int) -> list[dict]:
    """Current list of users in the room (deduplicated by user_id — the same
    person opening two tabs only appears once in the badge bar)."""
    conns = list(_rooms.get(report_id, set()))
    seen: dict[int, _Connection] = {}
    for c in conns:
        # keep the most recent connection for each user
        if c.user_id not in seen or c.last_seen > seen[c.user_id].last_seen:
            seen[c.user_id] = c
    return [c.info() for c in seen.values()]


async def update_focus(conn: _Connection, focus: Optional[dict]) -> None:
    conn.focus = focus
    conn.last_seen = datetime.utcnow()
    await _broadcast_presence(conn.report_id)


def touch(conn: _Connection) -> None:
    """Mark a connection as alive RIGHT NOW. Called from the ping handler so
    the idle reaper doesn't drop connections that are still actively
    pinging — but where the user never moves focus."""
    conn.last_seen = datetime.utcnow()


async def remove_user_from_room(user_id: int, report_id: int) -> int:
    """Force-drop every connection a user holds inside one specific room.

    Called by the explicit "I'm leaving" REST endpoint (sendBeacon target)
    so the user disappears from the badge bar the moment they navigate
    away — instead of lingering for up to PRESENCE_IDLE_SECONDS while the
    reaper notices the stale ping.

    Returns how many connections were dropped so the caller can decide
    whether to also release locks held by the user.
    """
    dropped: list[_Connection] = []
    async with _rooms_lock:
        room = _rooms.get(report_id)
        if not room:
            return 0
        for c in list(room):
            if c.user_id == user_id:
                room.discard(c)
                dropped.append(c)
        if not room:
            _rooms.pop(report_id, None)
    # Close any open sockets so the WS handler's finally-block doesn't try
    # to double-drop them. Best-effort — the user is leaving regardless.
    for c in dropped:
        try:
            await c.ws.close(code=1000, reason="left")
        except Exception:
            pass
    if dropped:
        await _broadcast_presence(report_id)
    return len(dropped)


async def reap_idle() -> None:
    """Drop connections whose `last_seen` is older than PRESENCE_IDLE_SECONDS.

    A background task (started on app startup) calls this every few
    seconds. It's the safety net for the case where `pagehide` / the
    sendBeacon leave call NEVER fire — e.g. the browser crashed, the OS
    killed the tab in the background, mobile data dropped mid-session.
    Without this, presence sticks forever after the WebSocket goes silent.
    """
    cutoff = datetime.utcnow() - timedelta(seconds=PRESENCE_IDLE_SECONDS)
    stale: list[_Connection] = []
    affected_rooms: set[int] = set()
    async with _rooms_lock:
        for rid, room in list(_rooms.items()):
            for c in list(room):
                if c.last_seen < cutoff:
                    room.discard(c)
                    stale.append(c)
                    affected_rooms.add(rid)
            if not room:
                _rooms.pop(rid, None)
    for c in stale:
        try:
            await c.ws.close(code=1001, reason="idle")
        except Exception:
            pass
    for rid in affected_rooms:
        await _broadcast_presence(rid)


_reaper_task: Optional[asyncio.Task] = None


async def start_reaper(interval_seconds: int = 15) -> None:
    """Spawn the idle-reaper as a background task. Safe to call more than
    once — only the first call wins."""
    global _reaper_task
    if _reaper_task is not None and not _reaper_task.done():
        return

    async def _loop() -> None:
        while True:
            try:
                await asyncio.sleep(interval_seconds)
                await reap_idle()
            except asyncio.CancelledError:
                raise
            except Exception:
                # Reaper must never die. Swallow and try again next tick.
                pass

    _reaper_task = asyncio.create_task(_loop(), name="presence-reaper")


async def _broadcast_presence(report_id: int) -> None:
    payload = {
        "type": "presence",
        "report_id": report_id,
        "users": presence_snapshot(report_id),
    }
    await _broadcast(report_id, payload)


# ============================================================
# Soft locks
# ============================================================

class _Lock:
    def __init__(self, resource_type: str, resource_id: int,
                 user_id: int, username: str, report_id: int):
        self.token = secrets.token_urlsafe(16)
        self.resource_type = resource_type
        self.resource_id = resource_id
        self.user_id = user_id
        self.username = username
        self.report_id = report_id
        self.acquired_at = datetime.utcnow()
        self.expires_at = self.acquired_at + timedelta(seconds=LOCK_TTL_SECONDS)

    def to_dict(self) -> dict:
        return {
            "resource_type": self.resource_type,
            "resource_id": self.resource_id,
            "user_id": self.user_id,
            "username": self.username,
            "report_id": self.report_id,
            "acquired_at": self.acquired_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "ttl_seconds": int((self.expires_at - datetime.utcnow()).total_seconds()),
        }


# (resource_type, resource_id) -> _Lock
_locks: dict[tuple[str, int], _Lock] = {}
_locks_lock = asyncio.Lock()


def _expire_locks() -> None:
    """Drop locks whose TTL has passed. Called on every read/write path."""
    now = datetime.utcnow()
    dead = [k for k, l in _locks.items() if l.expires_at < now]
    for k in dead:
        _locks.pop(k, None)


async def try_acquire(resource_type: str, resource_id: int,
                       user_id: int, username: str,
                       report_id: int) -> tuple[bool, dict]:
    """Try to take the lock. If already held by someone else, return
    (False, current_holder_info). If held by us, refresh TTL.
    """
    async with _locks_lock:
        _expire_locks()
        key = (resource_type, resource_id)
        existing = _locks.get(key)
        if existing and existing.user_id != user_id:
            return False, existing.to_dict()
        if existing and existing.user_id == user_id:
            existing.expires_at = datetime.utcnow() + timedelta(seconds=LOCK_TTL_SECONDS)
            lock = existing
        else:
            lock = _Lock(resource_type, resource_id, user_id, username, report_id)
            _locks[key] = lock
    # broadcast lock state to the room (outside the lock guard, deliberate)
    await _broadcast_lock_change(report_id)
    return True, lock.to_dict()


async def release(resource_type: str, resource_id: int, user_id: int) -> bool:
    """Release a lock only if the caller owns it. Returns True on success,
    False if missing or not owned by user_id.
    """
    async with _locks_lock:
        _expire_locks()
        key = (resource_type, resource_id)
        existing = _locks.get(key)
        if not existing or existing.user_id != user_id:
            return False
        report_id = existing.report_id
        _locks.pop(key, None)
    await _broadcast_lock_change(report_id)
    return True


async def release_all_for_user(user_id: int) -> set[int]:
    """Drop every lock held by this user. Used when a WebSocket disconnects
    so abandoned editor sessions don't strand resources. Returns the set of
    affected report_ids so the caller can broadcast updates.
    """
    affected: set[int] = set()
    async with _locks_lock:
        _expire_locks()
        for key, lock in list(_locks.items()):
            if lock.user_id == user_id:
                affected.add(lock.report_id)
                _locks.pop(key, None)
    for rid in affected:
        await _broadcast_lock_change(rid)
    return affected


def locks_for_report(report_id: int) -> list[dict]:
    _expire_locks()
    return [l.to_dict() for l in _locks.values() if l.report_id == report_id]


async def _broadcast_lock_change(report_id: int) -> None:
    payload = {
        "type": "locks",
        "report_id": report_id,
        "locks": locks_for_report(report_id),
    }
    await _broadcast(report_id, payload)


# ============================================================
# Broadcast helper (used by both presence + locks)
# ============================================================

async def _broadcast(report_id: int, payload: dict) -> None:
    conns = list(_rooms.get(report_id, set()))
    dead: list[_Connection] = []
    for c in conns:
        try:
            await c.ws.send_json(payload)
        except Exception:
            # client gone — schedule removal
            dead.append(c)
    if dead:
        async with _rooms_lock:
            room = _rooms.get(report_id)
            if room:
                for c in dead:
                    room.discard(c)
                if not room:
                    _rooms.pop(report_id, None)
