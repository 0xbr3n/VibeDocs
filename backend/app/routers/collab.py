"""
Live-collaboration HTTP + WebSocket endpoints.

WebSocket
  GET /ws/reports/{rid}/presence
    Cookie-authenticated (same access_token cookie the rest of the app uses).
    Server pushes:
      {"type":"presence", "users":[{user_id, username, full_name, color, focus}, ...]}
      {"type":"locks",    "locks":[{resource_type, resource_id, user_id, username, expires_at}, ...]}
    Client sends:
      {"type":"focus", "resource_type":"finding"|"section"|null, "resource_id":N|null}
      {"type":"ping"}    -- keepalive only; server replies with current presence
      {"type":"acquire", "resource_type":..., "resource_id":...}
      {"type":"release", "resource_type":..., "resource_id":...}

REST (fallback / non-WS usage)
  POST   /api/locks/{resource_type}/{resource_id}/acquire  body: {report_id}
  POST   /api/locks/{resource_type}/{resource_id}/refresh  body: {report_id}
  DELETE /api/locks/{resource_type}/{resource_id}
  GET    /api/reports/{rid}/locks            current locks for a report
  GET    /api/reports/{rid}/presence         current presence snapshot
"""
from typing import Optional

from fastapi import (
    APIRouter, Depends, HTTPException, WebSocket, WebSocketDisconnect,
    Query, Body,
)
from jose import JWTError, jwt
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ..database import get_db, SessionLocal
from ..models import User, Report, AccessLevel
from ..config import settings
from ..auth import get_current_user
from ..services import presence as presence_svc
from .permissions import effective_access, require_access


router = APIRouter(tags=["collab"])

ALLOWED_RESOURCE_TYPES = {"finding", "section", "report_details"}


def _validate_resource_type(rt: str) -> None:
    if rt not in ALLOWED_RESOURCE_TYPES:
        raise HTTPException(400, f"Unknown resource_type. Allowed: {sorted(ALLOWED_RESOURCE_TYPES)}")


# ============================================================
# WebSocket
# ============================================================

def _ws_authenticate(websocket: WebSocket) -> Optional[tuple[int, str, Optional[str]]]:
    """Decode the JWT from the access_token cookie. Returns
    (user_id, username, full_name) or None.

    The WS handshake doesn't carry a custom auth header from browsers, but
    cookies are sent automatically, so we lean on the same access_token
    cookie the rest of the app uses.
    """
    token = websocket.cookies.get("access_token")
    if not token:
        # Authorization: Bearer <token> as a fallback for non-browser clients
        auth_h = websocket.headers.get("authorization", "")
        if auth_h.lower().startswith("bearer "):
            parts = auth_h.split(None, 1)
            token = parts[1] if len(parts) == 2 else None
    if not token:
        return None
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
    except JWTError:
        return None
    username = payload.get("sub")
    if not username:
        return None
    # Need a DB lookup to map username -> user_id and resolve full_name + active
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.username == username,
                                     User.is_active == True).first()  # noqa: E712
        if not user:
            return None
        return user.id, user.username, user.full_name
    finally:
        db.close()


@router.websocket("/ws/reports/{rid}/presence")
async def presence_ws(websocket: WebSocket, rid: int):
    """Per-report presence channel. Verifies the user has at least `view`
    access on the report before accepting.
    """
    auth = _ws_authenticate(websocket)
    if not auth:
        await websocket.close(code=4401, reason="not authenticated")
        return
    user_id, username, full_name = auth

    # Authorisation: must have view+ access on the report
    db = SessionLocal()
    try:
        report = db.get(Report, rid)
        if not report:
            await websocket.close(code=4404, reason="report not found")
            return
        user = db.get(User, user_id)
        if not user or effective_access(db, user, report) is None:
            await websocket.close(code=4403, reason="no access")
            return
    finally:
        db.close()

    await websocket.accept()
    conn = await presence_svc.connect(websocket, user_id, username, full_name, rid)

    # Push the initial locks snapshot immediately so the client doesn't
    # need to wait for the first change event.
    try:
        await websocket.send_json({
            "type": "locks",
            "report_id": rid,
            "locks": presence_svc.locks_for_report(rid),
        })
    except Exception:
        pass

    try:
        while True:
            msg = await websocket.receive_json()
            mtype = (msg or {}).get("type")
            if mtype == "ping":
                # CRITICAL — refresh the per-connection liveness clock so the
                # idle reaper doesn't drop this connection. The old code
                # wrote `last_seen_at = None` (wrong attribute name) which
                # meant pings never actually advertised "I'm still here",
                # and the reaper would tear down every still-active session
                # after PRESENCE_IDLE_SECONDS.
                presence_svc.touch(conn)
                await websocket.send_json({"type": "pong"})
            elif mtype == "focus":
                rt = msg.get("resource_type")
                rid_focus = msg.get("resource_id")
                if rt is None or rid_focus is None:
                    await presence_svc.update_focus(conn, None)
                else:
                    if rt in ALLOWED_RESOURCE_TYPES:
                        try:
                            rid_focus_int = int(rid_focus)
                        except (TypeError, ValueError):
                            rid_focus_int = None
                        if rid_focus_int is not None:
                            await presence_svc.update_focus(conn,
                                {"resource_type": rt, "resource_id": rid_focus_int})
            elif mtype == "acquire":
                rt = msg.get("resource_type"); rid_lock = msg.get("resource_id")
                if rt in ALLOWED_RESOURCE_TYPES and rid_lock is not None:
                    try:
                        rid_lock_int = int(rid_lock)
                    except (TypeError, ValueError):
                        rid_lock_int = None
                    if rid_lock_int is not None:
                        ok, info = await presence_svc.try_acquire(
                            rt, rid_lock_int, user_id, username, rid,
                        )
                        await websocket.send_json({"type": "acquire_result",
                                                   "ok": ok, "lock": info})
            elif mtype == "release":
                rt = msg.get("resource_type"); rid_lock = msg.get("resource_id")
                if rt in ALLOWED_RESOURCE_TYPES and rid_lock is not None:
                    try:
                        rid_lock_int = int(rid_lock)
                    except (TypeError, ValueError):
                        rid_lock_int = None
                    if rid_lock_int is not None:
                        await presence_svc.release(rt, rid_lock_int, user_id)
            # any other type is silently ignored — be forward-compatible
    except WebSocketDisconnect:
        pass
    except Exception:
        # Don't let one bad message take down the connection silently —
        # but also don't crash the server.
        pass
    finally:
        await presence_svc.disconnect(conn)
        # Release any locks this user was holding only if no other tab of
        # the same user is still connected.
        same_user_still_here = any(
            c.user_id == user_id
            for c in presence_svc._rooms.get(rid, set())  # noqa: SLF001
        )
        if not same_user_still_here:
            await presence_svc.release_all_for_user(user_id)


# ============================================================
# REST API (works without WebSockets, used as fallback)
# ============================================================

class LockBody(BaseModel):
    report_id: int


def _require_report_access(db: Session, user: User, report_id: int,
                            need: AccessLevel = AccessLevel.view) -> Report:
    report = db.get(Report, report_id)
    if not report:
        raise HTTPException(404, "Report not found")
    require_access(db, user, report, need=need)
    return report


@router.post("/api/locks/{resource_type}/{resource_id}/acquire")
async def rest_acquire(resource_type: str, resource_id: int,
                       body: LockBody,
                       db: Session = Depends(get_db),
                       user: User = Depends(get_current_user)):
    _validate_resource_type(resource_type)
    _require_report_access(db, user, body.report_id, need=AccessLevel.edit)
    ok, info = await presence_svc.try_acquire(
        resource_type, resource_id, user.id, user.username, body.report_id,
    )
    if not ok:
        # 409 + holder info so the UI can show "held by <username>"
        raise HTTPException(409, detail={"error": "locked", "holder": info})
    return {"ok": True, "lock": info}


@router.post("/api/locks/{resource_type}/{resource_id}/refresh")
async def rest_refresh(resource_type: str, resource_id: int,
                       body: LockBody,
                       db: Session = Depends(get_db),
                       user: User = Depends(get_current_user)):
    """Refresh = re-acquire. If someone else has it, you'll get 409. If you
    have it, the TTL bumps."""
    _validate_resource_type(resource_type)
    _require_report_access(db, user, body.report_id, need=AccessLevel.edit)
    ok, info = await presence_svc.try_acquire(
        resource_type, resource_id, user.id, user.username, body.report_id,
    )
    if not ok:
        raise HTTPException(409, detail={"error": "locked", "holder": info})
    return {"ok": True, "lock": info}


@router.delete("/api/locks/{resource_type}/{resource_id}")
async def rest_release(resource_type: str, resource_id: int,
                       user: User = Depends(get_current_user)):
    _validate_resource_type(resource_type)
    released = await presence_svc.release(resource_type, resource_id, user.id)
    return {"ok": True, "released": released}


@router.get("/api/reports/{rid}/locks")
def rest_locks(rid: int,
               db: Session = Depends(get_db),
               user: User = Depends(get_current_user)):
    _require_report_access(db, user, rid, need=AccessLevel.view)
    return {"report_id": rid, "locks": presence_svc.locks_for_report(rid)}


@router.get("/api/reports/{rid}/presence")
def rest_presence(rid: int,
                  db: Session = Depends(get_db),
                  user: User = Depends(get_current_user)):
    _require_report_access(db, user, rid, need=AccessLevel.view)
    return {"report_id": rid, "users": presence_svc.presence_snapshot(rid)}


@router.post("/api/reports/{rid}/presence/leave")
async def rest_presence_leave(rid: int,
                              db: Session = Depends(get_db),
                              user: User = Depends(get_current_user)):
    """Explicit "I'm leaving this report" signal.

    Target for `navigator.sendBeacon` from the client when the page is
    being unloaded (the `pagehide` event). Beacons are guaranteed to be
    delivered by the browser even during unload, where a regular `fetch`
    would be cancelled — and far more reliable than relying on the WS
    close handshake to finish before the next page steals attention.

    Drops every connection this user is holding in the room, releases
    any locks they were the sole holder of, and re-broadcasts presence
    so other viewers see them disappear immediately rather than waiting
    up to PRESENCE_IDLE_SECONDS for the idle reaper.
    """
    _require_report_access(db, user, rid, need=AccessLevel.view)
    dropped = await presence_svc.remove_user_from_room(user.id, rid)
    # Only release locks if this was the user's LAST connection across
    # any room (they may still be editing the same finding from another
    # tab on another report — unlikely but cheap to check).
    still_present_anywhere = any(
        c.user_id == user.id
        for room in presence_svc._rooms.values()  # noqa: SLF001
        for c in room
    )
    if not still_present_anywhere:
        await presence_svc.release_all_for_user(user.id)
    return {"ok": True, "dropped": dropped}
