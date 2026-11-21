"""Session creation, safe checkpoint/redaction and decoy restore (SPEC 7.4)."""

from dataclasses import dataclass, field
import http.client
import json
import threading
from typing import Callable

from . import config
from .memory import (Heap, Session, from_snapshot, new_session, redact,
                     session_record, to_snapshot)


@dataclass
class ServerState:
    context: str
    mode: str
    redact: str
    name: str
    proxy_control_port: int
    heap: Heap
    sessions: dict = field(default_factory=dict)
    lock: threading.Lock = field(default_factory=threading.Lock)


class SessionForked(Exception):
    """Handled by server.py as the internal 204 + X-HP-Forked marker."""


SKIPPED = object()


def hp_init(state: ServerState, conn_id: str) -> Session:
    """Target-only: find or create one session and its heap record under lock."""
    if state.context != "target":
        raise ValueError("hp_init is target-only")
    with state.lock:
        current = state.sessions.get(conn_id)
        if current is not None:
            return current
        session = new_session(conn_id)
        # Never publish a session unless its token record was appended.
        state.heap.append(session_record(session))
        state.sessions[conn_id] = session
        return session


def checkpoint(state: ServerState, session: Session) -> tuple:
    """Snapshot one attacking session and a redacted heap, without mutating state."""
    with state.lock:
        sanitized_heap, count = redact(state.heap, session.conn_id, state.redact)
        # Snapshot data is serialized to strings while the lock is held.
        snapshot = to_snapshot(session, sanitized_heap)
    return snapshot, count


def terminate(state: ServerState, conn_id: str) -> None:
    """Remove a live session but keep its token in freed heap memory."""
    with state.lock:
        state.sessions.pop(conn_id, None)
        record = state.heap.get("S:" + conn_id)
        if record is not None:
            record.freed = True


def restore(state: ServerState, snapshot: dict) -> None:
    """Decoy-only atomic restore; validation failure leaves state unchanged."""
    if state.context != "decoy":
        raise ValueError("restore is decoy-only")
    session, heap = from_snapshot(snapshot)
    with state.lock:
        state.heap = heap
        state.sessions = {session.conn_id: session}


def _control_post(port: int, path: str, payload: dict) -> bool:
    """A failed control request is a failed fork, never an exception to server.py."""
    conn = None
    try:
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=config.UPSTREAM_TIMEOUT)
        raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        conn.request("POST", path, body=raw,
                     headers={"Content-Type": "application/json", "Content-Length": str(len(raw))})
        response = conn.getresponse()
        body = response.read()
        if response.status != 200:
            return False
        result = json.loads(body.decode("utf-8"))
        return isinstance(result, dict) and result.get("ok") is True
    except (OSError, http.client.HTTPException, ValueError, TypeError, OverflowError):
        return False
    finally:
        if conn is not None:
            conn.close()


def hp_fork(state: ServerState, session: Session) -> None:
    """Acquire, checkpoint, restore, then terminate; never hold the lock over HTTP."""
    if state.context == "decoy":
        return
    if not _control_post(state.proxy_control_port, "/fork/acquire", {"conn_id": session.conn_id}):
        return
    snapshot, count = checkpoint(state, session)
    if not _control_post(state.proxy_control_port, "/fork/restore",
                         {"conn_id": session.conn_id, "snapshot": snapshot, "redacted": count}):
        return
    terminate(state, session.conn_id)
    raise SessionForked()


def hp_skip(state: ServerState, block: Callable):
    return SKIPPED if state.context == "decoy" else block()
