"""Run B in an isolated package with explicit A API doubles.

These doubles are test scaffolding, not an implementation of part A.
No production dependency files are created in the project package.
"""
import importlib
from pathlib import Path
import shutil
import sys

import pytest


CONFIG = '''
READY_TIMEOUT = 20.0
UPSTREAM_TIMEOUT = 5.0
BUF_SIZE = 16
MAX_BODY = 4096
INDEX_HTML = b"<html><body><h1>hp-sim</h1></body></html>\\n"
REJECT_BODY = b"heartbeat rejected\\n"
BAD_REQUEST_BODY = b"bad request\\n"
'''

MEMORY = '''
import base64
from dataclasses import dataclass, field
@dataclass
class Record:
    id: str
    kind: str
    owner: str
    sensitive: bool
    freed: bool
    value: bytes
@dataclass
class Heap:
    records: list = field(default_factory=list)
@dataclass
class Session:
    conn_id: str
    token: bytes
    buf: bytearray
    requests: int = 0
def initial_heap():
    return Heap([Record("H0", "banner", "server", False, False, b"SRVMEM::"),
                 Record("H1", "session_token", "alice", True, False, b"tok_alice_7f3a9c2e51"),
                 Record("H2", "session_token", "bob", True, False, b"tok_bob_c41d88e0a7f2"),
                 Record("H3", "session_token", "carol", True, True, b"tok_carol_09be3d71c6"),
                 Record("H4", "api_key", "admin", True, False, b"key_admin_5d2f90ab13c7e8")])
def view(buf, heap):
    return buf + b"".join(r.value for r in heap.records)
def heap_to_list(heap):
    return [dict(vars(r), value=base64.b64encode(r.value).decode("ascii"))
            for r in heap.records]
'''

HONEYPATCH = '''
import base64
from dataclasses import dataclass, field
import threading
from .memory import Heap, Record, Session
@dataclass
class ServerState:
    context: str
    mode: str
    redact: str
    name: str
    proxy_control_port: int
    heap: Heap
    sessions: dict = field(default_factory=dict)
    lock: object = field(default_factory=threading.Lock)
class SessionForked(Exception):
    pass
SKIPPED = object()
def hp_init(state, conn_id):
    with state.lock:
        if conn_id not in state.sessions:
            s = Session(conn_id, b"tok_8aa31bd77f104c99", bytearray(b"." * 16))
            state.sessions[conn_id] = s
            state.heap.records.append(Record("S:" + conn_id, "session_token", conn_id,
                                             True, False, s.token))
        return state.sessions[conn_id]
def terminate(state, conn_id):
    with state.lock:
        state.sessions.pop(conn_id, None)
        for rec in state.heap.records:
            if rec.id == "S:" + conn_id:
                rec.freed = True
def hp_fork(state, session):
    # Port -1 is only a test double switch, never a production behavior.
    if state.context == "target" and state.proxy_control_port == -1:
        raise SessionForked()
def hp_skip(state, block):
    return SKIPPED if state.context == "decoy" else block()
def restore(state, snapshot):
    try:
        if snapshot["version"] != 1:
            raise ValueError()
        item = snapshot["session"]
        s = Session(item["conn_id"], base64.b64decode(item["token"]),
                    bytearray(base64.b64decode(item["buf"])), item["requests"])
        heap = Heap([Record(**dict(r, value=base64.b64decode(r["value"])))
                     for r in snapshot["heap"]])
    except (KeyError, TypeError):
        raise ValueError("bad snapshot")
    with state.lock:
        state.sessions = {s.conn_id: s}
        state.heap = heap
'''

CHILD = '''
import sys
import threading
from hpsim import proc
proc.exit_when_parent_dies()
mode = sys.argv[1]
if mode == "ready":
    proc.announce_ready({"port": 12345})
elif mode == "invalid":
    print("READY []", flush=True)
elif mode == "exit":
    sys.exit(7)
threading.Event().wait()
'''


@pytest.fixture
def sandbox(tmp_path, monkeypatch):
    root = Path(__file__).resolve().parents[1]
    package = tmp_path / "hpsim"
    package.mkdir()
    for name in ("__init__.py", "proc.py", "server.py", "pool.py"):
        shutil.copyfile(root / "hpsim" / name, package / name)
    for name, source in (("config.py", CONFIG), ("memory.py", MEMORY),
                         ("honeypatch.py", HONEYPATCH)):
        with (package / name).open("w", encoding="utf-8", newline="\n") as stream:
            stream.write(source)
    with (tmp_path / "b_test_child.py").open("w", encoding="utf-8", newline="\n") as stream:
        stream.write(CHILD)
    previous = {k: v for k, v in sys.modules.items() if k == "hpsim" or k.startswith("hpsim.")}
    for key in previous:
        del sys.modules[key]
    monkeypatch.syspath_prepend(str(tmp_path))
    importlib.invalidate_caches()
    try:
        yield importlib.import_module("hpsim.proc")
    finally:
        for key in list(sys.modules):
            if key == "hpsim" or key.startswith("hpsim."):
                del sys.modules[key]
        sys.modules.update(previous)
