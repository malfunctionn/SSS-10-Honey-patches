"""M3: real target + decoy, fake control server, no proxy or pool needed."""

import base64
from contextlib import contextmanager
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import threading

import pytest

from hpsim import proc
from hpsim.honeypatch import (ServerState, SessionForked, checkpoint, hp_fork,
                              hp_init, hp_skip, restore, terminate, SKIPPED)
from hpsim.memory import Heap, initial_heap, new_session, session_token, view


def request(port, method, path, payload=None, conn_id=None):
    """Use direct loopback HTTP, but keep server session identity in X-HP-Conn."""
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    headers = {}
    body = None
    if conn_id is not None:
        headers["X-HP-Conn"] = conn_id
    if payload is not None:
        body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        headers["Content-Type"] = "application/json"
    try:
        conn.request(method, path, body=body, headers=headers)
        response = conn.getresponse()
        return response.status, dict(response.getheaders()), response.read()
    finally:
        conn.close()


class FakeController(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, format, *args):
        pass

    def do_POST(self):
        try:
            size = int(self.headers["Content-Length"])
            data = json.loads(self.rfile.read(size).decode("utf-8"))
            if self.path == "/fork/acquire":
                self.server.acquires.append(data)
                reply = {"ok": not self.server.fail_acquire, "decoy": "decoy-1"}
            elif self.path == "/fork/restore":
                self.server.restores.append(data)
                if self.server.fail_restore:
                    reply = {"ok": False, "reason": "restore_failed"}
                else:
                    status, _, body = request(
                        self.server.decoy_port, "POST", "/_hp/restore", data["snapshot"])
                    reply = {"ok": status == 200 and json.loads(body)["ok"] is True}
            else:
                self.send_error(404)
                return
            raw = json.dumps(reply, sort_keys=True).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(raw)
        except (KeyError, ValueError, OSError):
            self.send_error(500)


@contextmanager
def servers():
    """Start decoy first, then fake control, then target; always clean up."""
    children = []
    controller = None
    thread = None
    try:
        decoy, decoy_ready = proc.spawn(
            "hpsim.server", ["--context", "decoy", "--mode", "honeypatched",
                             "--redact", "on", "--proxy-control", "0", "--name", "decoy-1"])
        children.append(decoy)
        controller = ThreadingHTTPServer(("127.0.0.1", 0), FakeController)
        controller.daemon_threads = True
        controller.decoy_port = decoy_ready["port"]
        controller.acquires = []
        controller.restores = []
        controller.fail_acquire = False
        controller.fail_restore = False
        thread = threading.Thread(target=controller.serve_forever, daemon=True)
        thread.start()
        target, target_ready = proc.spawn(
            "hpsim.server", ["--context", "target", "--mode", "honeypatched",
                             "--redact", "on", "--proxy-control", str(controller.server_port),
                             "--name", "target"])
        children.append(target)
        yield target_ready["port"], decoy_ready["port"], controller
    finally:
        for child in reversed(children):
            proc.stop(child)
        if controller is not None:
            controller.shutdown()
            controller.server_close()
        if thread is not None:
            thread.join(timeout=3)


def _state(port):
    status, _, body = request(port, "GET", "/_hp/state")
    assert status == 200
    return json.loads(body.decode("utf-8"))


def _records(data):
    return {item["id"]: item for item in data["heap"]}


def _raw(item):
    return base64.b64decode(item["value"])


def test_m3_six_step_fork_restore():
    with servers() as (target_port, decoy_port, control):
        # 1: first legitimate request establishes the session buffer.
        status, _, body = request(target_port, "POST", "/heartbeat",
                                  {"payload": "hello", "len": 5}, "c1")
        assert (status, body) == (200, b"hello")

        # 2: patched branch forks and marks a 204 for the proxy to intercept.
        status, headers, body = request(target_port, "POST", "/heartbeat",
                                         {"payload": "hi", "len": 64}, "c1")
        assert status == 204 and headers["X-HP-Forked"] == "1" and body == b""
        assert control.acquires == [{"conn_id": "c1"}]
        assert len(control.restores) == 1
        assert control.restores[0]["redacted"] == 4
        assert control.restores[0]["conn_id"] == "c1"

        # 3: snapshot is from BEFORE applying the second heartbeat.
        snapshot = control.restores[0]["snapshot"]
        assert snapshot["version"] == 1
        assert snapshot["session"]["conn_id"] == "c1"
        assert base64.b64decode(snapshot["session"]["buf"]) == b"hello..........."
        assert snapshot["session"]["requests"] == 1
        assert base64.b64decode(snapshot["session"]["token"]) == session_token("c1")
        rec = _records(snapshot)
        assert _raw(rec["H1"]) == b"tok_a9bd82d091d5d37e"
        assert _raw(rec["H2"]) == b"tok_6d6ecbe54f5f762b"
        assert _raw(rec["H3"]) == b"tok_5beae03b78e5d643" and rec["H3"]["freed"] is True
        assert _raw(rec["H4"]) == b"key_4bbbdc254ea321a390c5"
        assert _raw(rec["S:c1"]) == session_token("c1")

        # 4: original target session is gone but its heap token remains freed.
        target_state = _state(target_port)
        assert not any(item["conn_id"] == "c1" for item in target_state["sessions"])
        assert _records(target_state)["S:c1"]["freed"] is True
        assert _raw(_records(target_state)["H1"]) == b"tok_alice_7f3a9c2e51"

        # 5: replay the exact attack on decoy, which had the earlier buffer.
        status, _, body = request(decoy_port, "POST", "/heartbeat",
                                  {"payload": "hi", "len": 64}, "c1")
        assert status == 200
        assert body == (b"hillo...........SRVMEM::"
                        b"tok_a9bd82d091d5d37e"
                        b"tok_6d6ecbe54f5f762b")
        assert len(body) == 64

        # 6: /session increments requests from 2 to 3 and keeps own token.
        status, _, body = request(decoy_port, "GET", "/session", conn_id="c1")
        assert status == 200
        assert json.loads(body.decode("utf-8")) == {
            "requests": 3, "token": "tok_8aa31bd77f104c99"
        }


def test_fork_acquire_failure_preserves_server_state():
    with servers() as (target_port, _, control):
        assert request(target_port, "POST", "/heartbeat", {"payload": "hello", "len": 5}, "c1")[0] == 200
        before = _state(target_port)
        control.fail_acquire = True
        status, _, body = request(target_port, "POST", "/heartbeat",
                                  {"payload": "hi", "len": 64}, "c1")
        assert (status, body) == (400, b"heartbeat rejected\n")
        assert _state(target_port) == before
        assert len(control.restores) == 0


def test_fork_restore_failure_preserves_server_state():
    with servers() as (target_port, _, control):
        assert request(target_port, "POST", "/heartbeat", {"payload": "hello", "len": 5}, "c1")[0] == 200
        before = _state(target_port)
        control.fail_restore = True
        status, _, body = request(target_port, "POST", "/heartbeat",
                                  {"payload": "hi", "len": 64}, "c1")
        assert (status, body) == (400, b"heartbeat rejected\n")
        assert _state(target_port) == before
        assert len(control.restores) == 1


def test_honeypatch_api_and_snapshot_errors_are_atomic():
    state = ServerState("target", "honeypatched", "on", "target", -1, initial_heap())
    s = hp_init(state, "c1")
    assert hp_init(state, "c1") is s
    assert len(state.heap.records) == 6
    snapshot, count = checkpoint(state, s)
    assert count == 4 and snapshot["version"] == 1
    assert state.heap.get("H1").value == b"tok_alice_7f3a9c2e51"
    assert hp_skip(state, lambda: "blocked") == "blocked"
    hp_fork(state, s)  # invalid port: no exception; no state change
    assert state.sessions["c1"] is s
    assert state.heap.get("S:c1").freed is False
    decoy = ServerState("decoy", "honeypatched", "on", "decoy-1", 0, Heap())
    assert hp_skip(decoy, lambda: "blocked") is SKIPPED
    restore(decoy, snapshot)
    assert list(decoy.sessions) == ["c1"]
    assert decoy.sessions["c1"].requests == 0
    assert decoy.heap.get("H3").value == b"tok_5beae03b78e5d643"
    with pytest.raises(ValueError):
        restore(decoy, {"version": 99})
    assert list(decoy.sessions) == ["c1"]
    assert decoy.heap.get("H3").value == b"tok_5beae03b78e5d643"
    terminate(state, "c1")
    terminate(state, "c1")
    assert "c1" not in state.sessions
    assert state.heap.get("S:c1").freed is True
