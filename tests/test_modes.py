import base64
from contextlib import contextmanager
import http.client
import json

import pytest


@contextmanager
def backend(proc, mode="unpatched", context="target", control=0):
    child, info = proc.spawn("hpsim.server", ["--context", context, "--mode", mode,
                                            "--name", context, "--proxy-control", str(control)])
    connection = http.client.HTTPConnection("127.0.0.1", info["port"], timeout=5)
    try:
        yield connection
    finally:
        connection.close()
        proc.stop(child)


def request(conn, method, path, data=None, conn_id="c1", raw=None):
    headers = {} if conn_id is None else {"X-HP-Conn": conn_id}
    body = json.dumps(data).encode("utf-8") if data is not None else raw
    conn.request(method, path, body=body, headers=headers)
    response = conn.getresponse()
    body = response.read()
    if method != "HEAD":
        assert int(response.getheader("Content-Length")) == len(body)
    return response.status, body, dict(response.getheaders())


@pytest.mark.parametrize("mode,expected,count", [
    ("unpatched", 200, 3), ("patched", 400, 2), ("honeypatched", 400, 2),
])
def test_two_mode_flow_and_failed_fork(sandbox, mode, expected, count):
    with backend(sandbox, mode) as conn:
        assert request(conn, "POST", "/heartbeat", {"payload": "hello", "len": 5})[:2] == (200, b"hello")
        status, body, _ = request(conn, "POST", "/heartbeat", {"payload": "hi", "len": 64})
        assert status == expected
        if expected == 200:
            assert body == b"hillo...........SRVMEM::tok_alice_7f3a9c2e51tok_bob_c41d88e0a7f2"
        else:
            assert body == b"heartbeat rejected\n"
        status, body, _ = request(conn, "GET", "/session")
        assert status == 200
        assert body == ('{"requests":%d,"token":"tok_8aa31bd77f104c99"}' % count).encode()


@pytest.mark.parametrize("data", [
    {"payload": "hi", "len": -1}, {"payload": "hi", "len": "3"},
    {"payload": "hi", "len": True}, {"payload": "x" * 17, "len": 1},
    {"payload": "x"}, [], {"payload": 3, "len": 1},
    {"payload": "\uac00" * 6, "len": 1},
])
@pytest.mark.parametrize("mode", ["unpatched", "patched", "honeypatched"])
def test_bad_inputs_do_not_count(sandbox, mode, data):
    with backend(sandbox, mode) as conn:
        before = json.loads(request(conn, "GET", "/_hp/state", conn_id=None)[1])
        status, body, headers = request(conn, "POST", "/heartbeat", data)
        assert (status, body, headers["Content-Type"]) == (
            400, b"bad request\n", "application/octet-stream")
        after = json.loads(request(conn, "GET", "/_hp/state", conn_id=None)[1])
        assert after == before
        assert json.loads(request(conn, "GET", "/session")[1])["requests"] == 1


@pytest.mark.parametrize("mode", ["unpatched", "patched", "honeypatched"])
@pytest.mark.parametrize("raw", [b"not json", b"x" * 4097, b"\xff"])
def test_raw_errors_leave_initial_state_unchanged(sandbox, mode, raw):
    with backend(sandbox, mode) as conn:
        before = json.loads(request(conn, "GET", "/_hp/state", conn_id=None)[1])
        assert request(conn, "POST", "/heartbeat", raw=raw)[:2] == (400, b"bad request\n")
        # Oversized bodies close the HTTP connection; http.client reconnects
        # only for this internal inspection, using the same logical conn_id.
        after = json.loads(request(conn, "GET", "/_hp/state", conn_id=None)[1])
        assert after == before


def test_missing_header(sandbox):
    with backend(sandbox) as conn:
        assert request(conn, "GET", "/session", conn_id=None)[0] == 400


@pytest.mark.parametrize("method", ["PUT", "OPTIONS", "CUSTOM", "HEAD"])
def test_unsupported_method(sandbox, method):
    with backend(sandbox) as conn:
        status, body, headers = request(conn, method, "/session")
        assert (status, headers["Content-Type"]) == (404, "text/plain")
        assert int(headers["Content-Length"]) == len(b"not found\n")
        assert body == (b"" if method == "HEAD" else b"not found\n")


def test_index_clamp_and_close(sandbox):
    with backend(sandbox) as conn:
        assert request(conn, "GET", "/index.html")[:2] == (200, sandbox.config.INDEX_HTML)
        assert len(request(conn, "POST", "/heartbeat", {"payload": "hi", "len": 1000})[1]) == 128
        assert request(conn, "POST", "/_hp/close", {"conn_id": "c1"}, conn_id=None)[0] == 200
        state = json.loads(request(conn, "GET", "/_hp/state", conn_id=None)[1])
        assert state["sessions"] == []
        assert state["heap"][-1]["freed"] is True


def test_fork_marker(sandbox):
    with backend(sandbox, "honeypatched", control=-1) as conn:
        status, body, headers = request(conn, "POST", "/heartbeat", {"payload": "hi", "len": 64})
        assert (status, body, headers["X-HP-Forked"]) == (204, b"", "1")
        state = json.loads(request(conn, "GET", "/_hp/state")[1])
        assert state["sessions"][0]["requests"] == 0
        assert base64.b64decode(state["sessions"][0]["buf"]) == b"." * 16


def test_decoy_restore_replay_and_restriction(sandbox):
    b64 = lambda value: base64.b64encode(value).decode("ascii")
    token = "tok_8aa31bd77f104c99"
    snapshot = {"version": 1, "session": {"conn_id": "c1", "token": b64(token.encode("ascii")),
                "buf": b64(b"hello..........."), "requests": 1},
                "heap": [{"id": "H0", "kind": "banner", "owner": "server",
                          "sensitive": False, "freed": False, "value": b64(b"SRVMEM::")}]}
    with backend(sandbox, "honeypatched", "decoy") as conn:
        assert request(conn, "GET", "/session")[0] == 503
    with backend(sandbox, "honeypatched", "decoy") as conn:
        assert request(conn, "POST", "/_hp/restore", {"version": 2})[0] == 400
        assert request(conn, "POST", "/_hp/restore", snapshot)[0] == 200
        partial = dict(snapshot, heap=[{"id": "H0", "value": b64(b"partial")}])
        assert request(conn, "POST", "/_hp/restore", partial)[:2] == (400, b'{"ok":false}')
        state = json.loads(request(conn, "GET", "/_hp/state")[1])
        assert state["heap"] == snapshot["heap"]
        assert request(conn, "POST", "/heartbeat", {"payload": "hi", "len": 64})[:2] == (200, b"hillo...........SRVMEM::")
        assert json.loads(request(conn, "GET", "/session")[1]) == {"requests": 3, "token": token}
        assert request(conn, "GET", "/session", conn_id="c2")[0] == 503
