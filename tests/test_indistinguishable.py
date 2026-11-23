"""SPEC 11.3: unpatched and honeypatched look the same to the client. Owner: C.

Runs the real proxy (which spawns the real target and decoys) through proc.spawn,
sends attack.json's requests on one keep-alive connection, and compares.
"""
from contextlib import contextmanager
import http.client
import json
import socket

from hpsim import config, proc
from hpsim.memory import initial_heap, session_token

HOST = "127.0.0.1"
HEADER_NAMES = {"server", "date", "content-type", "content-length"}
ATTACK = [
    ("POST", "/heartbeat", {"payload": "hello", "len": 5}),
    ("POST", "/heartbeat", {"payload": "hi", "len": 64}),
    ("GET", "/session", None),
]


def control(port, method, path, body=None):
    conn = http.client.HTTPConnection(HOST, port, timeout=10)
    try:
        raw = None if body is None else json.dumps(body).encode("utf-8")
        conn.request(method, path, body=raw)
        resp = conn.getresponse()
        return resp.status, resp.read()
    finally:
        conn.close()


@contextmanager
def proxy(mode, pool=2, redact="on"):
    child, info = proc.spawn("hpsim.proxy", [
        "--mode", mode, "--redact", redact, "--pool", str(pool),
        "--idle-timeout", str(config.IDLE_TIMEOUT),
        "--session-timeout", str(config.SESSION_TIMEOUT)])
    ctl = int(info["control_port"])
    try:
        yield int(info["public_port"]), ctl
    finally:
        proc.stop(child, shutdown=lambda: control(ctl, "POST", "/shutdown"))
        assert child.poll() is not None


def events(ctl):
    status, body = control(ctl, "GET", "/events")
    assert status == 200
    return json.loads(body.decode("utf-8"))


def run_attack(mode):
    """attack.json's three requests on one connection. Records the socket object."""
    with proxy(mode) as (pub, ctl):
        conn = http.client.HTTPConnection(HOST, pub, timeout=10)
        results, socks = [], []
        try:
            for method, path, body in ATTACK:
                raw = None if body is None else json.dumps(body).encode("utf-8")
                headers = {} if raw is None else {"Content-Type": "application/json"}
                conn.request(method, path, body=raw, headers=headers)
                resp = conn.getresponse()
                data = resp.read()
                results.append((resp.status, resp.getheaders(), data))
                socks.append(conn.sock)
        finally:
            conn.close()
        log = events(ctl)
    return results, socks, log


def redaction_ranges(attacker):
    """Byte ranges in view() held by records the redaction replaces (SPEC 5.3)."""
    ranges, offset = [], config.BUF_SIZE
    for rec in initial_heap().records:
        if rec.sensitive and rec.owner != attacker:
            ranges.append((offset, offset + len(rec.value)))
        offset += len(rec.value)
    # The attacker's own S:c1 follows; it is never replaced.
    return ranges


def test_attack_is_indistinguishable():
    plain, plain_socks, _ = run_attack("unpatched")
    honey, honey_socks, honey_log = run_attack("honeypatched")
    allowed = redaction_ranges("c1")

    for (s1, h1, b1), (s2, h2, b2) in zip(plain, honey):
        d1, d2 = dict(h1), dict(h2)
        assert s1 == s2
        assert d1["Content-Type"] == d2["Content-Type"]
        assert d1["Content-Length"] == d2["Content-Length"] == str(len(b2))
        assert {k.lower() for k, _ in h1} == {k.lower() for k, _ in h2} == HEADER_NAMES
        assert len(h1) == len(h2) == 4
        assert d1["Server"] == d2["Server"] == "hp-sim"
        for name, _ in h1 + h2:
            assert not name.lower().startswith("x-hp")
        assert len(b1) == len(b2)
        diff = [i for i in range(len(b1)) if b1[i] != b2[i]]
        for i in diff:
            assert any(lo <= i < hi for lo, hi in allowed), (i, b1, b2)

    # The attack request really differed, only inside H1/H2, and was forked.
    assert plain[1][2] != honey[1][2]
    reqs = [e for e in honey_log if e["type"] == "request"]
    assert [e["handled_by"] for e in reqs] == ["target", "decoy", "decoy"]
    assert [e["forked"] for e in reqs] == [False, True, False]

    # Same client socket object before and after the fork: no reconnect.
    for socks in (plain_socks, honey_socks):
        assert socks[0] is not None
        assert all(s is socks[0] for s in socks)
    # And the proxy saw a single connection (c1) only.
    assert {e["conn_id"] for e in honey_log} == {"c1"}


def test_patched_headers_match_too():
    with proxy("patched") as (pub, _ctl):
        conn = http.client.HTTPConnection(HOST, pub, timeout=10)
        try:
            conn.request("POST", "/heartbeat", body=json.dumps({"payload": "hi", "len": 64}))
            resp = conn.getresponse()
            assert resp.read() == config.REJECT_BODY
            assert resp.status == 400
            assert {k.lower() for k, _ in resp.getheaders()} == HEADER_NAMES
        finally:
            conn.close()


def test_internal_path_is_not_forwarded():
    with proxy("honeypatched") as (pub, ctl):
        conn = http.client.HTTPConnection(HOST, pub, timeout=10)
        try:
            conn.request("GET", "/_hp/state")
            resp = conn.getresponse()
            assert (resp.status, resp.read()) == (404, b"not found\n")
            assert {k.lower() for k, _ in resp.getheaders()} == HEADER_NAMES
        finally:
            conn.close()
        reqs = [e for e in events(ctl) if e["type"] == "request"]
        assert reqs[0]["status"] == 404


def test_oversized_body_gets_400_and_closed_connection():
    with proxy("honeypatched") as (pub, _ctl):
        sock = socket.create_connection((HOST, pub), timeout=10)
        try:
            head = ("POST /heartbeat HTTP/1.1\r\nContent-Length: %d\r\n\r\n"
                    % (config.MAX_BODY + 1)).encode("ascii")
            sock.sendall(head)
            data = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break           # proxy closed the connection
                data += chunk
        finally:
            sock.close()
        assert data.startswith(b"HTTP/1.1 400 ")
        assert data.endswith(b"\r\n\r\n" + config.BAD_REQUEST_BODY)


def test_pool_exhausted_falls_back_to_patch():
    with proxy("honeypatched", pool=0) as (pub, ctl):
        conn = http.client.HTTPConnection(HOST, pub, timeout=10)
        try:
            conn.request("POST", "/heartbeat", body=json.dumps({"payload": "hi", "len": 64}))
            resp = conn.getresponse()
            assert (resp.status, resp.read()) == (400, config.REJECT_BODY)
        finally:
            conn.close()
        req = [e for e in events(ctl) if e["type"] == "request"][0]
        assert (req["handled_by"], req["forked"], req["fork_result"], req["redacted"]) \
            == ("target", False, "pool_exhausted", 0)


def test_close_event_comes_after_target_session_is_freed():
    """freed_session relies on this order: close record => S:c1 already freed."""
    with proxy("unpatched") as (pub, ctl):
        a = http.client.HTTPConnection(HOST, pub, timeout=10)
        a.request("POST", "/heartbeat", body=json.dumps({"payload": "hello", "len": 3}))
        assert a.getresponse().read() == b"hel"
        a.close()
        for _ in range(400):
            if any(e["type"] == "close" and e["conn_id"] == "c1" for e in events(ctl)):
                break
        else:
            raise AssertionError("no close event")
        b = http.client.HTTPConnection(HOST, pub, timeout=10)
        try:
            b.request("POST", "/heartbeat", body=json.dumps({"payload": "hi", "len": 128}))
            body = b.getresponse().read()
        finally:
            b.close()
        # c1's token is still in memory (unpatched reads it) - it was not removed,
        # and seq numbers order the close record before c2's request.
        assert session_token("c1") in body
        log = events(ctl)
        close = [e for e in log if e["type"] == "close" and e["conn_id"] == "c1"][0]
        req2 = [e for e in log if e["type"] == "request" and e["conn_id"] == "c2"][0]
        assert close["seq"] < req2["seq"]
