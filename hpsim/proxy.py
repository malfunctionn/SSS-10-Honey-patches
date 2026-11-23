"""Reverse proxy and fork coordinator (SPEC 9). Owner: C.

    python -m hpsim.proxy --mode M --redact R --pool N --idle-timeout T --session-timeout T

Two ThreadingHTTPServer instances on 127.0.0.1:
  - public port: one handler per client connection, forwards to the
    connection's current backend (target, or the decoy it was forked to).
  - control port: /fork/acquire, /fork/restore, /events, /shutdown. The target
    calls this port *while* a public request is still in flight, so it must be
    a threading server too.

12th-week scope (M4): no SESSION_TIMEOUT check, no 502 path, no GET /pool.
Only hpsim.config, hpsim.proc and hpsim.pool are imported (SPEC 3.1).
"""
import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import http.client
import json
import os
import threading
import time
from typing import Optional

from . import config, proc
from .pool import Pool

HOST = "127.0.0.1"
MODES = ("unpatched", "patched", "honeypatched")
REDACT_POLICIES = ("on", "off", "nofreed")
NOT_FOUND_BODY = b"not found\n"


class UpstreamError(Exception):
    """Backend unreachable, timed out or answered something unusable."""


# ---------------------------------------------------------------- shared state

class ProxyState:
    """Everything the two servers share. Protected by one lock that is never
    held across HTTP calls, proc calls or pool calls (SPEC 15.5, 8.1)."""

    def __init__(self, mode: str, redact: str, idle_timeout: float,
                 session_timeout: float) -> None:
        self.mode = mode
        self.redact = redact
        self.idle_timeout = idle_timeout
        self.session_timeout = session_timeout     # M6: not enforced in M4
        self.lock = threading.Lock()
        self.events = []
        self.seq = 0
        self.conn_count = 0
        # conn_id -> {"result": "acquired"|"ok"|"pool_exhausted"|"restore_failed",
        #             "decoy": Decoy or None, "redacted": int}
        self.attempts = {}
        self.target_proc = None
        self.target_port = 0
        self.pool = None                 # type: Optional[Pool]
        self._stopped = False

    def next_conn_id(self) -> str:
        with self.lock:
            self.conn_count += 1
            return "c%d" % self.conn_count

    def add_event(self, record: dict) -> None:
        with self.lock:
            self.seq += 1
            event = {"type": record.pop("type"), "seq": self.seq}
            event.update(record)
            self.events.append(event)

    def events_snapshot(self) -> list:
        with self.lock:
            return [dict(e) for e in self.events]

    def set_attempt(self, conn_id: str, attempt: Optional[dict]) -> Optional[dict]:
        """Replace this connection's fork attempt; return the previous one."""
        with self.lock:
            old = self.attempts.pop(conn_id, None)
            if attempt is not None:
                self.attempts[conn_id] = attempt
            return old

    def get_attempt(self, conn_id: str) -> Optional[dict]:
        with self.lock:
            return self.attempts.get(conn_id)

    def release(self, decoy) -> None:
        if decoy is not None and self.pool is not None:
            self.pool.release(decoy)

    def stop_children(self) -> None:
        """Stop target and every decoy. Safe to call more than once."""
        with self.lock:
            if self._stopped:
                return
            self._stopped = True
            target, pool = self.target_proc, self.pool
        if pool is not None:
            pool.close()
        if target is not None:
            proc.stop(target)


# ---------------------------------------------------------------- HTTP helpers

def upstream_call(port: int, method: str, path: str, body: bytes,
                  headers: dict) -> tuple:
    """One request on a fresh connection. Returns (status, headers, body).
    Only the given headers are sent (no Host, no Accept-Encoding)."""
    conn = http.client.HTTPConnection(HOST, port, timeout=config.UPSTREAM_TIMEOUT)
    try:
        conn.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
        for key, value in headers.items():
            conn.putheader(key, value)
        conn.endheaders(body if body else None)
        resp = conn.getresponse()
        data = resp.read()
        return resp.status, resp, data
    except (OSError, http.client.HTTPException, ValueError) as exc:
        raise UpstreamError(str(exc)) from exc
    finally:
        conn.close()


def json_bytes(data) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")


def post_json(port: int, path: str, data) -> tuple:
    raw = json_bytes(data)
    status, _resp, body = upstream_call(
        port, "POST", path, raw,
        {"Content-Type": "application/json", "Content-Length": str(len(raw))})
    return status, body


def parse_content_length(handler: BaseHTTPRequestHandler) -> Optional[int]:
    """Content-Length as an int, 0 if absent, None if the framing is unusable."""
    if handler.headers.get("Transfer-Encoding") is not None:
        return None
    values = handler.headers.get_all("Content-Length", [])
    if not values:
        return 0
    if len(values) != 1:
        return None
    raw = values[0].strip()
    if not raw.isascii() or not raw.isdecimal():
        return None
    return int(raw)


class QuietHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "hp-sim"
    sys_version = ""

    def log_message(self, format, *args):
        pass

    def version_string(self):
        # Default would be "hp-sim " (server_version + " " + sys_version).
        return self.server_version

    def send_plain(self, status: int, body: bytes, content_type: str) -> None:
        """Exactly four headers: Server, Date (send_response), Content-Type, Content-Length."""
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body and self.command != "HEAD":
            self.wfile.write(body)
        self.wfile.flush()


# ---------------------------------------------------------------- public port

class PublicHandler(QuietHandler):
    """One instance per client TCP connection (SPEC 9.1)."""

    def setup(self):
        self.proxy = self.server.proxy          # type: ProxyState
        self.timeout = self.proxy.idle_timeout  # read by StreamRequestHandler.setup
        self.conn_id = self.proxy.next_conn_id()
        self.decoy = None                       # set once this connection is forked
        super().setup()

    def finish(self):
        try:
            super().finish()
        except OSError:
            pass
        finally:
            self.cleanup()

    def cleanup(self) -> None:
        """Release the decoy, or close the target session and wait for its reply.
        The close event is logged only after that (SPEC 9.3)."""
        leftover = self.proxy.set_attempt(self.conn_id, None)
        if leftover is not None and leftover.get("decoy") is not self.decoy:
            self.proxy.release(leftover.get("decoy"))
        if self.decoy is not None:
            self.proxy.release(self.decoy)
        else:
            try:
                post_json(self.proxy.target_port, "/_hp/close", {"conn_id": self.conn_id})
            except UpstreamError:
                pass
        self.proxy.add_event({"type": "close", "conn_id": self.conn_id})

    # Any method goes through the same path; BaseHTTPRequestHandler reports an
    # unknown method as 501 via send_error, which we turn into a forward.
    def send_error(self, code, message=None, explain=None):
        if code == 501 and getattr(self, "command", None):
            self.handle_request()
            return
        self.close_connection = True
        body = NOT_FOUND_BODY if code == 404 else config.BAD_REQUEST_BODY
        try:
            self.send_plain(code, body, "text/plain")
        except OSError:
            pass

    def do_GET(self):
        self.handle_request()

    def do_POST(self):
        self.handle_request()

    def handle_request(self) -> None:
        start = time.perf_counter()
        event = {"type": "request", "conn_id": self.conn_id, "method": self.command,
                 "path": self.path, "handled_by": "proxy", "backend": "proxy",
                 "forked": False, "fork_result": "none", "redacted": 0}

        length = parse_content_length(self)
        if length is None or length > config.MAX_BODY:
            # Body is left unread, so the connection cannot be reused.
            self.close_connection = True
            self.reply(event, start, 400, config.BAD_REQUEST_BODY, "text/plain")
            return
        body = self.rfile.read(length) if length else b""
        if len(body) != length:
            self.close_connection = True
            self.reply(event, start, 400, config.BAD_REQUEST_BODY, "text/plain")
            return

        if self.path.startswith("/_hp/"):
            self.reply(event, start, 404, NOT_FOUND_BODY, "text/plain")
            return

        try:
            status, ctype, data = self.route(body, event)
        except UpstreamError:
            # M4: no 502 yet (SPEC 8 condition 3 is week 13). Drop the connection.
            self.close_connection = True
            event.update(status=None, body_len=0,
                         elapsed_ms=round((time.perf_counter() - start) * 1000.0, 1))
            self.proxy.add_event(event)
            return
        self.reply(event, start, status, data, ctype)

    def route(self, body: bytes, event: dict) -> tuple:
        """Forward to the current backend; follow a fork marker to the reserved decoy."""
        if self.decoy is not None:
            event.update(handled_by="decoy", backend=self.decoy.name)
            status, resp, data = self.forward(self.decoy.port, body)
            return status, resp.getheader("Content-Type"), data

        event.update(handled_by="target", backend="target")
        self.proxy.set_attempt(self.conn_id, None)
        try:
            status, resp, data = self.forward(self.proxy.target_port, body)
        except UpstreamError:
            attempt = self.proxy.set_attempt(self.conn_id, None)
            if attempt is not None:
                self.proxy.release(attempt.get("decoy"))
            raise
        attempt = self.proxy.set_attempt(self.conn_id, None)

        forked = resp.getheader("X-HP-Forked") == "1"
        if attempt is not None and attempt["result"] == "ok" and forked:
            self.decoy = attempt["decoy"]
            event.update(handled_by="decoy", backend=self.decoy.name, forked=True,
                         fork_result="ok", redacted=attempt["redacted"])
            status, resp, data = self.forward(self.decoy.port, body)
            return status, resp.getheader("Content-Type"), data

        if attempt is not None:
            # Acquired (or even restored) but the target did not hand the
            # session over: undo the reservation (SPEC 9.2).
            self.proxy.release(attempt.get("decoy"))
            result = attempt["result"]
            event["fork_result"] = result if result in ("pool_exhausted", "restore_failed") \
                else "restore_failed"
        if forked:
            raise UpstreamError("fork marker without a restored decoy")
        return status, resp.getheader("Content-Type"), data

    def forward(self, port: int, body: bytes) -> tuple:
        headers = {"X-HP-Conn": self.conn_id, "Content-Length": str(len(body))}
        ctype = self.headers.get("Content-Type")
        if ctype is not None:
            headers["Content-Type"] = ctype
        return upstream_call(port, self.command, self.path, body, headers)

    def reply(self, event: dict, start: float, status: int, body: bytes,
              content_type: Optional[str]) -> None:
        try:
            self.send_plain(status, body, content_type or "application/octet-stream")
        except OSError:
            self.close_connection = True
        event.update(status=status, body_len=len(body),
                     elapsed_ms=round((time.perf_counter() - start) * 1000.0, 1))
        self.proxy.add_event(event)


# ---------------------------------------------------------------- control port

class ControlHandler(QuietHandler):
    """Backend and runner only (SPEC 9.2)."""

    def send_error(self, code, message=None, explain=None):
        self.close_connection = True
        try:
            self.send_plain(code, NOT_FOUND_BODY if code == 404 else config.BAD_REQUEST_BODY,
                            "text/plain")
        except OSError:
            pass

    def send_json(self, status: int, data) -> None:
        self.send_plain(status, json_bytes(data), "application/json")

    def read_json(self):
        length = parse_content_length(self)
        if length is None:
            self.close_connection = True
            raise ValueError("bad framing")
        raw = self.rfile.read(length) if length else b""
        if len(raw) != length:
            self.close_connection = True
            raise ValueError("incomplete body")
        return json.loads(raw.decode("utf-8")) if raw else None

    def do_GET(self):
        proxy = self.server.proxy
        if self.path == "/events":
            self.send_json(200, proxy.events_snapshot())
        else:
            self.send_plain(404, NOT_FOUND_BODY, "text/plain")

    def do_POST(self):
        proxy = self.server.proxy
        try:
            data = self.read_json()
        except (ValueError, UnicodeError):
            self.send_json(400, {"ok": False})
            return
        if self.path == "/shutdown":
            proxy.stop_children()
            self.send_json(200, {"ok": True})
            self.close_connection = True
            threading.Thread(target=os._exit, args=(0,), daemon=True).start()
            return
        if self.path not in ("/fork/acquire", "/fork/restore"):
            self.close_connection = True
            self.send_plain(404, NOT_FOUND_BODY, "text/plain")
            return
        if not isinstance(data, dict) or not isinstance(data.get("conn_id"), str):
            self.send_json(400, {"ok": False})
            return
        if self.path == "/fork/acquire":
            self.send_json(200, self.acquire(proxy, data["conn_id"]))
        else:
            self.send_json(200, self.restore(proxy, data))

    @staticmethod
    def acquire(proxy: ProxyState, conn_id: str) -> dict:
        decoy = proxy.pool.acquire(conn_id) if proxy.pool is not None else None
        if decoy is None:
            old = proxy.set_attempt(conn_id, {"result": "pool_exhausted", "decoy": None,
                                              "redacted": 0})
        else:
            old = proxy.set_attempt(conn_id, {"result": "acquired", "decoy": decoy,
                                              "redacted": 0})
        if old is not None:
            proxy.release(old.get("decoy"))
        if decoy is None:
            return {"ok": False, "reason": "pool_exhausted"}
        return {"ok": True, "decoy": decoy.name}

    @staticmethod
    def restore(proxy: ProxyState, data: dict) -> dict:
        conn_id = data["conn_id"]
        failed = {"ok": False, "reason": "restore_failed"}
        attempt = proxy.get_attempt(conn_id)
        if attempt is None or attempt["result"] != "acquired" or attempt["decoy"] is None:
            return failed
        decoy = attempt["decoy"]
        redacted = data.get("redacted")
        snapshot = data.get("snapshot")
        ok = False
        if type(redacted) is int and redacted >= 0 and isinstance(snapshot, dict):
            try:
                status, body = post_json(decoy.port, "/_hp/restore", snapshot)
                result = json.loads(body.decode("utf-8"))
                ok = status == 200 and isinstance(result, dict) and result.get("ok") is True
            except (UpstreamError, ValueError, UnicodeError):
                ok = False
        if ok:
            proxy.set_attempt(conn_id, {"result": "ok", "decoy": decoy, "redacted": redacted})
            return {"ok": True}
        proxy.set_attempt(conn_id, {"result": "restore_failed", "decoy": None, "redacted": 0})
        proxy.release(decoy)
        return failed


# ---------------------------------------------------------------- entry point

def make_server(handler, proxy: ProxyState) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer((HOST, 0), handler)
    server.daemon_threads = True
    server.proxy = proxy
    return server


def main() -> None:
    proc.exit_when_parent_dies()
    parser = argparse.ArgumentParser(prog="hpsim.proxy")
    parser.add_argument("--mode", required=True, choices=MODES)
    parser.add_argument("--redact", default="on", choices=REDACT_POLICIES)
    parser.add_argument("--pool", type=int, default=2)
    parser.add_argument("--idle-timeout", type=float, default=config.IDLE_TIMEOUT)
    parser.add_argument("--session-timeout", type=float, default=config.SESSION_TIMEOUT)
    args = parser.parse_args()
    if args.pool < 0:
        parser.error("--pool must be >= 0")
    pool_size = args.pool if args.mode == "honeypatched" else 0

    proxy = ProxyState(args.mode, args.redact, args.idle_timeout, args.session_timeout)
    # Control port first: target and decoys need its number (SPEC 8.1).
    control = make_server(ControlHandler, proxy)
    threading.Thread(target=control.serve_forever, daemon=True).start()
    server_args = ["--mode", args.mode, "--redact", args.redact,
                   "--proxy-control", str(control.server_port)]
    try:
        target, info = proc.spawn("hpsim.server", server_args +
                                  ["--context", "target", "--name", "target"])
        proxy.target_proc, proxy.target_port = target, int(info["port"])
        proxy.pool = Pool(pool_size, server_args)
        public = make_server(PublicHandler, proxy)
        proc.announce_ready({"public_port": public.server_port,
                             "control_port": control.server_port})
        public.serve_forever()
    finally:
        proxy.stop_children()


if __name__ == "__main__":
    main()
