"""Scenario runner (spec 10). Owner: D.

For each mode it starts a fresh proxy (proc.spawn), runs the steps one at a time,
reads the proxy event log from the control port, and checks each request
against scenario["expect"][mode].

hpsim.config, hpsim.memory and hpsim.proc are imported inside the functions that
need them, so `cli compare` and the table code work before those modules exist.

12th-week scope: ops `sleep` and `wait_pool` are not implemented yet (M6).
"""
import base64
import http.client
import json
import time
from pathlib import Path
from typing import Dict, List, Optional, Union

ROOT = Path(__file__).resolve().parent.parent
HOST = "127.0.0.1"
MODES = ("unpatched", "patched", "honeypatched")
EVENT_FIELDS = ("handled_by", "forked", "fork_result", "redacted")
POLL_INTERVAL = 0.05     # seconds between /events polls
EVENT_WAIT = 2.0         # max wait for a request's event record to appear


# ---------------------------------------------------------------- scenario files

def resolve_path(path: Union[str, Path]) -> Path:
    """Use the path as given if it exists, otherwise relative to the repo root."""
    p = Path(path)
    if p.exists() or p.is_absolute():
        return p
    return ROOT / p


def load_scenario(path: Union[str, Path]) -> dict:
    with open(resolve_path(path), "r", encoding="utf-8") as f:
        data = json.load(f)
    for key in ("name", "steps", "expect"):
        if key not in data:
            raise ValueError("scenario is missing %r" % key)
    return data


def request_steps(steps: List[dict]) -> List[dict]:
    """Steps without an `op` are requests; expect[mode] pairs with these in order."""
    return [s for s in steps if "op" not in s]


def conn_ids(steps: List[dict]) -> Dict[str, str]:
    """Labels become c1, c2, ... in order of first appearance (spec 10.1)."""
    ids: Dict[str, str] = {}
    for s in steps:
        label = s.get("conn")
        if label is not None and label not in ids:
            ids[label] = "c%d" % (len(ids) + 1)
    return ids


# ---------------------------------------------------------------- leak counting (10.2)

def static_secrets() -> List[bytes]:
    """Values of the sensitive initial heap records (H1..H4)."""
    from hpsim import memory
    return [r.value for r in memory.initial_heap().records if r.sensitive]


def secrets_for(conn_id: str, all_conn_ids: List[str], base: List[bytes]) -> List[bytes]:
    """Real secrets for one connection: H1..H4 plus the other connections' tokens."""
    from hpsim import memory
    others = [memory.session_token(c) for c in all_conn_ids if c != conn_id]
    return list(base) + others


def count_leaked(body: bytes, secrets: List[bytes]) -> int:
    return sum(1 for s in secrets if s and s in body)


# ---------------------------------------------------------------- checking

def check(expect: dict, actual: dict) -> List[str]:
    """Compare only the fields written in `expect`. Returns mismatch descriptions."""
    from hpsim.report import show_body
    problems = []
    for key, want in expect.items():
        if key == "body":
            got = actual.get("body", b"")
            if got != want.encode("utf-8"):
                problems.append("body expected %s, got %s" % (show_body(want.encode("utf-8")), show_body(got)))
            continue
        if key in EVENT_FIELDS:
            event = actual.get("event")
            got = None if event is None else event.get(key)
        else:
            got = actual.get(key)
        if got != want:
            problems.append("%s expected %s, got %s" % (key, json.dumps(want), json.dumps(got)))
    return problems


# ---------------------------------------------------------------- HTTP helpers

def _ready_timeout() -> float:
    from hpsim import config
    return float(config.READY_TIMEOUT)


def control_call(port: int, method: str, path: str, body: Optional[dict] = None,
                 timeout: float = 5.0):
    conn = http.client.HTTPConnection(HOST, port, timeout=timeout)
    try:
        payload = None if body is None else json.dumps(body).encode("utf-8")
        headers = {} if payload is None else {"Content-Type": "application/json"}
        conn.request(method, path, body=payload, headers=headers)
        resp = conn.getresponse()
        return resp.status, resp.read()
    finally:
        conn.close()


def fetch_events(port: int) -> list:
    status, data = control_call(port, "GET", "/events")
    if status != 200:
        raise RuntimeError("GET /events returned %d" % status)
    obj = json.loads(data.decode("utf-8"))
    if isinstance(obj, dict):
        obj = obj.get("events", [])
    return obj


def _new_request_event(port: int, conn_id: str, seen: set, wait: float) -> Optional[dict]:
    """Newest request record for conn_id whose seq has not been used yet."""
    deadline = time.monotonic() + wait
    while True:
        fresh = [e for e in fetch_events(port)
                 if e.get("type") == "request" and e.get("conn_id") == conn_id
                 and e.get("seq") not in seen]
        if fresh:
            event = max(fresh, key=lambda e: e.get("seq", 0))
            seen.update(e.get("seq") for e in fresh)
            return event
        if time.monotonic() >= deadline:
            return None
        time.sleep(POLL_INTERVAL)


def _wait_close_event(port: int, conn_id: str, wait: float) -> None:
    deadline = time.monotonic() + wait
    while True:
        if any(e.get("type") == "close" and e.get("conn_id") == conn_id
               for e in fetch_events(port)):
            return
        if time.monotonic() >= deadline:
            raise RuntimeError("close record for %s did not appear in %.0fs" % (conn_id, wait))
        time.sleep(POLL_INTERVAL)


def _encode_body(body) -> Optional[bytes]:
    if body is None:
        return None
    if isinstance(body, str):          # raw body (malformed-input cases)
        return body.encode("utf-8")
    return json.dumps(body).encode("utf-8")


def send_request(conn: http.client.HTTPConnection, step: dict) -> dict:
    """Send one request on an existing connection. A dropped connection gives closed=True."""
    payload = _encode_body(step.get("body"))
    headers = {} if payload is None else {"Content-Type": "application/json"}
    start = time.perf_counter()
    try:
        conn.request(step["method"], step["path"], body=payload, headers=headers)
        resp = conn.getresponse()
        data = resp.read()
        result = {"status": resp.status, "body": data, "body_len": len(data), "closed": False}
    except (http.client.HTTPException, OSError):
        conn.close()
        result = {"status": None, "body": b"", "body_len": 0, "closed": True}
    result["ms"] = (time.perf_counter() - start) * 1000.0
    return result


# ---------------------------------------------------------------- running

def proxy_args(mode: str, options: dict) -> List[str]:
    from hpsim import config
    idle = options.get("idle_timeout", options.get("idle-timeout", config.IDLE_TIMEOUT))
    sess = options.get("session_timeout", options.get("session-timeout", config.SESSION_TIMEOUT))
    return ["--mode", mode, "--redact", str(options.get("redact", "on")),
            "--pool", str(options.get("pool", 2)),
            "--idle-timeout", str(idle), "--session-timeout", str(sess)]


def run_mode(scenario: dict, mode: str, options: dict) -> dict:
    """Run every step for one mode against a fresh proxy. Returns {"rows", "events"}."""
    from hpsim import proc

    steps = scenario["steps"]
    expects = scenario["expect"].get(mode, [])
    if len(expects) != len(request_steps(steps)):
        raise ValueError("expect[%s] has %d entries for %d request steps"
                         % (mode, len(expects), len(request_steps(steps))))
    ids = conn_ids(steps)
    all_ids = list(ids.values())
    base_secrets = static_secrets()
    ready_timeout = _ready_timeout()

    child, info = proc.spawn("hpsim.proxy", proxy_args(mode, options))
    public_port, control_port = int(info["public_port"]), int(info["control_port"])
    conns: Dict[str, http.client.HTTPConnection] = {}
    rows: List[dict] = []
    events: list = []
    seen: set = set()
    try:
        n = 0
        for step in steps:
            label = step.get("conn")
            op = step.get("op")
            if op == "close":
                c = conns.pop(label, None)
                if c is not None:
                    c.close()
                    _wait_close_event(control_port, ids[label], ready_timeout)
                continue
            if op is not None:
                raise NotImplementedError("op %r is planned for week 13 (M6)" % op)

            conn_id = ids[label]
            if label not in conns:
                conns[label] = http.client.HTTPConnection(HOST, public_port, timeout=ready_timeout)
            actual = send_request(conns[label], step)
            if actual["closed"]:
                conns.pop(label, None)
            actual["event"] = _new_request_event(
                control_port, conn_id, seen, 0.5 if actual["closed"] else EVENT_WAIT)
            actual["leaked"] = count_leaked(actual["body"], secrets_for(conn_id, all_ids, base_secrets))

            expect = expects[n]
            n += 1
            rows.append(make_row(n, mode, conn_id, actual, expect))
        events = fetch_events(control_port)
    finally:
        for c in conns.values():
            c.close()
        proc.stop(child, shutdown=lambda: control_call(control_port, "POST", "/shutdown"))
    return {"rows": rows, "events": events}


def make_row(step_no: int, mode: str, conn_id: str, actual: dict, expect: dict) -> dict:
    from hpsim.report import show_body
    event = actual.get("event") or {}
    mismatches = check(expect, actual)
    return {
        "step": step_no,
        "mode": mode,
        "mode_index": MODES.index(mode) if mode in MODES else len(MODES),
        "conn_id": conn_id,
        "status": actual["status"],
        "body_len": actual["body_len"],
        "closed": actual["closed"],
        "handled_by": event.get("handled_by"),
        "forked": event.get("forked"),
        "fork_result": event.get("fork_result"),
        "redacted": event.get("redacted"),
        "leaked": actual["leaked"],
        "ms": actual["ms"],
        "body_text": show_body(actual["body"]),
        "body_b64": base64.b64encode(actual["body"]).decode("ascii"),
        "event": actual.get("event"),
        "expect": expect,
        "pass": not mismatches,
        "mismatches": mismatches,
    }


def run_scenario(scenario: dict, modes=MODES, redact: Optional[str] = None,
                 pool: Optional[int] = None) -> dict:
    """Run the scenario for each mode. Command-line redact/pool override scenario options."""
    options = dict(scenario.get("options", {}))
    if redact is not None:
        options["redact"] = redact
    if pool is not None:
        options["pool"] = pool

    n_requests = len(request_steps(scenario["steps"]))
    rows: List[dict] = []
    errors: List[str] = []
    events: Dict[str, list] = {}
    total = 0
    for mode in modes:
        total += n_requests
        try:
            out = run_mode(scenario, mode, options)
            rows.extend(out["rows"])
            events[mode] = out["events"]
        except Exception as exc:  # report and keep going with the next mode
            errors.append("%s: %s: %s" % (mode, type(exc).__name__, exc))
    passed = sum(1 for r in rows if r["pass"])
    return {
        "name": scenario["name"],
        "options": options,
        "modes": list(modes),
        "rows": rows,
        "events": events,
        "errors": errors,
        "passed": passed,
        "total": total,
        "ok": passed == total and not errors,
    }
