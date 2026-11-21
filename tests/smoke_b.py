"""Standard-library smoke checks when pytest is unavailable.

Uses the same isolated A API doubles as conftest.py, without importing pytest.
Run: python tests/smoke_b.py
"""
import ast
import base64
import http.client
import importlib
import json
from pathlib import Path
import shutil
import sys
import tempfile


def main():
    root = Path(__file__).resolve().parents[1]
    sources = {}
    tree = ast.parse((root / "tests" / "conftest.py").read_text(encoding="utf-8"))
    for node in tree.body:
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant):
            sources[node.targets[0].id] = node.value.value
    with tempfile.TemporaryDirectory() as directory:
        temporary = Path(directory)
        package = temporary / "hpsim"
        package.mkdir()
        for name in ("__init__.py", "proc.py", "server.py", "pool.py"):
            shutil.copyfile(root / "hpsim" / name, package / name)
        for filename, key in (("config.py", "CONFIG"), ("memory.py", "MEMORY"),
                              ("honeypatch.py", "HONEYPATCH")):
            with (package / filename).open("w", encoding="utf-8", newline="\n") as stream:
                stream.write(sources[key])
        with (temporary / "b_test_child.py").open("w", encoding="utf-8", newline="\n") as stream:
            stream.write(sources["CHILD"])
        sys.path.insert(0, directory)
        proc = importlib.import_module("hpsim.proc")
        child, info = proc.spawn("b_test_child", ["ready"])
        try:
            assert info == {"port": 12345}
            child.stdin.close()
            assert child.wait(timeout=3) == 0
        finally:
            proc.stop(child)
            proc.stop(child)
        proc.config.READY_TIMEOUT = 0.5
        for mode in ("silent", "invalid", "exit"):
            try:
                proc.spawn("b_test_child", [mode])
            except RuntimeError as exc:
                assert "b_test_child" in str(exc) and "exit code" in str(exc)
            else:
                raise AssertionError("startup failure accepted")
        proc.config.READY_TIMEOUT = 20.0
        print("PASS process startup, errors, EOF and repeated stop")

        def request(conn, method, path, body=None):
            encoded = body if isinstance(body, bytes) else json.dumps(body) if body is not None else None
            conn.request(method, path, encoded,
                         {"X-HP-Conn": "c1"})
            response = conn.getresponse()
            data = response.read()
            assert int(response.getheader("Content-Length")) == len(data)
            return response.status, data, response

        for mode in ("unpatched", "patched", "honeypatched"):
            child, info = proc.spawn("hpsim.server", ["--context", "target", "--mode", mode, "--name", "target"])
            conn = http.client.HTTPConnection("127.0.0.1", info["port"], timeout=5)
            try:
                initial = json.loads(request(conn, "GET", "/_hp/state")[1])
                assert initial["sessions"] == []
                for bad in (b"not json", b"\xff", b"x" * 4097,
                            {"payload": "hi", "len": True}, {"payload": "x" * 17, "len": 1},
                            [], {"len": 3}):
                    assert request(conn, "POST", "/heartbeat", bad)[:2] == (400, b"bad request\n")
                    assert json.loads(request(conn, "GET", "/_hp/state")[1]) == initial
                assert request(conn, "POST", "/heartbeat", {"payload": "hello", "len": 5})[:2] == (200, b"hello")
                status, body, _ = request(conn, "POST", "/heartbeat", {"payload": "hi", "len": 64})
                if mode == "unpatched":
                    assert (status, body) == (200, b"hillo...........SRVMEM::tok_alice_7f3a9c2e51tok_bob_c41d88e0a7f2")
                else:
                    assert (status, body) == (400, b"heartbeat rejected\n")
                before = json.loads(request(conn, "GET", "/_hp/state")[1])["sessions"][0]
                for bad in ({"payload": "hi", "len": True}, {"payload": "x" * 17, "len": 1}, [], {"len": 3}):
                    assert request(conn, "POST", "/heartbeat", bad)[:2] == (400, b"bad request\n")
                after = json.loads(request(conn, "GET", "/_hp/state")[1])["sessions"][0]
                assert before == after
                result = json.loads(request(conn, "GET", "/session")[1])
                assert result["requests"] == (3 if mode == "unpatched" else 2)
                assert request(conn, "POST", "/_hp/close", {"conn_id": "c1"})[0] == 200
                state = json.loads(request(conn, "GET", "/_hp/state")[1])
                assert not state["sessions"] and state["heap"][-1]["freed"]
            finally:
                conn.close()
                proc.stop(child)
        print("PASS backend modes, malformed first-request state preservation, counters and close")

        child, info = proc.spawn("hpsim.server", ["--context", "decoy", "--mode", "honeypatched", "--name", "decoy-1"])
        conn = http.client.HTTPConnection("127.0.0.1", info["port"], timeout=5)
        b64 = lambda value: base64.b64encode(value).decode("ascii")
        try:
            snapshot = {"version": 1, "session": {"conn_id": "c1", "token": b64(b"own"),
                        "buf": b64(b"hello..........."), "requests": 1}, "heap": []}
            assert request(conn, "POST", "/_hp/restore", snapshot)[0] == 200
            assert request(conn, "POST", "/heartbeat", {"payload": "hi", "len": 64})[:2] == (200, b"hillo...........")
            assert json.loads(request(conn, "GET", "/session")[1]) == {"requests": 3, "token": "own"}
        finally:
            conn.close()
            proc.stop(child)
        print("PASS decoy restore and replay against A API doubles")
        Pool = importlib.import_module("hpsim.pool").Pool
        pool = Pool(2, ["--mode", "honeypatched"])
        try:
            first, second = pool.acquire("c1"), pool.acquire("c2")
            assert (first.name, second.name) == ("decoy-1", "decoy-2")
            assert pool.acquire("c3") is None
            pool.release(first)
            pool.release(first)
            first.proc.wait(timeout=5)
            assert pool.status()[0]["state"] == "recycling"
        finally:
            pool.close()
            pool.close()
        assert second.proc.poll() is not None
        assert Pool(0, []).acquire("c1") is None
        print("PASS pool acquisition, exhaustion, release and shutdown")
    print("ALL SMOKE CHECKS PASS")


if __name__ == "__main__":
    main()
