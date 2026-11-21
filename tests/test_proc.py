import importlib
import threading
from unittest.mock import Mock

import pytest


def test_ready_stop_and_idempotence(sandbox):
    child, info = sandbox.spawn("b_test_child", ["ready"])
    try:
        assert info == {"port": 12345}
        assert child.poll() is None
    finally:
        sandbox.stop(child)
    assert child.poll() is not None
    sandbox.stop(child, shutdown=Mock(side_effect=RuntimeError("ignored")))


def test_stdin_eof_exits_child(sandbox):
    child, _ = sandbox.spawn("b_test_child", ["ready"])
    try:
        child.stdin.close()
        assert child.wait(timeout=3) == 0
    finally:
        sandbox.stop(child)


@pytest.mark.parametrize("mode", ["silent", "invalid", "exit"])
def test_startup_failures_are_reaped(sandbox, monkeypatch, mode):
    monkeypatch.setattr(sandbox.config, "READY_TIMEOUT", 0.5)
    original = sandbox.subprocess.Popen
    children = []

    def tracked(*args, **kwargs):
        child = original(*args, **kwargs)
        children.append(child)
        return child

    monkeypatch.setattr(sandbox.subprocess, "Popen", tracked)
    with pytest.raises(RuntimeError, match=r"b_test_child: .*exit code"):
        sandbox.spawn("b_test_child", [mode])
    assert len(children) == 1
    assert children[0].poll() is not None


def test_pool_acquire_release_close(sandbox):
    pool_module = importlib.import_module("hpsim.pool")
    pool = pool_module.Pool(2, ["--mode", "honeypatched"])
    try:
        first = pool.acquire("c1")
        second = pool.acquire("c2")
        assert (first.name, second.name) == ("decoy-1", "decoy-2")
        assert pool.acquire("c3") is None
        pool.release(first)
        pool.release(first)
        assert first.conn_id is None
        assert pool.status()[0] == {"name": "decoy-1", "state": "recycling"}
        first.proc.wait(timeout=5)
        assert pool.acquire("c3") is None
    finally:
        pool.close()
        pool.close()
    assert second.proc.poll() is not None
    assert pool.acquire("c4") is None


def test_pool_zero(sandbox):
    Pool = importlib.import_module("hpsim.pool").Pool
    pool = Pool(0, [])
    assert pool.status() == []
    assert pool.acquire("c1") is None
    pool.close()


def test_pool_partial_startup_is_cleaned(sandbox, monkeypatch):
    Pool = importlib.import_module("hpsim.pool").Pool
    original = sandbox.spawn
    children = []

    def spawn(module, args):
        if children:
            raise RuntimeError("second child failed")
        child, ready = original(module, args)
        children.append(child)
        return child, ready

    monkeypatch.setattr(sandbox, "spawn", spawn)
    with pytest.raises(RuntimeError, match="second child"):
        Pool(2, ["--mode", "honeypatched"])
    assert children[0].poll() is not None
