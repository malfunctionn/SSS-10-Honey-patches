"""M1: exact SPEC 4-5 deterministic values, layouts, redaction and snapshots."""

import base64
import copy

import pytest

from hpsim import config
from hpsim.memory import (
    Heap, Record, fake_value, from_snapshot, heap_from_list, heap_to_list,
    initial_heap, new_session, redact, session_record, session_token,
    to_snapshot, view,
)


def test_constants_and_initial_heap_layout():
    assert config.SEED == "honeypatch-sim"
    assert config.BUF_SIZE == 16 and config.BUF_FILL == b"."
    assert config.MAX_BODY == 4096
    assert config.READY_TIMEOUT == 20.0
    heap = initial_heap()
    assert [r.id for r in heap.records] == ["H0", "H1", "H2", "H3", "H4"]
    assert [len(r.value) for r in heap.records] == [8, 20, 20, 20, 24]
    assert len(view(b"." * 16, heap)) == 108
    assert heap.get("H3").freed is True
    assert heap.get("H3").value == b"tok_carol_09be3d71c6"
    heap.get("H1").value = b"changed"
    assert initial_heap().get("H1").value == b"tok_alice_7f3a9c2e51"


@pytest.mark.parametrize("conn_id,expected", [
    ("c1", b"tok_8aa31bd77f104c99"),
    ("c2", b"tok_e2276907212c22f0"),
])
def test_session_token_reference_values(conn_id, expected):
    assert session_token(conn_id) == expected
    assert len(session_token(conn_id)) == 20


@pytest.mark.parametrize("record_id,value,expected", [
    ("H1", b"tok_alice_7f3a9c2e51", b"tok_a9bd82d091d5d37e"),
    ("H2", b"tok_bob_c41d88e0a7f2", b"tok_6d6ecbe54f5f762b"),
    ("H3", b"tok_carol_09be3d71c6", b"tok_5beae03b78e5d643"),
    ("H4", b"key_admin_5d2f90ab13c7e8", b"key_4bbbdc254ea321a390c5"),
    ("S:c2", b"tok_e2276907212c22f0", b"tok_3cc8dc7f7e58e11c"),
])
def test_fake_value_reference_values(record_id, value, expected):
    actual = fake_value(record_id, value)
    assert actual == expected
    assert len(actual) == len(value) and actual[:4] == value[:4]


def test_session_and_view_offsets_are_stable():
    heap = initial_heap()
    s1 = new_session("c1")
    s2 = new_session("c2")
    heap.append(session_record(s1))
    heap.append(session_record(s2))
    assert s1.buf == b"." * 16 and s1.requests == 0
    assert s1.token == b"tok_8aa31bd77f104c99"
    data = view(s1.buf, heap)
    assert len(data) == 148
    assert data[:16] == b"." * 16
    assert data[16:24] == b"SRVMEM::"
    assert data[24:44] == b"tok_alice_7f3a9c2e51"
    assert data[44:64] == b"tok_bob_c41d88e0a7f2"
    assert data[64:84] == b"tok_carol_09be3d71c6"
    assert data[84:108] == b"key_admin_5d2f90ab13c7e8"
    assert data[108:128] == s1.token
    assert data[128:148] == s2.token


def test_heap_copy_and_duplicate_prevention():
    heap = initial_heap()
    copied = heap.copy()
    assert copied is not heap
    assert copied.get("H1") is not heap.get("H1")
    copied.get("H1").freed = True
    copied.get("H1").value = b"other"
    assert heap.get("H1").freed is False
    assert heap.get("H1").value == b"tok_alice_7f3a9c2e51"
    assert heap.get("not-there") is None
    with pytest.raises(ValueError):
        heap.append(Record("H1", "test", "x", False, False, b"x"))


def _freed_heap():
    heap = initial_heap()
    s1, s2 = new_session("c1"), new_session("c2")
    r1 = session_record(s1)
    r1.freed = True
    heap.append(r1)
    heap.append(session_record(s2))
    return heap


@pytest.mark.parametrize("policy,count,ids,old_c1", [
    ("on", 5, {"H1", "H2", "H3", "H4", "S:c1"}, b"tok_8b6fdefa40886a62"),
    ("nofreed", 3, {"H1", "H2", "H4"}, b"tok_8aa31bd77f104c99"),
    ("off", 0, set(), b"tok_8aa31bd77f104c99"),
])
def test_redact_reference_freed_and_attacker_preservation(policy, count, ids, old_c1):
    heap = _freed_heap()
    original = heap_to_list(heap)
    changed, n = redact(heap, "c2", policy)
    assert n == count
    assert changed is not heap
    assert heap_to_list(heap) == original  # source is never mutated
    assert {r.id for r in changed.records if r.value != heap.get(r.id).value} == ids
    assert changed.get("S:c1").value == old_c1
    assert changed.get("S:c2").value == b"tok_e2276907212c22f0"
    assert changed.get("H0").value == b"SRVMEM::"
    assert changed.get("H3").freed is True
    assert changed.get("S:c1").freed is True


def test_redact_rejects_unrecognized_policy():
    with pytest.raises(ValueError):
        redact(initial_heap(), "c1", "maybe")


def test_snapshot_roundtrip_and_no_aliasing():
    heap = _freed_heap()
    session = new_session("c2")
    session.buf[:5] = b"hello"
    session.requests = 7
    snapshot = to_snapshot(session, heap)
    assert snapshot["version"] == 1
    assert snapshot["session"] == {
        "conn_id": "c2", "token": base64.b64encode(session.token).decode("ascii"),
        "buf": base64.b64encode(session.buf).decode("ascii"), "requests": 7,
    }
    assert [r["id"] for r in snapshot["heap"]] == ["H0", "H1", "H2", "H3", "H4", "S:c1", "S:c2"]
    restored_session, restored_heap = from_snapshot(snapshot)
    assert restored_session.conn_id == "c2"
    assert restored_session.buf == b"hello..........."
    assert restored_session.requests == 7
    assert heap_to_list(restored_heap) == heap_to_list(heap)
    restored_session.buf[0] = ord("X")
    restored_heap.get("H1").freed = True
    assert session.buf == b"hello..........."
    assert heap.get("H1").freed is False
    assert heap_to_list(heap_from_list(heap_to_list(heap))) == heap_to_list(heap)


@pytest.mark.parametrize("mutation", [
    lambda d: d.update({"version": 2}),
    lambda d: d.update({"version": True}),
    lambda d: d.update({"heap": "not-a-list"}),
    lambda d: d["session"].update({"requests": -1}),
    lambda d: d["session"].update({"requests": True}),
    lambda d: d["session"].update({"buf": "%%%"}),
    lambda d: d["session"].update({"buf": "YQ=="}),
    lambda d: d["heap"][0].update({"sensitive": "yes"}),
    lambda d: d["heap"].append(copy.deepcopy(d["heap"][0])),
])
def test_bad_snapshots_rejected(mutation):
    data = to_snapshot(new_session("c1"), initial_heap())
    mutation(data)
    with pytest.raises(ValueError):
        from_snapshot(data)
