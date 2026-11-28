"""13-week A counterexamples C01-C04/C21 (SPEC v1.5, appendix B).

Expected observations were fixed from the A assignment before running the tests.
Tests use only public hpsim.memory/config APIs and never modify B/C/D files.
"""

import hashlib

from hpsim import config
from hpsim.memory import (
    initial_heap, new_session, redact, session_record, view,
)


def _leaked(body, original_heap, attacker_id):
    """Count complete registered secrets in the returned body, excluding self."""
    return sum(
        1 for rec in original_heap.records
        if rec.sensitive and rec.owner != attacker_id and rec.value in body
    )


def _victim_with_closed_connection():
    """B=c1 closes before attacking A=c2 (the fixed freed-session scenario)."""
    heap = initial_heap()
    closed = new_session("c1")
    gone = session_record(closed)
    gone.freed = True
    heap.append(gone)
    attacker = new_session("c2")
    heap.append(session_record(attacker))
    attacker.buf[:2] = b"hi"
    return attacker, heap


def _first_attack(conn_id):
    """Prepare attack.json's second request, preserving its first-request buffer."""
    session = new_session(conn_id)
    session.buf[:5] = b"hello"
    session.buf[:2] = b"hi"
    heap = initial_heap()
    heap.append(session_record(session))
    return session, heap


def test_c01_freed_memory_policy_on_protects_both_freed_secrets():
    """C01: on=5/leaked=0; nofreed=3/leaked=2; not a default-policy bug."""
    session, heap = _victim_with_closed_connection()
    before = [rec.value for rec in heap.records]
    protected, changed_on = redact(heap, "c2", "on")
    unprotected, changed_nofreed = redact(heap, "c2", "nofreed")
    secure_body = view(session.buf, protected)[:148]
    unsafe_body = view(session.buf, unprotected)[:148]
    raw_body = view(session.buf, heap)[:148]

    assert changed_on == 5
    assert changed_nofreed == 3
    assert _leaked(secure_body, heap, "c2") == 0
    assert _leaked(unsafe_body, heap, "c2") == 2
    assert _leaked(raw_body, heap, "c2") == 5
    assert protected.get("H3").value == b"tok_5beae03b78e5d643"
    assert protected.get("S:c1").value == b"tok_8b6fdefa40886a62"
    assert unprotected.get("H3").value == b"tok_carol_09be3d71c6"
    assert unprotected.get("S:c1").value == b"tok_8aa31bd77f104c99"
    assert [rec.value for rec in heap.records] == before


def test_fake_value_predictable():
    """C02: independently predict the decoy H1 bytes from the public seed."""
    session, heap = _first_attack("c1")
    redacted_heap, replaced = redact(heap, "c1", "on")
    decoy_body = view(session.buf, redacted_heap)[:64]
    original_body = view(session.buf, heap)[:64]

    # Independent calculation: the implementation's fake_value() is NOT called.
    record_id = "H1"
    original = b"tok_alice_7f3a9c2e51"
    digest = hashlib.sha256(
        (config.SEED + ":fake:" + record_id).encode("utf-8")
    ).hexdigest()
    predicted = original[:4] + digest[:len(original) - 4].encode("ascii")

    assert replaced == 4
    assert predicted == b"tok_a9bd82d091d5d37e"
    assert decoy_body[24:44] == predicted
    assert original_body[24:44] == original
    assert decoy_body[24:44] != original_body[24:44]
    # Per SPEC memory layout, H3 occupies 64..83, not H1.
    assert decoy_body[44:64] == b"tok_6d6ecbe54f5f762b"


def test_c02_fake_values_repeat_across_clean_instances():
    """C02: a fixed public seed reproduces the same fake value each time."""
    seen = []
    for _ in range(3):
        session, heap = _first_attack("c1")
        new_heap, _ = redact(heap, "c1", "on")
        seen.append(view(session.buf, new_heap)[:64])
    assert seen[0] == seen[1] == seen[2]


def test_c03_same_attack_on_two_connections_same_64_byte_decoy_body():
    """C03: equal inputs produce equal decoy bodies; no third-party leaks."""
    protected = []
    vulnerable = []
    for conn_id in ("c1", "c2"):
        session, heap = _first_attack(conn_id)
        new_heap, replaced = redact(heap, conn_id, "on")
        safe = view(session.buf, new_heap)[:64]
        raw = view(session.buf, heap)[:64]
        assert replaced == 4
        assert _leaked(safe, heap, conn_id) == 0
        assert _leaked(raw, heap, conn_id) == 2
        protected.append(safe)
        vulnerable.append(raw)
    assert protected[0] == protected[1]
    assert vulnerable[0] == vulnerable[1]


def test_c04_attacker_own_token_preserved_at_view_bytes_108_to_127():
    """C04: 128-byte boundary includes the owner's unredacted token."""
    session = new_session("c1")
    session.buf[:2] = b"hi"
    heap = initial_heap()
    heap.append(session_record(session))
    protected_heap, count = redact(heap, "c1", "on")
    body = view(session.buf, protected_heap)[:128]

    assert len(body) == 128
    assert count == 4
    assert _leaked(body, heap, "c1") == 0
    assert body[108:128] == b"tok_8aa31bd77f104c99"
    assert protected_heap.get("S:c1").value == session.token


def test_c21_redact_off_intentionally_exposes_two_live_secrets():
    """C21/redact_off: documented configuration choice, not an algorithm bug."""
    session, heap = _first_attack("c1")
    redacted_heap, count = redact(heap, "c1", "off")
    body = view(session.buf, redacted_heap)[:64]

    assert count == 0
    assert _leaked(body, heap, "c1") == 2
    assert body[24:44] == b"tok_alice_7f3a9c2e51"
    assert body[44:64] == b"tok_bob_c41d88e0a7f2"


def test_c21_nofreed_leaks_one_freed_record_at_boundary_84():
    """C21/leak_freed: 84 bytes expose exactly the freed H3 token."""
    session = new_session("c1")
    session.buf[:2] = b"hi"
    heap = initial_heap()
    heap.append(session_record(session))
    nofreed_heap, nofreed_count = redact(heap, "c1", "nofreed")
    secure_heap, secure_count = redact(heap, "c1", "on")
    nofreed_body = view(session.buf, nofreed_heap)[:84]
    secure_body = view(session.buf, secure_heap)[:84]

    assert nofreed_count == 3
    assert secure_count == 4
    assert _leaked(nofreed_body, heap, "c1") == 1
    assert _leaked(secure_body, heap, "c1") == 0
    assert nofreed_body[64:84] == b"tok_carol_09be3d71c6"
    assert secure_body[64:84] == b"tok_5beae03b78e5d643"
