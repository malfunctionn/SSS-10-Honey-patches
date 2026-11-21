"""Pure, deterministic simulated heap, session and snapshot operations (SPEC 4-5)."""

import base64
import binascii
from dataclasses import dataclass, field
import hashlib
from typing import Optional

from . import config


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

    def copy(self) -> "Heap":
        """Deep-copy records (including each immutable bytes value)."""
        return Heap([Record(r.id, r.kind, r.owner, r.sensitive, r.freed,
                            bytes(bytearray(r.value))) for r in self.records])

    def get(self, record_id: str) -> Optional[Record]:
        for record in self.records:
            if record.id == record_id:
                return record
        return None

    def append(self, rec: Record) -> None:
        if self.get(rec.id) is not None:
            raise ValueError("duplicate record id: " + rec.id)
        self.records.append(rec)


@dataclass
class Session:
    conn_id: str
    token: bytes
    buf: bytearray
    requests: int = 0


def _hex(s: str, n: int) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()[:n]


def session_token(conn_id: str) -> bytes:
    return ("tok_" + _hex("{}:session:{}".format(config.SEED, conn_id), 16)).encode("ascii")


def fake_value(record_id: str, value: bytes) -> bytes:
    """Preserve the first four bytes and full length per SPEC 5.2."""
    count = max(0, len(value) - 4)
    return value[:4] + _hex("{}:fake:{}".format(config.SEED, record_id), count).encode("ascii")


def initial_heap() -> Heap:
    return Heap([
        Record("H0", "banner", "server", False, False, b"SRVMEM::"),
        Record("H1", "session_token", "alice", True, False, b"tok_alice_7f3a9c2e51"),
        Record("H2", "session_token", "bob", True, False, b"tok_bob_c41d88e0a7f2"),
        Record("H3", "session_token", "carol", True, True, b"tok_carol_09be3d71c6"),
        Record("H4", "api_key", "admin", True, False, b"key_admin_5d2f90ab13c7e8"),
    ])


def new_session(conn_id: str) -> Session:
    return Session(conn_id, session_token(conn_id),
                   bytearray(config.BUF_FILL * config.BUF_SIZE))


def session_record(session: Session) -> Record:
    return Record("S:" + session.conn_id, "session_token", session.conn_id,
                  True, False, session.token)


def view(buf: bytes, heap: Heap) -> bytes:
    return bytes(buf) + b"".join(rec.value for rec in heap.records)


def redact(heap: Heap, attacker_conn_id: str, policy: str) -> tuple:
    """Copy heap, replacing only eligible secrets; never mutate source heap."""
    if policy not in ("on", "nofreed", "off"):
        raise ValueError("invalid redact policy")
    result = heap.copy()
    replaced = 0
    if policy == "off":
        return result, replaced
    for rec in result.records:
        if not rec.sensitive or rec.owner == attacker_conn_id:
            continue
        if policy == "nofreed" and rec.freed:
            continue
        replacement = fake_value(rec.id, rec.value)
        if replacement != rec.value:
            rec.value = replacement
            replaced += 1
    return result, replaced


def _encode(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _decode(value: str) -> bytes:
    if not isinstance(value, str):
        raise ValueError("base64 field must be a string")
    try:
        return base64.b64decode(value.encode("ascii"), validate=True)
    except (binascii.Error, UnicodeError, ValueError) as exc:
        raise ValueError("invalid base64 field") from exc


def heap_to_list(heap: Heap) -> list:
    return [
        {"id": rec.id, "kind": rec.kind, "owner": rec.owner,
         "sensitive": rec.sensitive, "freed": rec.freed, "value": _encode(rec.value)}
        for rec in heap.records
    ]


def heap_from_list(items: list) -> Heap:
    if not isinstance(items, list):
        raise ValueError("heap must be a list")
    heap = Heap()
    for item in items:
        if not isinstance(item, dict):
            raise ValueError("heap entry must be an object")
        for key in ("id", "kind", "owner"):
            if not isinstance(item.get(key), str):
                raise ValueError("invalid heap " + key)
        for key in ("sensitive", "freed"):
            if type(item.get(key)) is not bool:
                raise ValueError("invalid heap " + key)
        rec = Record(item["id"], item["kind"], item["owner"],
                     item["sensitive"], item["freed"], _decode(item.get("value")))
        heap.append(rec)
    return heap


def to_snapshot(session: Session, heap: Heap) -> dict:
    return {
        "version": 1,
        "session": {"conn_id": session.conn_id, "token": _encode(session.token),
                    "buf": _encode(bytes(session.buf)), "requests": session.requests},
        "heap": heap_to_list(heap),
    }


def from_snapshot(data: dict) -> tuple:
    """Decode validated snapshot; reject malformed data before caller changes state."""
    if not isinstance(data, dict) or type(data.get("version")) is not int or data["version"] != 1:
        raise ValueError("invalid snapshot version")
    item = data.get("session")
    if not isinstance(item, dict):
        raise ValueError("invalid snapshot session")
    if not isinstance(item.get("conn_id"), str):
        raise ValueError("invalid snapshot conn_id")
    if type(item.get("requests")) is not int or item["requests"] < 0:
        raise ValueError("invalid snapshot requests")
    token = _decode(item.get("token"))
    buf = _decode(item.get("buf"))
    if len(token) != 20 or len(buf) != config.BUF_SIZE:
        raise ValueError("invalid snapshot session sizes")
    heap = heap_from_list(data.get("heap"))
    return Session(item["conn_id"], token, bytearray(buf), item["requests"]), heap
