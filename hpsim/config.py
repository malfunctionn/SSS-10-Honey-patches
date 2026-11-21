"""Fixed simulator constants and deterministic initial-memory configuration."""

SEED = "honeypatch-sim"
BUF_SIZE = 16
BUF_FILL = b"."
MAX_BODY = 4096
IDLE_TIMEOUT = 5.0
SESSION_TIMEOUT = 30.0
UPSTREAM_TIMEOUT = 5.0
READY_TIMEOUT = 20.0
INDEX_HTML = b"<html><body><h1>hp-sim</h1></body></html>\n"
REJECT_BODY = b"heartbeat rejected\n"
BAD_REQUEST_BODY = b"bad request\n"
