# B: server and process implementation

[SPEC.md](SPEC.md) v1.4.1, appendix A, 12-week scope.
All commands and code paths below are relative to the repository root.

Files: `hpsim/proc.py`, `hpsim/server.py`, `hpsim/pool.py`,
`tests/test_proc.py`, `tests/test_modes.py`.

Part A must supply `hpsim/config.py`, `hpsim/memory.py` and
`hpsim/honeypatch.py` with the public APIs in sections 4, 5.4 and 7.4.
Production code imports those APIs directly. No replacement A modules ship here.
Tests copy B into a temporary package and provide explicit A API doubles there;
they do not validate real redaction, checkpointing, or fork-control HTTP calls.
Run A's `test_fork.py` after integration to validate actual checkpoint/replay.

Tests (Python 3.9+, pytest):

- Windows: `py -m pytest tests/test_proc.py tests/test_modes.py`
- macOS: `python3 -m pytest tests/test_proc.py tests/test_modes.py`

After A integration, standalone example:

`py -m hpsim.server --context target --mode unpatched --redact on --proxy-control 0 --name target`

Keep stdin open. Read the port from `READY {"port": ...}`; send requests to
`127.0.0.1` with `X-HP-Conn: c1`. Closing stdin stops the backend.
Use `proc.spawn` / `proc.stop` for programmatic lifecycle management.

The backend binds exclusively to `127.0.0.1` on an automatically assigned port.
Internal `/_hp/*` endpoints have no authentication; the proxy must block those
paths on its public listener. Do not expose or forward backend ports externally.
Heartbeat framing and payload validation precede session creation, so malformed
first requests leave both the session table and heap unchanged.

The M4 pool acquires the lowest available decoy number. Release stops its
process asynchronously and leaves its state `recycling`. Regeneration and
timeout/failed-backend return conditions belong to M6 and are not implemented.

Verification: Windows, Python 3.13.18 (bundled interpreter, absent from PATH).
`python tests/smoke_b.py` passed real child-process and HTTP checks for startup,
failure cleanup, stdin EOF, repeated stop, backend modes, validation/state
preservation, close, decoy restore/replay, pool exhaustion and M4 release.
These checks use A API doubles. All source files also passed compilation.
The simulated fork marker and failed-fork fallback validate only the backend
contract with doubles. Real `hp_fork` success, acquisition/restore failure
fallback, and proxy routing changes still require A/C integration tests.
Pytest is unavailable and network policy blocked installation, so the pytest
suite has not been executed. macOS and integrated A/C/D validation remain required.
