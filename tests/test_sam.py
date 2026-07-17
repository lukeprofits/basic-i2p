"""
SAM client tests against an in-process fake SAM bridge.

The fake server speaks just enough of SAM v3.1 to drive SamConnection /
SamSession end to end — HELLO, DEST GENERATE, SESSION CREATE, STREAM
CONNECT / ACCEPT / FORWARD, NAMING LOOKUP — including error injection, so we
exercise the real client protocol handling with no i2pd and no network.
"""

from __future__ import annotations

import base64
import socket
import threading
import time

import pytest

from basic_i2p._sam import (
    I2PSocket,
    SAMError,
    SamSession,
    b32_address,
    dest_generate,
    naming_lookup,
)


def _make_dest(seed: int, nbytes: int = 400) -> str:
    raw = bytes((i * 31 + seed) % 256 for i in range(nbytes))
    return base64.b64encode(raw, altchars=b"-~").decode()


class FakeSam:
    """A threaded fake SAM bridge for one test.

    Each accepted connection is handled by parsing one command line at a time
    and replying per SAM v3.1. After a successful STREAM CONNECT/ACCEPT the
    connection becomes a byte pipe; the fake echoes bytes back (uppercased) so
    tests can assert the pipe is wired to the right socket.
    """

    #: name → destination that NAMING LOOKUP should resolve. "ME" is special.
    def __init__(self, fail_connect_to: str | None = None,
                 unresolvable: set[str] | None = None,
                 accept_delay: float = 0.0) -> None:
        self._srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind(("127.0.0.1", 0))
        self._srv.listen(8)
        self.port = self._srv.getsockname()[1]
        self._threads: list[threading.Thread] = []
        self._stop = False
        self._fail_connect_to = fail_connect_to
        self._unresolvable = unresolvable or set()
        self._accept_delay = accept_delay
        # A pending inbound peer for STREAM ACCEPT to hand back.
        self.incoming_remote = _make_dest(99)
        self._accept_thread = threading.Thread(target=self._serve, daemon=True)
        self._accept_thread.start()

    def _serve(self) -> None:
        while not self._stop:
            try:
                conn, _ = self._srv.accept()
            except OSError:
                return
            t = threading.Thread(target=self._handle, args=(conn,), daemon=True)
            t.start()
            self._threads.append(t)

    def _readline(self, conn: socket.socket, buf: bytearray) -> str | None:
        while b"\n" not in buf:
            chunk = conn.recv(4096)
            if not chunk:
                return None
            buf += chunk
        idx = buf.index(b"\n")
        line = bytes(buf[:idx]).decode()
        del buf[:idx + 1]
        return line.rstrip("\r")

    def _handle(self, conn: socket.socket) -> None:
        buf = bytearray()
        try:
            while True:
                line = self._readline(conn, buf)
                if line is None:
                    return
                if line.startswith("HELLO"):
                    conn.sendall(b"HELLO REPLY RESULT=OK VERSION=3.1\n")
                elif line.startswith("DEST GENERATE"):
                    pub, priv = _make_dest(1), _make_dest(1, nbytes=600)
                    conn.sendall(f"DEST REPLY PUB={pub} PRIV={priv}\n".encode())
                elif line.startswith("SESSION CREATE"):
                    priv = _field(line, "DESTINATION")
                    conn.sendall(f"SESSION STATUS RESULT=OK DESTINATION={priv}\n".encode())
                elif line.startswith("NAMING LOOKUP"):
                    name = _field(line, "NAME")
                    if name in self._unresolvable:
                        conn.sendall(
                            f"NAMING REPLY RESULT=KEY_NOT_FOUND NAME={name}\n".encode())
                    else:
                        value = _make_dest(hash(name) % 200)
                        conn.sendall(
                            f"NAMING REPLY RESULT=OK NAME={name} VALUE={value}\n".encode())
                elif line.startswith("STREAM CONNECT"):
                    dest = _field(line, "DESTINATION")
                    if self._fail_connect_to and dest.startswith(self._fail_connect_to[:20]):
                        conn.sendall(b"STREAM STATUS RESULT=CANT_REACH_PEER\n")
                        return
                    conn.sendall(b"STREAM STATUS RESULT=OK\n")
                    self._echo_pipe(conn, buf)
                    return
                elif line.startswith("STREAM ACCEPT"):
                    conn.sendall(b"STREAM STATUS RESULT=OK\n")
                    # Simulate a peer arriving: send its destination line, then pipe.
                    if self._accept_delay:
                        time.sleep(self._accept_delay)
                    conn.sendall(f"{self.incoming_remote}\n".encode())
                    self._echo_pipe(conn, buf)
                    return
                elif line.startswith("STREAM FORWARD"):
                    conn.sendall(b"STREAM STATUS RESULT=OK\n")
                    # Forward stays "open" — just hold the socket until close.
                    self._drain(conn, buf)
                    return
                else:
                    conn.sendall(b"HELLO REPLY RESULT=I2P_ERROR\n")
        except OSError:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def _echo_pipe(self, conn: socket.socket, buf: bytearray) -> None:
        # Echo any already-buffered bytes plus subsequent ones, uppercased.
        if buf:
            conn.sendall(bytes(buf).upper())
            buf.clear()
        while True:
            data = conn.recv(4096)
            if not data:
                return
            conn.sendall(data.upper())

    def _drain(self, conn: socket.socket, buf: bytearray) -> None:
        while True:
            data = conn.recv(4096)
            if not data:
                return

    def close(self) -> None:
        self._stop = True
        try:
            self._srv.close()
        except OSError:
            pass


def _field(line: str, key: str) -> str:
    for tok in line.split():
        if tok.startswith(key + "="):
            return tok[len(key) + 1:]
    return ""


@pytest.fixture
def sam():
    server = FakeSam()
    yield server
    server.close()


# ---------------------------------------------------------------------------
# Primitives
# ---------------------------------------------------------------------------


def test_dest_generate(sam):
    pub, priv = dest_generate("127.0.0.1", sam.port)
    assert pub and priv and pub != priv


def test_naming_lookup_ok(sam):
    value = naming_lookup("127.0.0.1", sam.port, "notbob.i2p")
    assert len(value) > 100


def test_naming_lookup_failure():
    server = FakeSam(unresolvable={"ghost.i2p"})
    try:
        with pytest.raises(SAMError) as exc:
            naming_lookup("127.0.0.1", server.port, "ghost.i2p")
        assert "ghost.i2p" in str(exc.value)
    finally:
        server.close()


# ---------------------------------------------------------------------------
# Sessions
# ---------------------------------------------------------------------------


def test_session_generates_key_and_b32(sam):
    s = SamSession("127.0.0.1", sam.port, session_id="t1")
    b32 = s.create()
    assert b32.endswith(".b32.i2p")
    assert s.private_key            # captured for persistence
    assert s.destination           # public dest set
    assert s.b32 == b32
    s.close()


def test_session_persistent_keys_give_stable_b32(sam):
    # Simulate a saved keypair: create once, reuse pub/priv → same address.
    first = SamSession("127.0.0.1", sam.port, session_id="a")
    first.create()
    pub, priv = first.destination, first.private_key
    first.close()

    second = SamSession("127.0.0.1", sam.port, session_id="b",
                        pub_b64=pub, priv_b64=priv)
    second.create()
    assert second.b32 == b32_address(pub)
    second.close()


def test_stream_connect_pipe(sam):
    s = SamSession("127.0.0.1", sam.port, session_id="c")
    s.create()
    dest = _make_dest(5)
    sock = s.connect(dest)
    assert isinstance(sock, I2PSocket)
    assert sock.remote == b32_address(dest)
    sock.sendall(b"hello")
    assert sock.recv(64) == b"HELLO"     # fake echoes uppercased
    sock.close()
    s.close()


def test_stream_connect_failure():
    bad = _make_dest(7)
    server = FakeSam(fail_connect_to=bad)
    try:
        s = SamSession("127.0.0.1", server.port, session_id="d")
        s.create()
        with pytest.raises(SAMError) as exc:
            s.connect(bad)
        assert "CANT_REACH_PEER" in str(exc.value)
        s.close()
    finally:
        server.close()


def test_stream_accept_returns_remote(sam):
    s = SamSession("127.0.0.1", sam.port, session_id="e")
    s.create()
    conn = s.accept()
    assert conn.remote == b32_address(sam.incoming_remote)
    conn.sendall(b"ping")
    assert conn.recv(64) == b"PING"
    conn.close()
    s.close()


def test_forward_keeps_session_open(sam):
    s = SamSession("127.0.0.1", sam.port, session_id="f")
    s.create()
    s.forward(8080)
    assert s.is_open()
    s.close()


def test_forward_is_idempotent(sam):
    # Re-forwarding the same host:port must be a no-op — a second STREAM
    # FORWARD for the same target would pile up connections (and i2pd may
    # refuse it), breaking an idempotent-looking host_service() call.
    s = SamSession("127.0.0.1", sam.port, session_id="f2")
    s.create()
    s.forward(8080)
    s.forward(8080)
    assert len(s._forwards) == 1
    s.forward(8081)  # a different port is a genuine new forward
    assert len(s._forwards) == 2
    s.close()


def test_accept_blocks_past_protocol_timeout():
    # accept(timeout=None) must wait indefinitely for a peer — the
    # connection's protocol timeout (here shrunk to 0.2s) must not apply to
    # the peer wait. Regression: it used to leak through and kill accept()
    # after 30s.
    server = FakeSam(accept_delay=0.6)
    try:
        s = SamSession("127.0.0.1", server.port, session_id="slow", timeout=0.2)
        s.create()
        conn = s.accept(timeout=None)
        assert conn.remote == b32_address(server.incoming_remote)
        conn.close()
        s.close()
    finally:
        server.close()


def test_accept_honours_explicit_timeout():
    server = FakeSam(accept_delay=5.0)
    try:
        s = SamSession("127.0.0.1", server.port, session_id="slow2")
        s.create()
        with pytest.raises(socket.timeout):  # TimeoutError alias on 3.10+
            s.accept(timeout=0.2)
        s.close()
    finally:
        server.close()


def test_connect_resolves_name_first(sam):
    # A .i2p name is not a literal dest, so connect() must NAMING LOOKUP it.
    s = SamSession("127.0.0.1", sam.port, session_id="g")
    s.create()
    sock = s.connect("notbob.i2p")
    assert sock.remote.endswith(".b32.i2p")
    sock.close()
    s.close()


# ---------------------------------------------------------------------------
# SAM command injection — values we splice into command lines must not be able
# to smuggle extra KEY=VALUE tokens (space) or extra commands (newline).
# ---------------------------------------------------------------------------


def test_naming_lookup_rejects_injection(sam):
    # A second NAME= token would silently redirect the lookup.
    with pytest.raises(SAMError):
        naming_lookup("127.0.0.1", sam.port, "x.i2p NAME=evil.i2p")
    with pytest.raises(SAMError):
        naming_lookup("127.0.0.1", sam.port, 'x.i2p"')


def test_session_id_rejects_injection():
    # Session ids ride on SESSION CREATE next to DESTINATION= — a space could
    # inject tunnel options (e.g. inbound.length=0).
    with pytest.raises(SAMError):
        SamSession("127.0.0.1", 1, session_id="x inbound.length=0")


def test_session_options_reject_injection(sam):
    s = SamSession("127.0.0.1", sam.port, session_id="h",
                   options={"inbound.length": "3 outbound.length=0"})
    with pytest.raises(SAMError):
        s.create()


def test_forward_rejects_injection(sam):
    s = SamSession("127.0.0.1", sam.port, session_id="i")
    s.create()
    with pytest.raises(SAMError):
        s.forward(8080, host="127.0.0.1 SILENT=false")
    with pytest.raises((SAMError, ValueError, TypeError)):
        s.forward("80 HOST=evil")  # type: ignore[arg-type]
    s.close()


def test_session_kind_mismatch_raises(sam, tmp_path, monkeypatch):
    # Asking for a transient identity under a name already open as persistent
    # (or vice versa) must fail loudly — silently returning the cached session
    # would hand back a linkable identity to a caller who asked for a fresh,
    # unlinkable one.
    import basic_i2p
    monkeypatch.setattr(basic_i2p, "DATA_DIR", tmp_path)
    basic_i2p._keys_dir().mkdir(parents=True)
    mgr = basic_i2p.I2pdManager()
    mgr._sam_port = sam.port

    first = mgr.open_session("app", persistent=True)
    assert mgr.open_session("app", persistent=True) is first  # same kind: cached
    with pytest.raises(ValueError) as exc:
        mgr.open_session("app", persistent=False)
    assert "persistent" in str(exc.value)
    # A different name is fine, and tracks its own kind.
    mgr.open_session("other", persistent=False)
    with pytest.raises(ValueError):
        mgr.open_session("other", persistent=True)
    for s in mgr._sessions.values():
        s.close()


def test_create_rejects_tampered_private_key(sam):
    # A keypair file tampered to contain whitespace must not reach the wire.
    s = SamSession("127.0.0.1", sam.port, session_id="j",
                   pub_b64=_make_dest(3), priv_b64=_make_dest(3) + " EXTRA=1")
    with pytest.raises(SAMError):
        s.create()
