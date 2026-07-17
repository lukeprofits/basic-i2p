"""
A minimal SAM v3.1 client.

Just enough of the SAM application bridge protocol
(https://geti2p.net/en/docs/api/samv3) to:

  * create a STREAM session bound to a destination (persistent or transient),
  * dial another destination (``STREAM CONNECT``),
  * accept inbound streams (``STREAM ACCEPT``) or forward them to a local
    port (``STREAM FORWARD``),
  * generate destination keys (``DEST GENERATE``) and resolve ``.i2p`` /
    ``.b32.i2p`` names (``NAMING LOOKUP``).

We deliberately do not depend on any existing SAM library: the protocol is a
line-oriented text handshake over a loopback TCP socket, after which the same
socket *becomes* the raw byte pipe to the remote destination. A dependency
would be larger than this file.

This module is intentionally free of any dependency on the rest of the package
so it can be unit-tested in isolation against a fake SAM server.
"""

from __future__ import annotations

import base64
import hashlib
import re
import socket

# SAM 3.1 is the newest version both i2pd and Java I2P have supported for
# years; it adds SIGNATURE_TYPE to SESSION CREATE (we want Ed25519, type 7).
_SAM_VERSION = "3.1"

# I2P's base64 alphabet replaces "+/" with "-~".
_I2P_B64_ALTCHARS = b"-~"

# A serialized destination is >= 387 bytes (516+ base64 chars). Anything that
# long and decodable is treated as a literal destination; everything else
# (b32 addresses, .i2p hostnames) goes through NAMING LOOKUP.
_MIN_DEST_B64_LEN = 516

_MAX_LINE_BYTES = 1 << 16  # SAM reply lines are small; a huge one is hostile.

# SAM commands are "KEY=VALUE" tokens separated by spaces on one line. Any
# value we interpolate must therefore contain no whitespace or quotes — a
# space in, say, a naming-lookup name would smuggle an extra KEY=VALUE pair
# into the command (e.g. a second NAME= that silently redirects the lookup).
# send_line() already blocks newlines; these pin down the rest per field.
_SESSION_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
# .i2p / .b32.i2p hostnames plus full base64 destinations (I2P alphabet).
_LOOKUP_NAME_RE = re.compile(r"^[A-Za-z0-9.\-~=_]{1,4096}$")
_FORWARD_HOST_RE = re.compile(r"^[A-Za-z0-9.\-:\[\]]{1,255}$")


def _require_safe(value: str, pattern: re.Pattern[str], what: str) -> str:
    if not pattern.match(value):
        raise SAMError(
            f"refusing to send unsafe {what} in a SAM command: {value[:80]!r} "
            f"(must match {pattern.pattern})"
        )
    return value


class SAMError(RuntimeError):
    """A SAM command failed or the bridge sent something malformed.

    The message carries the SAM ``RESULT=`` code and ``MESSAGE=`` text when
    present, so callers see e.g. ``CANT_REACH_PEER`` or ``DUPLICATED_ID``.
    """


def b32_address(dest_b64: str) -> str:
    """Derive the ``.b32.i2p`` address for a base64 destination.

    The b32 address is the SHA-256 of the binary destination, base32-encoded
    without padding — the same derivation every I2P router uses.
    """
    try:
        raw = base64.b64decode(dest_b64, altchars=_I2P_B64_ALTCHARS, validate=True)
    except (ValueError, TypeError) as exc:
        raise SAMError(f"not a valid base64 destination: {dest_b64[:40]!r}…") from exc
    digest = hashlib.sha256(raw).digest()
    b32 = base64.b32encode(digest).decode("ascii").rstrip("=").lower()
    return f"{b32}.b32.i2p"


def looks_like_dest(value: str) -> bool:
    """True if ``value`` is a full base64 destination rather than a name."""
    if len(value) < _MIN_DEST_B64_LEN or "." in value:
        return False
    try:
        base64.b64decode(value, altchars=_I2P_B64_ALTCHARS, validate=True)
        return True
    except (ValueError, TypeError):
        return False


def parse_reply(line: str) -> dict[str, str]:
    """Parse a SAM reply line into a dict.

    ``STREAM STATUS RESULT=I2P_ERROR MESSAGE="failed to reach"`` becomes
    ``{"_verb": "STREAM STATUS", "RESULT": "I2P_ERROR", "MESSAGE": "failed to reach"}``.
    Values may be double-quoted to contain spaces; quotes are stripped.
    """
    tokens = _tokenize(line)
    if len(tokens) < 2:
        raise SAMError(f"malformed SAM reply: {line!r}")
    out: dict[str, str] = {"_verb": f"{tokens[0]} {tokens[1]}"}
    for tok in tokens[2:]:
        key, sep, val = tok.partition("=")
        if sep:
            out[key] = val
    return out


def _tokenize(line: str) -> list[str]:
    """Split on spaces, keeping ``KEY="quoted value"`` as one token."""
    tokens: list[str] = []
    cur: list[str] = []
    in_quotes = False
    for ch in line:
        if ch == '"':
            in_quotes = not in_quotes
        elif ch == " " and not in_quotes:
            if cur:
                tokens.append("".join(cur))
                cur = []
        else:
            cur.append(ch)
    if in_quotes:
        raise SAMError(f"unterminated quote in SAM reply: {line!r}")
    if cur:
        tokens.append("".join(cur))
    return tokens


class I2PSocket:
    """A connected I2P stream.

    Wraps the TCP socket to the SAM bridge after the handshake phase; from
    that point the socket is a raw byte pipe to the remote destination.
    ``recv`` first drains any bytes the handshake line-reader over-read.

    Attributes:
        remote: the remote peer — a ``.b32.i2p`` address for accepted
            connections, or whatever you dialed for outbound ones.
    """

    def __init__(self, sock: socket.socket, pending: bytes = b"", remote: str = "") -> None:
        self._sock = sock
        self._pending = pending
        self.remote = remote

    def sendall(self, data: bytes) -> None:
        self._sock.sendall(data)

    def send(self, data: bytes) -> int:
        return self._sock.send(data)

    def recv(self, bufsize: int) -> bytes:
        if self._pending:
            out, self._pending = self._pending[:bufsize], self._pending[bufsize:]
            return out
        return self._sock.recv(bufsize)

    def settimeout(self, value: float | None) -> None:
        self._sock.settimeout(value)

    def fileno(self) -> int:
        return self._sock.fileno()

    def close(self) -> None:
        try:
            self._sock.close()
        except OSError:
            pass

    def __enter__(self) -> I2PSocket:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


class SamConnection:
    """One TCP connection to the SAM bridge, HELLO'd and line-buffered."""

    def __init__(self, host: str, port: int, timeout: float = 30.0) -> None:
        self._host = host
        self._port = port
        self._timeout = timeout
        self._sock: socket.socket | None = None
        self._buf = b""

    def connect(self) -> None:
        sock = socket.create_connection((self._host, self._port), timeout=self._timeout)
        sock.settimeout(self._timeout)
        self._sock = sock
        try:
            reply = self.command(
                f"HELLO VERSION MIN={_SAM_VERSION} MAX={_SAM_VERSION}", expect="HELLO REPLY"
            )
            if reply.get("RESULT") != "OK":
                raise SAMError(f"SAM HELLO rejected: {reply}")
        except BaseException:
            self.close()
            raise

    def close(self) -> None:
        if self._sock is not None:
            try:
                self._sock.close()
            finally:
                self._sock = None
        self._buf = b""

    def __enter__(self) -> SamConnection:
        self.connect()
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # ---------------- wire protocol ----------------

    def command(self, line: str, expect: str, timeout: float | None = None) -> dict[str, str]:
        """Send one command line, read one reply line, check its verb.

        ``timeout`` overrides the connection timeout for the reply read —
        SESSION CREATE legitimately takes as long as a tunnel build.
        """
        self.send_line(line)
        if timeout is not None:
            assert self._sock is not None
            self._sock.settimeout(timeout)
        try:
            reply = parse_reply(self.read_line())
        finally:
            if timeout is not None and self._sock is not None:
                self._sock.settimeout(self._timeout)
        if reply["_verb"] != expect:
            raise SAMError(f"expected {expect!r} reply, got: {reply}")
        return reply

    def send_line(self, line: str) -> None:
        if self._sock is None:
            raise SAMError("SAM connection is not open")
        # The protocol is line-oriented: a newline smuggled inside an argument
        # (e.g. a hostile session name) would be sent as a second command.
        if "\n" in line or "\r" in line:
            raise SAMError(f"SAM command must be a single line: {line!r}")
        self._sock.sendall(line.encode("utf-8") + b"\n")

    def set_timeout(self, value: float | None) -> None:
        """Socket timeout for subsequent reads. ``None`` blocks forever."""
        if self._sock is None:
            raise SAMError("SAM connection is not open")
        self._sock.settimeout(value)

    def read_line(self) -> str:
        while b"\n" not in self._buf:
            assert self._sock is not None
            chunk = self._sock.recv(4096)
            if not chunk:
                raise SAMError("SAM connection closed mid-reply")
            self._buf += chunk
            if len(self._buf) > _MAX_LINE_BYTES:
                raise SAMError("SAM reply line exceeded 64 KiB — refusing to buffer more")
        line, _, self._buf = self._buf.partition(b"\n")
        return line.decode("utf-8", errors="replace").rstrip("\r")

    def detach(self) -> tuple[socket.socket, bytes]:
        """Hand over the raw socket plus any over-read bytes; stop owning it."""
        assert self._sock is not None
        sock, buf = self._sock, self._buf
        self._sock = None
        self._buf = b""
        return sock, buf


def dest_generate(host: str, port: int, timeout: float = 30.0) -> tuple[str, str]:
    """Generate a new Ed25519 destination. Returns ``(pub_b64, priv_b64)``."""
    with SamConnection(host, port, timeout) as conn:
        reply = conn.command("DEST GENERATE SIGNATURE_TYPE=7", expect="DEST REPLY")
        pub, priv = reply.get("PUB"), reply.get("PRIV")
        if not pub or not priv:
            raise SAMError(f"DEST GENERATE returned no keys: {reply}")
        return pub, priv


def naming_lookup(host: str, port: int, name: str, timeout: float = 30.0) -> str:
    """Resolve a ``.i2p`` / ``.b32.i2p`` name to a base64 destination."""
    _require_safe(name, _LOOKUP_NAME_RE, "lookup name")
    with SamConnection(host, port, timeout) as conn:
        reply = conn.command(f"NAMING LOOKUP NAME={name}", expect="NAMING REPLY")
        if reply.get("RESULT") != "OK":
            raise SAMError(
                f"could not resolve {name!r}: {reply.get('RESULT')} "
                f"{reply.get('MESSAGE', '')}".strip()
            )
        value = reply.get("VALUE")
        if not value:
            raise SAMError(f"NAMING REPLY for {name!r} carried no VALUE: {reply}")
        return value


class SamSession:
    """A STREAM session bound to one destination.

    The session lives exactly as long as its control socket: SAM tears the
    session (and every stream in it) down when that socket closes, which is
    also our cleanup mechanism — no explicit session-destroy command needed.
    """

    def __init__(self, host: str, port: int, session_id: str,
                 pub_b64: str | None = None, priv_b64: str | None = None,
                 timeout: float = 30.0, create_timeout: float = 180.0,
                 options: dict[str, str] | None = None) -> None:
        self._host = host
        self._port = port
        self._timeout = timeout
        self._create_timeout = create_timeout
        self._options = dict(options or {})
        self.session_id = _require_safe(session_id, _SESSION_ID_RE, "session id")
        # pub+priv are either both given (persistent, loaded from disk) or both
        # None (generated in create()). We never mix.
        self.destination = pub_b64 or ""  # public dest b64
        self._priv = priv_b64
        self._control: SamConnection | None = None
        self._forwards: list[SamConnection] = []
        self._forward_addrs: set[tuple[str, int]] = set()

    @property
    def b32(self) -> str:
        return b32_address(self.destination)

    def create(self) -> str:
        """Create the session on the bridge; returns the ``.b32.i2p`` address.

        If no keypair was supplied, one is generated first so the public
        destination (and therefore the ``.b32.i2p`` address) is always known
        without parsing the binary private-key blob.
        """
        if not self._priv:
            self.destination, self._priv = dest_generate(
                self._host, self._port, self._timeout
            )
        # A keypair loaded from disk is data, not code: if the file was
        # corrupted or tampered into containing whitespace, refuse to splice
        # it into the command line.
        _require_safe(self._priv, _LOOKUP_NAME_RE, "private destination")
        conn = SamConnection(self._host, self._port, self._timeout)
        conn.connect()
        try:
            parts = [
                f"SESSION CREATE STYLE=STREAM ID={self.session_id} DESTINATION={self._priv}",
            ]
            for k, v in self._options.items():
                _require_safe(f"{k}{v}", _LOOKUP_NAME_RE, "session option")
                parts.append(f"{k}={v}")
            # Tunnel build happens inside this call — allow it session-create time.
            reply = conn.command(" ".join(parts), expect="SESSION STATUS",
                                 timeout=self._create_timeout)
            if reply.get("RESULT") != "OK":
                raise SAMError(
                    f"SESSION CREATE failed: {reply.get('RESULT')} "
                    f"{reply.get('MESSAGE', '')}".strip()
                )
        except BaseException:
            conn.close()
            raise
        self._control = conn
        return self.b32

    @property
    def private_key(self) -> str:
        """The full private destination (base64) — persist this to keep the address."""
        if not self._priv:
            raise SAMError("session has no private key yet — call create() first")
        return self._priv

    def connect(self, dest: str, timeout: float | None = None) -> I2PSocket:
        """Open a stream to ``dest`` (base64 destination, ``.b32.i2p``, or ``.i2p`` name)."""
        self._require_created()
        if not looks_like_dest(dest):
            dest = naming_lookup(self._host, self._port, dest, self._timeout)
        conn = SamConnection(self._host, self._port, self._timeout)
        conn.connect()
        try:
            # Building the outbound stream can take multiple tunnel hops.
            reply = conn.command(
                f"STREAM CONNECT ID={self.session_id} DESTINATION={dest} SILENT=false",
                expect="STREAM STATUS",
                timeout=timeout if timeout is not None else self._create_timeout,
            )
            if reply.get("RESULT") != "OK":
                raise SAMError(
                    f"could not connect to {b32_address(dest)}: {reply.get('RESULT')} "
                    f"{reply.get('MESSAGE', '')}".strip()
                )
        except BaseException:
            conn.close()
            raise
        sock, pending = conn.detach()
        sock.settimeout(None)
        return I2PSocket(sock, pending, remote=b32_address(dest))

    def accept(self, timeout: float | None = None) -> I2PSocket:
        """Block until a peer connects; returns the stream (``.remote`` = their b32).

        ``timeout=None`` waits indefinitely; a number raises ``socket.timeout``
        (``TimeoutError`` on 3.10+) if no peer dials within that many seconds.
        """
        self._require_created()
        conn = SamConnection(self._host, self._port, self._timeout)
        conn.connect()
        try:
            reply = conn.command(
                f"STREAM ACCEPT ID={self.session_id} SILENT=false",
                expect="STREAM STATUS",
            )
            if reply.get("RESULT") != "OK":
                raise SAMError(
                    f"STREAM ACCEPT failed: {reply.get('RESULT')} "
                    f"{reply.get('MESSAGE', '')}".strip()
                )
            # Now the bridge holds the socket until a peer arrives, then sends
            # one line: the remote destination (3.2+ appends FROM_PORT/TO_PORT).
            # The wait is unbounded unless the caller asked otherwise — the
            # connection's protocol timeout must not apply here.
            conn.set_timeout(timeout)
            first = conn.read_line()
        except BaseException:
            conn.close()
            raise
        remote_dest = first.split()[0] if first.split() else ""
        sock, pending = conn.detach()
        try:
            remote = b32_address(remote_dest) if remote_dest else ""
        except SAMError:
            sock.close()
            raise
        sock.settimeout(None)
        return I2PSocket(sock, pending, remote=remote)

    def forward(self, port: int, host: str = "127.0.0.1") -> None:
        """Forward inbound streams to a local ``host:port`` listener.

        SILENT=true so the forwarded connection carries only payload bytes —
        the local server (e.g. your HTTP app) never sees the SAM header line.
        Forwarding stays active while this session lives. Re-forwarding the
        same ``host:port`` is a no-op, so callers can be idempotent.
        """
        self._require_created()
        _require_safe(host, _FORWARD_HOST_RE, "forward host")
        port = int(port)
        if (host, port) in self._forward_addrs:
            return
        conn = SamConnection(self._host, self._port, self._timeout)
        conn.connect()
        try:
            reply = conn.command(
                f"STREAM FORWARD ID={self.session_id} PORT={port} HOST={host} SILENT=true",
                expect="STREAM STATUS",
            )
            if reply.get("RESULT") != "OK":
                raise SAMError(
                    f"STREAM FORWARD to {host}:{port} failed: {reply.get('RESULT')} "
                    f"{reply.get('MESSAGE', '')}".strip()
                )
        except BaseException:
            conn.close()
            raise
        # The forward lives as long as this socket — keep it open.
        self._forwards.append(conn)
        self._forward_addrs.add((host, port))

    def is_open(self) -> bool:
        return self._control is not None

    def close(self) -> None:
        for fwd in self._forwards:
            fwd.close()
        self._forwards.clear()
        self._forward_addrs.clear()
        if self._control is not None:
            self._control.close()
            self._control = None

    def _require_created(self) -> None:
        if self._control is None:
            raise SAMError("session is not open — call create() first")
