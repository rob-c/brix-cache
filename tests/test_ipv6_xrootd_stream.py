"""
tests/test_ipv6_xrootd_stream.py — root:// XRootD stream over IPv6 (raw-wire).

Phase-36 §7.2.1.  Drives the dedicated IPv6 stream instance
(`nginx_ipv6_stream.conf`, `listen [::1]:{PORT}`, auth none, allow_write on)
entirely over RAW TCP sockets to ("::1", IPV6_STREAM_PORT).  Raw wire is
mandatory here: the PyXRootD high-level client mishandles `root://[::1]`
literals in this environment ("[FATAL] Invalid address"), so every root://
assertion is built by hand from kXR frames — the framing helpers are copied
from tests/test_handshake_protocol_wire.py and tests/test_pgread_wire_conformance.py.

What this proves:
  * handshake + kXR_protocol + kXR_login bring-up over IPv6;
  * open/read byte-exact, write+readback, stat, dirlist, locate all work over
    the IPv6 loopback transport (REGRESSION / SMOKE — these work today);
  * the kXR_locate response for a server reached over IPv6 carries the
    BRACKETED "Sr[::1]:<port>" location token, never the bare "Sr::1:<port>"
    form (GATING — proves the AF_INET6 bracket-on-emit in src/read/locate.c).

Wire framing verified against /tmp/xrootd-src/src/XProtocol/XProtocol.hh:
  * ClientInitHandShake — five 32-bit BE words; word4==4, word5==2012.
  * ClientProtocolRequest / ClientLoginRequest — see the handshake-wire suite.
  * ClientOpenRequest    — streamid[2] reqid[2] mode[2] options[2] optiont[2]
                           reserved[6] fhtemplt[4] dlen[4]; fhandle in resp[:4].
  * ClientReadRequest    — streamid[2] reqid[2] fhandle[4] offset[8] rlen[4] dlen[4].
  * ClientWriteRequest   — streamid[2] reqid[2] fhandle[4] offset[8] pathid[1]
                           reserved[3] dlen[4] + data.
  * ClientStatRequest    — streamid[2] reqid[2] reserved[16] dlen[4] + path;
                           reply body is ASCII "<id> <size> <flags> <mtime>".
  * ClientDirlistRequest — streamid[2] reqid[2] reserved[15] options[1] dlen[4];
                           reply body is newline-delimited entry names.
  * ClientLocateRequest  — streamid[2] reqid[2] options[2] reserved[14] dlen[4];
                           data-server reply is "S<acc>[<host>]:<port>" (IPv6).

Skip discipline: every test depends on the session-scoped
`requires_ipv6_loopback` fixture (skips on hosts without ::1) AND a per-module
reachable6(port) probe (skips when the dedicated instance is down).  Instance
absence is never a failure.

Run:
    TEST_SKIP_SERVER_SETUP=1 PYTHONPATH=tests pytest tests/test_ipv6_xrootd_stream.py -v
"""

import hashlib
import os
import socket
import struct

import pytest

from settings import HOST6, IPV6_STREAM_DATA_ROOT, IPV6_STREAM_PORT


# ---------------------------------------------------------------------------
# IPv6 target.  PyXRootD cannot reach root://[::1]; we hand-build kXR frames
# over a raw AF_INET6 socket to (HOST6, port).  HOST6 defaults to "::1" so a
# local run is byte-identical; set TEST_HOST6 to split client/server nodes.
# ---------------------------------------------------------------------------

IPV6_HOST = HOST6
IPV6_PORT = IPV6_STREAM_PORT


# ---------------------------------------------------------------------------
# Wire constants (src/protocol/opcodes.h + flags.h, mirroring XProtocol.hh)
# ---------------------------------------------------------------------------

ROOTD_PQ         = 2012   # handshake 5th word magic
HANDSHAKE_FOURTH = 4      # handshake 4th word magic

kXR_dirlist  = 3004
kXR_close    = 3003
kXR_login    = 3007
kXR_open     = 3010
kXR_ping     = 3011
kXR_read     = 3013
kXR_protocol = 3006
kXR_stat     = 3017
kXR_write    = 3019
kXR_locate   = 3027

kXR_ok      = 0
kXR_error   = 4003
kXR_status  = 4007

# Open option flags (src/protocol/flags.h)
kXR_delete    = 0x0002   # open for write, truncating to zero (create-or-clobber)
kXR_open_read = 0x0010   # O_RDONLY
kXR_open_updt = 0x0020   # O_RDWR

kXR_PROTOCOLVERSION = 0x00000520
XROOTD_SESSION_ID_LEN = 16


# ---------------------------------------------------------------------------
# Raw socket helpers (mirror tests/test_pgread_wire_conformance.py exactly,
# but connect over AF_INET6 to ::1).
# ---------------------------------------------------------------------------

def _connect6(timeout=8):
    """Open a raw TCP socket to the IPv6 loopback instance.

    socket.create_connection resolves "::1" to an AF_INET6 endpoint, so this
    sidesteps the PyXRootD bracket-parsing bug entirely.
    """
    sock = socket.create_connection((IPV6_HOST, IPV6_PORT), timeout=timeout)
    sock.settimeout(timeout)
    return sock


def _recv_exact(sock, nbytes):
    data = bytearray()
    while len(data) < nbytes:
        chunk = sock.recv(nbytes - len(data))
        if not chunk:
            raise ConnectionError(
                f"socket closed, {nbytes - len(data)} bytes remaining")
        data.extend(chunk)
    return bytes(data)


def _read_response(sock):
    """Read one ServerResponseHdr (streamid[2] status[2] dlen[4]) + its body."""
    header = _recv_exact(sock, 8)
    streamid, status, dlen = struct.unpack("!2sHI", header)
    body = _recv_exact(sock, dlen) if dlen else b""
    return streamid, status, body


def _error_code(body):
    return struct.unpack("!I", body[:4])[0] if len(body) >= 4 else 0


def _handshake(sock):
    """Send the 20-byte ClientInitHandShake; consume the 8-byte server reply."""
    sock.sendall(struct.pack("!IIIII", 0, 0, 0, HANDSHAKE_FOURTH, ROOTD_PQ))
    _, status, body = _read_response(sock)
    assert status == kXR_ok, "IPv6 handshake unexpectedly rejected"
    return body


def _protocol(sock, streamid=b"\x00\x01"):
    """ClientProtocolRequest: streamid[2] reqid[2] clientpv[4] flags[1]
    expect[1] reserved[10] dlen[4]."""
    req = struct.pack("!2sHIBB10sI", streamid, kXR_protocol,
                      kXR_PROTOCOLVERSION, 0, 0, b"\x00" * 10, 0)
    sock.sendall(req)
    return _read_response(sock)


def _login(sock, streamid=b"\x00\x02"):
    """ClientLoginRequest: streamid[2] reqid[2] pid[4] username[8] ability2[1]
    ability[1] capver[1] reserved2[1] dlen[4]."""
    req = struct.pack("!2sHI8sBBBBI", streamid, kXR_login,
                      os.getpid() & 0xFFFFFFFF, b"pytest\x00\x00",
                      0, 0, 5, 0, 0)
    sock.sendall(req)
    return _read_response(sock)


def _session():
    """handshake + kXR_login -> a fully established session over IPv6."""
    sock = _connect6()
    _handshake(sock)
    _, status, _ = _login(sock)
    assert status == kXR_ok, "anonymous IPv6 login rejected"
    return sock


def _open(sock, path, options=kXR_open_read, streamid=b"\x00\x03"):
    """ClientOpenRequest; returns (streamid, status, body).  fhandle = body[:4]."""
    p = path.encode() + b"\x00" if isinstance(path, str) else path
    req = struct.pack("!2sHHH2s6s4sI",
                      streamid, kXR_open,
                      0o644, options, b"\x00\x00", b"\x00" * 6, b"\x00" * 4,
                      len(p))
    sock.sendall(req + p)
    return _read_response(sock)


def _close(sock, fhandle, streamid=b"\x00\x0e"):
    req = struct.pack("!2sH4s12sI", streamid, kXR_close, fhandle,
                      b"\x00" * 12, 0)
    sock.sendall(req)
    return _read_response(sock)


def _read(sock, fhandle, offset, rlen, streamid=b"\x00\x06"):
    """ClientReadRequest: streamid[2] reqid[2] fhandle[4] offset[8] rlen[4] dlen[4]."""
    req = struct.pack("!2sH4sqiI", streamid, kXR_read, fhandle,
                      offset, rlen, 0)
    sock.sendall(req)
    return _read_response(sock)


def _write(sock, fhandle, offset, data, streamid=b"\x00\x07"):
    """ClientWriteRequest: streamid[2] reqid[2] fhandle[4] offset[8] pathid[1]
    reserved[3] dlen[4] + data.  The pathid+reserved (4 zero bytes) are packed
    as a single int32 between offset and dlen, matching the wire spec layout
    (XProtocol.hh ClientWriteRequest) and tests/test_wire_protocol_security.py.
    """
    req = struct.pack("!2sH4sqiI", streamid, kXR_write, fhandle,
                      offset, 0, len(data))
    sock.sendall(req + data)
    return _read_response(sock)


def _stat(sock, path, streamid=b"\x00\x08"):
    """ClientStatRequest: streamid[2] reqid[2] reserved[16] dlen[4] + path."""
    p = path.encode() + b"\x00" if isinstance(path, str) else path
    req = struct.pack("!2sH16sI", streamid, kXR_stat, b"\x00" * 16, len(p))
    sock.sendall(req + p)
    return _read_response(sock)


def _dirlist(sock, path, streamid=b"\x00\x09"):
    """ClientDirlistRequest: streamid[2] reqid[2] reserved[15] options[1] dlen[4].

    options byte left 0 (name-only listing, no kXR_dstat), so the reply body is
    a newline-delimited list of entry names.
    """
    p = path.encode() + b"\x00" if isinstance(path, str) else path
    req = struct.pack("!2sH15sBI", streamid, kXR_dirlist,
                      b"\x00" * 15, 0, len(p))
    sock.sendall(req + p)
    return _read_response(sock)


def _locate(sock, path, options=0, streamid=b"\x00\x0a"):
    """ClientLocateRequest: streamid[2] reqid[2] options[2] reserved[14] dlen[4].

    A data-server reply is kXR_ok carrying a NUL-terminated "S<acc><host>:<port>"
    location token; for an IPv6 server <host> is bracketed: "Sr[::1]:<port>".
    """
    p = path.encode() + b"\x00" if isinstance(path, str) else path
    req = struct.pack("!2sHH14sI", streamid, kXR_locate,
                      options, b"\x00" * 14, len(p))
    sock.sendall(req + p)
    return _read_response(sock)


def _ping(sock, streamid=b"\x00\x0f"):
    req = struct.pack("!2sH16sI", streamid, kXR_ping, b"\x00" * 16, 0)
    sock.sendall(req)
    return _read_response(sock)


# ---------------------------------------------------------------------------
# Seed data + module guards.
# ---------------------------------------------------------------------------

HELLO_NAME = "/test.txt"
HELLO_BODY = b"hello from nginx-xrootd"          # 23 bytes
HELLO_LEN  = len(HELLO_BODY)

BIN_NAME = "/random.bin"
BIN_BODY = bytes((i * 37 + 11) & 0xFF for i in range(4096))

WRITE_NAME = "/test_ipv6_write.bin"
WRITE_BODY = bytes((i * 53 + 3) & 0xFF for i in range(64 * 1024))   # 64 KiB

DIR_NAME = "/ipv6dir"


def _reachable6(port, timeout=2.0):
    """[::1]:port up?  Mirrors the per-file reachability probe used by the rest
    of the IPv6 suite (and test_open_flags_lifecycle._reachable for AF_INET6)."""
    try:
        socket.create_connection((IPV6_HOST, port), timeout=timeout).close()
        return True
    except OSError:
        return False


@pytest.fixture(scope="module", autouse=True)
def _ipv6_stream_guard(requires_ipv6_loopback):
    """Gate the whole module: first the host must have a usable ::1 loopback
    (session fixture), then the dedicated IPv6 stream instance must be up.

    Both are skips, never failures — an absent instance must not redden the
    suite (TEST_SKIP_SERVER_SETUP=1 runs against pre-started servers only).
    """
    if not _reachable6(IPV6_PORT):
        pytest.skip(
            f"IPv6 stream instance [::1]:{IPV6_PORT} unreachable "
            f"(start-all not run, or dedicated instance down)")


@pytest.fixture(scope="module", autouse=True)
def _seed_data():
    """Materialise the known files under the IPv6 instance data root.

    Skips (does not error) when the data root is not locally writable — e.g.
    when the instance lives on a remote host this process cannot reach.
    """
    try:
        os.makedirs(IPV6_STREAM_DATA_ROOT, exist_ok=True)
        with open(os.path.join(IPV6_STREAM_DATA_ROOT,
                               HELLO_NAME.lstrip("/")), "wb") as f:
            f.write(HELLO_BODY)
        with open(os.path.join(IPV6_STREAM_DATA_ROOT,
                               BIN_NAME.lstrip("/")), "wb") as f:
            f.write(BIN_BODY)
    except OSError as exc:
        pytest.skip(f"IPv6 data root {IPV6_STREAM_DATA_ROOT!r} not locally "
                    f"writable: {exc}")
    return IPV6_STREAM_DATA_ROOT


# ===========================================================================
# Class 1 — connection bring-up over IPv6
# ===========================================================================

class TestIpv6Bringup:
    """The handshake/protocol/login sequence must complete unchanged over the
    IPv6 loopback transport (REGRESSION / SMOKE)."""

    def test_ipv6_connect_handshake_login(self):
        """ClientInitHandShake accepted (8-byte body, protover 0x520);
        kXR_protocol -> kXR_ok with kXR_isServer-bearing advert; kXR_login ->
        a 16-byte session id.  Proves the whole bring-up works over ::1."""
        sock = _connect6()
        try:
            body = _handshake(sock)
            assert len(body) == 8, "handshake body must be 8 bytes"
            protover, _kind = struct.unpack("!II", body)
            assert protover == kXR_PROTOCOLVERSION, f"protover=0x{protover:x}"

            _, pstatus, pbody = _protocol(sock)
            assert pstatus == kXR_ok, _error_code(pbody)
            assert len(pbody) >= 8, "short kXR_protocol advert"

            _, lstatus, lbody = _login(sock)
            assert lstatus == kXR_ok, _error_code(lbody)
            assert len(lbody) == XROOTD_SESSION_ID_LEN, \
                "anon login body must be the 16-byte session id"
            assert _ping(sock)[1] == kXR_ok
        finally:
            sock.close()

    def test_ipv6_ping_round_trip(self):
        """A kXR_ping liveness round-trip succeeds on an established IPv6
        session — the simplest end-to-end transport check."""
        sock = _session()
        try:
            assert _ping(sock)[1] == kXR_ok
        finally:
            sock.close()


# ===========================================================================
# Class 2 — read path over IPv6
# ===========================================================================

class TestIpv6Read:
    """open + read + close, byte-exact, over IPv6 (REGRESSION / SMOKE)."""

    def test_ipv6_open_read_scalar_byte_exact(self):
        """open(read) -> a valid handle; read(HELLO_LEN) returns exactly the
        seeded "hello from nginx-xrootd" bytes."""
        sock = _session()
        try:
            _, status, body = _open(sock, HELLO_NAME, kXR_open_read)
            assert status == kXR_ok, f"open failed: {_error_code(body)}"
            assert len(body) >= 4, "open ok-response missing the 4-byte handle"
            # Handles are slot indices 0-255 (src/connection/fd_table.c), so a
            # value of 0 is a perfectly valid first handle — the read below is
            # the real proof the handle works.
            fh = body[:4]

            _, rstatus, rbody = _read(sock, fh, 0, HELLO_LEN)
            assert rstatus == kXR_ok, f"read failed: {_error_code(rbody)}"
            assert rbody == HELLO_BODY, \
                f"scalar read not byte-exact: {rbody!r}"

            assert _close(sock, fh)[1] == kXR_ok
            assert _ping(sock)[1] == kXR_ok
        finally:
            sock.close()

    def test_ipv6_open_read_binary_byte_exact(self):
        """A larger binary file reads back byte-exact over IPv6 — proves the
        data path (not just a 23-byte payload) is faithful across the transport."""
        sock = _session()
        try:
            _, status, body = _open(sock, BIN_NAME, kXR_open_read)
            assert status == kXR_ok, f"open failed: {_error_code(body)}"
            fh = body[:4]

            _, rstatus, rbody = _read(sock, fh, 0, len(BIN_BODY))
            assert rstatus == kXR_ok, f"read failed: {_error_code(rbody)}"
            assert rbody == BIN_BODY, "binary read not byte-exact over IPv6"

            _close(sock, fh)
            assert _ping(sock)[1] == kXR_ok
        finally:
            sock.close()

    def test_ipv6_open_nonexistent_clean_error(self):
        """open of a path that does not exist returns a clean protocol error
        (NOT a crash / hang) and the session survives — negative control for
        the read path."""
        sock = _session()
        try:
            _, status, body = _open(sock, "/does-not-exist-ipv6.bin",
                                    kXR_open_read)
            assert status == kXR_error, "open of missing file must error"
            assert _ping(sock)[1] == kXR_ok
        finally:
            sock.close()


# ===========================================================================
# Class 3 — write path over IPv6
# ===========================================================================

class TestIpv6Write:
    """open(write) + write + read-back, byte-exact, over IPv6 (REGRESSION)."""

    def test_ipv6_write_open_new_byte_exact(self):
        """open(updt|delete) creates/truncates a file, write(64 KiB) lands the
        bytes, and an independent re-open+read returns the exact md5.  Also
        confirmed against the on-disk file when the data root is local."""
        sock = _session()
        try:
            _, status, body = _open(sock, WRITE_NAME,
                                    kXR_open_updt | kXR_delete)
            assert status == kXR_ok, f"write-open failed: {_error_code(body)}"
            fh = body[:4]

            _, wstatus, wbody = _write(sock, fh, 0, WRITE_BODY)
            assert wstatus == kXR_ok, f"write failed: {_error_code(wbody)}"
            assert _close(sock, fh)[1] == kXR_ok
        finally:
            sock.close()

        # Re-open in a fresh session and read the data straight back.
        sock2 = _session()
        try:
            _, status, body = _open(sock2, WRITE_NAME, kXR_open_read)
            assert status == kXR_ok, f"re-open failed: {_error_code(body)}"
            fh = body[:4]
            got = bytearray()
            off = 0
            while off < len(WRITE_BODY):
                _, rstatus, rbody = _read(sock2, fh, off,
                                          len(WRITE_BODY) - off)
                assert rstatus == kXR_ok, f"readback failed: {_error_code(rbody)}"
                if not rbody:
                    break
                got.extend(rbody)
                off += len(rbody)
            _close(sock2, fh)
            assert hashlib.md5(bytes(got)).hexdigest() == \
                hashlib.md5(WRITE_BODY).hexdigest(), \
                "written data did not read back byte-exact over IPv6"
        finally:
            sock2.close()

        # Belt-and-braces on-disk check when the data root is local to us.
        disk = os.path.join(IPV6_STREAM_DATA_ROOT, WRITE_NAME.lstrip("/"))
        if os.path.exists(disk):
            with open(disk, "rb") as f:
                assert f.read() == WRITE_BODY, "on-disk file mismatch"


# ===========================================================================
# Class 4 — metadata path over IPv6
# ===========================================================================

class TestIpv6Metadata:
    """stat + dirlist over IPv6 (REGRESSION / SMOKE)."""

    def test_ipv6_stat_size(self):
        """stat of the seeded text file returns a kXR_ok ASCII body
        "<id> <size> <flags> <mtime>" whose size field equals HELLO_LEN."""
        sock = _session()
        try:
            _, status, body = _stat(sock, HELLO_NAME)
            assert status == kXR_ok, f"stat failed: {_error_code(body)}"
            fields = body.split(b"\x00", 1)[0].split()
            assert len(fields) >= 4, f"malformed stat body: {body!r}"
            size = int(fields[1])
            assert size == HELLO_LEN, \
                f"stat size {size} != {HELLO_LEN} (body {body!r})"
            assert _ping(sock)[1] == kXR_ok
        finally:
            sock.close()

    def test_ipv6_stat_nonexistent_clean_error(self):
        """stat of a missing path returns a clean error, session survives —
        negative control proving stat is a real parse, not a blanket ok."""
        sock = _session()
        try:
            _, status, _body = _stat(sock, "/missing-ipv6-xyz.bin")
            assert status == kXR_error, "stat of missing path must error"
            assert _ping(sock)[1] == kXR_ok
        finally:
            sock.close()

    def test_ipv6_dirlist(self):
        """A dirlist of the root lists the seeded entries.  The name-only body
        is newline-delimited; test.txt must appear, and after the write test
        runs test_ipv6_write.bin would too — we only require the always-present
        seed files so the test is order-independent."""
        sock = _session()
        try:
            _, status, body = _dirlist(sock, "/")
            assert status == kXR_ok, f"dirlist failed: {_error_code(body)}"
            names = set(body.replace(b"\x00", b"").split(b"\n"))
            assert b"test.txt" in names, \
                f"test.txt missing from dirlist: {body!r}"
            assert b"random.bin" in names, \
                f"random.bin missing from dirlist: {body!r}"
            assert _ping(sock)[1] == kXR_ok
        finally:
            sock.close()


# ===========================================================================
# Class 5 — locate bracketing (the IPv6 wire-format assertion)
# ===========================================================================

class TestIpv6Locate:
    """kXR_locate on a data server reached over IPv6.  The local-locate path
    (src/read/locate.c, AF_INET6 branch) formats the response from
    c->local_sockaddr and MUST bracket the address."""

    def test_ipv6_locate_local_brackets_regression(self):
        """GATING for the bracket-on-emit contract over IPv6: the kXR_locate
        reply for a file on this IPv6 data server is the "S<acc>..." location
        token, and the host portion MUST be the bracketed form

            Sr[::1]:<port>   (or Sw[::1]:<port> when allow_write)

        and MUST NOT be the bare, colon-ambiguous form "S?::1:<port>".

        src/read/locate.c emits "S%c[%s]:%d" via inet_ntop on the AF_INET6
        local sockaddr; a regression to bare "%s:%d" would make the client
        mis-parse the embedded colons.  Asserting "[::1]:" appears proves the
        bracket is on the wire.
        """
        sock = _session()
        try:
            _, status, body = _locate(sock, HELLO_NAME)
            assert status == kXR_ok, \
                f"locate of an existing file failed: {_error_code(body)}"
            token = body.split(b"\x00", 1)[0]
            assert token[:1] == b"S", \
                f"locate token must start with 'S': {token!r}"
            # The data server reached us over ::1, so the emitted host is the
            # bracketed IPv6 loopback literal followed by ':<port>'.
            assert b"[::1]:" in token, (
                f"IPv6 locate token not bracketed (expected 'Sr[::1]:<port>'): "
                f"{token!r}")
            # And explicitly NOT the bare un-bracketed form that the fix replaces.
            assert b"S" + token[1:2] + b"::1:" not in token, (
                f"locate token used the bare un-bracketed IPv6 form: {token!r}")
            assert _ping(sock)[1] == kXR_ok
        finally:
            sock.close()

    def test_ipv6_locate_wildcard_self(self):
        """The '*' wildcard locate (locate the local server itself) also returns
        a bracketed IPv6 location token — exercises the same emit path without
        requiring a real file to exist."""
        sock = _session()
        try:
            _, status, body = _locate(sock, "*")
            assert status == kXR_ok, \
                f"wildcard locate failed: {_error_code(body)}"
            token = body.split(b"\x00", 1)[0]
            assert token[:1] == b"S", f"bad wildcard locate token: {token!r}"
            assert b"[::1]:" in token, (
                f"wildcard IPv6 locate not bracketed: {token!r}")
            assert _ping(sock)[1] == kXR_ok
        finally:
            sock.close()


# ===========================================================================
# Class 6 — concurrency isolation over IPv6
# ===========================================================================

class TestIpv6Concurrency:
    """Multiple IPv6 sessions are independent (REGRESSION)."""

    def test_ipv6_concurrent_streams_isolation(self):
        """Three simultaneous IPv6 sessions each open+read the same file
        byte-exact; closing one leaves the others usable.  Proves per-stream
        state isolation holds over the IPv6 transport."""
        socks = [_session() for _ in range(3)]
        try:
            handles = []
            for s in socks:
                _, status, body = _open(s, HELLO_NAME, kXR_open_read)
                assert status == kXR_ok, f"open failed: {_error_code(body)}"
                handles.append(body[:4])

            # Read on every stream — all byte-exact and independent.
            for s, fh in zip(socks, handles):
                _, rstatus, rbody = _read(s, fh, 0, HELLO_LEN)
                assert rstatus == kXR_ok, f"read failed: {_error_code(rbody)}"
                assert rbody == HELLO_BODY

            # Close the first stream entirely; the rest must keep working.
            _close(socks[0], handles[0])
            socks[0].close()
            for s, fh in zip(socks[1:], handles[1:]):
                _, rstatus, rbody = _read(s, fh, 0, HELLO_LEN)
                assert rstatus == kXR_ok, "surviving stream broke after a peer closed"
                assert rbody == HELLO_BODY
                assert _ping(s)[1] == kXR_ok
        finally:
            for s in socks:
                try:
                    s.close()
                except OSError:
                    pass
