"""
tests/test_ipv6_brix_stream.py — root:// XRootD stream over IPv6 (raw-wire).

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
    form (GATING — proves the AF_INET6 bracket-on-emit in src/protocols/root/read/locate.c).

Wire framing verified against /tmp/brix-src/src/XProtocol/XProtocol.hh:
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
    TEST_SKIP_SERVER_SETUP=1 PYTHONPATH=tests pytest tests/test_ipv6_brix_stream.py -v
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
# Wire constants (src/protocols/root/protocol/opcodes.h + flags.h, mirroring XProtocol.hh)
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

# Open option flags (src/protocols/root/protocol/flags.h)
kXR_delete    = 0x0002   # open for write, truncating to zero (create-or-clobber)
kXR_open_read = 0x0010   # O_RDONLY
kXR_open_updt = 0x0020   # O_RDWR

kXR_PROTOCOLVERSION = 0x00000520
BRIX_SESSION_ID_LEN = 16


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
            f"IPv6 stream instance [{HOST6}]:{IPV6_PORT} unreachable "
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
