"""Differential conformance for the kXR_open FLAGS MATRIX and RESPONSE shape.

Every case drives the SAME raw-wire kXR_open against BOTH servers — our
nginx-xrootd and the stock XRootD data server (via official_interop_lib.start_pair)
— and asserts they agree on:

  * success / failure CATEGORY (kXR_ok vs which kXR error code), and
  * on success, the RESPONSE FRAMING: the open response body is the 4-byte
    fhandle ONLY (dlen==4), unless kXR_retstat was requested, in which case a
    stat trailer follows (dlen>4 and parses to "id size flags modtime ...").
  * the on-disk EFFECT of mutating opens (created / truncated / persisted /
    removed-on-POSC-disconnect / file mode), pinned to the stock server.

Philosophy (per the maintainer): a divergence — wrong dlen/framing, wrong
success/failure, wrong on-disk effect, mode mismatch, POSC semantics differ —
is a BUG IN OUR SERVER. We pin the stock server's behavior.

Reference facts pinned (XProtocol.hh / XrdXrootdXeq.cc do_Open):
  * ClientOpenRequest: streamid[2] requestid[2] mode[2] options[2] optiont[2]
    reserved[6] fhtemplt[4] dlen[4] then path (XProtocol.hh:509).
  * option bits: kXR_open_read 0x10, kXR_delete 0x02, kXR_new 0x08,
    kXR_open_updt 0x20, kXR_mkpath 0x100, kXR_open_apnd 0x200,
    kXR_retstat 0x400, kXR_posc 0x1000, kXR_open_wrto 0x8000 (XProtocol.hh:482).
  * ServerResponseBody_Open: fhandle[4] (+cpsize/cptype only if compress/retstat)
    then stat text if retstat (XProtocol.hh:1090, Xeq:1742-1757).
  * do_Open: kXR_new -> O_CREAT (fail if exists unless force); kXR_delete ->
    O_TRUNC; mode = mapMode(mode) | S_IRUSR | S_IWUSR (Xeq:1521-1565).
  * mapError: ENOENT->NotFound, EISDIR->isDirectory, EEXIST->ItExists.

Self-provisioning on high ports; skips entirely without the stock toolchain.

Run:
  TEST_SKIP_SERVER_SETUP=1 PYTHONPATH=tests \
    python -m pytest tests/test_conf_openflags.py -q
"""

import os
import socket
import struct
import time

import pytest

import official_interop_lib as L
from settings import BIND_HOST

pytestmark = [pytest.mark.timeout(240),
              pytest.mark.skipif(not L.have_official(),
                                 reason="stock xrootd/xrdfs/xrdcp not installed")]

# Raw-socket connections go straight to these ports, so they must be the live
# fleet pair (worker_port() shifts into an unbound per-worker band → refused).
OUR_PORT = L.worker_port(14066)   # per-worker band (was shared L.FLEET_OUR_PORT → 20003 collisions)
OFF_PORT = L.worker_port(14067)
BIND = BIND_HOST

# opcodes / status
kXR_login, kXR_open, kXR_close = 3007, 3010, 3003
kXR_write, kXR_read = 3012, 3013
kXR_ok, kXR_error = 0, 4003
DROPPED = -1   # sentinel: server dropped the link instead of replying (a valid rejection)

# kXR_open option bits (XProtocol.hh:482-499)
kXR_compress = 0x0001
kXR_delete = 0x0002
kXR_force = 0x0004
kXR_new = 0x0008
kXR_open_read = 0x0010
kXR_open_updt = 0x0020
kXR_mkpath = 0x0100
kXR_open_apnd = 0x0200
kXR_retstat = 0x0400
kXR_posc = 0x1000
kXR_open_wrto = 0x8000

# error codes (XErrorCode, XProtocol.hh:1032+)
kXR_NotFound = 3011
kXR_isDirectory = 3016
kXR_ItExists = 3018


# --------------------------------------------------------------------------- #
# raw-wire client (minimal pattern copied from test_brix_conformance.py)
# --------------------------------------------------------------------------- #
def _recv_exact(s, n):
    b = b""
    while len(b) < n:
        try:
            c = s.recv(n - len(b))
        except (ConnectionResetError, ConnectionAbortedError, OSError):
            raise EOFError("connection reset")
        if not c:
            raise EOFError("connection closed")
        b += c
    return b


def _resp(s):
    h = _recv_exact(s, 8)
    sid = h[0:2]
    status = struct.unpack("!H", h[2:4])[0]
    dlen = struct.unpack("!I", h[4:8])[0]
    body = _recv_exact(s, dlen) if dlen else b""
    return sid, status, body


def _connect(port):
    s = socket.create_connection((BIND, port), timeout=10)
    s.sendall(struct.pack("!IIIII", 0, 0, 0, 4, 2012))
    _, st, _ = _resp(s)  # handshake reply
    assert st == kXR_ok, "handshake failed"
    return s


def _login(s):
    s.sendall(struct.pack("!2sHI8sBBBBI", b"\x00\x01", kXR_login,
                          os.getpid() & 0x7fffffff, b"opfl\x00\x00\x00\x00",
                          0, 0, 0, 0, 0))
    _, st, _ = _resp(s)
    assert st == kXR_ok, "anon login failed"


def _session(port):
    s = _connect(port)
    _login(s)
    return s


def _open(s, path, options, mode=0, sid=b"\x00\x03"):
    """Raw kXR_open with full flag/mode control. Returns (status, body)."""
    p = path.encode()
    # streamid(2) requestid(2) mode(2) options(2) optiont(2) reserved(6)
    # fhtemplt(4) dlen(4)
    req = struct.pack("!2sHHHH6s4sI", sid, kXR_open, mode, options, 0,
                      b"\x00" * 6, b"\x00" * 4, len(p)) + p
    try:
        s.sendall(req)
        _, st, body = _resp(s)
    except (EOFError, BrokenPipeError, ConnectionResetError, OSError):
        return DROPPED, b""   # link drop is a valid rejection (treated as error)
    return st, body


def _write(s, fhandle, offset, data, sid=b"\x00\x07"):
    s.sendall(struct.pack("!2sH4sqiI", sid, kXR_write, fhandle, offset, 0,
                          len(data)) + data)
    _, st, _ = _resp(s)
    return st


def _close(s, fhandle, sid=b"\x00\x0e"):
    s.sendall(struct.pack("!2sH4s12sI", sid, kXR_close, fhandle, b"\x00" * 12, 0))
    try:
        _, st, _ = _resp(s)
        return st
    except EOFError:
        return None


def _errnum(body):
    return struct.unpack("!i", body[0:4])[0] if len(body) >= 4 else None


def _rejected(status):
    """A protocol error OR a link drop both count as a rejection."""
    return status in (kXR_error, DROPPED)


def _category(status, body):
    """Coarse success/failure category for differential comparison."""
    if status == kXR_ok:
        return "ok"
    if status == DROPPED:
        return "dropped"
    return "err:%s" % _errnum(body)


def _stat_trailer(body):
    """For a retstat open response: skip fhandle(4)+cpsize(4)+cptype(4)=12 and
    return the parsed stat fields; or, if the server appended the trailer right
    after the 4-byte handle, fall back to that. Returns list[str] or None."""
    for skip in (12, 4):
        if len(body) > skip:
            txt = body[skip:].split(b"\x00")[0].decode("ascii", "replace").strip()
            fields = txt.split()
            if len(fields) >= 4 and all(f.lstrip("-").isdigit() for f in fields[:4]):
                return fields
    return None


# --------------------------------------------------------------------------- #
# server pair fixture
# --------------------------------------------------------------------------- #
@pytest.fixture(scope="module")
def srv(tmp_path_factory):
    base = str(tmp_path_factory.mktemp("openflags"))
    try:
        procs, ctx = L.start_pair(base, our_port=OUR_PORT, off_port=OFF_PORT)
    except RuntimeError as e:
        pytest.skip(f"server pair did not start: {e}")
    yield ctx
    L.stop_pair(procs)


def our_disk(ctx, path):
    return os.path.join(ctx["our_data"], path.lstrip("/"))


def off_disk(ctx, path):
    return os.path.join(ctx["off_data"], path.lstrip("/"))


def _both(srv):
    return _session(OUR_PORT), _session(OFF_PORT)


def diff_open(srv, path, options, mode=0):
    """Open `path` with `options`/`mode` on BOTH servers; return
    (our_status, our_body, off_status, off_body, raw)."""
    so, sf = _both(srv)
    try:
        st_o, b_o = _open(so, path, options, mode)
        st_f, b_f = _open(sf, path, options, mode)
        raw = (f"\n  OURS  cat={_category(st_o, b_o)} dlen={len(b_o)} body={b_o[:48]!r}"
               f"\n  STOCK cat={_category(st_f, b_f)} dlen={len(b_f)} body={b_f[:48]!r}")
        return st_o, b_o, st_f, b_f, raw
    finally:
        so.close()
        sf.close()


def assert_same_category(srv, path, options, mode=0):
    st_o, b_o, st_f, b_f, raw = diff_open(srv, path, options, mode)
    co, cf = _category(st_o, b_o), _category(st_f, b_f)
    assert (st_o == kXR_ok) == (st_f == kXR_ok), \
        f"open({path}, opts=0x{options:x}) success differs:{raw}"
    if st_o != kXR_ok:
        assert co == cf, f"open({path}, opts=0x{options:x}) error category differs:{raw}"
    return st_o, b_o, st_f, b_f, raw


# =========================================================================== #
# A. READ-OPEN MATRIX — response shape parity (dlen==4, fhandle only)
# =========================================================================== #
READ_FILES = [
    "/hello.txt", "/data.bin", "/empty.txt", "/sub/nested.txt",
    "/sz_1.bin", "/sz_255.bin", "/sz_4095.bin", "/sz_4096.bin",
    "/sz_4097.bin", "/sz_8192.bin", "/sz_65536.bin",
    "/with space.txt", "/cksum.bin", "/big1m.bin",
    "/deep/a/b/c/leaf.txt", "/many/f00.txt", "/many/f11.txt",
]

def _seed_pair(srv, our_w, off_w, payload=b""):
    """Create identical files on both data roots out-of-band (for fail-if-exists
    differentials) so each server sees the same starting state."""
    with open(our_disk(srv, our_w), "wb") as f:
        f.write(payload)
    with open(off_disk(srv, off_w), "wb") as f:
        f.write(payload)
    # The fleet stock server runs as `nobody`; harmonize the seeded files (owner
    # triad mirrored into group+other) so it can truncate/overwrite them exactly
    # as our root-run server can, and so their stat flags agree.
    L.harmonize_perms(our_disk(srv, our_w), off_disk(srv, off_w))

def _open_our(path, options=kXR_open_read):
    """Open `path` on OURS only; return (status, body)."""
    s = _session(OUR_PORT)
    try:
        return _open(s, path, options)
    finally:
        s.close()
