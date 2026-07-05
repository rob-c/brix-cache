# _test_conf_rename_helpers.py - shared header/helpers/fixtures/constants for the Phase-38
# split of test_conf_rename.py.  `from _test_conf_rename_helpers import *` re-exports EVERYTHING via
# the __all__ below so the test functions keep their exact module namespace.


"""Differential conformance for kXR_mv (rename / move) and directory-manipulation
semantics IN DEPTH — stock XRootD tools (xrdfs/xrdcp) + RAW WIRE against BOTH our
nginx-xrootd server and the stock xrootd data server, on identical throwaway
trees.

This file goes DEEPER than test_conf_write_ops.py (basic mv/mkdir/rmdir) and
test_conf_errors.py (mv error categories) — it exhaustively probes rename edge
cases: same-dir rename, cross-dir move, missing-dest-parent, overwrite-onto-file,
onto-empty-dir, onto-nonempty-dir, directory rename (subtree move), same-path
no-op, trailing-slash forms, case-only differences, special names, src-under-dst,
content/mode/mtime preservation, round-trips, and the RAW kXR_mv framing contract
(arg1len + space separator, out-of-range arg1len, embedded NUL, missing dst).

Philosophy (per the maintainer): a divergence is a BUG IN OUR SERVER unless there
is positive evidence otherwise. EVERY mutating operation is run on BOTH servers,
on PARALLEL UNIQUE paths (so neither tree pollutes the other test's
expectations), and we require:

  * same success/failure class ((rc == 0) on OUR  ==  (rc == 0) on STOCK), and
  * the SAME coarse error category if it fails (L.err_code, alias-normalized), and
  * the SAME on-disk effect (src gone, dst present, exact content bytes, mode/
    mtime as stock leaves them), and
  * confinement: a traversal src/dst is DENIED on OUR server and nothing escapes.

Any wrong success/failure, wrong on-disk effect, content/mode not preserved,
framing-handling difference, or confinement bypass is flagged as a BUG. We pin
the stock server's behavior — no xfail/skip is used to hide a real divergence.

kXR_mv wire contract (XProtocol.hh ClientMvRequest + XrdXrootdXeq.cc do_Mv):
  struct: streamid[2] requestid(u16) reserved[14] arg1len(int16) dlen(int32)
  data buffer: "<oldpath> <newpath>" (single space separator).
  do_Mv: if arg1len != 0, byte at offset arg1len MUST be ' ' (else kXR_ArgInvalid
  'invalid path specification') and arg1len must satisfy 0 <= n < dlen; oldpath is
  buff[0..arg1len), newpath is buff[arg1len+1..]. If arg1len == 0 the server
  splits on the first space itself. A missing new path -> kXR_ArgMissing.

Harness: official_interop_lib (PYTHONPATH=tests). Self-provisions our + stock
servers on high ports; skips entirely without the stock xrootd toolchain.
"""

import hashlib
import os
import socket
import struct

import pytest

import official_interop_lib as L

pytestmark = [pytest.mark.timeout(300),
              pytest.mark.skipif(not L.have_official(),
                                 reason="stock xrootd/xrdfs/xrdcp not installed")]

OUR_PORT = L.worker_port(14048)
OFF_PORT = L.worker_port(14049)
# --------------------------------------------------------------------------- #
# Module fixture: one server pair (rich tree) for the whole file. Extra fixture
# dirs/files are built IDENTICALLY on both data roots so every differential is
# byte-exact from the same starting state.
# --------------------------------------------------------------------------- #
@pytest.fixture(scope="module")
def srv(tmp_path_factory):
    base = str(tmp_path_factory.mktemp("confrename"))
    try:
        procs, ctx = L.start_pair(base, our_port=OUR_PORT, off_port=OFF_PORT)
    except RuntimeError as e:
        pytest.skip(f"server pair did not start: {e}")
    # Build identical extra scaffolding on BOTH roots.
    for data in (ctx["our_data"], ctx["off_data"]):
        _seed_scaffold(data)
    yield ctx
    L.stop_pair(procs)


def _seed_scaffold(data):
    """Identical extra dirs/files on each data root (idempotent)."""
    j = os.path.join
    for d in ("rn_d1", "rn_d2", "rn_deep/x/y/z", "rn_empty_target"):
        os.makedirs(j(data, *d.split("/")), exist_ok=True)


# --------------------------------------------------------------------------- #
# Stock-client runners + on-disk verification helpers.
# --------------------------------------------------------------------------- #
def fs(url, *args, timeout=60):
    """Stock xrdfs runner -> (rc, out, err)."""
    return L.run([L.OFF_XRDFS, url, *args], timeout=timeout)


# Collapse the coarse L.err_code keys that name the SAME underlying XRootD error
# under different wordings, so the differential compares semantics, not phrasing.
_CATEGORY_ALIASES = {
    "no such file": "notfound",
    "not found": "notfound",
    "not authorized": "auth",
    "permission": "auth",
    "already exists": "exists",
    "exists": "exists",
    "is a directory": "isdir",
    "not a directory": "notdir",
    "not empty": "notempty",
    "invalid": "invalid",
    "no space": "nospace",
    "unsupported": "unsupported",
}


def _category(text):
    return _CATEGORY_ALIASES.get(L.err_code(text), L.err_code(text))


def our_disk(ctx, path):
    return os.path.join(ctx["our_data"], path.lstrip("/"))


def off_disk(ctx, path):
    return os.path.join(ctx["off_data"], path.lstrip("/"))


def make_local(path, n, seed=11):
    with open(path, "wb") as f:
        f.write(bytes((i * 37 + seed) & 0xff for i in range(n)))
    return path


def write_disk(ctx, wire, data):
    """Write identical content to the same wire path on BOTH data roots."""
    for disk in (our_disk(ctx, wire), off_disk(ctx, wire)):
        os.makedirs(os.path.dirname(disk), exist_ok=True)
        mode = "wb" if isinstance(data, (bytes, bytearray)) else "w"
        with open(disk, mode) as f:
            f.write(data)


def mkdir_disk(ctx, wire):
    for disk in (our_disk(ctx, wire), off_disk(ctx, wire)):
        os.makedirs(disk, exist_ok=True)


def md5_file(path):
    h = hashlib.md5()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def mv_both(ctx, our_src, our_dst, off_src, off_dst):
    """Run `mv` on each server with its own (unique) src/dst -> raw diagnostics."""
    rc_o, o_o, e_o = fs(ctx["our"], "mv", our_src, our_dst)
    rc_f, o_f, e_f = fs(ctx["off"], "mv", off_src, off_dst)
    raw = (f"\n  OURS  rc={rc_o} cat={_category(o_o + e_o)!r} :: {(o_o + e_o).strip()!r}"
           f"\n  STOCK rc={rc_f} cat={_category(o_f + e_f)!r} :: {(o_f + e_f).strip()!r}")
    return (rc_o, _category(o_o + e_o)), (rc_f, _category(o_f + e_f)), raw


def assert_mv_parity(ctx, our_src, our_dst, off_src, off_dst):
    """mv on each server (parallel unique paths): success-class must match, and
    if failing the category must match too. Returns (rc_our, rc_stock, raw)."""
    (rc_o, cat_o), (rc_f, cat_f), raw = mv_both(ctx, our_src, our_dst, off_src, off_dst)
    assert (rc_o == 0) == (rc_f == 0), f"mv success-class divergence:{raw}"
    if rc_o != 0:
        assert cat_o == cat_f, f"mv error-category divergence:{raw}"
    return rc_o, rc_f, raw


# =========================================================================== #
# 20. CONFINEMENT — mv with src or dst escaping the root must be DENIED on OUR
#     server (rc != 0), no host escape; compare to stock denial. (4 tests)
# =========================================================================== #
TRAVERSAL_SRCS = [
    "/../../etc/passwd",
    "/../../../etc/passwd",
    "/../../../../etc/passwd",
    "/rn_d1/../../../etc/passwd",
]


# =========================================================================== #
# RAW-WIRE kXR_mv framing conformance.
#
# A minimal raw-wire XRootD client (adapted from test_conf_errors.py) pointed at
# EITHER server, so the same kXR_mv frame gets the same accept/reject from OUR
# and the STOCK server. We exercise the arg1len + space-separator contract that
# do_Mv() enforces directly.
# =========================================================================== #
kXR_login, kXR_mv = 3007, 3009
kXR_ok, kXR_error = 0, 4003
kXR_ArgInvalid, kXR_ArgMissing = 3000, 3001
kXR_InvalidRequest, kXR_NotFound = 3006, 3011
kXR_NotAuthorized = 3010

# Reject codes that all name "the mv request itself is illegal / not allowed".
_REJECT_CLASS = {kXR_ArgInvalid, kXR_ArgMissing, kXR_InvalidRequest,
                 kXR_NotAuthorized, kXR_NotFound, 3002}  # 3002 = kXR_ArgTooLong


def _port_of(url):
    return int(url.rsplit(":", 1)[1])


def _recv_exact(s, n):
    b = b""
    while len(b) < n:
        c = s.recv(n - len(b))
        if not c:
            raise EOFError("closed")
        b += c
    return b


def _resp(s):
    h = _recv_exact(s, 8)
    status = struct.unpack("!H", h[2:4])[0]
    dlen = struct.unpack("!I", h[4:8])[0]
    body = _recv_exact(s, dlen) if dlen else b""
    return status, body


def _connect(url):
    s = socket.create_connection((L.BIND, _port_of(url)), timeout=10)
    s.sendall(struct.pack("!IIIII", 0, 0, 0, 4, 2012))
    return s


def _login(s, sid=b"\x00\x01"):
    s.sendall(struct.pack("!2sHI8sBBBBI", sid, kXR_login,
                          os.getpid() & 0x7fffffff, b"err\x00\x00\x00\x00\x00",
                          0, 0, 0, 0, 0))
    st, _ = _resp(s)
    assert st == kXR_ok, "anon login failed"


def _session(url):
    s = _connect(url)
    st, _ = _resp(s)               # handshake reply
    assert st == kXR_ok
    _login(s)
    return s


def _err(body):
    return struct.unpack("!i", body[0:4])[0] if len(body) >= 4 else None


def _mv_frame(buf, arg1len, sid=b"\x00\x07"):
    """Build a raw kXR_mv request:
       streamid[2] requestid(u16) reserved[14] arg1len(int16) dlen(int32) + buf
    """
    return (struct.pack("!2sH14shi", sid, kXR_mv, b"\x00" * 14,
                        arg1len, len(buf)) + buf)


def _send_mv(url, buf, arg1len):
    """Logged-in session -> send one kXR_mv frame -> (status, errnum)."""
    s = _session(url)
    try:
        s.sendall(_mv_frame(buf, arg1len))
        try:
            st, body = _resp(s)
        except EOFError:
            return ("EOF", None)
        return (st, _err(body))
    finally:
        s.close()


def _wire_reject(st):
    return st == kXR_error or st == "EOF"

__all__ = [n for n in dir() if not n.startswith('__')]
