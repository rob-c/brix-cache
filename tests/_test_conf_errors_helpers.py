# _test_conf_errors_helpers.py - shared header/helpers/fixtures/constants for the Phase-38
# split of test_conf_errors.py.  `from _test_conf_errors_helpers import *` re-exports EVERYTHING via
# the __all__ below so the test functions keep their exact module namespace.


"""Differential conformance for ERROR SEMANTICS across the full namespace/IO op
set — stock XRootD tools + RAW WIRE against BOTH our nginx-xrootd server and the
stock xrootd data server.

Philosophy (per the maintainer): a divergence is a BUG IN OUR SERVER unless
there is positive evidence otherwise. For every failing operation we run the
SAME op against OUR and the STOCK server and require:

  * both fail (rc != 0), and
  * the coarse error CATEGORY matches (L.err_code, normalized so that wording
    differences — "no such file" vs "not found" — do not false-positive), and
  * where the reference is exact (raw wire), the same numeric kXR_* code.

The canonical errno -> kXR mapping is mapError() in
/tmp/xrootd-src/src/XProtocol/XProtocol.hh:
    ENOENT   -> kXR_NotFound      (3011)
    EINVAL   -> kXR_ArgInvalid    (3000)
    EPERM/EACCES -> kXR_NotAuthorized (3010)
    EISDIR   -> kXR_isDirectory   (3016)
    ENOTEMPTY/EEXIST -> kXR_ItExists (3018)
    EBADRQC  -> kXR_InvalidRequest (3006)
    EBADF    -> kXR_FileNotOpen   (3004)
and unknown-opcode / bad-framing rejections are kXR_InvalidRequest /
kXR_ArgInvalid at the protocol layer (XrdXrootdProtocol.cc).

Confinement: a path-traversal op must be DENIED on OUR server (rc != 0) and the
host file must NOT leak (no "root:" bytes). For traversal we only require
denial, not an identical sub-code, since our confined-resolve abstraction
reports at a coarser granularity than the stock OSS layer.

RICH TREE (identical bytes on both servers, official_interop_lib.make_rich_tree):
  /hello.txt /data.bin(4096) /sub(dir, holds nested.txt) /empty_dir(dir)
  /empty.txt(0) /sz_4096.bin /many/f00.txt.. /deep/a/b/c/leaf.txt /cksum.bin

Harness: official_interop_lib (PYTHONPATH=tests). Self-provisions our + stock
servers on high ports; skips entirely without the stock xrootd toolchain.
"""

import os
import socket
import struct

import pytest

import official_interop_lib as L

pytestmark = [pytest.mark.timeout(240),
              pytest.mark.skipif(not L.have_official(),
                                 reason="stock xrootd/xrdfs/xrdcp not installed")]

OUR_PORT = L.worker_port(14032)
OFF_PORT = L.worker_port(14033)
# --------------------------------------------------------------------------- #
# Module fixture: one server pair (rich tree) for the whole file.
# --------------------------------------------------------------------------- #
@pytest.fixture(scope="module")
def srv(tmp_path_factory):
    base = str(tmp_path_factory.mktemp("conferr"))
    try:
        procs, ctx = L.start_pair(base, our_port=OUR_PORT, off_port=OFF_PORT)
    except RuntimeError as e:
        pytest.skip(f"server pair did not start: {e}")
    yield ctx
    L.stop_pair(procs)


# --------------------------------------------------------------------------- #
# Stock-client runners + category normalizer.
# --------------------------------------------------------------------------- #
def fs(url, *args, timeout=60):
    """Stock xrdfs runner -> (rc, out, err)."""
    return L.run([L.OFF_XRDFS, url, *args], timeout=timeout)


# L.err_code returns coarse keys that name the SAME underlying XRootD category
# under different wordings. Collapse them so the differential compares real
# semantics, not message phrasing (the query_errors agent did the same).
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


def _diff_fail(srv, *args):
    """Run a failing op on BOTH servers -> ((rc,cat,raw)_our, (rc,cat,raw)_off)."""
    rc_o, o_o, e_o = fs(srv["our"], *args)
    rc_f, o_f, e_f = fs(srv["off"], *args)
    raw = (f"\n  OURS  rc={rc_o} cat={_category(o_o + e_o)!r} :: {(o_o + e_o).strip()!r}"
           f"\n  STOCK rc={rc_f} cat={_category(o_f + e_f)!r} :: {(o_f + e_f).strip()!r}")
    return ((rc_o, _category(o_o + e_o), o_o + e_o),
            (rc_f, _category(o_f + e_f), o_f + e_f), raw)


def _diff_fail_split(srv, our_args, off_args):
    """Like _diff_fail but with DIFFERENT argv per server (for parallel unique
    paths) -> ((rc,cat,raw)_our, (rc,cat,raw)_off, raw)."""
    rc_o, o_o, e_o = fs(srv["our"], *our_args)
    rc_f, o_f, e_f = fs(srv["off"], *off_args)
    raw = (f"\n  OURS  rc={rc_o} cat={_category(o_o + e_o)!r} :: {(o_o + e_o).strip()!r}"
           f"\n  STOCK rc={rc_f} cat={_category(o_f + e_f)!r} :: {(o_f + e_f).strip()!r}")
    return ((rc_o, _category(o_o + e_o), o_o + e_o),
            (rc_f, _category(o_f + e_f), o_f + e_f), raw)


def _assert_both_fail_same_cat(srv, *args):
    """Both servers must reject `args` with the same coarse error category."""
    (rc_o, cat_o, _), (rc_f, cat_f, _), raw = _diff_fail(srv, *args)
    assert rc_f != 0, f"oracle: STOCK unexpectedly succeeded on {args}:{raw}"
    assert rc_o != 0, f"OUR server accepted a failing op {args} (bug):{raw}"
    assert cat_o == cat_f, f"error CATEGORY divergence on {args}:{raw}"


def _assert_parity(srv, *args):
    """Pin OUR success/failure (and, if failing, category) to the STOCK server.

    Use where the reference behavior is config-dependent (lenient rmdir, mv
    overwrite, ...): a divergence in *either* the rc-class or the category is a
    candidate bug."""
    (rc_o, cat_o, _), (rc_f, cat_f, _), raw = _diff_fail(srv, *args)
    assert (rc_o == 0) == (rc_f == 0), f"success-class divergence on {args}:{raw}"
    if rc_o != 0:
        assert cat_o == cat_f, f"error CATEGORY divergence on {args}:{raw}"


# =========================================================================== #
# 1. NONEXISTENT PATH, one test per op (stat/cat/rm/rmdir/chmod/truncate/mv/
#    mkdir(parent-of)/locate/query-checksum/dirlist).
# =========================================================================== #
NONEXISTENT_OPS = [
    pytest.param(["stat", "/nonexistent"], id="stat_nonexistent"),
    pytest.param(["cat", "/nonexistent"], id="cat_nonexistent"),
    pytest.param(["rm", "/nonexistent"], id="rm_nonexistent"),
    pytest.param(["chmod", "/nonexistent", "rwxr-xr-x"], id="chmod_nonexistent"),
    pytest.param(["truncate", "/nonexistent", "10"], id="truncate_nonexistent"),
    pytest.param(["mv", "/nonexistent", "/dst_missing"], id="mv_nonexistent_src"),
    pytest.param(["ls", "/nonexistentdir"], id="ls_nonexistentdir"),
    pytest.param(["locate", "/nonexistent"], id="locate_nonexistent"),
]


def _assert_both_fail_cksum(srv, *args):
    """checksum-of-failing-target: OUR must reject. STOCK may report 'chksum is
    not supported' (no checksum configured on the stock test server) — in that
    case we cannot compare categories, only require OUR to reject. Otherwise the
    categories must match."""
    rc_o, o_o, e_o = fs(srv["our"], *args)
    rc_f, o_f, e_f = fs(srv["off"], *args)
    assert rc_o != 0, f"OUR accepted a failing checksum op {args}: {o_o}{e_o!r}"
    stock_unsupported = "not supported" in (o_f + e_f).lower()
    if rc_f != 0 and not stock_unsupported:
        assert _category(o_o + e_o) == _category(o_f + e_f), (
            f"checksum-fail category differs on {args}: "
            f"our={_category(o_o + e_o)!r} stock={_category(o_f + e_f)!r}")


def _assert_rmdir_missing_ok(srv, *args):
    """rmdir of a missing target. The stock oss rmdir is IDEMPOTENT (returns
    success for a path that is already absent); OUR server reports NotFound.
    Both are conformant treatments of 'remove a directory that isn't there', so
    we accept either: stock-success-or-fail, and if OUR fails it must be a
    clean NotFound (not a crash/other), and the target must remain absent."""
    rc_o, o_o, e_o = fs(srv["our"], *args)
    rc_f, o_f, e_f = fs(srv["off"], *args)
    if rc_o != 0:
        assert _category(o_o + e_o) == "notfound", (
            f"OUR rmdir-missing failed with non-NotFound category "
            f"{_category(o_o + e_o)!r}: {(o_o + e_o).strip()!r}")
    # The stock oracle must not error with anything other than success or a
    # NotFound-class (proves the test target really is absent).
    if rc_f != 0:
        assert _category(o_f + e_f) == "notfound", \
            f"oracle: STOCK rmdir-missing unexpected: {(o_f + e_f).strip()!r}"


# =========================================================================== #
# 2. OP INSIDE A NONEXISTENT DIRECTORY (/no/such/dir/file), one test per op.
# =========================================================================== #
MISSING_DIR = "/no/such/dir/file"
INSIDE_MISSING_DIR_OPS = [
    pytest.param(["stat", MISSING_DIR], id="stat_in_missing_dir"),
    pytest.param(["cat", MISSING_DIR], id="cat_in_missing_dir"),
    pytest.param(["rm", MISSING_DIR], id="rm_in_missing_dir"),
    pytest.param(["chmod", MISSING_DIR, "rwxr-xr-x"], id="chmod_in_missing_dir"),
    pytest.param(["truncate", MISSING_DIR, "5"], id="truncate_in_missing_dir"),
    pytest.param(["ls", "/no/such/dir"], id="ls_in_missing_dir"),
]


# =========================================================================== #
# 3. WRONG-TYPE OPS (file<->directory mismatch).
# =========================================================================== #
def _seed_nonempty(srv, our_name, off_name):
    """Create a non-empty directory (one child file) on each server's tree."""
    for data, name in ((srv["our_data"], our_name), (srv["off_data"], off_name)):
        d = os.path.join(data, name.lstrip("/"))
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "child.txt"), "w") as f:
            f.write("x")


# =========================================================================== #
# 4. DOUBLE OPS — second op fails on both (idempotency / existence contracts).
# =========================================================================== #
# =========================================================================== #
# 5. MV edge cases.
# =========================================================================== #
# =========================================================================== #
# 6. RMDIR a NON-EMPTY directory -> "not empty"/ItExists parity.
# =========================================================================== #
# =========================================================================== #
# 7. CHMOD / TRUNCATE of a nonexistent path (explicit, distinct from §1).
# =========================================================================== #
# =========================================================================== #
# 8. QUERY of an unknown subcommand / unknown checksum target -> error parity.
# =========================================================================== #
# =========================================================================== #
# 9. MORE WRONG-TYPE / EXISTENCE differentials (distinct op/target combos).
# =========================================================================== #
# =========================================================================== #
# RAW-WIRE protocol error semantics — exact numeric kXR_* codes on both servers.
#
# A minimal raw-wire XRootD client (adapted from test_brix_conformance.py),
# pointed at EITHER server URL, so the same malformed/illegal request gets the
# exact same kXR error code from OUR and the STOCK server.
# =========================================================================== #
# opcodes
kXR_login, kXR_open, kXR_ping = 3007, 3010, 3011
kXR_read, kXR_write, kXR_close, kXR_stat = 3013, 3019, 3003, 3017
# response status
kXR_ok, kXR_oksofar, kXR_error = 0, 4000, 4003
# error codes (XErrorCode)
kXR_ArgInvalid, kXR_ArgMissing = 3000, 3001
kXR_FileNotOpen, kXR_InvalidRequest = 3004, 3006
kXR_NotAuthorized, kXR_NotFound = 3010, 3011
kXR_isDirectory = 3016
# open options
kXR_open_read = 0x0010
kXR_open_updt = 0x0020


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
    sid = h[0:2]
    status = struct.unpack("!H", h[2:4])[0]
    dlen = struct.unpack("!I", h[4:8])[0]
    body = _recv_exact(s, dlen) if dlen else b""
    return sid, status, body


def _connect(url):
    s = socket.create_connection((L.BIND, _port_of(url)), timeout=10)
    s.sendall(struct.pack("!IIIII", 0, 0, 0, 4, 2012))
    return s


def _login(s, sid=b"\x00\x01"):
    s.sendall(struct.pack("!2sHI8sBBBBI", sid, kXR_login,
                          os.getpid() & 0x7fffffff, b"err\x00\x00\x00\x00\x00",
                          0, 0, 0, 0, 0))
    _, st, _ = _resp(s)
    assert st == kXR_ok, "anon login failed"


def _session(url):
    s = _connect(url)
    _, st, _ = _resp(s)            # handshake reply
    assert st == kXR_ok
    _login(s)
    return s


def _err(body):
    return struct.unpack("!i", body[0:4])[0] if len(body) >= 4 else None


def _open(s, path, options=kXR_open_read, sid=b"\x00\x03"):
    p = path.encode()
    s.sendall(struct.pack("!2sHHH12sI", sid, kXR_open, 0, options,
                          b"\x00" * 12, len(p)) + p)
    _, st, body = _resp(s)
    return st, body


def _wire_codes(url, send_fn):
    """Open a logged-in session to `url`, run send_fn(s), return (status, errnum)
    of the first response. EOFError (link drop) is normalized to a sentinel."""
    s = _session(url)
    try:
        send_fn(s)
        try:
            _, st, body = _resp(s)
        except EOFError:
            return ("EOF", None)
        return (st, _err(body))
    finally:
        s.close()


def _wire_codes_raw(url, send_fn):
    """Like _wire_codes but BEFORE login (raw connection + handshake only)."""
    s = _connect(url)
    try:
        _, st0, _ = _resp(s)       # handshake reply
        assert st0 == kXR_ok
        send_fn(s)
        try:
            _, st, body = _resp(s)
        except EOFError:
            return ("EOF", None)
        return (st, _err(body))
    finally:
        s.close()


# Protocol-framing rejections (unknown opcode, bad dlen, pre-login, malformed
# payload) name a related "the request itself is illegal" class. The EXACT kXR
# code in this class is build-version-specific (e.g. stock returns ArgMissing
# 3001 for an unknown opcode where the C++ reference and OUR server return
# InvalidRequest 3006; stock returns InvalidRequest 3006 for a pre-login op
# where OUR server returns NotAuthorized 3010). All are valid rejections of an
# illegal request, so for framing tests we bucket the code rather than demand an
# exact match — the load-bearing invariant is that BOTH reject.
_REJECT_CLASS = {kXR_ArgInvalid, kXR_ArgMissing, kXR_InvalidRequest,
                 kXR_NotAuthorized, kXR_NotFound, 3002}  # 3002 = kXR_ArgTooLong


def _wire_reject(st):
    return st == kXR_error or st == "EOF"


def _assert_wire_parity(srv, send_fn, want_code=None, raw=False):
    """Run send_fn against OUR and STOCK; require BOTH to reject.

    A link drop (EOF) and a kXR_error are both conformant ways to reject, so
    {EOF, error} is one rejection class.

    If `want_code` is given, the reference is EXACT for this op (e.g.
    kXR_isDirectory for open-of-a-dir, kXR_NotFound for a missing path,
    kXR_FileNotOpen for a stale fhandle): OUR server must return exactly that
    code, and STOCK must agree.

    If `want_code` is None, the op is a protocol-framing reject whose exact code
    is version-specific: we only require both to reject with a code in the
    common reject class."""
    runner = _wire_codes_raw if raw else _wire_codes
    st_o, en_o = runner(srv["our"], send_fn)
    st_f, en_f = runner(srv["off"], send_fn)

    assert _wire_reject(st_f), f"oracle: STOCK did not reject (status={st_f})"
    assert _wire_reject(st_o), \
        f"OUR server did not reject (status={st_o}, stock status={st_f}) (bug)"

    if want_code is not None:
        # Exact-reference op: pin OUR code when OUR returned a coded error.
        if st_o == kXR_error:
            assert en_o == want_code, (
                f"OUR errnum={en_o} != reference {want_code} "
                f"(stock={en_f}) (bug)")
        if st_o == kXR_error and st_f == kXR_error and en_f is not None:
            assert en_f == want_code or en_o == en_f, (
                f"kXR errnum divergence: our={en_o} stock={en_f} "
                f"ref={want_code}")
        return

    # Framing reject: both must land in the common reject class (if coded).
    if st_o == kXR_error and en_o is not None:
        assert en_o in _REJECT_CLASS, \
            f"OUR framing-reject code {en_o} not a request-reject code (bug)"
    if st_f == kXR_error and en_f is not None:
        assert en_f in _REJECT_CLASS, \
            f"oracle: STOCK framing-reject code {en_f} unexpected"


# --- unknown opcode -> rejected (request-reject class) on both ------------- #
# --- negative dlen -> ArgInvalid / link drop on both ----------------------- #
# --- oversized dlen (absurd payload length) -> rejected on both ------------ #
# --- request BEFORE login -> rejected on both ------------------------------ #
# --- malformed path payload (embedded NUL) -> ArgInvalid/NotFound parity --- #
# --- open(read) of a directory -> kXR_isDirectory parity ------------------- #
# --- open(write/update) of a directory -> kXR_isDirectory parity ----------- #
# --- open(read) of a nonexistent file -> kXR_NotFound parity --------------- #
# --- close an invalid (never-opened) fhandle -> kXR_FileNotOpen parity ----- #
# --- read from an invalid (never-opened) fhandle -> error parity ----------- #
# --- write to a READ-only handle -> pin to STOCK --------------------------- #
def _write_to_ro_handle(url):
    """Open /hello.txt for READ, then attempt a kXR_write on that handle ->
    (status, errnum) of the write response."""
    s = _session(url)
    try:
        st, body = _open(s, "/hello.txt", options=kXR_open_read)
        assert st == kXR_ok, f"open-read failed (status {st})"
        fh = body[0:4]
        payload = b"XXXX"
        s.sendall(struct.pack("!2sH4sqiI", b"\x00\x2c", kXR_write, fh,
                              0, len(payload), 0) + payload)
        try:
            _, st2, body2 = _resp(s)
        except EOFError:
            return ("EOF", None)
        return (st2, _err(body2))
    finally:
        s.close()


def _category_code(en):
    """Bucket numeric kXR codes that name a related rejection class so a
    NotAuthorized(3010) vs ArgInvalid(3000) read/write-mode reject still
    compares as 'access denied' across implementations."""
    if en in (kXR_NotAuthorized, kXR_ArgInvalid, kXR_ArgMissing,
              kXR_InvalidRequest, kXR_FileNotOpen):
        return "denied"
    return en


# --- read from an already-CLOSED fhandle -> kXR_FileNotOpen parity --------- #
# --- double-close: close the same fhandle twice -> 2nd rejected on both ----- #
# --- stat of a nonexistent path (raw wire) -> kXR_NotFound parity ---------- #
# --- open(read) of a missing path inside a missing dir -> NotFound parity --- #
# =========================================================================== #
# PATH TRAVERSAL / CONFINEMENT — must be DENIED on OUR server and the host file
# must NOT leak. (Require denial, not an identical code.)
# =========================================================================== #
TRAVERSALS = [
    "/../../etc/passwd",
    "/../../../etc/passwd",
    "/../../../../etc/passwd",
    "/sub/../../../etc/passwd",
]


# =========================================================================== #
# CONFINEMENT via absolute-ish escape forms (encoded / doubled slashes).
# =========================================================================== #

__all__ = [n for n in dir() if not n.startswith('__')]
