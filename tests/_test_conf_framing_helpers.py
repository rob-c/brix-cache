# _test_conf_framing_helpers.py - shared header/helpers/fixtures/constants for the Phase-38
# split of test_conf_framing.py.  `from _test_conf_framing_helpers import *` re-exports EVERYTHING via
# the __all__ below so the test functions keep their exact module namespace.


"""Differential conformance for RAW PROTOCOL FRAMING & ROBUSTNESS — every probe
sends a malformed / boundary / adversarial XRootD request on a RAW SOCKET to
BOTH our nginx-xrootd server and the stock xrootd data server and asserts our
server reacts the SAME WAY the stock server does (accept / reject / close) and,
above all, NEVER crashes or hangs.

Philosophy (per the maintainer, mirroring test_conf_errors.py): a divergence is
a BUG IN OUR SERVER unless there is positive evidence otherwise. The pinned
oracle is the stock xrootd data server. For each probe we run the IDENTICAL raw
bytes against OUR and STOCK and require:

  * the same coarse OUTCOME CLASS — ok / reject(error|EOF) — and
  * where the reference is exact, the same numeric kXR_* error code; and
  * the MOST IMPORTANT INVARIANT: OUR server returns a DEFINITE outcome inside a
    sane per-socket timeout (no crash, no indefinite hang). A hang is a test
    FAILURE to investigate, never silently tolerated.

Why bucket some codes: a protocol-framing rejection (unknown opcode, bad dlen,
pre-login op) names a "the request itself is illegal" class whose EXACT kXR code
is build-version-specific (stock returns kXR_ArgMissing 3001 for an unknown
opcode where the C++ reference and OUR server return kXR_InvalidRequest 3006;
stock returns kXR_InvalidRequest 3006 for a pre-login op where OUR returns
kXR_NotAuthorized 3010). All are valid rejections, so for framing probes we
require BOTH to reject and bucket the code rather than demand an exact match.
For positional/existence ops (open-of-dir, stat-missing, close-of-stale-handle)
the reference IS exact and we pin the numeric code.

Wire reference: /tmp/xrootd-src/src/XProtocol/XProtocol.hh
  ClientRequestHdr = streamid[2] requestid[2] <12 body bytes> dlen[4 BE].
  XRequestTypes 3000..3032 (kXR_REQFENCE=3033); error codes 3000..3035.

RICH TREE (identical bytes both servers): /hello.txt /data.bin(4096)
/sz_4096.bin and the rest of official_interop_lib.make_rich_tree.

Harness: official_interop_lib (PYTHONPATH=tests). Self-provisions our + stock
servers on high ports; skips entirely without the stock xrootd toolchain.
"""

import os
import socket
import struct

import pytest

import official_interop_lib as L

pytestmark = [pytest.mark.timeout(360),
              pytest.mark.skipif(not L.have_official(),
                                 reason="stock xrootd/xrdfs/xrdcp not installed")]

OUR_PORT = L.worker_port(14054)
OFF_PORT = L.worker_port(14055)
# Per-socket deadline. A malformed probe that does not get a definite outcome in
# this window is treated as a HANG (test failure), the load-bearing invariant.
SOCK_TIMEOUT = 5.0

# Path-length boundary (src/compat/path.h XROOTD_PATH_MAX).
MAX_PATH = 4096


# --------------------------------------------------------------------------- #
# Server pair (rich tree) for the whole file.
# --------------------------------------------------------------------------- #
@pytest.fixture(scope="module")
def srv(tmp_path_factory):
    base = str(tmp_path_factory.mktemp("confframe"))
    try:
        procs, ctx = L.start_pair(base, our_port=OUR_PORT, off_port=OFF_PORT)
    except RuntimeError as e:
        pytest.skip(f"server pair did not start: {e}")
    yield ctx
    L.stop_pair(procs)


# =========================================================================== #
# opcodes / status / error codes (XProtocol.hh).
# =========================================================================== #
kXR_auth, kXR_query, kXR_chmod, kXR_close, kXR_dirlist = 3000, 3001, 3002, 3003, 3004
kXR_gpfile, kXR_protocol, kXR_login, kXR_mkdir, kXR_mv = 3005, 3006, 3007, 3008, 3009
kXR_open, kXR_ping, kXR_chkpoint, kXR_read, kXR_rm = 3010, 3011, 3012, 3013, 3014
kXR_rmdir, kXR_sync, kXR_stat, kXR_set, kXR_write = 3015, 3016, 3017, 3018, 3019
kXR_fattr, kXR_prepare, kXR_statx, kXR_endsess, kXR_bind = 3020, 3021, 3022, 3023, 3024
kXR_readv, kXR_pgwrite, kXR_locate, kXR_truncate, kXR_sigver = 3025, 3026, 3027, 3028, 3029
kXR_pgread, kXR_writev, kXR_clone = 3030, 3031, 3032
kXR_REQFENCE = 3033

# response status
kXR_ok, kXR_oksofar, kXR_error = 0, 4000, 4003
kXR_redirect, kXR_wait, kXR_waitresp, kXR_status = 4004, 4005, 4006, 4007

# error codes
kXR_ArgInvalid, kXR_ArgMissing, kXR_ArgTooLong = 3000, 3001, 3002
kXR_FileNotOpen, kXR_InvalidRequest = 3004, 3006
kXR_NotAuthorized, kXR_NotFound = 3010, 3011
kXR_Unsupported, kXR_NotFile, kXR_isDirectory = 3013, 3015, 3016

# open options
kXR_open_read = 0x0010
kXR_open_updt = 0x0020

# The common "this request is illegal" rejection class — any of these is a
# conformant framing reject; the exact one is build-specific.
_REJECT_CLASS = {kXR_ArgInvalid, kXR_ArgMissing, kXR_ArgTooLong,
                 kXR_FileNotOpen, kXR_InvalidRequest, kXR_NotAuthorized,
                 kXR_NotFound, kXR_Unsupported}


# =========================================================================== #
# Raw-wire client primitives (timeout-bounded; a hang surfaces as socket.timeout
# which the runners normalize to a "HANG" sentinel = test failure).
# =========================================================================== #
def _port_of(url):
    return int(url.rsplit(":", 1)[1])


def _recv_exact(s, n):
    b = b""
    while len(b) < n:
        try:
            c = s.recv(n - len(b))
        except socket.timeout:
            raise
        except (ConnectionError, OSError):
            # A peer RST / abrupt close mid-read is a conformant rejection,
            # equivalent to a clean EOF for differential purposes.
            raise EOFError("reset") from None
        if not c:
            raise EOFError("closed")
        b += c
    return b


def _resp(s):
    """Read one 8-byte response header + its body. Raises EOFError on link drop
    and socket.timeout if the server neither answers nor closes in time."""
    h = _recv_exact(s, 8)
    sid = h[0:2]
    status = struct.unpack("!H", h[2:4])[0]
    dlen = struct.unpack("!I", h[4:8])[0]
    body = _recv_exact(s, dlen) if dlen else b""
    return sid, status, body


def _connect(url):
    s = socket.create_connection((L.BIND, _port_of(url)), timeout=SOCK_TIMEOUT)
    s.settimeout(SOCK_TIMEOUT)
    s.sendall(struct.pack("!IIIII", 0, 0, 0, 4, 2012))   # handshake
    return s


def _login(s, name=b"frm", sid=b"\x00\x01"):
    uname = (name + b"\x00" * 8)[:8]
    s.sendall(struct.pack("!2sHI8sBBBBI", sid, kXR_login,
                          os.getpid() & 0x7fffffff, uname,
                          0, 0, 0, 0, 0))
    _, st, _ = _resp(s)
    return st


def _session(url):
    s = _connect(url)
    _, st, _ = _resp(s)            # handshake reply
    assert st == kXR_ok, "handshake did not return kXR_ok"
    assert _login(s) == kXR_ok, "anon login failed"
    return s


def _err(body):
    return struct.unpack("!i", body[0:4])[0] if len(body) >= 4 else None


def _stat_bytes(path, sid=b"\x00\x02"):
    p = path.encode() if isinstance(path, str) else path
    return struct.pack("!2sH16sI", sid, kXR_stat, b"\x00" * 16, len(p)) + p


def _open_bytes(path, options=kXR_open_read, sid=b"\x00\x03"):
    p = path.encode() if isinstance(path, str) else path
    return struct.pack("!2sHHH12sI", sid, kXR_open, 0, options,
                       b"\x00" * 12, len(p)) + p


# Outcome sentinels for a single probe.
HANG = "HANG"   # no definite outcome inside SOCK_TIMEOUT (a bug to investigate)
EOF = "EOF"     # link dropped (a conformant rejection class)


def _run_probe(url, send_fn, prelogin=False):
    """Open a (logged-in unless prelogin) session, run send_fn(s), read ONE
    response. Returns (status, errnum):

      (kXR_ok|kXR_error|other-status, errnum-or-None)  -> server answered
      (EOF, None)                                      -> server closed the link
      (HANG, None)                                     -> server neither answered
                                                          nor closed in time (BUG)

    send_fn may itself raise on a broken pipe mid-send (peer already closed) —
    that is also a rejection, normalized to EOF."""
    try:
        s = _connect(url) if prelogin else _session(url)
    except (socket.timeout, EOFError, ConnectionError, OSError) as e:
        # A clean refusal/close before we even probe is still "rejected", but a
        # timeout connecting is a hang.
        if isinstance(e, socket.timeout):
            return (HANG, None)
        return (EOF, None)
    if prelogin:
        try:
            _, st0, _ = _resp(s)   # handshake reply
            if st0 != kXR_ok:
                s.close()
                return (st0, None)
        except (socket.timeout,):
            s.close()
            return (HANG, None)
        except EOFError:
            s.close()
            return (EOF, None)
    try:
        try:
            send_fn(s)
        except (BrokenPipeError, ConnectionError, OSError):
            return (EOF, None)
        try:
            _, st, body = _resp(s)
        except socket.timeout:
            return (HANG, None)
        except (EOFError, ConnectionError, OSError):
            return (EOF, None)
        return (st, _err(body))
    finally:
        try:
            s.close()
        except OSError:
            pass


# =========================================================================== #
# Outcome classification + differential assertions.
# =========================================================================== #
def _is_reject(st):
    return st == kXR_error or st == EOF


def _is_ok(st):
    return st == kXR_ok or st == kXR_oksofar


def _class(st):
    """Coarse outcome class for differential comparison."""
    if st == HANG:
        return "hang"
    if _is_ok(st):
        return "ok"
    if _is_reject(st):
        return "reject"
    # any other coded status (wait/redirect/status) — keep distinct
    return f"status:{st}"


def _assert_no_hang(label, st_o, st_f):
    """The load-bearing invariant: OUR server must give a definite outcome.

    A stock hang is an oracle problem (skip-worthy info), but OUR hang is always
    flagged HIGH as a bug."""
    assert st_o != HANG, (
        f"[{label}] HIGH: OUR server HUNG (no response/close within "
        f"{SOCK_TIMEOUT}s) on a malformed probe — stock outcome={st_f!r}. "
        f"This is the primary robustness invariant.")
    assert st_f != HANG, (
        f"[{label}] oracle: STOCK server hung (status={st_f!r}); cannot pin.")


def _assert_reject_parity(srv, label, send_fn, want_code=None, prelogin=False):
    """Both servers must REJECT the probe (kXR_error or EOF). OUR must not hang.

    want_code: when the reference is exact, pin OUR coded error to it (and require
    stock to agree or match OUR). When None, only require both to land in the
    common framing-reject class."""
    st_o, en_o = _run_probe(srv["our"], send_fn, prelogin=prelogin)
    st_f, en_f = _run_probe(srv["off"], send_fn, prelogin=prelogin)
    _assert_no_hang(label, st_o, st_f)
    assert _is_reject(st_f), (
        f"[{label}] oracle: STOCK did not reject (status={st_f!r} "
        f"errnum={en_f}); cannot pin this as a reject probe.")
    assert _is_reject(st_o), (
        f"[{label}] OUR server did NOT reject (status={st_o!r} errnum={en_o}); "
        f"stock rejected (status={st_f!r} errnum={en_f}) (BUG).")
    if want_code is not None:
        if st_o == kXR_error:
            assert en_o == want_code or en_o == en_f, (
                f"[{label}] OUR errnum={en_o} != reference {want_code} "
                f"(stock={en_f}) (BUG).")
        return
    if st_o == kXR_error and en_o is not None:
        assert en_o in _REJECT_CLASS, (
            f"[{label}] OUR framing-reject code {en_o} is not a request-reject "
            f"code (stock={en_f}) (BUG).")
    if st_f == kXR_error and en_f is not None:
        assert en_f in _REJECT_CLASS, (
            f"[{label}] oracle: STOCK framing-reject code {en_f} unexpected.")


def _assert_class_parity(srv, label, send_fn, prelogin=False):
    """Pin OUR coarse outcome CLASS (ok / reject) to STOCK. Use where the spec
    permits either (the server MAY ignore extra bytes or MAY reject). OUR must
    never hang."""
    st_o, en_o = _run_probe(srv["our"], send_fn, prelogin=prelogin)
    st_f, en_f = _run_probe(srv["off"], send_fn, prelogin=prelogin)
    _assert_no_hang(label, st_o, st_f)
    cls_o, cls_f = _class(st_o), _class(st_f)
    assert cls_o == cls_f, (
        f"[{label}] outcome-class divergence: OUR={cls_o} "
        f"(status={st_o!r} errnum={en_o}) vs STOCK={cls_f} "
        f"(status={st_f!r} errnum={en_f}) (BUG).")
    # If both rejected with a code, the codes should at least share a class.
    if st_o == kXR_error and st_f == kXR_error and en_o is not None and en_f is not None:
        same_class = (en_o == en_f) or (en_o in _REJECT_CLASS and en_f in _REJECT_CLASS)
        assert same_class, (
            f"[{label}] both rejected but with unrelated codes: OUR={en_o} "
            f"STOCK={en_f} (BUG).")


def _assert_ok_parity(srv, label, send_fn):
    """Both must ACCEPT (kXR_ok / oksofar). OUR must not hang."""
    st_o, en_o = _run_probe(srv["our"], send_fn)
    st_f, en_f = _run_probe(srv["off"], send_fn)
    _assert_no_hang(label, st_o, st_f)
    assert _is_ok(st_f), f"[{label}] oracle: STOCK did not accept (status={st_f!r})"
    assert _is_ok(st_o), (
        f"[{label}] OUR server did not accept a valid request (status={st_o!r} "
        f"errnum={en_o}); stock accepted (BUG).")


# =========================================================================== #
# 1. EVERY OPCODE in the request range, post-login, with an empty/minimal body.
#    Classify each server's outcome and require the coarse CLASS to match. This
#    is the broad "no opcode crashes/hangs our server" sweep.
# =========================================================================== #
# Curated opcode set: all valid request codes (3000..3032) plus several invalid /
# reserved / out-of-range numbers. Each gets a header-only (dlen=0) request.
_ALL_OPCODES = list(range(3000, 3033)) + [
    2999,            # one below the first request
    3033,            # kXR_REQFENCE (one past the last valid)
    3040, 3100,      # in the 3000s but above the fence
    0, 1, 42,        # tiny numbers
    9999, 0x7fff,    # large in-range-for-u16
    0xffff,          # max u16
]


# =========================================================================== #
# 3. PARTIAL / SPLIT SENDS — header or body split across two segments.
# =========================================================================== #
def _split_send(s, payload, head):
    """Send the first `head` bytes, then (after a tiny pause via separate send)
    the remainder. TCP may coalesce, but two sendall() calls exercise the
    server's partial-read accumulation path."""
    s.sendall(payload[:head])
    s.sendall(payload[head:])


# =========================================================================== #
# 7. ZERO-LENGTH BODY for path-requiring ops -> ArgMissing class parity.
# =========================================================================== #
_NEEDS_PATH_OPS = [
    ("stat", kXR_stat, "!2sH16sI"),
    ("open", kXR_open, None),       # open header has the option fields
    ("rm", kXR_rm, "!2sH16sI"),
    ("rmdir", kXR_rmdir, "!2sH16sI"),
    ("mkdir", kXR_mkdir, None),
    ("dirlist", kXR_dirlist, "!2sH16sI"),
    ("truncate", kXR_truncate, "!2sH16sI"),
    ("statx", kXR_statx, "!2sH16sI"),
]


# =========================================================================== #
# 12. STREAMID echoing — all-zero / all-0xff / random must round-trip verbatim.
# =========================================================================== #
_STREAMIDS = [b"\x00\x00", b"\xff\xff", b"\xab\xcd", b"\x12\x34", b"\x7f\x80"]


# =========================================================================== #
# 18. PRE-LOGIN data ops (raw connection, handshake only) -> reject on both.
# =========================================================================== #
_PRELOGIN_OPS = [
    ("stat", lambda: _stat_bytes("/hello.txt", sid=b"\x00\x81")),
    ("open", lambda: _open_bytes("/hello.txt", sid=b"\x00\x82")),
    ("dirlist", lambda: struct.pack("!2sH16sI", b"\x00\x83", kXR_dirlist,
                                    b"\x00" * 16, 1) + b"/"),
    ("ping", lambda: struct.pack("!2sH16sI", b"\x00\x84", kXR_ping, b"\x00" * 16, 0)),
]

__all__ = [n for n in dir() if not n.startswith('__')]
