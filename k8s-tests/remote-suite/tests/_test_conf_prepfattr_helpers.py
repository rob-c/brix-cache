# _test_conf_prepfattr_helpers.py - shared header/helpers/fixtures/constants for the Phase-38
# split of test_conf_prepfattr.py.  `from _test_conf_prepfattr_helpers import *` re-exports EVERYTHING via
# the __all__ below so the test functions keep their exact module namespace.


"""Differential conformance for kXR_prepare (staging) and kXR_fattr (xattr).

Every case drives the SAME request — either via the stock `xrdfs` client or via
a RAW WIRE frame — against BOTH servers (our nginx-xrootd and the stock XRootD
data server, launched on identical data trees by official_interop_lib) and
asserts they agree on:

  * success / failure CATEGORY (kXR_ok vs which kXR error code),
  * the RESPONSE FRAMING (prepare: empty body for non-stage, request-id text for
    stage; fattr: nvec/vvec record layout, per-attr rc codes),
  * attribute VALUE parity (set -> get round-trips the exact bytes), and
  * the on-disk EFFECT (the attribute lands under ctx["our_data"]).

Philosophy (per the maintainer): a divergence — wrong response framing, wrong
rc/category, attr value mismatch, a leaked internal namespace, a missing subop —
is a BUG IN OUR SERVER. We pin the stock server's behavior. A confirmed
our-bug that cannot be fixed from the test is recorded with an imperative
pytest.xfail carrying the exact OURS-vs-STOCK detail (never a bare skip that
hides a real diff).

Reference facts pinned (XProtocol.hh / XrdXrootdXeq.cc / XrdXrootdXeqFAttr.cc):

  * ClientPrepareRequest: streamid[2] requestid[2] options[1] prty[1] port[2]
    optionX[2] reserved[10] dlen[4], then a newline-separated path list
    (XProtocol.hh:633). Option bits: kXR_cancel 1, kXR_notify 2, kXR_noerrs 4,
    kXR_stage 8, kXR_wmode 16, kXR_coloc 32, kXR_fresh 64, kXR_usetcp 128;
    optionX kXR_evict 0x0001 (XProtocol.hh:620).
  * do_Prepare: a NON-stage prepare returns an EMPTY ok body (Response.Send(),
    Xeq:2028); a kXR_stage prepare returns the request-id text
    (Response.Send(reqid, strlen(reqid)), Xeq:2029). The reqid is host-qualified,
    e.g. "<hexhost>:<id>:<seq>" (Xeq:1912).
  * ClientFattrRequest: streamid[2] requestid[2] fhandle[4] subcode[1]
    numattr[1] options[1] reserved[9] dlen[4] (XProtocol.hh:315). Subcodes:
    Del 0, Get 1, List 2, Set 3 (XProtocol.hh:299). Limits: faMaxVars 16,
    faMaxNlen 248, faMaxVlen 65536. Options: isNew 0x01, aData 0x10.
  * fattr payload (path-targeted): path + NUL, then for Get/Del/Set an nvec of
    name records — each "rc[2]=0 || name || NUL" (NVecInsert, XProtocol.cc:176)
    — and for Set additionally a vvec of value records — each
    "vlen[4 BE] || value" (VVecInsert, XProtocol.cc:192). List sends just the
    path with numattr==0 (Xeq:328).
  * do_FAttr: usxMaxNsz==0 -> kXR_Unsupported; subcode>3 -> kXR_ArgInvalid;
    numattr wrong -> kXR_ArgInvalid (Xeq:242-317). Server prefixes stored attrs
    with the FATTR_NAMESPACE ("user", Xeq:322) — that prefix MUST NOT leak back
    in List output (the stock server strips it; XeqFALsd, Xeq:474).
  * Get response: faRC[2] + nvec(name records, each with a per-attr rc) +,
    per attr, VLen[4 BE] + value (XeqFAGet, Xeq:417-446). A missing attr is NOT
    a request-level error: it is reported as a non-zero per-attr rc inside the
    nvec, the request still returns kXR_ok (Xeq:430).

Self-provisioning on high ports; skips entirely without the stock toolchain.

Run:
  TEST_SKIP_SERVER_SETUP=1 PYTHONPATH=tests \
    python -m pytest tests/test_conf_prepfattr.py -q
"""

import os
import socket
import struct

import pytest

import official_interop_lib as L

pytestmark = [pytest.mark.timeout(300),
              pytest.mark.skipif(not L.have_official(),
                                 reason="stock xrootd/xrdfs/xrdcp not installed")]

OUR_PORT = L.worker_port(14040)
OFF_PORT = L.worker_port(14041)
BIND = "127.0.0.1"

# opcodes / status
kXR_login = 3007
kXR_prepare = 3021
kXR_fattr = 3020
kXR_ok, kXR_oksofar, kXR_error = 0, 4000, 4003
DROPPED = -1   # sentinel: server dropped the link instead of replying

# kXR_prepare option byte (XProtocol.hh:620)
kXR_cancel = 1
kXR_notify = 2
kXR_noerrs = 4
kXR_stage = 8
kXR_wmode = 16
kXR_coloc = 32
kXR_fresh = 64
kXR_usetcp = 128
# kXR_prepare optionX (uint16)
kXR_evict = 0x0001

# kXR_fattr subcodes (XProtocol.hh:299)
kXR_fattrDel = 0
kXR_fattrGet = 1
kXR_fattrList = 2
kXR_fattrSet = 3
# kXR_fattr options
FA_isNew = 0x01
FA_aData = 0x10

# error codes (XErrorCode, XProtocol.hh:1032+)
kXR_ArgInvalid = 3000
kXR_NotFound = 3011


# --------------------------------------------------------------------------- #
# raw-wire client (minimal pattern copied from test_conf_openflags.py)
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
                          os.getpid() & 0x7fffffff, b"pfat\x00\x00\x00\x00",
                          0, 0, 0, 0, 0))
    _, st, _ = _resp(s)
    assert st == kXR_ok, "anon login failed"


def _session(port):
    s = _connect(port)
    _login(s)
    return s


def _both():
    return _session(OUR_PORT), _session(OFF_PORT)


# --------------------------------------------------------------------------- #
# raw kXR_prepare framing
# --------------------------------------------------------------------------- #
def _prepare(s, paths, options=0, prty=0, optionX=0, sid=b"\x00\x05"):
    """Raw kXR_prepare. `paths` is a list -> newline-separated payload.
    streamid[2] reqid[2] options[1] prty[1] port[2] optionX[2] reserved[10]
    dlen[4] (XProtocol.hh:633). Returns (status, body)."""
    payload = "\n".join(paths).encode()
    req = struct.pack("!2sHBBHH10sI", sid, kXR_prepare, options, prty,
                      0, optionX, b"\x00" * 10, len(payload)) + payload
    try:
        s.sendall(req)
        _, st, body = _resp(s)
    except (EOFError, BrokenPipeError, ConnectionResetError, OSError):
        return DROPPED, b""
    return st, body


# --------------------------------------------------------------------------- #
# raw kXR_fattr framing (nvec / vvec per XProtocol.cc:176/192)
# --------------------------------------------------------------------------- #
def _nvec(name):
    """One nvec record: rc[2]=0 || name || NUL (NVecInsert)."""
    return b"\x00\x00" + name.encode() + b"\x00"


def _vvec(value):
    """One vvec record: vlen[4 BE] || value (VVecInsert)."""
    v = value if isinstance(value, bytes) else value.encode()
    return struct.pack("!i", len(v)) + v


def _fattr(s, path, subcode, numattr, names=(), values=(), options=0,
           sid=b"\x00\x06"):
    """Raw kXR_fattr (path-targeted). Payload = path + NUL + nvec[+vvec].
    Returns (status, body)."""
    payload = path.encode() + b"\x00"
    payload += b"".join(_nvec(n) for n in names)
    payload += b"".join(_vvec(v) for v in values)
    req = struct.pack("!2sH4sBBB9sI", sid, kXR_fattr, b"\x00" * 4,
                      subcode, numattr, options, b"\x00" * 9,
                      len(payload)) + payload
    try:
        s.sendall(req)
        _, st, body = _resp(s)
    except (EOFError, BrokenPipeError, ConnectionResetError, OSError):
        return DROPPED, b""
    return st, body


# --------------------------------------------------------------------------- #
# response decoders
# --------------------------------------------------------------------------- #
def _errnum(body):
    return struct.unpack("!i", body[0:4])[0] if len(body) >= 4 else None


def _rejected(status):
    return status in (kXR_error, DROPPED)


def _category(status, body):
    if status == kXR_ok:
        return "ok"
    if status == DROPPED:
        return "dropped"
    return "err:%s" % _errnum(body)


def _fattr_get_decode(body):
    """Decode an XeqFAGet response: faRC[2], then per attr: nvec record
    (rc[2] + name + NUL); then per attr: VLen[4 BE] + value. Returns
    list[(name, per_attr_rc, value_or_None)] or None on parse failure."""
    if len(body) < 2:
        return None
    nerr = struct.unpack("!H", body[0:2])[0]
    p = 2
    names = []
    # number of attrs is not in the body; walk the nvec until value section.
    # Each nvec record is rc[2] + cstring. The vvec section begins after all
    # nvec records. We rely on the request having had numattr==1 for our probes
    # but decode generically: read records until the remaining bytes can only be
    # values. We detect this by capturing the nvec for exactly the queried count
    # by the caller, so here we expose a one-attr decoder.
    rc = struct.unpack("!H", body[p:p + 2])[0]
    p += 2
    end = body.index(b"\x00", p)
    name = body[p:end].decode("ascii", "replace")
    p = end + 1
    names.append((name, rc))
    # value section: VLen[4 BE] + value (only present if rc==0 and VLen>0)
    if p + 4 <= len(body):
        vlen = struct.unpack("!i", body[p:p + 4])[0]
        p += 4
        val = body[p:p + vlen] if vlen > 0 else b""
        return [(name, rc, val, nerr)]
    return [(name, rc, None, nerr)]


def _fattr_list_names(body):
    """Decode an XeqFALsd/XeqFALst response into a set of attr names. The list
    body is a sequence of "name NUL + VLen[4 BE] + value" records when aData is
    set, or just "name NUL" records otherwise. We extract just the leading
    cstring names robustly by scanning NUL-terminated tokens that look like attr
    names (printable, contain a '.')."""
    names = set()
    p = 0
    n = len(body)
    while p < n:
        z = body.find(b"\x00", p)
        if z < 0:
            break
        tok = body[p:z]
        try:
            s = tok.decode("ascii")
        except UnicodeDecodeError:
            s = None
        # A name token: non-empty, printable, no control chars.
        if s and all(32 <= ord(c) < 127 for c in s) and "." in s:
            names.add(s)
        p = z + 1
    return names


# --------------------------------------------------------------------------- #
# server pair fixture
# --------------------------------------------------------------------------- #
@pytest.fixture(scope="module")
def srv(tmp_path_factory):
    base = str(tmp_path_factory.mktemp("prepfattr"))
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


# =========================================================================== #
# A. STOCK xrdfs `prepare` — non-stage returns no id; rc/category parity
# =========================================================================== #
PREP_EXISTING = ["/hello.txt", "/data.bin", "/sub/nested.txt", "/sz_4096.bin",
                 "/big1m.bin", "/empty.txt", "/many/f00.txt", "/cksum.bin"]


# =========================================================================== #
# C. STOCK xrdfs prepare option variants (-c cancel, -e evict, -f, -w, -p)
# =========================================================================== #
PREP_OPT_VARIANTS = [
    ("-c", "/hello.txt"),    # cancel
    ("-e", "/hello.txt"),    # evict
    ("-f", "/data.bin"),     # fresh
    ("-w", "/data.bin"),     # wmode
]


# =========================================================================== #
# D. STOCK xrdfs prepare missing-path behavior (pin stock)
# =========================================================================== #
PREP_MISSING = ["/nope.txt", "/sub/absent.bin", "/many/gone.txt"]


# =========================================================================== #
# F. RAW kXR_prepare — non-stage empty body, stage id-text framing
# =========================================================================== #
RAW_PREP_FILES = ["/hello.txt", "/data.bin", "/sz_4096.bin", "/empty.txt",
                  "/many/f01.txt", "/sub/nested.txt"]


# =========================================================================== #
# G. STOCK xrdfs xattr set/get round-trip — VALUE parity + on-disk effect
# =========================================================================== #
# (name, value) cases: simple, empty value, "binary-ish" printable, long value
XATTR_CASES = [
    ("user.simple", "bar"),
    ("user.empty", ""),
    ("user.spaced", "a b c"),
    ("user.eq", "k=v=w"),
    ("user.long", "L" * 4000),
    ("user.num", "1234567890"),
    ("user.dots", "a.b.c.d"),
    ("user.hex", "deadbeefcafef00d"),
]


def _make_pair_file(srv, rel, payload=b""):
    """Create identical files at `rel` on both data roots (out-of-band) so each
    server sees the same starting state for an xattr probe."""
    with open(our_disk(srv, rel), "wb") as f:
        f.write(payload)
    with open(off_disk(srv, rel), "wb") as f:
        f.write(payload)


def _disk_xattrs(path):
    """Return {key: value_bytes} of user.* xattrs on `path`, or None if the FS
    does not support listing xattrs."""
    try:
        keys = os.listxattr(path)
    except (OSError, AttributeError):
        return None
    out = {}
    for k in keys:
        try:
            out[k] = os.getxattr(path, k)
        except OSError:
            out[k] = b""
    return out


def _find_attr_value(attrs, name):
    """Find the value for logical attr `name` regardless of namespace prefixing
    (stock stores user.<name> as on-disk key "user.U.<name>")."""
    bare = name.split(".", 1)[1] if name.startswith("user.") else name
    candidates = (name, "user.U." + name, "user.U.user." + bare,
                  "user." + bare, "user.U." + bare)
    for c in candidates:
        if c in attrs:
            return attrs[c]
    # fall back: any key ending with the bare name
    for k, v in attrs.items():
        if k.endswith("." + bare) or k.endswith(name):
            return v
    return None


# =========================================================================== #
# K. RAW kXR_fattr — Set/Get round-trip framing parity
# =========================================================================== #
RAW_FA_FILES = ["/hello.txt", "/data.bin", "/sz_4096.bin", "/many/f03.txt"]

__all__ = [n for n in dir() if not n.startswith('__')]
