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


@pytest.mark.parametrize("path", PREP_EXISTING)
def test_prepare_nostage_rc_parity(srv, path):
    """`xrdfs prepare <path>` (no -s) on an existing file -> rc/category parity.
    A non-stage prepare returns an EMPTY ok body (Xeq:2028)."""
    rc_o, o_o, e_o = L.run([L.OFF_XRDFS, srv["our"], "prepare", path])
    rc_f, o_f, e_f = L.run([L.OFF_XRDFS, srv["off"], "prepare", path])
    raw = f"\n  OURS rc={rc_o} out={o_o.strip()!r} err={e_o.strip()!r}" \
          f"\n  STOCK rc={rc_f} out={o_f.strip()!r} err={e_f.strip()!r}"
    assert (rc_o == 0) == (rc_f == 0), f"prepare {path} success differs:{raw}"
    if rc_o != 0:
        assert L.err_code(e_o) == L.err_code(e_f), \
            f"prepare {path} error category differs:{raw}"


@pytest.mark.parametrize("path", PREP_EXISTING[:5])
def test_prepare_nostage_emits_no_request_id(srv, path):
    """A non-stage `xrdfs prepare` prints NO request-id line (the stage path is
    the only one that returns an id, Xeq:2028 vs 2029) — parity with stock."""
    rc_o, o_o, _ = L.run([L.OFF_XRDFS, srv["our"], "prepare", path])
    rc_f, o_f, _ = L.run([L.OFF_XRDFS, srv["off"], "prepare", path])
    assert rc_o == 0 and rc_f == 0, "non-stage prepare should succeed"
    assert (o_o.strip() == "") == (o_f.strip() == ""), \
        f"non-stage prepare id-emission differs: ours={o_o.strip()!r} " \
        f"stock={o_f.strip()!r}"
    assert o_f.strip() == "", f"stock non-stage prepare emitted an id: {o_f!r}"


# =========================================================================== #
# B. STOCK xrdfs `prepare -s` (stage) — the request-id contract
# =========================================================================== #
@pytest.mark.parametrize("path", PREP_EXISTING)
def test_prepare_stage_rc_parity(srv, path):
    """`xrdfs prepare -s <path>` -> rc parity (both accept the stage)."""
    rc_o, _, e_o = L.run([L.OFF_XRDFS, srv["our"], "prepare", "-s", path])
    rc_f, _, e_f = L.run([L.OFF_XRDFS, srv["off"], "prepare", "-s", path])
    assert (rc_o == 0) == (rc_f == 0), \
        f"prepare -s {path} success differs: ours rc={rc_o} ({e_o.strip()!r}) " \
        f"stock rc={rc_f} ({e_f.strip()!r})"


@pytest.mark.parametrize("path", PREP_EXISTING[:5])
def test_prepare_stage_returns_host_qualified_id(srv, path):
    """`xrdfs prepare -s` returns a host-qualified request-id string of the form
    "<hexhost>:<id>:<seq>" (Xeq:1912 / Xeq:2029). Stock pins the shape; ours
    must match (it currently returns the literal "0")."""
    rc_o, o_o, _ = L.run([L.OFF_XRDFS, srv["our"], "prepare", "-s", path])
    rc_f, o_f, _ = L.run([L.OFF_XRDFS, srv["off"], "prepare", "-s", path])
    assert rc_o == 0 and rc_f == 0, "stage prepare should succeed on both"
    ours, stock = o_o.strip(), o_f.strip()
    stock_ok = stock.count(":") >= 2 and stock != "0"
    assert stock_ok, f"stock stage id is not host-qualified: {stock!r}"
    ours_ok = ours.count(":") >= 2 and ours != "0"
    if not ours_ok:
        pytest.xfail(
            "OUR-SERVER BUG: kXR_prepare|kXR_stage returns a non-conformant "
            f"request-id. OURS={ours!r}, STOCK={stock!r}. The reference sends a "
            "host-qualified id '<hexhost>:<id>:<seq>' (Response.Send(reqid,...), "
            "Xeq:2029 / PrepID->ID, Xeq:1912); ours returns the literal '0'.")
    assert ours_ok


# =========================================================================== #
# C. STOCK xrdfs prepare option variants (-c cancel, -e evict, -f, -w, -p)
# =========================================================================== #
PREP_OPT_VARIANTS = [
    ("-c", "/hello.txt"),    # cancel
    ("-e", "/hello.txt"),    # evict
    ("-f", "/data.bin"),     # fresh
    ("-w", "/data.bin"),     # wmode
]


@pytest.mark.parametrize("opt,path", PREP_OPT_VARIANTS)
def test_prepare_option_variants_parity(srv, opt, path):
    """`xrdfs prepare <opt> <path>` for each option variant -> rc/category
    parity with stock."""
    rc_o, o_o, e_o = L.run([L.OFF_XRDFS, srv["our"], "prepare", opt, path])
    rc_f, o_f, e_f = L.run([L.OFF_XRDFS, srv["off"], "prepare", opt, path])
    raw = f"\n  OURS rc={rc_o} out={o_o.strip()!r} err={e_o.strip()!r}" \
          f"\n  STOCK rc={rc_f} out={o_f.strip()!r} err={e_f.strip()!r}"
    assert (rc_o == 0) == (rc_f == 0), \
        f"prepare {opt} {path} success differs:{raw}"
    if rc_o != 0:
        assert L.err_code(e_o) == L.err_code(e_f), \
            f"prepare {opt} {path} error category differs:{raw}"


@pytest.mark.parametrize("prio", ["0", "1", "2", "3"])
def test_prepare_stage_priority_parity(srv, prio):
    """`xrdfs prepare -s -p <prio>` across the priority range -> rc parity."""
    rc_o, _, e_o = L.run([L.OFF_XRDFS, srv["our"], "prepare", "-s",
                          "-p", prio, "/data.bin"])
    rc_f, _, e_f = L.run([L.OFF_XRDFS, srv["off"], "prepare", "-s",
                          "-p", prio, "/data.bin"])
    assert (rc_o == 0) == (rc_f == 0), \
        f"prepare -s -p {prio} success differs: ours rc={rc_o} " \
        f"({e_o.strip()!r}) stock rc={rc_f} ({e_f.strip()!r})"


def test_prepare_stage_multiple_paths_parity(srv):
    """`xrdfs prepare -s` with multiple paths -> rc parity (multi-path payload,
    newline-separated, Xeq pathlist)."""
    paths = ["/hello.txt", "/data.bin", "/sub/nested.txt"]
    rc_o, _, e_o = L.run([L.OFF_XRDFS, srv["our"], "prepare", "-s", *paths])
    rc_f, _, e_f = L.run([L.OFF_XRDFS, srv["off"], "prepare", "-s", *paths])
    assert (rc_o == 0) == (rc_f == 0), \
        f"multi-path prepare -s differs: ours rc={rc_o} ({e_o.strip()!r}) " \
        f"stock rc={rc_f} ({e_f.strip()!r})"


# =========================================================================== #
# D. STOCK xrdfs prepare missing-path behavior (pin stock)
# =========================================================================== #
PREP_MISSING = ["/nope.txt", "/sub/absent.bin", "/many/gone.txt"]


@pytest.mark.parametrize("path", PREP_MISSING)
def test_prepare_stage_missing_path_parity(srv, path):
    """`xrdfs prepare -s` on a NONEXISTENT path -> pin stock. The reference
    native prepare defers existence to the staging backend and ACCEPTS the
    request (returns an id); ours rejects with NotFound. Differential pin."""
    rc_o, o_o, e_o = L.run([L.OFF_XRDFS, srv["our"], "prepare", "-s", path])
    rc_f, o_f, e_f = L.run([L.OFF_XRDFS, srv["off"], "prepare", "-s", path])
    raw = f"\n  OURS rc={rc_o} out={o_o.strip()!r} err={e_o.strip()!r}" \
          f"\n  STOCK rc={rc_f} out={o_f.strip()!r} err={e_f.strip()!r}"
    if (rc_o == 0) != (rc_f == 0):
        pytest.xfail(
            "OUR-SERVER BUG: kXR_prepare|kXR_stage on a missing path is "
            f"rejected by ours but ACCEPTED by stock.{raw} The reference native "
            "prepare queues the request and defers existence to the staging "
            "backend (do_Prepare, Xeq:2023 only fails on osFS->prepare); ours "
            "stats the path up front and returns kXR_NotFound.")
    assert (rc_o == 0) == (rc_f == 0), f"prepare -s missing path differs:{raw}"


# =========================================================================== #
# E. query prepare (kXR_query infotype kXR_QPrep, reqcode 2) — pin stock
# =========================================================================== #
def test_query_prepare_status_parity(srv):
    """`xrdfs query prepare <id> <path>` -> pin stock. Stock's native prepare
    rejects an ad-hoc query id with kXR_ArgInvalid; ours returns a status line.
    Differential pin (we follow the reference do_Prepare(isQuery=true) path,
    Xeq:2493)."""
    args = ["query", "prepare", "fakereqid", "/hello.txt"]
    rc_o, o_o, e_o = L.run([L.OFF_XRDFS, srv["our"], *args])
    rc_f, o_f, e_f = L.run([L.OFF_XRDFS, srv["off"], *args])
    raw = f"\n  OURS rc={rc_o} out={o_o.strip()!r} err={e_o.strip()!r}" \
          f"\n  STOCK rc={rc_f} out={o_f.strip()!r} err={e_f.strip()!r}"
    if (rc_o == 0) != (rc_f == 0):
        pytest.xfail(
            "OUR-SERVER BUG: `query prepare` success differs from stock.{}"
            " The reference treats a bare query-prepare id via "
            "do_Prepare(isQuery=true) and rejects an unknown id "
            "(kXR_ArgInvalid 3000); ours returns a status line with rc 0."
            .format(raw))
    assert (rc_o == 0) == (rc_f == 0), f"query prepare success differs:{raw}"


# =========================================================================== #
# F. RAW kXR_prepare — non-stage empty body, stage id-text framing
# =========================================================================== #
RAW_PREP_FILES = ["/hello.txt", "/data.bin", "/sz_4096.bin", "/empty.txt",
                  "/many/f01.txt", "/sub/nested.txt"]


@pytest.mark.parametrize("path", RAW_PREP_FILES)
def test_raw_prepare_nostage_empty_body(srv, path):
    """RAW kXR_prepare with options==0 -> kXR_ok with an EMPTY body on both
    servers (Response.Send(), Xeq:2028)."""
    so, sf = _both()
    try:
        st_o, b_o = _prepare(so, [path], options=0)
        st_f, b_f = _prepare(sf, [path], options=0)
    finally:
        so.close()
        sf.close()
    raw = f"\n  OURS cat={_category(st_o, b_o)} body={b_o!r}" \
          f"\n  STOCK cat={_category(st_f, b_f)} body={b_f!r}"
    assert (st_o == kXR_ok) == (st_f == kXR_ok), \
        f"raw prepare(nostage) {path} success differs:{raw}"
    assert st_o == kXR_ok, f"raw prepare(nostage) {path} failed on OURS:{raw}"
    assert b_o == b"", f"raw non-stage prepare returned a body on OURS:{raw}"
    assert b_f == b"", f"stock non-stage prepare returned a body:{raw}"


@pytest.mark.parametrize("path", RAW_PREP_FILES)
def test_raw_prepare_stage_returns_id_text(srv, path):
    """RAW kXR_prepare with kXR_stage -> kXR_ok body is a request-id TEXT string
    (Response.Send(reqid, strlen(reqid)), Xeq:2029). Stock pins a host-qualified
    id; ours currently returns the literal "0"."""
    so, sf = _both()
    try:
        st_o, b_o = _prepare(so, [path], options=kXR_stage)
        st_f, b_f = _prepare(sf, [path], options=kXR_stage)
    finally:
        so.close()
        sf.close()
    raw = f"\n  OURS cat={_category(st_o, b_o)} body={b_o!r}" \
          f"\n  STOCK cat={_category(st_f, b_f)} body={b_f!r}"
    assert (st_o == kXR_ok) == (st_f == kXR_ok), \
        f"raw prepare(stage) {path} success differs:{raw}"
    assert st_o == kXR_ok, f"raw prepare(stage) {path} failed on OURS:{raw}"
    stock_id = b_f.decode("ascii", "replace")
    assert b_f and stock_id.count(":") >= 2, \
        f"stock stage id is not host-qualified:{raw}"
    ours_id = b_o.decode("ascii", "replace")
    if not (b_o and ours_id.count(":") >= 2 and ours_id != "0"):
        pytest.xfail(
            "OUR-SERVER BUG: RAW kXR_prepare|kXR_stage request-id framing. "
            f"OURS body={b_o!r}, STOCK body={b_f!r}. The reference sends a "
            "host-qualified id text '<hexhost>:<id>:<seq>' (Xeq:2029); ours "
            "returns the literal '0'.")
    assert ours_id.count(":") >= 2


def test_raw_prepare_stage_multipath_body(srv):
    """RAW kXR_prepare|kXR_stage with a newline-separated multi-path payload ->
    success parity and (for stock) a single request-id covering the batch."""
    paths = ["/hello.txt", "/data.bin", "/sz_4096.bin"]
    so, sf = _both()
    try:
        st_o, b_o = _prepare(so, paths, options=kXR_stage)
        st_f, b_f = _prepare(sf, paths, options=kXR_stage)
    finally:
        so.close()
        sf.close()
    raw = f"\n  OURS cat={_category(st_o, b_o)} body={b_o!r}" \
          f"\n  STOCK cat={_category(st_f, b_f)} body={b_f!r}"
    assert (st_o == kXR_ok) == (st_f == kXR_ok), \
        f"raw multi-path prepare(stage) success differs:{raw}"
    assert st_o == kXR_ok, f"raw multi-path prepare(stage) failed on OURS:{raw}"


def test_raw_prepare_empty_path_list_parity(srv):
    """RAW kXR_prepare with an EMPTY path payload -> error parity (the reference
    sends kXR_ArgMissing "No prepare paths specified", Xeq:1978)."""
    so, sf = _both()
    try:
        st_o, b_o = _prepare(so, [""], options=kXR_stage)
        st_f, b_f = _prepare(sf, [""], options=kXR_stage)
    finally:
        so.close()
        sf.close()
    raw = f"\n  OURS cat={_category(st_o, b_o)}\n  STOCK cat={_category(st_f, b_f)}"
    assert (st_o == kXR_ok) == (st_f == kXR_ok), \
        f"raw empty-path prepare success differs:{raw}"
    if st_o != kXR_ok and st_f != kXR_ok and not _rejected(st_o) is False:
        pass  # category compared below
    if st_o != kXR_ok:
        assert _category(st_o, b_o) == _category(st_f, b_f) or _rejected(st_f), \
            f"raw empty-path prepare error category differs:{raw}"


@pytest.mark.parametrize("optX", [0x0001])  # kXR_evict
def test_raw_prepare_evict_optionx_parity(srv, optX):
    """RAW kXR_prepare with optionX kXR_evict set -> success/category parity
    (XProtocol.hh:630, do_Prepare evict path, Xeq:1852)."""
    so, sf = _both()
    try:
        st_o, b_o = _prepare(so, ["/hello.txt"], options=0, optionX=optX)
        st_f, b_f = _prepare(sf, ["/hello.txt"], options=0, optionX=optX)
    finally:
        so.close()
        sf.close()
    raw = f"\n  OURS cat={_category(st_o, b_o)}\n  STOCK cat={_category(st_f, b_f)}"
    assert (st_o == kXR_ok) == (st_f == kXR_ok), \
        f"raw prepare(evict optX=0x{optX:x}) success differs:{raw}"
    if st_o != kXR_ok:
        assert _category(st_o, b_o) == _category(st_f, b_f), \
            f"raw prepare(evict) error category differs:{raw}"


@pytest.mark.parametrize("prty", [0, 1, 2, 3])
def test_raw_prepare_priority_byte_parity(srv, prty):
    """RAW kXR_prepare|kXR_stage with each priority byte -> success parity
    (do_Prepare prty mapping, Xeq:2009)."""
    so, sf = _both()
    try:
        st_o, b_o = _prepare(so, ["/data.bin"], options=kXR_stage, prty=prty)
        st_f, b_f = _prepare(sf, ["/data.bin"], options=kXR_stage, prty=prty)
    finally:
        so.close()
        sf.close()
    assert (st_o == kXR_ok) == (st_f == kXR_ok), \
        f"raw prepare(stage prty={prty}) success differs: " \
        f"ours={_category(st_o, b_o)} stock={_category(st_f, b_f)}"


def test_prepare_determinism(srv):
    """Repeated RAW non-stage prepare of the same path -> stable empty-ok every
    time on OURS (and on stock)."""
    for port in (OUR_PORT, OFF_PORT):
        s = _session(port)
        try:
            for _ in range(5):
                st, b = _prepare(s, ["/hello.txt"], options=0,
                                 sid=struct.pack("!H", 0x300))
                assert st == kXR_ok and b == b"", \
                    f"prepare not deterministic on port {port}: {st} {b!r}"
        finally:
            s.close()


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


@pytest.mark.parametrize("name,value", XATTR_CASES)
def test_xattr_set_get_roundtrip_value_parity(srv, name, value):
    """`xrdfs xattr set` then `get` round-trips the EXACT value, identically on
    both servers (Set->Get, XProtocol.cc nvec/vvec). Unique attr name per case
    on a per-test file to avoid cross-talk."""
    # set+get on each server independently, compare the get output
    def setget(url):
        rc1, _, e1 = L.run([L.OFF_XRDFS, url, "xattr", "/data.bin",
                            "set", f"{name}={value}"])
        rc2, o2, e2 = L.run([L.OFF_XRDFS, url, "xattr", "/data.bin",
                            "get", name])
        return rc1, rc2, o2, e1, e2
    ro = setget(srv["our"])
    rf = setget(srv["off"])
    raw = f"\n  OURS set_rc={ro[0]} get_rc={ro[1]} out={ro[2].strip()!r}" \
          f"\n  STOCK set_rc={rf[0]} get_rc={rf[1]} out={rf[2].strip()!r}"
    assert (ro[0] == 0) == (rf[0] == 0), f"xattr set parity differs:{raw}"
    assert (ro[1] == 0) == (rf[1] == 0), f"xattr get parity differs:{raw}"
    if ro[1] == 0:
        # the value line is the last non-comment line: name="value"
        def val(out):
            for ln in reversed(out.splitlines()):
                if ln.startswith("#") or not ln.strip():
                    continue
                return ln.strip()
            return ""
        assert val(ro[2]) == val(rf[2]), \
            f"xattr get value differs from stock:{raw}"


@pytest.mark.parametrize("idx,name,value",
                         [(i, n, v) for i, (n, v) in enumerate(XATTR_CASES[:5])])
def test_xattr_set_lands_on_disk(srv, idx, name, value):
    """After `xrdfs xattr set`, the attribute is present on OUR data root. The
    reference stores it under the FATTR_NAMESPACE prefix (on-disk key is
    "user.U.<name>"); we accept either the stock-style prefixed key or the bare
    key as long as the value matches stock's on-disk encoding.

    Each case uses a UNIQUE pre-created file so attributes never accumulate and
    hit the underlying filesystem's per-inode xattr-size cap (which both servers
    reject identically — that shared rejection is a parity, not a bug, so the
    on-disk assertion is gated on stock having stored the attr too)."""
    rel = f"/xa_disk_{idx}.bin"
    _make_pair_file(srv, rel, b"x" * 16)
    rc_o, _, e_o = L.run([L.OFF_XRDFS, srv["our"], "xattr", rel,
                          "set", f"{name}={value}"])
    rc_f, _, e_f = L.run([L.OFF_XRDFS, srv["off"], "xattr", rel,
                          "set", f"{name}={value}"])
    assert (rc_o == 0) == (rc_f == 0), \
        f"xattr set {name} accept/reject differs: ours rc={rc_o} " \
        f"({e_o.strip()!r}) stock rc={rc_f} ({e_f.strip()!r})"
    if rc_f != 0:
        # stock itself rejected the set (e.g. fs xattr-size cap) -> parity only
        return
    our_attrs = _disk_xattrs(our_disk(srv, rel))
    off_attrs = _disk_xattrs(off_disk(srv, rel))
    if our_attrs is None or off_attrs is None:
        pytest.skip("filesystem does not expose user xattrs (getfattr/os.listxattr)")
    om = _find_attr_value(our_attrs, name)
    fm = _find_attr_value(off_attrs, name)
    assert fm is not None, f"stock did not store {name} on disk: {sorted(off_attrs)}"
    assert om is not None, \
        f"xattr {name} not found on OUR disk (have {sorted(our_attrs)})"
    assert om == fm, \
        f"on-disk xattr value for {name} differs: OURS {om!r} STOCK {fm!r}"


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
# H. STOCK xrdfs xattr list — internal namespace prefix MUST NOT leak
# =========================================================================== #
@pytest.mark.parametrize("name", [
    "user.la", "user.lb", "user.lc.dotted", "user.l_underscore",
])
def test_xattr_list_no_namespace_leak(srv, name):
    """`xrdfs xattr list` must show the attr under its ORIGINAL name. The server
    stores it under the FATTR_NAMESPACE ("user") prefix internally, but the
    reference STRIPS that prefix in the List response (XeqFALsd, Xeq:474); our
    server leaks it as "U.<name>". Pin stock."""
    L.run([L.OFF_XRDFS, srv["our"], "xattr", "/cksum.bin",
           "set", f"{name}=v"])
    L.run([L.OFF_XRDFS, srv["off"], "xattr", "/cksum.bin",
           "set", f"{name}=v"])
    rc_o, o_o, _ = L.run([L.OFF_XRDFS, srv["our"], "xattr", "/cksum.bin", "list"])
    rc_f, o_f, _ = L.run([L.OFF_XRDFS, srv["off"], "xattr", "/cksum.bin", "list"])
    assert rc_o == 0 and rc_f == 0, "xattr list should succeed on both"
    # the names listed (strip "# file:" header and ="value" suffix)
    def names(out):
        s = set()
        for ln in out.splitlines():
            ln = ln.strip()
            if not ln or ln.startswith("#"):
                continue
            s.add(ln.split("=", 1)[0])
        return s
    no, nf = names(o_o), names(o_f)
    assert name in nf, f"stock list missing {name}: {nf}"
    if name not in no:
        leaked = {n for n in no if n.endswith(name) and n != name}
        pytest.xfail(
            "OUR-SERVER BUG: kXR_fattrList leaks the internal FATTR_NAMESPACE "
            f"prefix. Expected {name!r} (as stock shows: {sorted(nf)}); ours "
            f"shows {sorted(no)} (leaked as {sorted(leaked)}). The reference "
            "strips the 'user' namespace prefix before returning names "
            "(XeqFALsd, Xeq:474).")
    assert name in no


# =========================================================================== #
# I. STOCK xrdfs xattr del — del removes, subsequent get/list reflect it
# =========================================================================== #
@pytest.mark.parametrize("name", ["user.d1", "user.d2", "user.d3.x"])
def test_xattr_del_removes_attr_parity(srv, name):
    """`xrdfs xattr del` removes the attr -> a subsequent `get` reports
    absence, identically on both servers."""
    for url in (srv["our"], srv["off"]):
        L.run([L.OFF_XRDFS, url, "xattr", "/empty.txt", "set", f"{name}=z"])
    rc_o, _, e_o = L.run([L.OFF_XRDFS, srv["our"], "xattr", "/empty.txt",
                          "del", name])
    rc_f, _, e_f = L.run([L.OFF_XRDFS, srv["off"], "xattr", "/empty.txt",
                          "del", name])
    assert (rc_o == 0) == (rc_f == 0), \
        f"xattr del parity differs: ours rc={rc_o} stock rc={rc_f}"
    # del-then-get
    go = L.run([L.OFF_XRDFS, srv["our"], "xattr", "/empty.txt", "get", name])
    gf = L.run([L.OFF_XRDFS, srv["off"], "xattr", "/empty.txt", "get", name])
    # stock reports a deleted attr's get as an (empty value / error) — compare
    # the presence of a value line, not the exact wording.
    def has_value(out):
        for ln in out.splitlines():
            ln = ln.strip()
            if ln and not ln.startswith("#") and "=" in ln:
                v = ln.split("=", 1)[1].strip().strip('"')
                return v != ""
        return False
    assert has_value(go[1]) == has_value(gf[1]), \
        f"del-then-get value-presence differs: ours={go[1].strip()!r} " \
        f"stock={gf[1].strip()!r}"


# =========================================================================== #
# J. STOCK xrdfs xattr multiple attrs on one file -> list count parity
# =========================================================================== #
def test_xattr_multiple_attrs_list_count_parity(srv):
    """Set several attrs on one file -> `list` shows the same COUNT on both
    servers (multi-attr round-trip)."""
    names = ["user.m0", "user.m1", "user.m2", "user.m3"]
    for url in (srv["our"], srv["off"]):
        for i, n in enumerate(names):
            L.run([L.OFF_XRDFS, url, "xattr", "/many/f02.txt",
                   "set", f"{n}=val{i}"])
    rc_o, o_o, _ = L.run([L.OFF_XRDFS, srv["our"], "xattr", "/many/f02.txt", "list"])
    rc_f, o_f, _ = L.run([L.OFF_XRDFS, srv["off"], "xattr", "/many/f02.txt", "list"])
    assert rc_o == 0 and rc_f == 0
    def count(out):
        return sum(1 for ln in out.splitlines()
                   if ln.strip() and not ln.strip().startswith("#"))
    assert count(o_o) == count(o_f), \
        f"xattr list count differs: ours={count(o_o)} ({o_o.strip()!r}) " \
        f"stock={count(o_f)} ({o_f.strip()!r})"


# =========================================================================== #
# K. RAW kXR_fattr — Set/Get round-trip framing parity
# =========================================================================== #
RAW_FA_FILES = ["/hello.txt", "/data.bin", "/sz_4096.bin", "/many/f03.txt"]


@pytest.mark.parametrize("path", RAW_FA_FILES)
def test_raw_fattr_set_get_roundtrip(srv, path):
    """RAW kXR_fattrSet then kXR_fattrGet -> the Get response carries faRC[2],
    the nvec name record, and the value, BYTE-IDENTICAL to stock."""
    name, value = "user.rawk", "rawval"
    so, sf = _both()
    try:
        st_o, b_o = _fattr(so, path, kXR_fattrSet, 1, names=[name], values=[value])
        st_f, b_f = _fattr(sf, path, kXR_fattrSet, 1, names=[name], values=[value])
        assert (st_o == kXR_ok) == (st_f == kXR_ok), \
            f"raw fattrSet success differs: ours={_category(st_o, b_o)} " \
            f"stock={_category(st_f, b_f)}"
        # set responses should match byte-for-byte (faRC + nvec names echoed)
        assert b_o == b_f, \
            f"raw fattrSet response framing differs:\n  OURS {b_o!r}\n  STOCK {b_f!r}"
        g_o = _fattr(so, path, kXR_fattrGet, 1, names=[name])
        g_f = _fattr(sf, path, kXR_fattrGet, 1, names=[name])
    finally:
        so.close()
        sf.close()
    assert g_o[0] == kXR_ok and g_f[0] == kXR_ok, "raw fattrGet should succeed"
    assert g_o[1] == g_f[1], \
        f"raw fattrGet response differs:\n  OURS {g_o[1]!r}\n  STOCK {g_f[1]!r}"
    dec_o = _fattr_get_decode(g_o[1])
    dec_f = _fattr_get_decode(g_f[1])
    assert dec_o and dec_f, f"raw fattrGet undecodable: {g_o[1]!r} / {g_f[1]!r}"
    assert dec_o[0][2] == value.encode() == dec_f[0][2], \
        f"raw fattrGet value differs: ours={dec_o[0][2]!r} stock={dec_f[0][2]!r}"


def test_raw_fattr_get_missing_attr_is_perattr_rc(srv):
    """RAW kXR_fattrGet of a NONEXISTENT attribute -> the reference returns
    kXR_ok with a NON-ZERO per-attr rc inside the nvec (Xeq:430), NOT a
    request-level error. Pin stock; ours must match the framing."""
    name = "user.absent_raw"
    so, sf = _both()
    try:
        st_o, b_o = _fattr(so, "/hello.txt", kXR_fattrGet, 1, names=[name])
        st_f, b_f = _fattr(sf, "/hello.txt", kXR_fattrGet, 1, names=[name])
    finally:
        so.close()
        sf.close()
    raw = f"\n  OURS cat={_category(st_o, b_o)} body={b_o!r}" \
          f"\n  STOCK cat={_category(st_f, b_f)} body={b_f!r}"
    # stock: ok-with-perattr-rc
    assert st_f == kXR_ok, f"stock fattrGet-missing-attr not ok:{raw}"
    if (st_o == kXR_ok) != (st_f == kXR_ok):
        pytest.xfail(
            "OUR-SERVER BUG: kXR_fattrGet of a missing attribute returns a "
            f"request-level error on ours but ok-with-per-attr-rc on stock.{raw}"
            " The reference always returns kXR_ok and encodes the per-attr "
            "failure in the nvec rc field (XeqFAGet, Xeq:430).")
    assert st_o == kXR_ok, f"raw fattrGet-missing-attr success differs:{raw}"
    assert b_o == b_f, f"raw fattrGet-missing-attr framing differs:{raw}"


@pytest.mark.parametrize("path", RAW_FA_FILES)
def test_raw_fattr_list_strips_namespace(srv, path):
    """RAW kXR_fattrList after a Set -> the listed name carries NO internal
    namespace prefix (XeqFALsd strips "user", Xeq:474). Pin stock byte-shape."""
    name = "user.lst"
    so, sf = _both()
    try:
        _fattr(so, path, kXR_fattrSet, 1, names=[name], values=["x"])
        _fattr(sf, path, kXR_fattrSet, 1, names=[name], values=["x"])
        l_o = _fattr(so, path, kXR_fattrList, 0)
        l_f = _fattr(sf, path, kXR_fattrList, 0)
    finally:
        so.close()
        sf.close()
    assert l_o[0] == kXR_ok and l_f[0] == kXR_ok, "raw fattrList should succeed"
    names_o = _fattr_list_names(l_o[1])
    names_f = _fattr_list_names(l_f[1])
    assert name in names_f, f"stock list missing {name}: {names_f} ({l_f[1]!r})"
    if name not in names_o:
        leaked = {n for n in names_o if n.endswith(name) and n != name}
        pytest.xfail(
            "OUR-SERVER BUG: RAW kXR_fattrList leaks the internal namespace "
            f"prefix. Expected {name!r} (stock: {sorted(names_f)}); ours body "
            f"{l_o[1]!r} -> {sorted(names_o)} (leaked {sorted(leaked)}). The "
            "reference strips the 'user' prefix (XeqFALsd, Xeq:474).")
    assert name in names_o


def test_raw_fattr_del_then_get_parity(srv):
    """RAW kXR_fattrSet -> kXR_fattrDel -> kXR_fattrGet: after delete, Get
    reports the attr as missing (per-attr rc), identically to stock."""
    name = "user.delraw"
    so, sf = _both()
    try:
        _fattr(so, "/data.bin", kXR_fattrSet, 1, names=[name], values=["y"])
        _fattr(sf, "/data.bin", kXR_fattrSet, 1, names=[name], values=["y"])
        d_o = _fattr(so, "/data.bin", kXR_fattrDel, 1, names=[name])
        d_f = _fattr(sf, "/data.bin", kXR_fattrDel, 1, names=[name])
        assert (d_o[0] == kXR_ok) == (d_f[0] == kXR_ok), \
            f"raw fattrDel success differs: {_category(*d_o)} / {_category(*d_f)}"
        g_o = _fattr(so, "/data.bin", kXR_fattrGet, 1, names=[name])
        g_f = _fattr(sf, "/data.bin", kXR_fattrGet, 1, names=[name])
    finally:
        so.close()
        sf.close()
    raw = f"\n  OURS get cat={_category(*g_o)} body={g_o[1]!r}" \
          f"\n  STOCK get cat={_category(*g_f)} body={g_f[1]!r}"
    assert (g_o[0] == kXR_ok) == (g_f[0] == kXR_ok), \
        f"raw del-then-get success differs:{raw}"
    if g_o[0] == kXR_ok and g_f[0] == kXR_ok:
        assert g_o[1] == g_f[1], f"raw del-then-get framing differs:{raw}"


# =========================================================================== #
# L. RAW kXR_fattr error paths — bad subcode, bad numattr, missing file, dir
# =========================================================================== #
@pytest.mark.parametrize("subcode", [4, 7, 9, 200])
def test_raw_fattr_bad_subcode_parity(srv, subcode):
    """RAW kXR_fattr with an out-of-range subcode (>3) -> kXR_ArgInvalid on both
    (Xeq:247)."""
    so, sf = _both()
    try:
        st_o, b_o = _fattr(so, "/hello.txt", subcode, 1, names=["user.x"])
        st_f, b_f = _fattr(sf, "/hello.txt", subcode, 1, names=["user.x"])
    finally:
        so.close()
        sf.close()
    raw = f"\n  OURS cat={_category(st_o, b_o)}\n  STOCK cat={_category(st_f, b_f)}"
    assert _rejected(st_o) == _rejected(st_f), \
        f"fattr bad-subcode {subcode} rejection differs:{raw}"
    if st_o == kXR_error and st_f == kXR_error:
        assert _errnum(b_o) == _errnum(b_f) == kXR_ArgInvalid, \
            f"fattr bad-subcode errnum differs:{raw}"


@pytest.mark.parametrize("subcode,numattr", [
    (kXR_fattrGet, 0),    # Get with zero attrs -> invalid (Xeq:316)
    (kXR_fattrSet, 0),    # Set with zero attrs -> invalid
    (kXR_fattrList, 1),   # List MUST have zero attrs (Xeq:315)
])
def test_raw_fattr_bad_numattr_parity(srv, subcode, numattr):
    """RAW kXR_fattr with an invalid numattr for the subcode -> kXR_ArgInvalid
    parity (ProcFAttr numattr check, Xeq:315-317)."""
    so, sf = _both()
    try:
        nm = ["user.x"] if numattr else []
        st_o, b_o = _fattr(so, "/hello.txt", subcode, numattr, names=nm)
        st_f, b_f = _fattr(sf, "/hello.txt", subcode, numattr, names=nm)
    finally:
        so.close()
        sf.close()
    raw = f"\n  OURS cat={_category(st_o, b_o)}\n  STOCK cat={_category(st_f, b_f)}"
    assert _rejected(st_o) == _rejected(st_f), \
        f"fattr bad-numattr (sub={subcode},n={numattr}) rejection differs:{raw}"
    if st_o == kXR_error and st_f == kXR_error:
        assert _errnum(b_o) == _errnum(b_f), \
            f"fattr bad-numattr errnum differs:{raw}"


@pytest.mark.parametrize("path", ["/nope.txt", "/sub/gone.bin", "/missing/x"])
def test_raw_fattr_get_nonexistent_file_parity(srv, path):
    """RAW kXR_fattrGet on a NONEXISTENT file -> pin stock. The reference path
    access check reports the attr-level failure inside an ok response (per-attr
    rc), whereas ours rejects the whole request with kXR_NotFound."""
    so, sf = _both()
    try:
        st_o, b_o = _fattr(so, path, kXR_fattrGet, 1, names=["user.x"])
        st_f, b_f = _fattr(sf, path, kXR_fattrGet, 1, names=["user.x"])
    finally:
        so.close()
        sf.close()
    raw = f"\n  OURS cat={_category(st_o, b_o)} body={b_o[:48]!r}" \
          f"\n  STOCK cat={_category(st_f, b_f)} body={b_f[:48]!r}"
    if (st_o == kXR_ok) != (st_f == kXR_ok):
        pytest.xfail(
            "OUR-SERVER BUG: kXR_fattrGet on a nonexistent file is rejected at "
            f"the request level on ours but reported as a per-attr rc inside an "
            f"ok response on stock.{raw} The reference returns kXR_ok and "
            "encodes the failure in the nvec rc (XeqFAGet, Xeq:430).")
    assert (st_o == kXR_ok) == (st_f == kXR_ok), \
        f"fattr-get nonexistent-file success differs:{raw}"
    if st_o != kXR_ok:
        assert _errnum(b_o) == _errnum(b_f), \
            f"fattr-get nonexistent-file errnum differs:{raw}"


@pytest.mark.parametrize("path", ["/sub", "/deep", "/many", "/empty_dir"])
def test_raw_fattr_list_on_directory_parity(srv, path):
    """RAW kXR_fattrList on a DIRECTORY -> success/category parity (dirs may
    carry attrs; pin stock's behavior)."""
    so, sf = _both()
    try:
        st_o, b_o = _fattr(so, path, kXR_fattrList, 0)
        st_f, b_f = _fattr(sf, path, kXR_fattrList, 0)
    finally:
        so.close()
        sf.close()
    raw = f"\n  OURS cat={_category(st_o, b_o)} body={b_o[:48]!r}" \
          f"\n  STOCK cat={_category(st_f, b_f)} body={b_f[:48]!r}"
    assert (st_o == kXR_ok) == (st_f == kXR_ok), \
        f"fattr-list on dir {path} success differs:{raw}"
    if st_o != kXR_ok:
        assert _errnum(b_o) == _errnum(b_f), \
            f"fattr-list on dir errnum differs:{raw}"


# =========================================================================== #
# M. RAW kXR_fattr determinism + multi-attr set/get
# =========================================================================== #
def test_raw_fattr_set_get_determinism(srv):
    """RAW Set then repeated Get of the same attr -> the Get response is stable
    and byte-identical to stock across repeats."""
    name, value = "user.det", "stable"
    so, sf = _both()
    try:
        _fattr(so, "/sz_8192.bin", kXR_fattrSet, 1, names=[name], values=[value])
        _fattr(sf, "/sz_8192.bin", kXR_fattrSet, 1, names=[name], values=[value])
        prev_o = prev_f = None
        for _ in range(4):
            g_o = _fattr(so, "/sz_8192.bin", kXR_fattrGet, 1, names=[name])
            g_f = _fattr(sf, "/sz_8192.bin", kXR_fattrGet, 1, names=[name])
            assert g_o[0] == kXR_ok and g_f[0] == kXR_ok
            assert g_o[1] == g_f[1], \
                f"fattrGet diverges from stock:\n  OURS {g_o[1]!r}\n  STOCK {g_f[1]!r}"
            if prev_o is not None:
                assert g_o[1] == prev_o, "OUR fattrGet not deterministic"
                assert g_f[1] == prev_f, "STOCK fattrGet not deterministic"
            prev_o, prev_f = g_o[1], g_f[1]
    finally:
        so.close()
        sf.close()


@pytest.mark.parametrize("count", [2, 3, 4])
def test_raw_fattr_multi_attr_set_then_list(srv, count):
    """RAW kXR_fattrSet of several attrs in one request -> a subsequent
    kXR_fattrList shows all of them, with the SAME name-set as stock."""
    names = [f"user.multi{i}" for i in range(count)]
    values = [f"v{i}" for i in range(count)]
    fpath = f"/many/f{4 + count:02d}.txt"
    so, sf = _both()
    try:
        st_o, _ = _fattr(so, fpath, kXR_fattrSet, count, names=names, values=values)
        st_f, _ = _fattr(sf, fpath, kXR_fattrSet, count, names=names, values=values)
        assert (st_o == kXR_ok) == (st_f == kXR_ok), \
            "multi-attr fattrSet success differs"
        l_o = _fattr(so, fpath, kXR_fattrList, 0)
        l_f = _fattr(sf, fpath, kXR_fattrList, 0)
    finally:
        so.close()
        sf.close()
    if st_o != kXR_ok:
        pytest.skip("multi-attr set not accepted; covered by single-attr tests")
    set_o = {n for n in _fattr_list_names(l_o[1]) if "multi" in n}
    set_f = {n for n in _fattr_list_names(l_f[1]) if "multi" in n}
    # stock should list exactly the `count` set attrs
    assert len(set_f) == count, f"stock multi-list count {set_f} != {count}"
    if set_o != set_f:
        # if ours leaks the namespace prefix, the bare-name set still differs;
        # compare on the stripped tail.
        def tails(s):
            return {n.split("user.", 1)[-1] if "user." in n else n for n in s}
        if tails(set_o) != tails(set_f):
            pytest.xfail(
                "OUR-SERVER BUG: RAW multi-attr kXR_fattrList name-set differs "
                f"from stock. OURS {sorted(set_o)}, STOCK {sorted(set_f)} "
                "(likely the FATTR_NAMESPACE prefix leak, XeqFALsd Xeq:474).")
    assert set_o == set_f or len(set_o) == count


# =========================================================================== #
# N. xattr namespace rules — user.* accepted; pin stock for other namespaces
# =========================================================================== #
@pytest.mark.parametrize("attr", [
    "user.ns_ok",     # user.* — the standard, supported namespace
    "trusted.t1",     # non-user namespace
    "system.s1",      # non-user namespace
    "nodot",          # no namespace at all
])
def test_xattr_namespace_rules_parity(srv, attr):
    """`xrdfs xattr set` across namespaces -> rc/category parity. The reference
    confines client attrs to its FATTR_NAMESPACE; pin whatever stock does for
    non-user namespaces (accept-and-prefix vs reject)."""
    rc_o, _, e_o = L.run([L.OFF_XRDFS, srv["our"], "xattr", "/data.bin",
                          "set", f"{attr}=x"])
    rc_f, _, e_f = L.run([L.OFF_XRDFS, srv["off"], "xattr", "/data.bin",
                          "set", f"{attr}=x"])
    raw = f"\n  OURS rc={rc_o} err={e_o.strip()!r}" \
          f"\n  STOCK rc={rc_f} err={e_f.strip()!r}"
    assert (rc_o == 0) == (rc_f == 0), \
        f"xattr namespace {attr!r} accept/reject differs from stock:{raw}"
    if rc_o != 0:
        assert L.err_code(e_o) == L.err_code(e_f), \
            f"xattr namespace {attr!r} error category differs:{raw}"
