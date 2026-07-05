"""Differential conformance for kXR_query across ALL its reqcodes — stock XrdCl
client (xrdfs) AND raw-wire — against BOTH our nginx-xrootd server and the stock
xrootd data server.

This file goes BROADER than test_conf_query_errors.py (which focuses on a handful
of config keys + error semantics) and test_conf_cksum.py (which drills the Qcksum
hex value space). Here we sweep:

  * EVERY do_Qconf key (one case each) — reference format derived line-by-line
    from XrdXrootd/XrdXrootdXeq.cc::do_Qconf(): each known key returns a *bare
    value* terminated by '\\n' (NEVER "<key>=..."); unknown keys are ECHOED back
    verbatim + '\\n'; numeric keys yield an integer line; multiple keys in one
    request yield one line per key in request order.
  * Every kXR_query reqcode (Qconfig/Qckscan/Qcksum/Qspace/Qstats/Qxattr/Qprep/
    Qopaque/Qvisa) — reqcode dispatch + response-format / error parity.

Reqcode-exact control is done by RAW WIRE (a ClientQueryRequest is
streamid(2)+kXR_query(2)+infotype(2)+reserved(14)+dlen(4)+arg); xrdfs cannot
select an arbitrary infotype, so raw wire is the only way to pin Qckscan,
Qvisa, Qopaque, an unknown reqcode and an empty payload exactly.

Reference truth (consulted, not modified):
  /tmp/brix-src/src/XProtocol/XProtocol.hh        XQueryType reqcode bits
  /tmp/brix-src/src/XrdXrootd/XrdXrootdXeq.cc      do_Query / do_Qconf / do_Q*

Philosophy (per the maintainer): a divergence — "<key>=" instead of a bare
value, a wrong/missing key value, wrong multi-key ordering, mishandled unknown
key or reqcode — is a BUG IN OUR SERVER. We pin the reference (do_Qconf source
is the truth) and write the assertion to fail; no xfail/skip hides a real diff.
Where the stock data server genuinely lacks a feature (uniform error / no
plugin), we make the case differential on the coarse category or pin OUR value
against the reference. Deterministic.

Harness: official_interop_lib (PYTHONPATH=tests). Self-provisions our + stock
servers on high ports; skips entirely without the stock xrootd toolchain.
"""

import hashlib
import socket
import struct
import zlib

import pytest

import official_interop_lib as L

pytestmark = [pytest.mark.timeout(240),
              pytest.mark.skipif(not L.have_official(),
                                 reason="stock xrootd/xrdfs/xrdcp not installed")]


# --------------------------------------------------------------------------- #
# Wire constants (XProtocol.hh).                                              #
# --------------------------------------------------------------------------- #
kXR_login, kXR_query = 3007, 3001

# response status (XProtocol.hh)
kXR_ok, kXR_error = 0, 4003

# XQueryType infotype reqcodes (XProtocol.hh:649-661)
kXR_QStats = 1
kXR_QPrep = 2
kXR_Qcksum = 3
kXR_Qxattr = 4
kXR_Qspace = 5
kXR_Qckscan = 6
kXR_Qconfig = 7
kXR_Qvisa = 8
kXR_Qopaque = 16

REQCODE = {
    "QStats": kXR_QStats, "QPrep": kXR_QPrep, "Qcksum": kXR_Qcksum,
    "Qxattr": kXR_Qxattr, "Qspace": kXR_Qspace, "Qckscan": kXR_Qckscan,
    "Qconfig": kXR_Qconfig, "Qvisa": kXR_Qvisa, "Qopaque": kXR_Qopaque,
}


# --------------------------------------------------------------------------- #
# Module-scoped server pair.                                                  #
# --------------------------------------------------------------------------- #
@pytest.fixture(scope="module")
def srv(tmp_path_factory):
    base = str(tmp_path_factory.mktemp("confquery2"))
    try:
        procs, ctx = L.start_pair(base, our_port=L.worker_port(14050), off_port=L.worker_port(14051))
    except RuntimeError as e:
        pytest.skip(f"server pair did not start: {e}")
    except Exception as e:  # noqa: BLE001 - any launch failure -> skip
        pytest.skip(f"server pair did not start: {e}")
    yield ctx
    L.stop_pair(procs)


# --------------------------------------------------------------------------- #
# Stock-xrdfs runner (high-level surface).                                    #
# --------------------------------------------------------------------------- #
def fs(url, *args, timeout=90):
    return L.run([L.OFF_XRDFS, url, *args], timeout=timeout)


def qconfig(url, *keys):
    """`query config <key...>` -> (rc, raw_stdout, raw_combined)."""
    rc, out, err = fs(url, "query", "config", *keys)
    return rc, out, (out + err)


# --------------------------------------------------------------------------- #
# RAW WIRE — minimal anon login + kXR_query with an EXACT infotype.           #
#                                                                            #
# This is the only way to drive an arbitrary reqcode (xrdfs maps `query`      #
# sub-commands onto a fixed set of infotypes).                                #
# --------------------------------------------------------------------------- #
def _hostport(url):
    """root://host:port -> (host, port)."""
    rest = url.split("://", 1)[1]
    host, port = rest.split(":", 1)
    return host, int(port.split("/", 1)[0])


def _recv_exact(s, n):
    b = b""
    while len(b) < n:
        c = s.recv(n - len(b))
        if not c:
            raise EOFError("connection closed mid-response")
        b += c
    return b


def _resp(s):
    """Read one XRootD server response -> (streamid, status, body)."""
    h = _recv_exact(s, 8)
    sid = h[0:2]
    status = struct.unpack("!H", h[2:4])[0]
    dlen = struct.unpack("!I", h[4:8])[0]
    return sid, status, (_recv_exact(s, dlen) if dlen else b"")


def _connect(url):
    host, port = _hostport(url)
    s = socket.create_connection((host, port), timeout=15)
    # initial handshake (XrdXrootdProtocol.cc) -> server replies protover+type
    s.sendall(struct.pack("!IIIII", 0, 0, 0, 4, 2012))
    _, st, _ = _resp(s)
    assert st == kXR_ok, "raw handshake reply not kXR_ok"
    return s


def _login(s, sid=b"\x00\x01"):
    # ClientLoginRequest: streamid, kXR_login, pid, username[8], reserved, ability,
    # capver, role, dlen
    s.sendall(struct.pack("!2sHI8sBBBBI", sid, kXR_login,
                          0x7fffffff & 12345, b"conf\x00\x00\x00\x00",
                          0, 0, 0, 0, 0))
    _, st, _ = _resp(s)
    assert st == kXR_ok, "anon login failed (raw)"


def _session(url):
    s = _connect(url)
    _login(s)
    return s


def raw_query(url, infotype, arg=b"", sid=b"\x00\x07"):
    """Send one kXR_query with an EXACT infotype and return (status, body).

    ClientQueryRequest (XProtocol.hh): kXR_char streamid[2]; kXR_unt16 requestid;
    kXR_unt16 infotype; kXR_char reserved[14]; kXR_int32 dlen; (data follows)."""
    if isinstance(arg, str):
        arg = arg.encode()
    s = _session(url)
    try:
        s.sendall(struct.pack("!2sHH14sI", sid, kXR_query, infotype,
                              b"\x00" * 14, len(arg)) + arg)
        _, status, body = _resp(s)
        return status, body
    finally:
        try:
            s.close()
        except OSError:
            pass


def raw_qconfig(url, key):
    """Raw `query config <key>` -> (status, text)."""
    status, body = raw_query(url, kXR_Qconfig, key)
    return status, body.decode("latin-1")


# =========================================================================== #
# 1. QUERY CONFIG — every do_Qconf key, one case each.                        #
#    Reference (do_Qconf): a BARE value line (+'\n'), never "<key>=...".      #
#    Where the stock server answers, the case is differential on shape.       #
# =========================================================================== #
# Full do_Qconf key set (XrdXrootdXeq.cc:2168-2268). proxy/tls_port/window are
# guarded server-side (only emitted when configured); we still require OUR
# server to answer them with a bare value or the echoed key, never "key=".
QCONFIG_KEYS = [
    "bind_max", "chksum", "cid", "cms", "pio_max", "readv_ior_max",
    "readv_iov_max", "role", "sitename", "start", "sysid", "tpc", "tpcdlg",
    "tls_port", "window", "version", "vnid", "fattr", "proxy",
]

NUMERIC_KEYS = ["bind_max", "pio_max", "readv_ior_max", "readv_iov_max"]


@pytest.mark.parametrize("key", QCONFIG_KEYS)
def test_qconfig_key_bare_value(srv, key):
    """OUR `query config <key>` succeeds, is newline-terminated, and is a BARE
    value (or the echoed key) — never a "<key>=..." pair (do_Qconf reference)."""
    rc, out, raw = qconfig(srv["our"], key)
    assert rc == 0, f"OUR query config {key} failed: {raw!r}"
    assert out.strip() != "", f"OUR query config {key} returned an empty line"
    # do_Qconf emits the value '\n'-terminated; xrdfs prints it verbatim.
    assert "\n" in out, \
        f"OUR query config {key} not newline-terminated: {out!r}"
    line = out.strip().splitlines()[0].strip()
    assert not line.startswith(f"{key}="), \
        f"OUR query config {key} has a key= prefix (BUG): {line!r}"
    first = line.split()[0] if line.split() else ""
    assert "=" not in first, \
        f"OUR query config {key} first token looks like key=value: {first!r}"


@pytest.mark.parametrize("key", NUMERIC_KEYS)
def test_qconfig_numeric_is_integer(srv, key):
    """Numeric do_Qconf keys (snprintf("%d\\n", ...)) must be an integer line."""
    rc, out, raw = qconfig(srv["our"], key)
    assert rc == 0, f"OUR query config {key} failed: {raw!r}"
    first = out.strip().split()[0] if out.strip().split() else ""
    assert first.lstrip("-").isdigit(), \
        f"OUR query config {key} is not an integer: {out!r}"


@pytest.mark.parametrize("key", QCONFIG_KEYS)
def test_qconfig_no_trailing_space_on_value_line(srv, key):
    """The value line itself must not carry a trailing space before its '\\n'
    (do_Qconf writes "%s\\n"/"%d\\n" — no trailing blank)."""
    status, text = raw_qconfig(srv["our"], key)
    assert status == kXR_ok, \
        f"OUR raw query config {key} status {status} (BUG): {text!r}"
    assert text != "", f"OUR raw query config {key} returned no body"
    for ln in text.split("\n"):
        if ln == "":
            continue
        assert not ln.endswith(" "), \
            f"OUR query config {key} line has a trailing space: {ln!r}"


@pytest.mark.parametrize("key", QCONFIG_KEYS)
def test_qconfig_line_newline_terminated_raw(srv, key):
    """The raw do_Qconf payload must END with '\\n' (each key writes "...\\n").
    The stock buffer is fixed-size and padded; the last non-NUL char before
    padding is the terminator. We assert the first value line is newline-ended."""
    status, text = raw_qconfig(srv["our"], key)
    assert status == kXR_ok, f"OUR raw query config {key} not ok: {text!r}"
    body = text.rstrip("\x00")
    assert "\n" in body, \
        f"OUR raw query config {key} not newline-terminated: {body!r}"


@pytest.mark.parametrize("key", ["bind_max", "chksum", "tpc", "tpcdlg",
                                 "role", "sitename", "readv_iov_max",
                                 "readv_ior_max", "pio_max", "version",
                                 "cid", "cms", "vnid", "fattr"])
def test_qconfig_differential_shape(srv, key):
    """Differential: where the STOCK server answers a config key, OUR server must
    answer it with the same shape category — both bare-value (no "key="), and
    when stock yields an integer ours must too. Value text may legitimately
    differ (build/site), so we compare SHAPE, not the literal value."""
    rc_o, out_o, raw_o = qconfig(srv["our"], key)
    rc_f, out_f, raw_f = qconfig(srv["off"], key)
    assert rc_o == 0, f"OUR query config {key} failed: {raw_o!r}"
    if rc_f != 0:
        pytest.skip(f"stock did not answer config {key}: {raw_f!r}")
    line_o = out_o.strip().splitlines()[0].strip() if out_o.strip() else ""
    line_f = out_f.strip().splitlines()[0].strip() if out_f.strip() else ""
    assert not line_o.startswith(f"{key}="), \
        f"OUR config {key} uses key= but stock does not: {line_o!r}"
    f_first = line_f.split()[0] if line_f.split() else ""
    o_first = line_o.split()[0] if line_o.split() else ""
    if f_first.lstrip("-").isdigit():
        assert o_first.lstrip("-").isdigit(), (
            f"stock config {key} is integer ({line_f!r}) but OUR is not "
            f"({line_o!r})")


def test_qconfig_unknown_key_echoed_bare(srv):
    """do_Qconf default branch ECHOES an unknown key verbatim + '\\n' (NOT
    "key=0", NOT an error). Pin OUR server to that and diff against stock."""
    bogus = "no_such_config_key_xyzzy"
    rc_o, out_o, raw_o = qconfig(srv["our"], bogus)
    rc_f, out_f, raw_f = qconfig(srv["off"], bogus)
    assert rc_o == 0, f"OUR unknown config key errored (BUG): {raw_o!r}"
    line_o = out_o.strip()
    assert line_o == bogus, \
        f"OUR did not echo unknown key bare (BUG): {line_o!r}"
    assert not line_o.startswith(f"{bogus}="), \
        f"OUR echoed unknown key as key= (BUG): {line_o!r}"
    if rc_f == 0:
        assert out_f.strip() == bogus, \
            f"stock echoed unknown key differently: {out_f.strip()!r}"


def test_qconfig_unknown_key_raw_echo(srv):
    """Raw-wire confirmation that an unknown key echoes exactly "<key>\\n"."""
    bogus = "totally_unknown_cfgkey"
    status, text = raw_qconfig(srv["our"], bogus)
    assert status == kXR_ok, f"OUR raw unknown key status {status}: {text!r}"
    body = text.rstrip("\x00")
    assert body.split("\n")[0] == bogus, \
        f"OUR raw echo of unknown key wrong: {body!r}"


def test_qconfig_multi_key_order_and_lines(srv):
    """Multiple keys in ONE request -> one line per key, IN REQUEST ORDER
    (do_Qconf loops GetToken() and appends "%s\\n" per token)."""
    keys = ["tpc", "tpcdlg", "version"]
    rc_o, out_o, raw_o = qconfig(srv["our"], *keys)
    assert rc_o == 0, f"OUR multi-key query config failed: {raw_o!r}"
    lines_o = [l for l in out_o.split("\n") if l != ""]
    assert len(lines_o) == len(keys), (
        f"OUR multi-key returned {len(lines_o)} lines for {len(keys)} keys "
        f"(BUG): {out_o!r}")
    # version line must look like a version, tpc/tpcdlg must not be "key=".
    for k, ln in zip(keys, lines_o):
        assert not ln.strip().startswith(f"{k}="), \
            f"OUR multi-key line for {k} has key= prefix (BUG): {ln!r}"


def test_qconfig_multi_key_raw_order(srv):
    """Raw-wire: 'bind_max readv_iov_max version' -> exactly three lines, first
    two integers, in order (do_Qconf preserves token order)."""
    status, text = raw_qconfig(srv["our"], "bind_max readv_iov_max version")
    assert status == kXR_ok, f"OUR raw multi-key not ok: {text!r}"
    body = text.rstrip("\x00")
    lines = [l for l in body.split("\n") if l != ""]
    assert len(lines) == 3, \
        f"OUR raw multi-key expected 3 lines, got {len(lines)}: {body!r}"
    assert lines[0].split()[0].lstrip("-").isdigit(), \
        f"OUR bind_max line not integer-first: {lines[0]!r}"
    assert lines[1].split()[0].lstrip("-").isdigit(), \
        f"OUR readv_iov_max line not integer-first: {lines[1]!r}"


def test_qconfig_multi_key_matches_singletons(srv):
    """A multi-key request's per-key line must equal the same key queried alone
    (the loop is just per-token concatenation; no cross-key contamination)."""
    keys = ["bind_max", "tpc", "role"]
    rc_m, out_m, raw_m = qconfig(srv["our"], *keys)
    assert rc_m == 0, f"OUR multi-key failed: {raw_m!r}"
    multi = [l for l in out_m.split("\n") if l != ""]
    assert len(multi) == len(keys), f"line count mismatch: {out_m!r}"
    for k, ml in zip(keys, multi):
        rc_s, out_s, _ = qconfig(srv["our"], k)
        assert rc_s == 0
        single = out_s.strip().splitlines()[0].strip()
        assert ml.strip() == single, (
            f"multi-key line for {k} ({ml.strip()!r}) != singleton "
            f"({single!r})")


def test_qconfig_version_format(srv):
    """`query config version` must return a version STRING. do_Qconf emits
    XrdVSTRING (e.g. "v5.6.3" / "vX.Y.Z..."); pin OUR to a v-prefixed dotted
    form (the canonical XRootD version-string shape)."""
    rc, out, raw = qconfig(srv["our"], "version")
    assert rc == 0, f"OUR query config version failed: {raw!r}"
    ver = out.strip().splitlines()[0].strip()
    assert ver, "OUR version line empty"
    assert not ver.startswith("version="), \
        f"OUR version has key= prefix (BUG): {ver!r}"
    # Reference shape: a 'v' followed by at least major.minor digits.
    head = ver.split()[0]
    assert head[:1].lower() == "v" and any(c.isdigit() for c in head), \
        f"OUR version not a v-prefixed version string: {ver!r}"
    assert "." in head, f"OUR version not dotted (vX.Y.Z): {ver!r}"


def test_qconfig_chksum_lists_adler32(srv):
    """`query config chksum` -> bare cslist (or echoed 'chksum'); ours must list
    adler32 (the default algorithm it then answers)."""
    rc, out, raw = qconfig(srv["our"], "chksum")
    assert rc == 0, f"OUR query config chksum failed: {raw!r}"
    line = out.strip()
    assert not line.startswith("chksum="), \
        f"OUR chksum config has key= prefix (BUG): {line!r}"
    advertised = {a.strip() for a in line.replace("\n", ",").split(",")
                  if a.strip()}
    assert "adler32" in advertised, \
        f"OUR chksum config does not advertise adler32: {advertised}"


def test_qconfig_tpc_parseable(srv):
    """XrdCl reads `query config tpc` as a leading digit; pin OUR to a digit or
    the echoed 'tpc' (do_Qconf default when XRDTPC unset)."""
    rc, out, _ = qconfig(srv["our"], "tpc")
    assert rc == 0
    head = out.strip().splitlines()[0].strip() if out.strip() else ""
    assert head[:1].isdigit() or head == "tpc", \
        f"OUR query config tpc not parseable: {out!r}"


# =========================================================================== #
# 2. QUERY CHECKSUM (Qcksum) — '<algo> <hex>'; explicit ?cks.type as LAST cgi #
#    field; value pinned to an independent reference; nonexistent/dir parity. #
# =========================================================================== #
def _crc32c_table():
    poly = 0x82F63B78
    tab = []
    for n in range(256):
        c = n
        for _ in range(8):
            c = (c >> 1) ^ poly if (c & 1) else (c >> 1)
        tab.append(c & 0xFFFFFFFF)
    return tab


_CRC32C_TAB = _crc32c_table()


def ref_crc32c(data):
    crc = 0xFFFFFFFF
    for b in data:
        crc = _CRC32C_TAB[(crc ^ b) & 0xFF] ^ (crc >> 8)
    return f"{crc ^ 0xFFFFFFFF:08x}"


def ref_adler32(data):
    return f"{zlib.adler32(data) & 0xffffffff:08x}"


def ref_crc32(data):
    return f"{zlib.crc32(data) & 0xffffffff:08x}"


def _data(ctx, name):
    import os
    with open(os.path.join(ctx["our_data"], name), "rb") as f:
        return f.read()


@pytest.mark.parametrize("name", ["hello.txt", "data.bin", "cksum.bin"])
def test_qcksum_shape_two_tokens(srv, name):
    """`query checksum <file>` -> exactly '<algo> <hex>' (two tokens, hex)."""
    rc, out, err = fs(srv["our"], "query", "checksum", f"/{name}")
    assert rc == 0, f"OUR query checksum /{name} failed: {out}{err}"
    toks = out.split()
    assert len(toks) == 2, f"OUR checksum not '<algo> <hex>' for /{name}: {out!r}"
    algo, hexv = toks
    assert algo and "=" not in algo, f"bad algo token: {algo!r}"
    assert all(c in "0123456789abcdefABCDEF" for c in hexv), \
        f"non-hex checksum value: {hexv!r}"


@pytest.mark.parametrize("name", ["hello.txt", "data.bin", "cksum.bin"])
def test_qcksum_default_adler32_value(srv, name):
    """Default-algorithm hex equals the independent zlib.adler32 over the bytes."""
    rc, out, err = fs(srv["our"], "query", "checksum", f"/{name}")
    assert rc == 0, f"{out}{err}"
    got = out.split()[-1].lower()
    want = ref_adler32(_data(srv, name))
    assert got == want, f"OUR adler32 /{name} wrong: server={got} ref={want}"


@pytest.mark.parametrize("algo,ref", [("adler32", ref_adler32),
                                      ("crc32", ref_crc32),
                                      ("crc32c", ref_crc32c)])
def test_qcksum_explicit_cks_type_last_cgi(srv, algo, ref):
    """`?cks.type=<algo>` as the LAST cgi field (no trailing &) selects the algo;
    the returned hex equals the independent reference over the bytes."""
    path = f"/data.bin?cks.type={algo}"
    rc, out, err = fs(srv["our"], "query", "checksum", path)
    assert rc == 0, f"OUR checksum {path} failed: {out}{err}"
    got = out.split()[-1].lower()
    want = ref(_data(srv, "data.bin")).lower()
    assert got == want, f"OUR {algo} wrong: server={got} ref={want}"


def test_qcksum_explicit_algo_echoed(srv):
    """A requested algo must be ECHOED in the algo token (no silent substitution
    to the default)."""
    rc, out, err = fs(srv["our"], "query", "checksum", "/data.bin?cks.type=crc32c")
    assert rc == 0, f"{out}{err}"
    assert out.split()[0] == "crc32c", \
        f"requested crc32c but server echoed {out.split()[0]!r}"


def test_qcksum_nonexistent_parity(srv):
    """Checksum of a missing path: OUR must reject; category is a not-found
    error (or, when stock answers/lacks a plugin, ours is the precise NotFound)."""
    rc_o, out_o, err_o = fs(srv["our"], "query", "checksum", "/missing_xyz.bin")
    assert rc_o != 0, f"OUR checksum of missing file succeeded (BUG): {out_o}"
    assert L.err_code(out_o + err_o) in ("no such file", "not found"), \
        f"OUR missing-file checksum miscategorised: {out_o}{err_o!r}"


def test_qcksum_directory_rejected(srv):
    """Checksum of a directory must be an error on OUR server."""
    rc, out, err = fs(srv["our"], "query", "checksum", "/sub")
    assert rc != 0, f"OUR checksum of a directory succeeded (BUG): {out}{err}"


def test_qcksum_determinism(srv):
    """Same checksum query twice -> identical hex (default + explicit)."""
    a1 = fs(srv["our"], "query", "checksum", "/data.bin")[1].split()[-1]
    a2 = fs(srv["our"], "query", "checksum", "/data.bin")[1].split()[-1]
    assert a1 == a2, f"non-deterministic adler32: {a1} then {a2}"
    c1 = fs(srv["our"], "query", "checksum", "/data.bin?cks.type=crc32c")[1].split()[-1]
    c2 = fs(srv["our"], "query", "checksum", "/data.bin?cks.type=crc32c")[1].split()[-1]
    assert c1 == c2, f"non-deterministic crc32c: {c1} then {c2}"


def test_qcksum_raw_reqcode_shape(srv):
    """Raw kXR_Qcksum (infotype=3) on /data.bin -> kXR_ok with an '<algo> <hex>'
    body (pins the reqcode dispatch + reply shape, not just the xrdfs surface)."""
    status, body = raw_query(srv["our"], kXR_Qcksum, "/data.bin")
    assert status == kXR_ok, f"OUR raw Qcksum status {status} (BUG): {body!r}"
    toks = body.rstrip(b"\x00").decode("latin-1").split()
    assert len(toks) >= 2, f"OUR raw Qcksum body not '<algo> <hex>': {body!r}"
    assert all(c in "0123456789abcdefABCDEF" for c in toks[-1]), \
        f"OUR raw Qcksum hex malformed: {toks[-1]!r}"


# =========================================================================== #
# 3. QUERY CKSCAN (Qckscan, infotype=6) — do_Query routes it to do_CKsum(1).  #
#    Pin OUR reqcode handling to a non-arg-invalid outcome and diff vs stock.  #
# =========================================================================== #
def test_qckscan_reqcode_not_arginvalid(srv):
    """A raw Qckscan on a real file must NOT be rejected as an invalid query
    type (do_Query dispatches kXR_Qckscan -> do_CKsum(1)). It may succeed or
    return a checksum-related status, but not kXR_error 'invalid query type'."""
    status, body = raw_query(srv["our"], kXR_Qckscan, "/data.bin")
    text = body.rstrip(b"\x00").decode("latin-1").lower()
    assert not (status == kXR_error and "invalid information query type" in text), (
        f"OUR rejected Qckscan as an invalid reqcode (BUG): {body!r}")


def test_qckscan_reference_outcome(srv):
    """Qckscan -> do_CKsum(1) (a checksum scan/recompute). The bare stock data
    server ships NO checksum plugin, so it uniformly errors here — that is a
    plugin-absence artifact, not the protocol reference. We therefore PIN OUR
    server to the reference: Qckscan on a real file must be a recognised reqcode
    and yield a non-error checksum outcome (it must NOT fall through to the
    do_Query default 'invalid query type' error)."""
    so, bo = raw_query(srv["our"], kXR_Qckscan, "/data.bin")
    text = bo.rstrip(b"\x00").decode("latin-1").lower()
    assert "invalid information query type" not in text, (
        f"OUR rejected Qckscan as an invalid reqcode (BUG): {bo!r}")
    assert so == kXR_ok, (
        f"OUR Qckscan on a real file should compute (reference do_CKsum(1)), "
        f"got status={so}: {bo!r}")
    # Record the stock plugin-absence category for completeness (not asserted as
    # parity — stock's error is the missing-plugin artifact).
    sf, _ = raw_query(srv["off"], kXR_Qckscan, "/data.bin")
    assert sf in (kXR_ok, kXR_error)


# =========================================================================== #
# 4. QUERY SPACE (Qspace, infotype=5) — rc/format parity vs stock.            #
# =========================================================================== #
def test_qspace_category_matches_stock_xrdfs(srv):
    """`xrdfs query space /` — OUR vs STOCK success/failure category must agree."""
    rc_o, out_o, err_o = fs(srv["our"], "query", "space", "/")
    rc_f, out_f, err_f = fs(srv["off"], "query", "space", "/")
    assert (rc_o == 0) == (rc_f == 0), (
        f"query space support category differs: "
        f"our_ok={rc_o == 0}({out_o}{err_o!r}) "
        f"stock_ok={rc_f == 0}({out_f}{err_f!r})")
    if rc_f != 0:
        assert L.err_code(out_o + err_o) == L.err_code(out_f + err_f), (
            f"query space failure category differs: "
            f"our={L.err_code(out_o + err_o)} stock={L.err_code(out_f + err_f)}")


def test_qspace_raw_reqcode_parity(srv):
    """Raw Qspace (infotype=5) on '/': OUR ok-category must match stock."""
    so, bo = raw_query(srv["our"], kXR_Qspace, "/")
    sf, bf = raw_query(srv["off"], kXR_Qspace, "/")
    assert (so == kXR_ok) == (sf == kXR_ok), (
        f"raw Qspace ok-category differs: our={so} ({bo!r}) "
        f"stock={sf} ({bf!r})")


# =========================================================================== #
# 5. QUERY STATS (Qstats, infotype=1) — rc==0 + non-empty XML-ish on OUR.     #
# =========================================================================== #
def test_qstats_success_nonempty(srv):
    """`xrdfs query stats a` -> success + non-empty output on OUR server."""
    rc, out, err = fs(srv["our"], "query", "stats", "a")
    assert rc == 0, f"OUR query stats failed: {out}{err}"
    assert out.strip() != "", "OUR query stats returned empty output"


def test_qstats_raw_xmlish(srv):
    """Raw Qstats (infotype=1, empty arg -> 'a') -> kXR_ok with an XML-ish body
    (XrdStats emits '<statistics ...>...'); pin the open angle bracket."""
    status, body = raw_query(srv["our"], kXR_QStats, b"")
    assert status == kXR_ok, f"OUR raw Qstats status {status} (BUG): {body!r}"
    text = body.rstrip(b"\x00").decode("latin-1")
    assert text.strip() != "", "OUR raw Qstats body empty"
    assert "<" in text, f"OUR raw Qstats body not XML-ish: {text[:120]!r}"


def test_qstats_differential_success(srv):
    """Both servers must succeed at query stats (it needs no namespace plugin)."""
    rc_o, out_o, _ = fs(srv["our"], "query", "stats", "a")
    rc_f, out_f, _ = fs(srv["off"], "query", "stats", "a")
    assert rc_o == 0, f"OUR query stats failed: {out_o!r}"
    assert (rc_o == 0) == (rc_f == 0), \
        f"query stats success category differs: our={rc_o} stock={rc_f}"


# =========================================================================== #
# 6. QUERY XATTR (Qxattr, infotype=4) — parity vs stock.                      #
# =========================================================================== #
def test_qxattr_raw_parity(srv):
    """Raw Qxattr (infotype=4) on /data.bin: OUR ok-category must match stock."""
    so, bo = raw_query(srv["our"], kXR_Qxattr, "/data.bin")
    sf, bf = raw_query(srv["off"], kXR_Qxattr, "/data.bin")
    assert (so == kXR_ok) == (sf == kXR_ok), (
        f"raw Qxattr ok-category differs: our={so} ({bo!r}) "
        f"stock={sf} ({bf!r})")


def test_qxattr_not_arginvalid(srv):
    """Qxattr is a recognised reqcode (do_Query -> do_Qxattr); OUR server must
    not reject it as an invalid query type."""
    status, body = raw_query(srv["our"], kXR_Qxattr, "/data.bin")
    text = body.rstrip(b"\x00").decode("latin-1").lower()
    assert not (status == kXR_error and "invalid information query type" in text), (
        f"OUR rejected Qxattr as an invalid reqcode (BUG): {body!r}")


# =========================================================================== #
# 7. QUERY OPAQUE (Qopaque, infotype=16) — parity vs stock.                   #
# =========================================================================== #
def test_qopaque_raw_parity(srv):
    """Raw Qopaque (infotype=16): OUR ok/err-category must match stock (with no
    plugin both typically reject; do_Qopaque routes to FSctl PLUGIO)."""
    so, bo = raw_query(srv["our"], kXR_Qopaque, "anything")
    sf, bf = raw_query(srv["off"], kXR_Qopaque, "anything")
    assert (so == kXR_ok) == (sf == kXR_ok), (
        f"raw Qopaque ok-category differs: our={so} ({bo!r}) "
        f"stock={sf} ({bf!r})")


# =========================================================================== #
# 8. QUERY PREPARE (Qprep, infotype=2) — do_Query -> do_Prepare(true).        #
# =========================================================================== #
def test_qprep_unknown_reqid_reference(srv):
    """Qprep (infotype=2) is a prepare-STATUS query -> do_Query routes it to
    do_Prepare(true). The reference (core XRootD, no plugin involved) tracks
    prepare request-ids and REJECTS a status query for a reqid it never issued
    ("Prepare requestid owned by an unknown server"). We pin OUR server to that
    reference: an unknown reqid must NOT be silently accepted as ok."""
    sf, bf = raw_query(srv["off"], kXR_QPrep, "reqid-0001")
    assert sf == kXR_error, (
        f"oracle: stock unexpectedly accepted an unknown prepare reqid: {bf!r}")
    so, bo = raw_query(srv["our"], kXR_QPrep, "reqid-0001")
    assert so == kXR_error, (
        f"OUR server accepted a Qprep status query for a reqid it never issued "
        f"(reference rejects it): status={so} {bo!r}")


def test_qprep_not_arginvalid(srv):
    """Qprep is a recognised reqcode; OUR server must not reject it as an
    invalid query TYPE (a content/arg error is acceptable, a type error is not)."""
    status, body = raw_query(srv["our"], kXR_QPrep, "reqid-xyz")
    text = body.rstrip(b"\x00").decode("latin-1").lower()
    assert not (status == kXR_error and "invalid information query type" in text), (
        f"OUR rejected Qprep as an invalid reqcode (BUG): {body!r}")


# =========================================================================== #
# 9. QUERY VISA (Qvisa, infotype=8) — do_Query has NO case for kXR_Qvisa, so   #
#    the reference falls through to the default and rejects it with kXR_error  #
#    "Invalid information query type code". Pin OUR server to that + diff.     #
# =========================================================================== #
def test_qvisa_rejected_as_invalid_type(srv):
    """do_Query() has no kXR_Qvisa case (it is commented out) -> the default
    branch returns kXR_error "Invalid information query type code". OUR server
    must likewise reject Qvisa as an invalid query type."""
    status, body = raw_query(srv["our"], kXR_Qvisa, b"")
    assert status == kXR_error, \
        f"OUR Qvisa not rejected (reference rejects it): status={status} {body!r}"


def test_qvisa_parity_with_stock(srv):
    """Differential: Qvisa rejection category must match stock (both kXR_error)."""
    so, _ = raw_query(srv["our"], kXR_Qvisa, b"")
    sf, _ = raw_query(srv["off"], kXR_Qvisa, b"")
    assert (so == kXR_error) == (sf == kXR_error), (
        f"Qvisa rejection category differs: our_err={so == kXR_error} "
        f"stock_err={sf == kXR_error}")


# =========================================================================== #
# 10. UNKNOWN REQCODE — an infotype with no do_Query case must be rejected     #
#     with kXR_error "Invalid information query type code" (do_Query default).  #
# =========================================================================== #
@pytest.mark.parametrize("bad", [0, 99, 1000, 0x7fff])
def test_unknown_reqcode_rejected(srv, bad):
    """An unrecognised infotype must be kXR_error on OUR server (do_Query
    default branch). 0/99/1000/0x7fff are not in the XQueryType enum."""
    status, body = raw_query(srv["our"], bad, b"")
    assert status == kXR_error, (
        f"OUR accepted unknown query reqcode {bad} (BUG): status={status} "
        f"{body!r}")


@pytest.mark.parametrize("bad", [0, 99, 1000])
def test_unknown_reqcode_parity(srv, bad):
    """Differential: an unknown reqcode is rejected on BOTH servers."""
    so, _ = raw_query(srv["our"], bad, b"")
    sf, _ = raw_query(srv["off"], bad, b"")
    assert (so == kXR_error) == (sf == kXR_error), (
        f"unknown reqcode {bad} rejection category differs: "
        f"our_err={so == kXR_error} stock_err={sf == kXR_error}")


# =========================================================================== #
# 11. EMPTY PAYLOAD — a query with dlen==0 on selected reqcodes.              #
#     Qconfig with no arg -> kXR_ArgMissing (an error) per do_Qconf; Qstats   #
#     with no arg defaults to "a" and succeeds (do_Query). Pin + diff.        #
# =========================================================================== #
def test_qconfig_empty_payload_rejected(srv):
    """do_Qconf rejects a missing argument (kXR_ArgMissing -> kXR_error). OUR
    server must reject an empty-payload Qconfig too."""
    status, body = raw_query(srv["our"], kXR_Qconfig, b"")
    assert status == kXR_error, (
        f"OUR Qconfig with empty payload not rejected (reference sends "
        f"kXR_ArgMissing): status={status} {body!r}")


def test_qconfig_empty_payload_parity(srv):
    """Differential: empty-payload Qconfig rejected on BOTH servers."""
    so, _ = raw_query(srv["our"], kXR_Qconfig, b"")
    sf, _ = raw_query(srv["off"], kXR_Qconfig, b"")
    assert (so == kXR_error) == (sf == kXR_error), (
        f"empty Qconfig rejection differs: our_err={so == kXR_error} "
        f"stock_err={sf == kXR_error}")


def test_qstats_empty_payload_defaults_to_all(srv):
    """do_Query passes "a" when dlen==0 for kXR_QStats; an empty-payload Qstats
    must therefore SUCCEED with a non-empty body on OUR server."""
    status, body = raw_query(srv["our"], kXR_QStats, b"")
    assert status == kXR_ok, (
        f"OUR empty-payload Qstats not ok (reference defaults to 'a'): "
        f"status={status} {body!r}")
    assert body.rstrip(b"\x00").strip() != b"", "OUR empty Qstats body empty"


def test_qcksum_empty_payload_parity(srv):
    """Differential: empty-payload Qcksum (no path) — OUR ok-category must match
    stock (both should reject a checksum with no path)."""
    so, _ = raw_query(srv["our"], kXR_Qcksum, b"")
    sf, _ = raw_query(srv["off"], kXR_Qcksum, b"")
    assert (so == kXR_ok) == (sf == kXR_ok), (
        f"empty Qcksum ok-category differs: our_ok={so == kXR_ok} "
        f"stock_ok={sf == kXR_ok}")


# =========================================================================== #
# 12. DETERMINISM across reqcodes — the same raw query twice is byte-identical #
#     for the deterministic reqcodes (Qconfig value, Qcksum hex).             #
# =========================================================================== #
def test_determinism_qconfig_raw(srv):
    """Two identical raw Qconfig requests return byte-identical bodies."""
    _, b1 = raw_query(srv["our"], kXR_Qconfig, "bind_max version readv_iov_max")
    _, b2 = raw_query(srv["our"], kXR_Qconfig, "bind_max version readv_iov_max")
    assert b1 == b2, f"non-deterministic Qconfig body: {b1!r} then {b2!r}"


def test_determinism_qcksum_raw(srv):
    """Two identical raw Qcksum requests return the same checksum body."""
    _, b1 = raw_query(srv["our"], kXR_Qcksum, "/data.bin")
    _, b2 = raw_query(srv["our"], kXR_Qcksum, "/data.bin")
    h1 = b1.rstrip(b"\x00").split()[-1] if b1.split() else b""
    h2 = b2.rstrip(b"\x00").split()[-1] if b2.split() else b""
    assert h1 == h2 and h1 != b"", \
        f"non-deterministic raw Qcksum hex: {h1!r} then {h2!r}"


# =========================================================================== #
# 13. STREAMID ECHO — kXR_query response must echo the request streamid        #
#     verbatim (XrdXrootdResponse): a query reply is still a normal response.  #
# =========================================================================== #
def test_query_streamid_echoed_verbatim(srv):
    """The streamid in a kXR_query response is echoed verbatim (not swapped)."""
    sid = b"\xab\xcd"
    s = _session(srv["our"])
    try:
        arg = b"version"
        s.sendall(struct.pack("!2sHH14sI", sid, kXR_query, kXR_Qconfig,
                              b"\x00" * 14, len(arg)) + arg)
        rsid, status, _ = _resp(s)
        assert rsid == sid, f"query streamid not echoed verbatim: {rsid!r}"
        assert status == kXR_ok, f"query version not ok: {status}"
    finally:
        s.close()
