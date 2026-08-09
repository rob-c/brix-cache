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
