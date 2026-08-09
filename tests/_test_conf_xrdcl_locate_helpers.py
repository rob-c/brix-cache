"""Differential conformance for XrdCl::FileSystem locate / deeplocate / query —
driven through the REAL libXrdCl bindings (``from XRootD import client``, hosted
out-of-process by the tests/_xrdcl_worker proxy) against BOTH our nginx-xrootd
server AND the stock xrootd data server, on identical data trees.

This is exactly gfal/FTS/Rucio's code path: they call ``FileSystem::Locate`` /
``DeepLocate`` / ``Query`` and parse the binding result objects (LocationInfo,
raw query buffers). A divergence from stock is treated as a BUG IN OUR SERVER
(stock is truth), unless there is positive evidence otherwise (e.g. the bare
stock data server simply lacks a checksum/prepare plugin, in which case we pin
OUR value against an INDEPENDENT reference rather than against the stock error).

Contract citations (consulted, never modified):
  * LocationInfo wire parse — XrdClXRootDResponses.cc:26 (ProcessLocation):
    space-split; token[0] = type char M/m/S/s (ManagerOnline/ManagerPending/
    ServerOnline/ServerPending), token[1] = access char r (Read) / w (ReadWrite),
    rest = host:port; a bad type/access char makes XrdCl reject the WHOLE
    response; a token shorter than its 2-char prefix + host is rejected.
    LocationType enum — XrdClXRootDResponses.hh:49  (0=ManagerOnline,
    1=ManagerPending, 2=ServerOnline, 3=ServerPending).
    AccessType enum   — XrdClXRootDResponses.hh:60  (0=Read, 1=ReadWrite).
  * QueryCode enum — XrdClFileSystem.hh:48 (Config/ChecksumCancel/Checksum/
    Opaque/OpaqueFile/Prepare/Space/Stats/Visa/XAttr/...).
  * do_Qconf bare-value format / unknown-key echo / role / sitename cases —
    XrdXrootd/XrdXrootdXeq.cc:2168-2268.
  * do_Query reqcode dispatch (Qvisa has NO case -> rejected; Qprep ->
    do_Prepare(true) -> unknown reqid rejected) — XrdXrootdXeq.cc::do_Query.

Because the binding REJECTS the entire locate response on a single malformed
token, ``status.ok`` on a locate is itself a strong structural assertion: it
proves every emitted token had a valid type char, a valid access char, and a
non-empty host:port. We additionally compare the parsed type/access enum values
our-vs-stock, and parity of status.ok / errno across the whole tree.

Harness: official_interop_lib (PYTHONPATH=tests). The central registry owns both
servers; missing servers, tools, or real bindings are hard setup failures.
"""

import os
import zlib
import hashlib

import pytest

import official_interop_lib as L
from _xrdcl_proxy import real_bindings_available

# The bindings are reached through the in-repo shadow XRootD package (proxy to
# an out-of-process real-libXrdCl worker). The fixture verifies that the real
# package behind the shadow is available.
try:
    from XRootD import client
    from XRootD.client.flags import OpenFlags, QueryCode
    _HAVE_BINDINGS = True
except Exception:  # noqa: BLE001 - any import failure -> skip module
    _HAVE_BINDINGS = False

pytestmark = [
    pytest.mark.timeout(360),
    pytest.mark.registry_servers("interop-our", "interop-off"),
    pytest.mark.xdist_group("interop-central"),
]


# --------------------------------------------------------------------------- #
# Module-scoped attachment to the central registry pair.                      #
# --------------------------------------------------------------------------- #
@pytest.fixture(scope="module")
def srv():
    assert L.have_official(), "stock xrootd tools are required"
    assert real_bindings_available(), (
        "real libXrdCl bindings unavailable; run the suite with its configured venv")
    return L.central_pair()


@pytest.fixture(scope="module")
def fs_our(srv):
    return client.FileSystem(srv["our"])


@pytest.fixture(scope="module")
def fs_off(srv):
    return client.FileSystem(srv["off"])


# --------------------------------------------------------------------------- #
# LocationInfo enum constants (XrdClXRootDResponses.hh).                       #
# --------------------------------------------------------------------------- #
LT_MGR_ONLINE, LT_MGR_PENDING, LT_SRV_ONLINE, LT_SRV_PENDING = 0, 1, 2, 3
ACC_READ, ACC_READWRITE = 0, 1


# Tree contents (make_rich_tree). Each entry: (path, is_dir).
TREE_FILES = [
    "/hello.txt", "/data.bin", "/empty.txt", "/sub/nested.txt",
    "/deep/a/b/c/leaf.txt", "/with space.txt", "/cksum.bin", "/big1m.bin",
    "/sz_1.bin", "/sz_255.bin", "/sz_4095.bin", "/sz_4096.bin",
    "/sz_4097.bin", "/sz_8192.bin", "/sz_65536.bin",
    "/many/f00.txt", "/many/f05.txt", "/many/f11.txt",
]
TREE_DIRS = ["/", "/sub", "/deep", "/deep/a", "/deep/a/b", "/deep/a/b/c",
             "/empty_dir", "/many"]
TREE_MISSING = ["/nope.bin", "/sub/missing.txt", "/deep/a/zzz/none.txt",
                "/no_such_dir/", "/missing_top_level"]

# The binding exposes a subset of OpenFlags; PREFNAME is absent in some builds,
# so we fall back to FORCE (also a benign locate hint) to keep three variants.
_THIRD_FLAG = ("PREFNAME", getattr(OpenFlags, "PREFNAME", None))
if _THIRD_FLAG[1] is None:
    _THIRD_FLAG = ("FORCE", OpenFlags.FORCE)

LOCATE_FLAGS = [
    ("NONE", OpenFlags.NONE),
    ("REFRESH", OpenFlags.REFRESH),
    _THIRD_FLAG,
]


# --------------------------------------------------------------------------- #
# Helpers.                                                                     #
# --------------------------------------------------------------------------- #
def _locs(loc):
    """LocationInfo -> list of (type, accesstype, address) tuples."""
    out = []
    if loc:
        for l in loc:
            out.append((l.type, l.accesstype, l.address))
    return out


def _read_bytes(ctx, path):
    with open(os.path.join(ctx["our_data"], path.lstrip("/")), "rb") as f:
        return f.read()


def ref_adler32(data):
    return f"{zlib.adler32(data) & 0xffffffff:08x}"


def ref_crc32(data):
    return f"{zlib.crc32(data) & 0xffffffff:08x}"


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


# =========================================================================== #
# 1. LOCATE — every tree FILE, every flag. The binding rejects the whole       #
#    response on a single malformed token, so status.ok already proves the     #
#    type/access chars and host:port are well-formed.                          #
# =========================================================================== #

def _q(fs, key):
    st, r = fs.query(QueryCode.CONFIG, key)
    text = (r or b"").rstrip(b"\x00").decode("latin-1") if r else ""
    return st, text

def _cksum(fs, arg):
    st, r = fs.query(QueryCode.CHECKSUM, arg)
    text = (r or b"").rstrip(b"\x00").decode("latin-1") if r else ""
    return st, text

def _parse_oss(text):
    out = {}
    for pair in text.split("&"):
        if "=" in pair:
            k, v = pair.split("=", 1)
            out[k] = v
    return out


def _space(fs, path="/"):
    st, r = fs.query(QueryCode.SPACE, path)
    text = (r or b"").rstrip(b"\x00").decode("latin-1") if r else ""
    return st, text



def _stats(fs, arg="a"):
    st, r = fs.query(QueryCode.STATS, arg)
    text = (r or b"").rstrip(b"\x00").decode("latin-1", "replace") if r else ""
    return st, text



def _xattr(fs, path):
    st, r = fs.query(QueryCode.XATTR, path)
    text = (r or b"").rstrip(b"\x00").decode("latin-1", "replace") if r else ""
    return st, text
