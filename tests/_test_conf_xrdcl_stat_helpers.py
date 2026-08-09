"""
tests/test_conf_xrdcl_stat.py

Differential conformance for XrdCl::FileSystem.stat / statvfs driven through the
REAL libXrdCl python bindings — the exact code path gfal / FTS / Rucio take.

Every operation runs against BOTH servers owned by the central registry:
  * ``ctx['our']``  — this module (nginx-xrootd)
  * ``ctx['off']``  — stock ``xrootd`` v5.x

The two servers serve byte-identical trees, so the parsed ``StatInfo`` /
``StatInfoVFS`` objects (and the ``XRootDStatus`` they ride in) must AGREE.
Stock is ground truth: any divergence is treated as OUR bug.

Contract sources (cited inline):
  * StatInfoImpl::ParseServerResponse  XrdClXRootDResponses.cc:140
      response is space-split; chunks[0]=id (string), chunks[1]=size
      (strtoll base 0 — MUST be a clean integer or the WHOLE parse fails),
      chunks[2]=flags (strtol), chunks[3]=modtime; if >=9 chunks then
      [4]=ctime [5]=atime [6]=mode-string(>=4 chars) [7]=owner [8]=group.
  * StatInfo::Flags enum  XrdClXRootDResponses.hh:420
      XBitSet=1 IsDir=2 Other=4 Offline=8 IsReadable=16 IsWritable=32
      POSCPending=64 BackUpExists=128.
  * StatInfoVFS::ParseServerResponse  XrdClXRootDResponses.cc:452
      six fields: nrw frw urw nstg fstg ustg.
  * id formula  XrdXrootdProtocol::StatGen  XrdXrootdProtocol.cc:755-767
      Dev.uuid = (st_dev << 32) | st_ino  (hi=st_dev, lo=st_ino).

Because the id encodes the real on-disk (dev, ino) of two SEPARATE servers, its
*value* can never match across the pair; the contract we can assert is that BOTH
emit a clean, non-empty, base-0-parseable integer (what XrdCl requires).  The
known "ours = inode only, stock = (dev<<32)|ino" difference is recorded as a
DIVERGENCE note below and pinned at the shape level.

Isolation: libXrdCl runs out-of-process via tests/_xrdcl_worker.py (imported as
``from XRootD import client``); a hung op becomes a test failure, never a frozen
interpreter.  Honour XRDCL_PROXY_TIMEOUT.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import official_interop_lib as L  # noqa: E402
from _xrdcl_proxy import real_bindings_available  # noqa: E402

# --------------------------------------------------------------------------
# Module gate: infrastructure is required and fails loudly from ``ctx``.
# --------------------------------------------------------------------------
pytestmark = [
    pytest.mark.registry_servers("interop-our", "interop-off"),
    pytest.mark.xdist_group("interop-central"),
]

try:
    from XRootD import client
    from XRootD.client.flags import StatInfoFlags
    _HAVE_BINDINGS = real_bindings_available()
    _BIND_ERR = "real libXrdCl bindings unavailable"
except Exception as exc:  # pragma: no cover - environment dependent
    _HAVE_BINDINGS = False
    _BIND_ERR = repr(exc)

bindings_required = pytest.mark.usefixtures("ctx")

# --------------------------------------------------------------------------
# StatInfo::Flags — captured from XrdClXRootDResponses.hh:420 for decode tests.
# --------------------------------------------------------------------------
F_XBITSET = 1
F_ISDIR = 2
F_OTHER = 4
F_OFFLINE = 8
F_READABLE = 16
F_WRITABLE = 32
F_POSCPEND = 64
F_BKPEXIST = 128


# --------------------------------------------------------------------------
# Module-scoped fixture: attach to the ONE registry pair for the whole file.
# --------------------------------------------------------------------------
@pytest.fixture(scope="module")
def ctx():
    assert L.have_official(), "stock xrootd tools are required"
    assert real_bindings_available(), (
        "real libXrdCl bindings unavailable; run the suite with its configured venv")
    return L.central_pair()


@pytest.fixture(scope="module")
def fs_our(ctx):
    return client.FileSystem(ctx["our"])


@pytest.fixture(scope="module")
def fs_off(ctx):
    return client.FileSystem(ctx["off"])


# --------------------------------------------------------------------------
# Helpers — decode the differential surface XrdCl exposes.
# --------------------------------------------------------------------------
def _stat(fs, path):
    """Return (status, statinfo) for one stat; never raises on protocol error."""
    return fs.stat(path)


def _statvfs(fs, path):
    """fs.statvfs(path) -> (status, StatInfoVFS). The op gfal df / space uses."""
    return fs.statvfs(path)


def _id_is_clean_int(sid):
    """XrdCl chunks[0]=id then size strtoll base-0: the id itself is a free
    string in the contract, but stock and ours both emit a base-10 integer.
    A clean, non-empty integer string is the shape we pin (the *value* differs
    because it encodes a per-server (dev,ino); see DIVERGENCE note)."""
    if sid is None:
        return False
    s = str(sid).strip()
    if s == "":
        return False
    try:
        int(s, 0)
        return True
    except (TypeError, ValueError):
        return False


def _decode_flags(flags):
    """Decode a StatInfo.flags bitmask into the canonical predicate dict the
    contract (XrdClXRootDResponses.hh:420) defines."""
    return {
        "XBitSet": bool(flags & F_XBITSET),
        "IsDir": bool(flags & F_ISDIR),
        "Other": bool(flags & F_OTHER),
        "Offline": bool(flags & F_OFFLINE),
        "IsReadable": bool(flags & F_READABLE),
        "IsWritable": bool(flags & F_WRITABLE),
        "POSCPending": bool(flags & F_POSCPEND),
        "BackUpExists": bool(flags & F_BKPEXIST),
    }


def _status_tuple(st):
    """The differential status surface: ok / code / errno."""
    return (bool(st.ok), int(st.code), int(st.errno))


# --------------------------------------------------------------------------
# Path catalogue.  Existing-OK paths vs. error paths are split so each gets the
# appropriate assertion shape.
# --------------------------------------------------------------------------
FILE_PATHS = [
    "/hello.txt",
    "/data.bin",
    "/empty.txt",
    "/big1m.bin",
    "/sz_1.bin",
    "/sz_255.bin",
    "/sz_4095.bin",
    "/sz_4096.bin",
    "/sz_4097.bin",
    "/sz_8192.bin",
    "/sz_65536.bin",
    "/cksum.bin",
    "/with space.txt",
    "/sub/nested.txt",
    "/deep/a/b/c/leaf.txt",
    "/many/f00.txt",
    "/many/f05.txt",
    "/many/f11.txt",
]

DIR_PATHS = [
    "/",
    "/sub",
    "/deep",
    "/deep/a",
    "/deep/a/b",
    "/deep/a/b/c",
    "/empty_dir",
    "/many",
]

# Expected on-disk sizes for the byte-identical tree (make_rich_tree).
FILE_SIZES = {
    "/hello.txt": 12,
    "/data.bin": 4096,
    "/empty.txt": 0,
    "/big1m.bin": 1024 * 1024,
    "/sz_1.bin": 1,
    "/sz_255.bin": 255,
    "/sz_4095.bin": 4095,
    "/sz_4096.bin": 4096,
    "/sz_4097.bin": 4097,
    "/sz_8192.bin": 8192,
    "/sz_65536.bin": 65536,
    "/cksum.bin": 10000,
    "/with space.txt": 7,
    "/sub/nested.txt": 7,
    "/deep/a/b/c/leaf.txt": 5,
    "/many/f00.txt": 7,   # "file 0\n"
    "/many/f05.txt": 7,   # "file 5\n"
    "/many/f11.txt": 8,   # "file 11\n"
}

# Trailing-slash variants of directories — stat must agree on both servers.
DIR_TRAILING = [
    "/sub/",
    "/deep/",
    "/deep/a/b/c/",
    "/empty_dir/",
    "/many/",
]

# Paths that must NOT exist — both servers must report an error and AGREE on it.
MISSING_PATHS = [
    "/missing",
    "/no_such_dir/x",
    "/sub/missing",
    "/deep/a/b/c/nope.txt",
    "/many/f99.txt",
    "/empty_dir/ghost",
    "/sz_9999.bin",
    "/.hidden_missing",
    "/with space missing.txt",
    "/deep/zz/leaf.txt",
]

# Trailing-slash applied to a FILE — illegal "not a directory" shape; both
# servers must agree on the failure.
FILE_TRAILING = [
    "/hello.txt/",
    "/data.bin/",
    "/sz_1.bin/",
    "/with space.txt/",
    "/sub/nested.txt/",
]


# ==========================================================================
# 1. Files — status, size, flags, id/modtime shape all agree with stock.
# ==========================================================================
