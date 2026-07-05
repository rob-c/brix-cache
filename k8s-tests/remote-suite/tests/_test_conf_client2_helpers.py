# _test_conf_client2_helpers.py - shared header/helpers/fixtures/constants for the Phase-38
# split of test_conf_client2.py.  `from _test_conf_client2_helpers import *` re-exports EVERYTHING via
# the __all__ below so the test functions keep their exact module namespace.


"""Deep differential conformance for OUR native client tools.

This suite goes DEEPER than test_conf_client.py / test_conf_xrdfs.py: it holds
OUR ``client/bin/xrdfs`` and ``client/bin/xrdcp`` to the behavior of the STOCK
``xrdfs``/``xrdcp`` reference clients, with the STOCK client as the ORACLE run
against the SAME stock server. Both clients hit one stock xrootd data server, so
any OURS-vs-STOCK divergence (output / bytes / rc / on-disk effect) is, by the
maintainer's rule, a BUG IN OUR CLIENT.

Quadrants (see official_interop_lib.py):
  * OUR   xrdfs/xrdcp -> STOCK server   (Q2: a failure is a BUG IN OUR CLIENT)
  * STOCK xrdfs/xrdcp -> STOCK server   (Q4: the reference ORACLE)
  * a small subset of OUR xrdfs -> OUR server (sanity)

Where the stock data server lacks a feature (e.g. the checksum plugin) the test
asserts category/rc parity, and where the prompt demands a positive answer it
uses an independent oracle (hashlib/zlib) — never an xfail to hide a real diff.

Confirmed CLIENT GAPS / BUGS (pinned with imperative xfail carrying the exact
OURS-vs-STOCK detail, never a silent skip):
  * xrdcp has no ``--posc`` flag (stock accepts it; ours spells it ``-P``).
  * xrdcp ``-r`` flattens the source dir name into the destination
    (ours: ``dst/f00.txt``; stock: ``dst/many/f00.txt``).
  * xrdcp download to an existing DIRECTORY destination fails to place the file
    (rename error to a temp name) yet still exits 0; stock places ``<name>``.

Rich tree (official_interop_lib.make_rich_tree):
  /hello.txt /data.bin(4096) /sub/nested.txt /empty.txt(0) /empty_dir
  /many/f00..f11 /deep/a/b/c/leaf.txt /sz_{1,255,4095,4096,4097,8192,65536}.bin
  /big1m.bin(1MB) "/with space.txt" /cksum.bin(10000)

Self-provisioning on high ports; the module skips without the stock toolchain.
Mutation paths are unique per test so the shared module fixture is deterministic.
"""

import hashlib
import os
import subprocess
import zlib

import pytest

import official_interop_lib as L

pytestmark = [pytest.mark.timeout(300),
              pytest.mark.skipif(not L.have_official(),
                                 reason="stock xrootd/xrdfs/xrdcp not installed")]

OUR_PORT = L.worker_port(14058)
OFF_PORT = L.worker_port(14059)
# --------------------------------------------------------------------------- #
# Module fixture — our server + stock server on identical rich trees.
# --------------------------------------------------------------------------- #
@pytest.fixture(scope="module")
def srv(tmp_path_factory):
    base = str(tmp_path_factory.mktemp("confclient2"))
    try:
        procs, ctx = L.start_pair(base, our_port=OUR_PORT, off_port=OFF_PORT)
    except RuntimeError as e:
        pytest.skip(f"server pair launch failed: {e}")
    yield ctx
    L.stop_pair(procs)


# --------------------------------------------------------------------------- #
# Runners — `ourfs`/`ourcp` are OUR client; `fs`/`cp` are the STOCK oracle.
# --------------------------------------------------------------------------- #
def ourfs(url, *args, timeout=60):
    return L.run([L.OUR_XRDFS, url, *args], timeout=timeout)


def fs(url, *args, timeout=60):
    return L.run([L.OFF_XRDFS, url, *args], timeout=timeout)


def ourcp(*args, timeout=120):
    return L.run([L.OUR_XRDCP, *args], timeout=timeout)


def cp(*args, timeout=120):
    return L.run([L.OFF_XRDCP, *args], timeout=timeout)


def cat_bytes(binpath, url, remote, timeout=60):
    """Raw-byte capture of `xrdfs <url> cat <remote>` (L.run is text mode)."""
    r = subprocess.run([binpath, url, "cat", remote],
                       capture_output=True, timeout=timeout)
    return r.returncode, r.stdout


# --------------------------------------------------------------------------- #
# Parsers
# --------------------------------------------------------------------------- #
def _names(out):
    names = set()
    for line in out.splitlines():
        s = line.strip()
        if not s:
            continue
        # `ls -R` emits per-directory header lines ("/deep:"); these are not
        # entries — drop them so a recursive listing compares on real leaves.
        if s.endswith(":"):
            continue
        base = os.path.basename(s.rstrip("/"))
        if not base or base.startswith(".nginx-xrootd"):
            continue
        names.add(base)
    return names


def _fields(out):
    d = {}
    for line in out.splitlines():
        if ":" in line:
            k, _, v = line.partition(":")
            d[k.strip()] = v.strip()
    return d


def _read(p):
    with open(p, "rb") as f:
        return f.read()


def _ondisk(srv, side, rel):
    return os.path.join(srv[f"{side}_data"], rel.lstrip("/"))


# Sizes present in the rich tree as /sz_<n>.bin
_SZ = (1, 255, 4095, 4096, 4097, 8192, 65536)


# =========================================================================== #
# OUR xrdfs query config — bare-value parity across every config key            #
# =========================================================================== #
_CFG_KEYS = ["bind_max", "readv_iov_max", "readv_ior_max", "chksum", "tpc",
             "pio_max", "cms", "role", "sitename", "version", "wan_port",
             "window"]


# =========================================================================== #
# OUR xrdcp recursive — vs the stock client's resulting tree                    #
# =========================================================================== #
def _rel_fileset(root):
    out = set()
    for dirpath, _, files in os.walk(root):
        for fn in files:
            full = os.path.join(dirpath, fn)
            out.add(os.path.relpath(full, root))
    return out

__all__ = [n for n in dir() if not n.startswith('__')]
