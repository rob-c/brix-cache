"""Differential gfal2 conformance — nginx-xrootd vs stock xrootd v5.x.

The FTS/Rucio production data layer drives the official ``libXrdCl`` through the
gfal2 CLI suite (gfal-stat/ls/mkdir/rm/copy/sum/rename/xattr).  This file runs
the SAME gfal command against BOTH our server (``ctx['our']``) and the stock
server (``ctx['off']``) launched on byte-identical trees by
``official_interop_lib.start_pair`` and asserts they agree on:

  * return code (rc),
  * key stdout fields (gfal-stat Size/type/Mode; gfal-ls -l name set + sizes;
    gfal-sum digest equality — also cross-checked against our native client
    ``client/bin/xrdcrc32c`` / ``xrdadler32``),
  * the coarse error-wording category (``L.err_code``).

Stock is truth: a divergence is OUR bug unless positively explained.  gfal must
use the SYSTEM libXrdCl, so ``_clean_env()`` drops ``LD_LIBRARY_PATH`` (same
pattern as ``tests/test_gfal_interop.py``).  The whole module skips cleanly if
gfal2 or the stock tooling is absent — it never ERRORs.

Known, explained divergences are pinned with ``@pytest.mark.xfail`` and a
``DIVERGENCE:`` comment so the suite stays green; see the module docstring tail
and the final report for the rationale (checksum support is a stock-server
*config* gap, not a protocol bug — our digests are independently verified
correct against our native checksum tools and against python's zlib/hashlib).
"""
import os
import shutil
import subprocess
import tempfile

import pytest

import official_interop_lib as L

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NATIVE_CRC32C = os.path.join(REPO, "client", "bin", "xrdcrc32c")
NATIVE_ADLER32 = os.path.join(REPO, "client", "bin", "xrdadler32")

OUR_PORT = L.worker_port(14912)
OFF_PORT = L.worker_port(14913)
pytestmark = pytest.mark.skipif(
    shutil.which("gfal-stat") is None or not L.have_official(),
    reason="gfal2-util or stock xrootd tooling not installed",
)


# --------------------------------------------------------------------------- #
# environment + command runner
# --------------------------------------------------------------------------- #
def _clean_env():
    """gfal must bind the SYSTEM libXrdCl, not a conda one — drop LD_LIBRARY_PATH
    (mirrors tests/test_gfal_interop.py._clean_env)."""
    e = dict(os.environ)
    e.pop("LD_LIBRARY_PATH", None)
    return e


def _gfal(*argv, timeout=90):
    """Run a gfal CLI command; return (rc, stdout, stderr)."""
    r = subprocess.run([str(a) for a in argv], capture_output=True, text=True,
                       timeout=timeout, env=_clean_env())
    return r.returncode, r.stdout, r.stderr


# --------------------------------------------------------------------------- #
# module-scoped server pair (one launch on our assigned port range)
# --------------------------------------------------------------------------- #
@pytest.fixture(scope="module")
def ctx():
    _tr_tmp = os.path.join(os.environ.get("TEST_ROOT", "/tmp/xrd-test"), "tmp")
    base = tempfile.mkdtemp(prefix="gfal_ops_", dir=_tr_tmp
                            if os.path.isdir(_tr_tmp) else None)
    try:
        procs, c = L.start_pair(base, our_port=OUR_PORT, off_port=OFF_PORT)
    except RuntimeError as exc:                       # setup failure → skip
        pytest.skip(f"server pair unavailable: {exc}")
    yield c
    L.stop_pair(procs)


def _url(ctx, side, path):
    """Build a gfal root:// URL: root://127.0.0.1:PORT//<path>."""
    return f"{ctx[side]}/" + path if path.startswith("/") else f"{ctx[side]}//{path}"


def _scratch(ctx, side, name):
    """A per-test scratch dir under each data root, created identically."""
    return _url(ctx, side, f"gfal_scr_{name}")


# --------------------------------------------------------------------------- #
# stdout field parsers (XrdCl/gfal output formats)
# --------------------------------------------------------------------------- #
def _parse_stat(out):
    """Parse gfal-stat output into {size, type, mode}.  Format:
      File: '...'
      Size: 12      regular file
      Access: (0600/-rw-------) ...
    """
    info = {}
    for line in out.splitlines():
        s = line.strip()
        if s.startswith("Size:"):
            # 'Size: 12\tregular file'
            rest = s[len("Size:"):].strip()
            parts = rest.split(None, 1)
            info["size"] = parts[0]
            info["type"] = parts[1].strip() if len(parts) > 1 else ""
        elif s.startswith("Access:") and "(" in s and "/" in s:
            # 'Access: (0600/-rw-------)\tUid: ...'
            frag = s.split("(", 1)[1].split(")", 1)[0]      # '0600/-rw-------'
            info["mode"] = frag.split("/", 1)[0]
    return info


def _parse_ls_l(out):
    """gfal-ls -l → {name: size} mapping.  Fixed long format (XrdCl/gfal):
      perms  links  uid  gid  size  mon  day  time  name
    e.g. '-rw-rw-rw-   0 0     0           255 Jun 24 14:04 sz_255.bin'.
    size is positional column index 4; name is the final token."""
    names = {}
    for line in out.splitlines():
        line = line.rstrip()
        if not line:
            continue
        cols = line.split()
        if len(cols) < 9:           # perms..time + name
            continue
        # name may contain spaces ('with space.txt') → rejoin tokens 8..end
        names[" ".join(cols[8:])] = cols[4]
    return names


def _sum_digest(out):
    """gfal-sum prints '<url> <hex>'; return the lower-case hex digest."""
    toks = out.split()
    return toks[-1].lower() if toks else ""


def _native(tool, path):
    """Our native checksum tool's hex for local bytes — the integrity oracle."""
    if not os.path.exists(tool):
        return None
    r = subprocess.run([tool, str(path)], capture_output=True, text=True, timeout=30)
    if r.returncode != 0:
        return None
    return r.stdout.split()[0].lower()


# --------------------------------------------------------------------------- #
# differential helper — run identical op both sides, return both results
# --------------------------------------------------------------------------- #
def _both(ctx, build):
    """build(side) -> argv list; runs on our + off; returns (our_res, off_res)."""
    return _gfal(*build("our")), _gfal(*build("off"))


def _assert_rc_and_errcat(our, off, msg):
    """rc must match; when both fail, the coarse error category must match."""
    o_rc, _, o_err = our
    f_rc, _, f_err = off
    assert o_rc == f_rc, f"{msg}: rc our={o_rc} off={f_rc}\nour:{o_err}\noff:{f_err}"
    if o_rc != 0:
        assert L.err_code(o_err) == L.err_code(f_err), (
            f"{msg}: error-category our={L.err_code(o_err)!r} "
            f"off={L.err_code(f_err)!r}\nour:{o_err}\noff:{f_err}")


# tree paths shared by both servers (from make_rich_tree)
FILES = [
    "hello.txt", "data.bin", "empty.txt", "cksum.bin", "with space.txt",
    "sub/nested.txt", "deep/a/b/c/leaf.txt",
    "sz_1.bin", "sz_255.bin", "sz_4095.bin", "sz_4096.bin", "sz_4097.bin",
    "sz_8192.bin", "sz_65536.bin", "big1m.bin",
]
DIRS = ["sub", "deep", "deep/a", "deep/a/b", "deep/a/b/c", "empty_dir", "many"]
MISSING = ["nope.txt", "deep/missing", "no_such_dir/x", "many/zzz.txt"]
EXPECT_SIZE = {
    "hello.txt": "12", "data.bin": "4096", "empty.txt": "0", "cksum.bin": "10000",
    "sub/nested.txt": "7", "deep/a/b/c/leaf.txt": "5", "with space.txt": "7",
    "sz_1.bin": "1", "sz_255.bin": "255", "sz_4095.bin": "4095",
    "sz_4096.bin": "4096", "sz_4097.bin": "4097", "sz_8192.bin": "8192",
    "sz_65536.bin": "65536", "big1m.bin": "1048576",
}


# --------------------------------------------------------------------------- #
# gfal-stat — files
# --------------------------------------------------------------------------- #
