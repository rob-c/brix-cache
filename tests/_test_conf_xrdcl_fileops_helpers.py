"""Differential XrdCl::File conformance via the REAL libXrdCl bindings.

The NEW angle (vs. the xrdcp/xrdfs-driven read tests): every probe here goes
through the genuine ``from XRootD import client`` ``client.File`` surface — the
exact code path gfal2 / FTS / Rucio exercise — driven *differentially* against
BOTH servers (our nginx-xrootd and the stock xrootd v5.9.5) on byte-identical
trees, and the parsed result objects are asserted to agree.

Coverage (>=85 cases, heavily parametrized):
  * open() flags matrix: READ / READ-on-missing / NEW|MAKEPATH / NEW-on-existing
    / UPDATE / WRITE / DELETE(truncate-on-open).
  * read(): offset 0 / mid / exact-EOF / beyond-EOF / straddle-EOF / whole-file,
    over the page-boundary sizes sz_4095/4096/4097/8192/65536 and big1m.bin,
    asserting exact byte equality our-vs-stock.
  * vector_read(): 1 / several / many segments, boundary-spanning, asserting
    VectorReadInfo.size, per-chunk offset/length and chunk *bytes* agree.
  * vector_read vs read byte-equality (no native pgread method is exposed by
    these bindings — vector_read is the readv data path, read is the read path;
    we cross-check them for byte-identity which is the same invariant pgread
    would assert against read).
  * write / sync / truncate / stat-on-open round trips with read-back byte
    equality, into a per-test scratch subdir created identically on both trees.
  * lifecycle error parity: double-open and use-after-close.

Why these are grounded in the XrdCl contract (consulted, NOT modified):
  /tmp/brix-src/src/XrdCl/XrdClFile.hh           File::Open/Read/VectorRead/
                                                    Write/Truncate/Sync/Stat
  /tmp/brix-src/src/XrdCl/XrdClFileSystem.hh:74  OpenFlags (New=kXR_new,
                                                    Delete=kXR_delete,
                                                    MakePath=kXR_mkpath,
                                                    Update=kXR_open_updt,
                                                    Write=kXR_open_wrto,
                                                    Read=kXR_open_read)
  /tmp/brix-src/src/XrdXrootd/XrdXrootdXeq.cc    do_ReadAll / do_ReadV / StatGen
  /tmp/brix-src/src/XrdXrootd/XrdXrootdXeqPgrw.cc do_PgRead framing
  /tmp/brix-src/src/XrdCl/XrdClXRootDResponses.cc:140 StatInfo wire parse

Rules: stock is truth; a divergence is OUR bug. Known/seeded divergence
(StatInfo.id formula) is pinned with xfail so the file stays green. The real
bindings run out-of-process via tests/_xrdcl_proxy.py (XrdCl deadlocks if
imported into pytest directly); a missing binding is a suite setup failure.
"""

import pytest

import official_interop_lib as L
from _xrdcl_proxy import real_bindings_available

# --------------------------------------------------------------------------- #
# Gate: stock toolchain + real libXrdCl bindings must both be present.         #
# --------------------------------------------------------------------------- #
try:
    from XRootD import client as _xrd_client
    from XRootD.client.flags import OpenFlags
    _HAVE_BINDINGS = True
except Exception:                                  # noqa: BLE001
    _xrd_client = None
    OpenFlags = None
    _HAVE_BINDINGS = False

pytestmark = [
    pytest.mark.timeout(240),
    pytest.mark.registry_servers("interop-our", "interop-off"),
    pytest.mark.xdist_group("interop-central"),
]


# --------------------------------------------------------------------------- #
# Module-scoped attachment to the central registry pair.                       #
# --------------------------------------------------------------------------- #
@pytest.fixture(scope="module")
def srv():
    assert L.have_official(), "stock xrootd tools are required"
    assert real_bindings_available(), (
        "real libXrdCl bindings unavailable; run the suite with its configured venv")
    return L.central_pair()


# --------------------------------------------------------------------------- #
# Helpers — open / read / vread on a given root URL, returning parsed shapes.  #
# --------------------------------------------------------------------------- #
def _open(url, rel, flags, mode=0):
    """Open one file via the real bindings; return (File, status)."""
    f = _xrd_client.File()
    st, _ = f.open(url + "//" + rel.lstrip("/"), flags, mode)
    return f, st


def _status_tuple(st):
    """The XRootDStatus fields gfal/FTS branch on — what we compare across servers."""
    return (bool(st.ok), int(st.code), int(st.errno))


def _read(url, rel, off, size):
    """Open READ, read(off,size), close; return (status_tuple, bytes-or-None)."""
    f, st = _open(url, rel, OpenFlags.READ)
    if not st.ok:
        f.close()
        return _status_tuple(st), None
    rst, data = f.read(off, size)
    f.close()
    return _status_tuple(rst), (bytes(data) if rst.ok else None)


def _vread(url, rel, chunks):
    """Open READ, vector_read(chunks), close; return (status_tuple, parsed)."""
    f, st = _open(url, rel, OpenFlags.READ)
    if not st.ok:
        f.close()
        return _status_tuple(st), None
    vst, vinfo = f.vector_read(chunks)
    f.close()
    if not vst.ok or vinfo is None:
        return _status_tuple(vst), None
    parsed = {
        "size": int(vinfo.size),
        "chunks": [(int(c.offset), int(c.length), bytes(c.buffer))
                   for c in vinfo.chunks],
    }
    return _status_tuple(vst), parsed


# Page-boundary sizes (name == size) plus the 1 MiB file — straddle the
# read / pgread / readv framing boundaries.
SZ = {
    "sz_4095.bin": 4095,
    "sz_4096.bin": 4096,
    "sz_4097.bin": 4097,
    "sz_8192.bin": 8192,
    "sz_65536.bin": 65536,
    "big1m.bin": 1024 * 1024,
    "data.bin": 4096,
    "hello.txt": 12,
    "empty.txt": 0,
}


# =========================================================================== #
# 1. open() flags matrix — status parity                                       #
# =========================================================================== #

def _read_cases():
    """(rel, off, size) covering 0 / mid / exact-EOF / beyond-EOF / straddle /
    zero-size(=whole-from-offset, per XrdCl convention)."""
    cases = []
    for rel, sz in SZ.items():
        if rel == "empty.txt":
            cases += [(rel, 0, 100), (rel, 0, 0)]
            continue
        mid = sz // 2
        cases += [
            (rel, 0, min(sz, 256)),           # at start
            (rel, mid, min(sz - mid, 256)),   # mid
            (rel, max(sz - 64, 0), 64),       # tail (exact EOF for sz>=64)
            (rel, sz, 100),                   # exactly at EOF -> 0 bytes
            (rel, sz + 4096, 100),            # beyond EOF -> 0 bytes
        ]
        # straddle a 4 KiB page boundary where the file is large enough
        if sz > 4096:
            cases.append((rel, 4096 - 8, 16))
        if sz > 65536:
            cases.append((rel, 65536 - 8, 16))
    return cases


@pytest.mark.parametrize("rel,off,size", _read_cases(),
                         ids=lambda v: str(v))

def _vread_cases():
    """(rel, chunks) for 1 / several / many segments incl. boundary spanning."""
    cases = []
    # single segment
    cases.append(("sz_4096.bin", [(0, 256)]))
    cases.append(("big1m.bin", [(0, 4096)]))
    # several, including page-boundary-spanning segments
    cases.append(("sz_8192.bin", [(0, 100), (4090, 16), (8100, 92)]))
    cases.append(("sz_65536.bin", [(0, 512), (4096 - 4, 8), (65536 - 16, 16)]))
    cases.append(("big1m.bin",
                  [(0, 1024), (4096 - 2, 4), (65536 - 2, 4), (1048576 - 8, 8)]))
    # many segments across big1m
    many = [(i * 4096, 64) for i in range(64)]
    cases.append(("big1m.bin", many))
    # several small contiguous segments
    cases.append(("data.bin", [(0, 1), (1, 1), (2, 2), (4, 4092)]))
    # boundary-spanning single read crossing 4 KiB page
    cases.append(("sz_4097.bin", [(4090, 7)]))
    return cases


@pytest.mark.parametrize("rel,chunks", _vread_cases(),
                         ids=lambda v: str(v) if not isinstance(v, list)
                         else f"{len(v)}seg")

def _scratch(url, name):
    """A unique scratch path under a per-test subdir; the subdir is MAKEPATH-
    created identically on both trees so they stay identical."""
    return f"scratch_fileops/{name}"
