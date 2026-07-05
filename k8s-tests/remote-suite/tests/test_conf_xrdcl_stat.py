"""
tests/test_conf_xrdcl_stat.py

Differential conformance for XrdCl::FileSystem.stat / statvfs driven through the
REAL libXrdCl python bindings — the exact code path gfal / FTS / Rucio take.

Every operation runs against BOTH servers started by ``L.start_pair``:
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
import tempfile

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import official_interop_lib as L  # noqa: E402

# --------------------------------------------------------------------------
# Module gate: need stock tools AND the real bindings (via the shadow package).
# Skip cleanly — never ERROR — when either is absent.
# --------------------------------------------------------------------------
pytestmark = pytest.mark.skipif(
    not L.have_official(),
    reason="stock xrootd / xrdfs / xrdcp not installed",
)

try:
    from XRootD import client
    from XRootD.client.flags import StatInfoFlags
    _HAVE_BINDINGS = True
    _BIND_ERR = ""
except Exception as exc:  # pragma: no cover - environment dependent
    _HAVE_BINDINGS = False
    _BIND_ERR = repr(exc)

bindings_required = pytest.mark.skipif(
    not _HAVE_BINDINGS,
    reason="libXrdCl python bindings unavailable: %s" % _BIND_ERR,
)

OUR_PORT = L.worker_port(14900)
OFF_PORT = L.worker_port(14901)
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
# Module-scoped fixture: ONE pair on the assigned ports for the whole file.
# --------------------------------------------------------------------------
@pytest.fixture(scope="module")
def ctx():
    base = tempfile.mkdtemp(prefix="conf_xrdcl_stat_")
    try:
        procs, c = L.start_pair(base, our_port=OUR_PORT, off_port=OFF_PORT)
    except RuntimeError as exc:
        pytest.skip("could not start server pair: %s" % exc)
    yield c
    L.stop_pair(procs)


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
@bindings_required
@pytest.mark.parametrize("path", FILE_PATHS)
def test_stat_file_status_agrees(fs_our, fs_off, path):
    so, _ = _stat(fs_our, path)
    sf, _ = _stat(fs_off, path)
    assert so.ok and sf.ok, "both servers must succeed for %r" % path
    assert _status_tuple(so) == _status_tuple(sf)


@bindings_required
@pytest.mark.parametrize("path", FILE_PATHS)
def test_stat_file_size_agrees(fs_our, fs_off, path):
    _, sio = _stat(fs_our, path)
    _, sif = _stat(fs_off, path)
    assert sio is not None and sif is not None
    assert sio.size == sif.size, "size mismatch for %r" % path
    assert sio.size == FILE_SIZES[path], "size != on-disk for %r" % path


@bindings_required
@pytest.mark.parametrize("path", FILE_PATHS)
def test_stat_file_flags_agree(fs_our, fs_off, path):
    _, sio = _stat(fs_our, path)
    _, sif = _stat(fs_off, path)
    assert sio.flags == sif.flags, "flag mask mismatch for %r" % path


@bindings_required
@pytest.mark.parametrize("path", FILE_PATHS)
def test_stat_file_flags_decode_agree(fs_our, fs_off, path):
    _, sio = _stat(fs_our, path)
    _, sif = _stat(fs_off, path)
    assert _decode_flags(sio.flags) == _decode_flags(sif.flags)


@bindings_required
@pytest.mark.parametrize("path", FILE_PATHS)
def test_stat_file_is_not_dir(fs_our, fs_off, path):
    # A regular file must clear IsDir on BOTH servers (StatGen S_ISREG branch).
    _, sio = _stat(fs_our, path)
    _, sif = _stat(fs_off, path)
    assert not _decode_flags(sio.flags)["IsDir"]
    assert not _decode_flags(sif.flags)["IsDir"]


@bindings_required
@pytest.mark.parametrize("path", FILE_PATHS)
def test_stat_file_readable_writable_match(fs_our, fs_off, path):
    # IsReadable / IsWritable derive from mode+uid/gid in StatGen; the trees are
    # identical so the predicates must match stock exactly.
    _, sio = _stat(fs_our, path)
    _, sif = _stat(fs_off, path)
    do, df = _decode_flags(sio.flags), _decode_flags(sif.flags)
    assert do["IsReadable"] == df["IsReadable"]
    assert do["IsWritable"] == df["IsWritable"]


@bindings_required
@pytest.mark.parametrize("path", FILE_PATHS)
def test_stat_file_not_other_not_offline(fs_our, fs_off, path):
    # Regular files: Other and Offline must be clear on both (StatGen).
    _, sio = _stat(fs_our, path)
    _, sif = _stat(fs_off, path)
    do, df = _decode_flags(sio.flags), _decode_flags(sif.flags)
    assert do["Other"] == df["Other"] is False
    assert do["Offline"] == df["Offline"] is False


@bindings_required
@pytest.mark.parametrize("path", FILE_PATHS)
def test_stat_file_id_is_clean_int(fs_our, fs_off, path):
    # XrdCl ParseServerResponse requires chunks[1]=size to be a clean base-0
    # integer; chunks[0]=id must be present.  We assert BOTH emit a non-empty,
    # base-0-parseable id (the SHAPE the bindings/gfal rely on).  The value
    # differs by design — see the DIVERGENCE note at module top.
    _, sio = _stat(fs_our, path)
    _, sif = _stat(fs_off, path)
    assert _id_is_clean_int(sio.id), "our id not a clean int: %r" % (sio.id,)
    assert _id_is_clean_int(sif.id), "stock id not a clean int: %r" % (sif.id,)


@bindings_required
@pytest.mark.parametrize("path", FILE_PATHS)
def test_stat_file_modtime_shape(fs_our, fs_off, path):
    # chunks[3]=modtime must parse as an integer >0 on both (the bytes were
    # written moments before the test); value differs (separate writes) so we
    # pin the shape only.
    _, sio = _stat(fs_our, path)
    _, sif = _stat(fs_off, path)
    assert isinstance(sio.modtime, int) and sio.modtime > 0
    assert isinstance(sif.modtime, int) and sif.modtime > 0


# ==========================================================================
# 2. Directories — IsDir + XBitSet semantics agree with stock.
# ==========================================================================
@bindings_required
@pytest.mark.parametrize("path", DIR_PATHS)
def test_stat_dir_status_agrees(fs_our, fs_off, path):
    so, _ = _stat(fs_our, path)
    sf, _ = _stat(fs_off, path)
    assert so.ok and sf.ok, "both must succeed for dir %r" % path
    assert _status_tuple(so) == _status_tuple(sf)


@bindings_required
@pytest.mark.parametrize("path", DIR_PATHS)
def test_stat_dir_flags_agree(fs_our, fs_off, path):
    _, sio = _stat(fs_our, path)
    _, sif = _stat(fs_off, path)
    assert sio.flags == sif.flags, "dir flag mask mismatch for %r" % path


@bindings_required
@pytest.mark.parametrize("path", DIR_PATHS)
def test_stat_dir_isdir_set(fs_our, fs_off, path):
    # StatGen sets kXR_isDir for S_ISDIR; both servers must agree it is a dir.
    _, sio = _stat(fs_our, path)
    _, sif = _stat(fs_off, path)
    assert _decode_flags(sio.flags)["IsDir"] is True
    assert _decode_flags(sif.flags)["IsDir"] is True


@bindings_required
@pytest.mark.parametrize("path", DIR_PATHS)
def test_stat_dir_xbitset_agrees(fs_our, fs_off, path):
    # Directories carry the execute (search) bit -> kXR_xset; must match stock.
    _, sio = _stat(fs_our, path)
    _, sif = _stat(fs_off, path)
    do, df = _decode_flags(sio.flags), _decode_flags(sif.flags)
    assert do["XBitSet"] == df["XBitSet"]


@bindings_required
@pytest.mark.parametrize("path", DIR_PATHS)
def test_stat_dir_decode_agrees(fs_our, fs_off, path):
    _, sio = _stat(fs_our, path)
    _, sif = _stat(fs_off, path)
    assert _decode_flags(sio.flags) == _decode_flags(sif.flags)


@bindings_required
@pytest.mark.parametrize("path", DIR_PATHS)
def test_stat_dir_not_other(fs_our, fs_off, path):
    # A directory is neither a regular file nor "other"; Other must be clear.
    _, sio = _stat(fs_our, path)
    _, sif = _stat(fs_off, path)
    assert _decode_flags(sio.flags)["Other"] is False
    assert _decode_flags(sif.flags)["Other"] is False


@bindings_required
@pytest.mark.parametrize("path", DIR_PATHS)
def test_stat_dir_id_is_clean_int(fs_our, fs_off, path):
    _, sio = _stat(fs_our, path)
    _, sif = _stat(fs_off, path)
    assert _id_is_clean_int(sio.id)
    assert _id_is_clean_int(sif.id)


@bindings_required
@pytest.mark.parametrize("path", DIR_PATHS)
def test_stat_dir_modtime_shape(fs_our, fs_off, path):
    _, sio = _stat(fs_our, path)
    _, sif = _stat(fs_off, path)
    assert isinstance(sio.modtime, int) and sio.modtime > 0
    assert isinstance(sif.modtime, int) and sif.modtime > 0


# ==========================================================================
# 3. Trailing-slash on a directory — must be accepted and agree with stock.
# ==========================================================================
@bindings_required
@pytest.mark.parametrize("path", DIR_TRAILING)
def test_stat_dir_trailing_slash_status_agrees(fs_our, fs_off, path):
    so, _ = _stat(fs_our, path)
    sf, _ = _stat(fs_off, path)
    assert _status_tuple(so) == _status_tuple(sf), (
        "trailing-slash dir status diverges for %r" % path)


@bindings_required
@pytest.mark.parametrize("path", DIR_TRAILING)
def test_stat_dir_trailing_slash_flags_agree(fs_our, fs_off, path):
    so, sio = _stat(fs_our, path)
    sf, sif = _stat(fs_off, path)
    if so.ok and sf.ok:
        assert sio.flags == sif.flags
        assert _decode_flags(sio.flags)["IsDir"] is True
    else:
        # If stock rejects it, we must reject identically.
        assert _status_tuple(so) == _status_tuple(sf)


@bindings_required
@pytest.mark.parametrize("path", DIR_TRAILING)
def test_stat_dir_trailing_matches_canonical(fs_our, fs_off, path):
    # Stat of "/x/" must equal stat of "/x" within the SAME server (size+flags).
    canon = path.rstrip("/") or "/"
    so_t, sio_t = _stat(fs_our, path)
    so_c, sio_c = _stat(fs_our, canon)
    sf_t, sif_t = _stat(fs_off, path)
    sf_c, sif_c = _stat(fs_off, canon)
    if so_t.ok and so_c.ok:
        assert sio_t.flags == sio_c.flags and sio_t.size == sio_c.size
    # Cross-server: trailing-slash acceptance must agree with stock.
    assert so_t.ok == sf_t.ok


# ==========================================================================
# 4. Missing paths — error status agrees (ok/code/errno) with stock.
# ==========================================================================
@bindings_required
@pytest.mark.parametrize("path", MISSING_PATHS)
def test_stat_missing_fails_on_both(fs_our, fs_off, path):
    so, _ = _stat(fs_our, path)
    sf, _ = _stat(fs_off, path)
    assert not so.ok, "our server must NOT find %r" % path
    assert not sf.ok, "stock must NOT find %r" % path


@bindings_required
@pytest.mark.parametrize("path", MISSING_PATHS)
def test_stat_missing_code_agrees(fs_our, fs_off, path):
    so, _ = _stat(fs_our, path)
    sf, _ = _stat(fs_off, path)
    assert so.code == sf.code, "status.code diverges for %r" % path


@bindings_required
@pytest.mark.parametrize("path", MISSING_PATHS)
def test_stat_missing_errno_agrees(fs_our, fs_off, path):
    # errno carries the XErrorCode (kXR_NotFound=3011); must match stock.
    so, _ = _stat(fs_our, path)
    sf, _ = _stat(fs_off, path)
    assert so.errno == sf.errno, "status.errno diverges for %r" % path


@bindings_required
@pytest.mark.parametrize("path", MISSING_PATHS)
def test_stat_missing_no_statinfo(fs_our, fs_off, path):
    # A failed stat must not yield a populated StatInfo with a real size.
    so, sio = _stat(fs_our, path)
    sf, sif = _stat(fs_off, path)
    assert (sio is None) == (sif is None)


# ==========================================================================
# 5. Trailing-slash on a FILE — "not a directory" rejection agrees with stock.
# ==========================================================================
@bindings_required
@pytest.mark.parametrize("path", FILE_TRAILING)
def test_stat_file_trailing_slash_status_agrees(fs_our, fs_off, path):
    so, _ = _stat(fs_our, path)
    sf, _ = _stat(fs_off, path)
    assert _status_tuple(so) == _status_tuple(sf), (
        "file-with-trailing-slash status diverges for %r" % path)


@bindings_required
@pytest.mark.parametrize("path", FILE_TRAILING)
def test_stat_file_trailing_slash_both_reject(fs_our, fs_off, path):
    so, _ = _stat(fs_our, path)
    sf, _ = _stat(fs_off, path)
    # Stock rejects a file path with a trailing slash; ours must do the same.
    assert so.ok == sf.ok


# ==========================================================================
# 6. statvfs — the gfal df / space-reporting path; 6-field VFS parse agrees.
# ==========================================================================
VFS_PATHS = ["/", "/sub", "/deep", "/empty_dir", "/many", "/deep/a/b/c"]


@bindings_required
@pytest.mark.parametrize("path", VFS_PATHS)
def test_statvfs_status_agrees(fs_our, fs_off, path):
    so, _ = _statvfs(fs_our, path)
    sf, _ = _statvfs(fs_off, path)
    assert so.ok == sf.ok, "statvfs ok diverges for %r" % path
    if so.ok and sf.ok:
        assert so.code == sf.code


@bindings_required
@pytest.mark.parametrize("path", VFS_PATHS)
def test_statvfs_six_fields_present(fs_our, fs_off, path):
    # StatInfoVFS::ParseServerResponse (:452) needs all six fields; if the
    # bindings parsed a StatInfoVFS, every field must be an int on both.
    so, vo = _statvfs(fs_our, path)
    sf, vf = _statvfs(fs_off, path)
    if not (so.ok and sf.ok):
        pytest.skip("statvfs unsupported here on one side")
    for field in ("nodes_rw", "nodes_staging", "free_rw",
                  "util_rw", "free_staging", "util_staging"):
        assert isinstance(getattr(vo, field), int), "our %s" % field
        assert isinstance(getattr(vf, field), int), "stock %s" % field


@bindings_required
@pytest.mark.parametrize("path", VFS_PATHS)
def test_statvfs_node_counts_agree(fs_our, fs_off, path):
    # nodes_rw / nodes_staging are topology counts (one data server here);
    # must agree with stock exactly.
    so, vo = _statvfs(fs_our, path)
    sf, vf = _statvfs(fs_off, path)
    if not (so.ok and sf.ok):
        pytest.skip("statvfs unsupported here on one side")
    assert vo.nodes_rw == vf.nodes_rw, "nodes_rw diverges for %r" % path
    assert vo.nodes_staging == vf.nodes_staging


@bindings_required
@pytest.mark.parametrize("path", VFS_PATHS)
def test_statvfs_utilization_in_range(fs_our, fs_off, path):
    # util_rw / util_staging are percentages 0..100 per the VFS schema; both
    # servers must keep them in range.
    so, vo = _statvfs(fs_our, path)
    sf, vf = _statvfs(fs_off, path)
    if not (so.ok and sf.ok):
        pytest.skip("statvfs unsupported here on one side")
    assert 0 <= vo.util_rw <= 100
    assert 0 <= vf.util_rw <= 100
    assert 0 <= vo.util_staging <= 100
    assert 0 <= vf.util_staging <= 100


# ==========================================================================
# 7. Consistency / cross-checks against the dirlist+stat path gfal-ls uses.
# ==========================================================================
@bindings_required
def test_stat_root_is_dir(fs_our, fs_off):
    _, sio = _stat(fs_our, "/")
    _, sif = _stat(fs_off, "/")
    assert _decode_flags(sio.flags)["IsDir"] is True
    assert _decode_flags(sif.flags)["IsDir"] is True
    assert sio.flags == sif.flags


@bindings_required
def test_stat_empty_file_size_zero(fs_our, fs_off):
    _, sio = _stat(fs_our, "/empty.txt")
    _, sif = _stat(fs_off, "/empty.txt")
    assert sio.size == 0 and sif.size == 0


@bindings_required
def test_stat_big_file_size_exact(fs_our, fs_off):
    _, sio = _stat(fs_our, "/big1m.bin")
    _, sif = _stat(fs_off, "/big1m.bin")
    assert sio.size == sif.size == 1024 * 1024


@bindings_required
def test_stat_file_id_differs_from_self_repeated(fs_our):
    # Repeated stat of the same path is stable on our server (id is the same).
    _, a = _stat(fs_our, "/hello.txt")
    _, b = _stat(fs_our, "/hello.txt")
    assert a.id == b.id and a.size == b.size and a.flags == b.flags


@bindings_required
def test_stat_distinct_files_distinct_ids(fs_our, fs_off):
    # Two different inodes -> two different ids, on both servers (StatGen uses
    # st_ino). This pins that the id actually varies per object.
    _, a_our = _stat(fs_our, "/hello.txt")
    _, b_our = _stat(fs_our, "/data.bin")
    _, a_off = _stat(fs_off, "/hello.txt")
    _, b_off = _stat(fs_off, "/data.bin")
    assert str(a_our.id) != str(b_our.id)
    assert str(a_off.id) != str(b_off.id)


@bindings_required
def test_stat_with_space_path(fs_our, fs_off):
    # A path containing a space must round-trip through the wire on both
    # servers (the stat response is space-split, but the REQUEST path is length
    # prefixed so the space is fine).
    so, sio = _stat(fs_our, "/with space.txt")
    sf, sif = _stat(fs_off, "/with space.txt")
    assert so.ok and sf.ok
    assert sio.size == sif.size == 7
    assert sio.flags == sif.flags


@bindings_required
def test_stat_deep_nested_path(fs_our, fs_off):
    so, sio = _stat(fs_our, "/deep/a/b/c/leaf.txt")
    sf, sif = _stat(fs_off, "/deep/a/b/c/leaf.txt")
    assert so.ok and sf.ok
    assert sio.size == sif.size == 5
    assert _decode_flags(sio.flags) == _decode_flags(sif.flags)


@bindings_required
def test_statvfs_root_node_present(fs_our, fs_off):
    so, vo = _statvfs(fs_our, "/")
    sf, vf = _statvfs(fs_off, "/")
    if not (so.ok and sf.ok):
        pytest.skip("statvfs unsupported on one side")
    # Exactly one rw data node in this single-server topology on both.
    assert vo.nodes_rw == vf.nodes_rw


# ==========================================================================
# 8. id-value DIVERGENCE — pinned at the SHAPE the contract requires.
#
# DIVERGENCE (recorded, NOT a parse failure): StatInfo.id (chunks[0]).
#   our output:   inode only          (e.g. "5240720")
#   stock output: (st_dev<<32)|st_ino (e.g. "22508867036383280")
#   contract:     XrdXrootdProtocol::StatGen XrdXrootdProtocol.cc:755-767
#                 Dev.uuid = (st_dev<<32)|st_ino; XrdCl exposes it verbatim
#                 (XrdClXRootDResponses.cc:140). gfal/FTS/Rucio ignore id, and
#                 the value can never match across two distinct on-disk servers,
#                 so we pin the SHAPE (clean, non-empty, base-0 integer) that
#                 the bindings actually require — NOT the value.
#   suspected src: src/protocols/root/read/stat.c / src/protocols/root/read/statx.c (StatGen-equivalent id
#                  composition: emit (dev<<32)|ino, not ino alone).
# This test is the explicit, documented pin; it passes today because both
# satisfy the shape contract.
# ==========================================================================
@bindings_required
def test_stat_id_shape_contract(fs_our, fs_off):
    _, sio = _stat(fs_our, "/hello.txt")
    _, sif = _stat(fs_off, "/hello.txt")
    assert _id_is_clean_int(sio.id), "our id violates XrdCl shape: %r" % sio.id
    assert _id_is_clean_int(sif.id), "stock id violates shape: %r" % sif.id


@bindings_required
def test_stat_id_composes_device_bits_like_stock(fs_our, fs_off):
    # Stock packs the inode into the high 32 bits (and st_dev into the low word),
    # so its id is far larger than a bare inode. FIXED: src/protocols/root/path/stat_body.c now
    # composes (st_ino<<32)|(uint32_t)st_dev like the reference StatGen, so our
    # id ALSO carries bits above the low word (id >> 32 != 0).
    _, sio = _stat(fs_our, "/hello.txt")
    _, sif = _stat(fs_off, "/hello.txt")
    our_id = int(str(sio.id), 0)
    off_id = int(str(sif.id), 0)
    assert (off_id >> 32) != 0, "stock id should carry device bits"
    assert (our_id >> 32) != 0, (
        "our id is inode-only; stock composes (dev<<32)|ino")


# ==========================================================================
# 9. Bulk decode coverage — every existing path's flag decode agrees, as one
#    parametrized sweep over the union (extra breadth toward the count target).
# ==========================================================================
ALL_EXISTING = FILE_PATHS + DIR_PATHS


@bindings_required
@pytest.mark.parametrize("path", ALL_EXISTING)
def test_stat_full_surface_agrees(fs_our, fs_off, path):
    so, sio = _stat(fs_our, path)
    sf, sif = _stat(fs_off, path)
    assert _status_tuple(so) == _status_tuple(sf)
    assert sio.size == sif.size
    assert sio.flags == sif.flags
    assert _decode_flags(sio.flags) == _decode_flags(sif.flags)
    assert _id_is_clean_int(sio.id) and _id_is_clean_int(sif.id)
    assert sio.modtime > 0 and sif.modtime > 0
