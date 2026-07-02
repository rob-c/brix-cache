"""Differential conformance: XrdCl::FileSystem metadata / namespace ops.

Theme
-----
Drive the **real** ``libXrdCl`` python bindings (``from XRootD import client``) —
the exact code path gfal / FTS / Rucio use — against BOTH our nginx-xrootd server
and the stock ``xrootd`` v5.9.5 server, and assert the parsed result objects agree.
Stock is the source of truth: any divergence is OUR bug (pinned with xfail +
``# DIVERGENCE:``), unless positive evidence says otherwise.

Coverage
--------
* dirlist: ``/``, ``/sub``, ``/many``, ``/empty_dir``, ``/deep`` (recursive),
  missing dir — compare entry name-sets, and with ``Stat`` flag the per-entry
  flags + sizes, our-vs-stock.
* mkdir: new / existing (kXR_ItExists parity) / nested without MakePath
  (kXR_NotFound parity) / nested with MakePath.
* chmod: ``Access::Mode`` bit combinations, then stat-flag readback parity.
* rm: file / missing / directory (must NOT recurse — data-loss guard) ;
  rmdir: empty / non-empty (ENOTEMPTY parity).
* mv/rename: file / onto existing / into missing parent / missing source —
  compare status.code/errno AND resulting on-disk tree.
* truncate, and the simple query codes (Config / Space / Stats) + statvfs.

Every mutating op runs against a per-test scratch subdir created identically
under ``ctx['our_data']`` and ``ctx['off_data']`` so the two on-disk trees stay
byte-identical; after each mutating op we assert ``os.walk`` of the two roots
match exactly.

Contract citations
------------------
* DirListFlags / MkDirFlags / Access::Mode:
  ``/tmp/xrootd-src/src/XrdCl/XrdClFileSystem.hh:127-174``.
* DirectoryList / StatInfo wire parse: ``XrdClXRootDResponses.cc``.
* kXR error numbers (3005 FSError, 3011 NotFound, 3018 ItExists) and the
  errno->kXR mapping (ENOTEMPTY/EEXIST -> kXR_ItExists,
  ``XProtocol.hh:1407-1474``).
* Stock server handlers: ``/tmp/xrootd-src/src/XrdXrootd/``.
"""

import os

import pytest

import official_interop_lib as L

pytestmark = pytest.mark.skipif(
    not L.have_official(), reason="stock xrootd tools not available"
)

# kXR error numbers (XProtocol.hh:1032+)
kXR_FSError = 3005
kXR_NotFound = 3011
kXR_ItExists = 3018

# Real libXrdCl bindings are an optional dep — skip the whole module cleanly.
try:
    from XRootD import client  # noqa: E402
    from XRootD.client.flags import (  # noqa: E402
        AccessMode,
        DirListFlags,
        MkDirFlags,
        QueryCode,
    )

    _HAVE_BINDINGS = True
except Exception:  # noqa: BLE001
    _HAVE_BINDINGS = False

pytestmark = [
    pytestmark,
    pytest.mark.skipif(not _HAVE_BINDINGS, reason="python3-xrootd bindings missing"),
]

OUR_PORT = L.worker_port(14908)
OFF_PORT = L.worker_port(14909)
# --------------------------------------------------------------------------- #
# Module fixture: ONE server pair on this file's assigned port range.
# --------------------------------------------------------------------------- #
@pytest.fixture(scope="module")
def pair(tmp_path_factory):
    base = str(tmp_path_factory.mktemp("xrdcl_fs"))
    try:
        procs, ctx = L.start_pair(base, our_port=OUR_PORT, off_port=OFF_PORT)
    except RuntimeError as exc:
        pytest.skip(f"server pair unavailable: {exc}")
    try:
        yield ctx
    finally:
        L.stop_pair(procs)


def _fs(url):
    return client.FileSystem(url)


def _both(pair):
    return (
        ("our", pair["our"], pair["our_data"]),
        ("off", pair["off"], pair["off_data"]),
    )


# --------------------------------------------------------------------------- #
# Scratch-tree helpers: create the SAME structure under both data roots so the
# two trees start byte-identical for mutating ops, and so we can diff them after.
# --------------------------------------------------------------------------- #
def _walk(root):
    """Sorted list of (relpath, is_dir, size_if_file) for the whole tree."""
    out = []
    for dirpath, dirnames, filenames in os.walk(root):
        for d in dirnames:
            rel = os.path.relpath(os.path.join(dirpath, d), root)
            out.append((rel, True, -1))
        for fn in filenames:
            full = os.path.join(dirpath, fn)
            rel = os.path.relpath(full, root)
            out.append((rel, False, os.path.getsize(full)))
    return sorted(out)


def _mk_scratch(pair, name, builder):
    """Build identical scratch dir ``/<name>`` under both data roots.

    ``builder(disk_dir)`` populates the on-disk directory; called once per root
    with the absolute disk path. Returns the logical path ``/<name>``.
    """
    logical = "/" + name
    for _, _, data in _both(pair):
        d = os.path.join(data, name)
        # fresh each time so re-runs are deterministic
        if os.path.isdir(d):
            _rmtree(d)
        os.makedirs(d, exist_ok=True)
        builder(d)
    return logical


def _rmtree(d):
    for dirpath, dirnames, filenames in os.walk(d, topdown=False):
        for fn in filenames:
            os.remove(os.path.join(dirpath, fn))
        for dn in dirnames:
            os.rmdir(os.path.join(dirpath, dn))
    if os.path.isdir(d):
        os.rmdir(d)


def _assert_trees_match(pair, subdir):
    """After a mutating op, the two scratch subtrees must be byte-structurally
    identical (same dir/file set, same file sizes). Stock is truth."""
    our = _walk(os.path.join(pair["our_data"], subdir))
    off = _walk(os.path.join(pair["off_data"], subdir))
    assert our == off, f"tree diverged under /{subdir}:\n our={our}\n off={off}"


# --------------------------------------------------------------------------- #
# 1. dirlist — name-set parity (plain), per-test path matrix
# --------------------------------------------------------------------------- #
DIRLIST_PATHS = ["/", "/sub", "/many", "/empty_dir", "/deep", "/deep/a/b/c"]


@pytest.mark.parametrize("path", DIRLIST_PATHS)
def test_dirlist_nameset_plain(pair, path):
    """dirlist names must be the same set on both servers (order-insensitive)."""
    names = {}
    for tag, url, _ in _both(pair):
        st, lst = _fs(url).dirlist(path, DirListFlags.NONE)
        assert st.ok, f"{tag} dirlist {path} failed: {st.message}"
        names[tag] = sorted(e.name for e in lst) if lst else []
    assert names["our"] == names["off"]


@pytest.mark.parametrize("path", DIRLIST_PATHS)
def test_dirlist_entry_count(pair, path):
    """Number of returned entries must match."""
    counts = {}
    for tag, url, _ in _both(pair):
        st, lst = _fs(url).dirlist(path, DirListFlags.NONE)
        assert st.ok, f"{tag} {st.message}"
        counts[tag] = lst.size if lst else 0
    assert counts["our"] == counts["off"]


@pytest.mark.parametrize("path", DIRLIST_PATHS)
def test_dirlist_parent_path(pair, path):
    """DirectoryList.parent (the listed path) must agree."""
    parents = {}
    for tag, url, _ in _both(pair):
        st, lst = _fs(url).dirlist(path, DirListFlags.NONE)
        assert st.ok, f"{tag} {st.message}"
        parents[tag] = lst.parent if lst else None
    assert parents["our"] == parents["off"]


# --------------------------------------------------------------------------- #
# 2. dirlist with Stat — per-entry flags + sizes parity
# --------------------------------------------------------------------------- #
STAT_DIRS = ["/", "/sub", "/many", "/deep/a/b/c"]


@pytest.mark.parametrize("path", STAT_DIRS)
def test_dirlist_stat_sizes(pair, path):
    """With DirListFlags.Stat, per-entry sizes (keyed by name) must match."""
    sizes = {}
    for tag, url, _ in _both(pair):
        st, lst = _fs(url).dirlist(path, DirListFlags.STAT)
        assert st.ok, f"{tag} stat-dirlist {path}: {st.message}"
        sizes[tag] = {
            e.name: (e.statinfo.size if e.statinfo else None) for e in lst
        }
    assert sizes["our"] == sizes["off"]


@pytest.mark.parametrize("path", STAT_DIRS)
def test_dirlist_stat_flags(pair, path):
    """With DirListFlags.Stat, per-entry flag bytes (keyed by name) must match.

    StatInfo flags enum: XrdClXRootDResponses.hh:420 (IsDir/IsReadable/...).
    """
    flags = {}
    for tag, url, _ in _both(pair):
        st, lst = _fs(url).dirlist(path, DirListFlags.STAT)
        assert st.ok, f"{tag} {st.message}"
        flags[tag] = {
            e.name: (e.statinfo.flags if e.statinfo else None) for e in lst
        }
    assert flags["our"] == flags["off"]


@pytest.mark.parametrize("path", STAT_DIRS)
def test_dirlist_stat_isdir_bit(pair, path):
    """IsDir bit (kXR_isDir) per entry must agree — gfal-ls relies on this to
    distinguish files from dirs."""
    from XRootD.client.flags import StatInfoFlags

    isdir = {}
    for tag, url, _ in _both(pair):
        st, lst = _fs(url).dirlist(path, DirListFlags.STAT)
        assert st.ok, f"{tag} {st.message}"
        isdir[tag] = {
            e.name: bool(e.statinfo.flags & StatInfoFlags.IS_DIR)
            for e in lst
            if e.statinfo
        }
    assert isdir["our"] == isdir["off"]


# --------------------------------------------------------------------------- #
# 3. dirlist recursive — name-set parity across whole subtree
# --------------------------------------------------------------------------- #
RECURSIVE_DIRS = ["/deep", "/many", "/sub", "/empty_dir"]


@pytest.mark.parametrize("path", RECURSIVE_DIRS)
def test_dirlist_recursive_nameset(pair, path):
    rec = {}
    for tag, url, _ in _both(pair):
        st, lst = _fs(url).dirlist(path, DirListFlags.RECURSIVE)
        assert st.ok, f"{tag} recursive {path}: {st.message}"
        rec[tag] = sorted(e.name for e in lst) if lst else []
    assert rec["our"] == rec["off"]


@pytest.mark.parametrize("path", RECURSIVE_DIRS)
def test_dirlist_recursive_count(pair, path):
    rec = {}
    for tag, url, _ in _both(pair):
        st, lst = _fs(url).dirlist(path, DirListFlags.RECURSIVE)
        assert st.ok, f"{tag} {st.message}"
        rec[tag] = lst.size if lst else 0
    assert rec["our"] == rec["off"]


@pytest.mark.parametrize("path", ["/deep", "/many"])
def test_dirlist_recursive_stat_sizes(pair, path):
    """Recursive + Stat: name->size map across the whole subtree must match."""
    rec = {}
    for tag, url, _ in _both(pair):
        st, lst = _fs(url).dirlist(path, DirListFlags.RECURSIVE | DirListFlags.STAT)
        assert st.ok, f"{tag} {st.message}"
        rec[tag] = {
            e.name: (e.statinfo.size if e.statinfo else None) for e in lst
        }
    assert rec["our"] == rec["off"]


# --------------------------------------------------------------------------- #
# 4. dirlist of missing dir — error parity (status.code + errno)
# --------------------------------------------------------------------------- #
MISSING_DIRS = ["/no_such_dir", "/sub/no_such", "/deep/a/b/c/d", "/many/missing"]


@pytest.mark.parametrize("path", MISSING_DIRS)
def test_dirlist_missing_not_ok(pair, path):
    for tag, url, _ in _both(pair):
        st, _ = _fs(url).dirlist(path, DirListFlags.NONE)
        assert not st.ok, f"{tag} dirlist of missing {path} unexpectedly ok"


@pytest.mark.parametrize("path", MISSING_DIRS)
def test_dirlist_missing_errno_parity(pair, path):
    errs = {}
    for tag, url, _ in _both(pair):
        st, _ = _fs(url).dirlist(path, DirListFlags.NONE)
        errs[tag] = st.errno
    assert errs["our"] == errs["off"] == kXR_NotFound


@pytest.mark.parametrize("path", MISSING_DIRS)
def test_dirlist_missing_code_parity(pair, path):
    codes = {}
    for tag, url, _ in _both(pair):
        st, _ = _fs(url).dirlist(path, DirListFlags.NONE)
        codes[tag] = st.code
    assert codes["our"] == codes["off"]


# --------------------------------------------------------------------------- #
# 5. mkdir — new / existing / nested(no-makepath) / nested(makepath)
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("name", ["a", "b_dir", "with_under", "d123"])
def test_mkdir_new_ok(pair, name):
    sub = _mk_scratch(pair, f"mk_new_{name}", lambda d: None)
    res = {}
    for tag, url, _ in _both(pair):
        st, _ = _fs(url).mkdir(f"{sub}/{name}", MkDirFlags.NONE)
        res[tag] = st.ok
    assert res["our"] == res["off"] is True
    _assert_trees_match(pair, f"mk_new_{name}")


@pytest.mark.parametrize("name", ["existing1", "existing2"])
def test_mkdir_existing_ok_status_parity(pair, name):
    """mkdir of an already-existing directory.

    DIVERGENCE: stock returns ok=True (idempotent — ENOTEMPTY/EEXIST treated as
    success by XrdXrootd's mkdir handler), but OURS returns kXR_ItExists(3018).
    Contract: XProtocol.hh:1425-1427 maps EEXIST->kXR_ItExists, but stock's
    mkdir handler in /tmp/xrootd-src/src/XrdXrootd/XrdXrootdXeq.cc swallows the
    existing-dir case and replies OK. Suspected src: src/protocols/root/write/mkdir.c.
    """
    sub = _mk_scratch(
        pair, f"mk_exist_{name}", lambda d: os.makedirs(os.path.join(d, "d"))
    )
    res = {}
    for tag, url, _ in _both(pair):
        st, _ = _fs(url).mkdir(f"{sub}/d", MkDirFlags.NONE)
        res[tag] = st.ok
    # tree is unchanged either way (the dir already exists) — verify no data loss
    _assert_trees_match(pair, f"mk_exist_{name}")
    if res["our"] != res["off"]:
        pytest.xfail(
            "DIVERGENCE mkdir-existing: stock ok=True, ours kXR_ItExists(3018); "
            "suspected src/protocols/root/write/mkdir.c"
        )
    assert res["our"] == res["off"]


@pytest.mark.parametrize("depth", ["x/y", "p/q/r", "one/two/three/four"])
def test_mkdir_nested_no_makepath_fails(pair, depth):
    """Without MakePath, a missing parent must fail with kXR_NotFound on both."""
    sub = _mk_scratch(pair, "mk_nomp_" + depth.replace("/", "_"), lambda d: None)
    errs = {}
    for tag, url, _ in _both(pair):
        st, _ = _fs(url).mkdir(f"{sub}/{depth}", MkDirFlags.NONE)
        assert not st.ok, f"{tag} nested mkdir w/o makepath unexpectedly ok"
        errs[tag] = st.errno
    assert errs["our"] == errs["off"] == kXR_NotFound
    _assert_trees_match(pair, "mk_nomp_" + depth.replace("/", "_"))


@pytest.mark.parametrize("depth", ["x/y", "p/q/r", "one/two/three/four"])
def test_mkdir_nested_makepath_ok(pair, depth):
    """With MakePath, the full tree is created and both trees match."""
    sub = _mk_scratch(pair, "mk_mp_" + depth.replace("/", "_"), lambda d: None)
    res = {}
    for tag, url, _ in _both(pair):
        st, _ = _fs(url).mkdir(f"{sub}/{depth}", MkDirFlags.MAKEPATH)
        res[tag] = st.ok
    assert res["our"] == res["off"] is True
    _assert_trees_match(pair, "mk_mp_" + depth.replace("/", "_"))


# --------------------------------------------------------------------------- #
# 6. chmod — Access::Mode combos + stat-flag readback parity
# --------------------------------------------------------------------------- #
CHMOD_COMBOS = [
    ("UR", AccessMode.UR),
    ("UW", AccessMode.UW),
    ("UR_UW", AccessMode.UR | AccessMode.UW),
    ("UR_UX", AccessMode.UR | AccessMode.UX),
    ("UR_UW_UX", AccessMode.UR | AccessMode.UW | AccessMode.UX),
    ("UR_GR", AccessMode.UR | AccessMode.GR),
    ("UR_GR_OR", AccessMode.UR | AccessMode.GR | AccessMode.OR),
    ("UR_UW_GR_OR", AccessMode.UR | AccessMode.UW | AccessMode.GR | AccessMode.OR),
    (
        "ALL",
        AccessMode.UR
        | AccessMode.UW
        | AccessMode.UX
        | AccessMode.GR
        | AccessMode.GW
        | AccessMode.GX
        | AccessMode.OR
        | AccessMode.OW
        | AccessMode.OX,
    ),
    ("GR_GW", AccessMode.GR | AccessMode.GW),
    ("OR", AccessMode.OR),
    ("UX", AccessMode.UX),
]


@pytest.mark.parametrize("label,mode", CHMOD_COMBOS, ids=[c[0] for c in CHMOD_COMBOS])
def test_chmod_status_ok_parity(pair, label, mode):
    sub = _mk_scratch(
        pair,
        f"chm_st_{label}",
        lambda d: open(os.path.join(d, "f.txt"), "w").write("x"),
    )
    res = {}
    for tag, url, _ in _both(pair):
        st, _ = _fs(url).chmod(f"{sub}/f.txt", mode)
        res[tag] = st.ok
    assert res["our"] == res["off"] is True


@pytest.mark.parametrize("label,mode", CHMOD_COMBOS, ids=[c[0] for c in CHMOD_COMBOS])
def test_chmod_stat_flag_readback(pair, label, mode):
    """After chmod, stat the file on both and compare StatInfo.flags — the
    permission bits the wire surfaces (XBitSet/readable/writable) must agree."""
    sub = _mk_scratch(
        pair,
        f"chm_rb_{label}",
        lambda d: open(os.path.join(d, "f.txt"), "w").write("x"),
    )
    flags = {}
    for tag, url, _ in _both(pair):
        fs = _fs(url)
        fs.chmod(f"{sub}/f.txt", mode)
        st, si = fs.stat(f"{sub}/f.txt")
        assert st.ok, f"{tag} stat after chmod: {st.message}"
        flags[tag] = si.flags
    assert flags["our"] == flags["off"]


@pytest.mark.parametrize("label,mode", CHMOD_COMBOS[:6], ids=[c[0] for c in CHMOD_COMBOS[:6]])
def test_chmod_dir_status_parity(pair, label, mode):
    """chmod on a directory (not just files)."""
    sub = _mk_scratch(
        pair, f"chm_dir_{label}", lambda d: os.makedirs(os.path.join(d, "sd"))
    )
    res = {}
    for tag, url, _ in _both(pair):
        st, _ = _fs(url).chmod(f"{sub}/sd", mode)
        res[tag] = st.ok
    assert res["our"] == res["off"]


def test_chmod_missing_file_errno_parity(pair):
    sub = _mk_scratch(pair, "chm_missing", lambda d: None)
    errs = {}
    for tag, url, _ in _both(pair):
        st, _ = _fs(url).chmod(f"{sub}/nope.txt", AccessMode.UR | AccessMode.UW)
        assert not st.ok
        errs[tag] = st.errno
    assert errs["our"] == errs["off"] == kXR_NotFound


# --------------------------------------------------------------------------- #
# 7. rm — file / missing / directory (data-loss guard)
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("fname", ["f.txt", "data.bin", "with_space"])
def test_rm_file_ok(pair, fname):
    sub = _mk_scratch(
        pair,
        f"rm_file_{fname.replace('.', '_').replace(' ', '_')}",
        lambda d: open(os.path.join(d, fname), "w").write("payload"),
    )
    res = {}
    for tag, url, _ in _both(pair):
        st, _ = _fs(url).rm(f"{sub}/{fname}")
        res[tag] = st.ok
    assert res["our"] == res["off"] is True
    _assert_trees_match(
        pair, f"rm_file_{fname.replace('.', '_').replace(' ', '_')}"
    )


@pytest.mark.parametrize("fname", ["nope.txt", "ghost.bin", "absent"])
def test_rm_missing_errno_parity(pair, fname):
    sub = _mk_scratch(pair, f"rm_miss_{fname.replace('.', '_')}", lambda d: None)
    errs = {}
    for tag, url, _ in _both(pair):
        st, _ = _fs(url).rm(f"{sub}/{fname}")
        assert not st.ok
        errs[tag] = st.errno
    assert errs["our"] == errs["off"] == kXR_NotFound


def _dir_with_child(d):
    inner = os.path.join(d, "victim")
    os.makedirs(inner)
    open(os.path.join(inner, "child.txt"), "w").write("must survive")


@pytest.mark.parametrize("trial", [0, 1, 2])
def test_rm_directory_does_not_recurse(pair, trial):
    """rm of a NON-EMPTY directory must FAIL and leave the child intact on BOTH
    servers — the data-loss guard. (rm == unlink; a dir is not a file.)"""
    sub = _mk_scratch(pair, f"rm_dir_{trial}", _dir_with_child)
    for tag, url, data in _both(pair):
        st, _ = _fs(url).rm(f"{sub}/victim")
        assert not st.ok, f"{tag} rm of non-empty dir unexpectedly succeeded"
        child = os.path.join(data, f"rm_dir_{trial}", "victim", "child.txt")
        assert os.path.exists(child), f"{tag} DATA LOSS: child removed by rm-of-dir"
    _assert_trees_match(pair, f"rm_dir_{trial}")


@pytest.mark.parametrize("trial", [0, 1])
def test_rm_directory_errno_parity(pair, trial):
    """rm of a non-empty dir returns an error on both.

    DIVERGENCE: errno differs. Stock maps ENOTEMPTY->kXR_ItExists(3018)
    (XProtocol.hh:1425-1427), ours returns kXR_FSError(3005). The data-loss
    guard holds on both (child survives), only the error code diverges.
    Suspected src: src/protocols/root/write/rm.c error mapping.
    """
    sub = _mk_scratch(pair, f"rm_dir_err_{trial}", _dir_with_child)
    errs = {}
    for tag, url, _ in _both(pair):
        st, _ = _fs(url).rm(f"{sub}/victim")
        errs[tag] = st.errno
    assert errs["off"] == kXR_ItExists
    if errs["our"] != errs["off"]:
        pytest.xfail(
            f"DIVERGENCE rm-of-dir errno: stock={errs['off']}(ItExists) "
            f"ours={errs['our']}(FSError); suspected src/protocols/root/write/rm.c"
        )
    assert errs["our"] == errs["off"]


# --------------------------------------------------------------------------- #
# 8. rmdir — empty / non-empty
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("dname", ["empty1", "empty2", "to_remove"])
def test_rmdir_empty_ok(pair, dname):
    sub = _mk_scratch(
        pair, f"rmdir_e_{dname}", lambda d: os.makedirs(os.path.join(d, dname))
    )
    res = {}
    for tag, url, _ in _both(pair):
        st, _ = _fs(url).rmdir(f"{sub}/{dname}")
        res[tag] = st.ok
    assert res["our"] == res["off"] is True
    _assert_trees_match(pair, f"rmdir_e_{dname}")


@pytest.mark.parametrize("dname", ["miss1", "miss2"])
def test_rmdir_missing_status_parity(pair, dname):
    """rmdir of a missing dir — status (ok + errno) must match stock.

    Stock's rmdir handler returns OK for an absent directory (idempotent
    remove), and ours agrees; we assert byte-for-byte parity rather than a
    specific code so the contract stays "whatever stock does".
    """
    sub = _mk_scratch(pair, f"rmdir_m_{dname}", lambda d: None)
    res = {}
    for tag, url, _ in _both(pair):
        st, _ = _fs(url).rmdir(f"{sub}/{dname}")
        res[tag] = (st.ok, st.errno)
    assert res["our"] == res["off"]
    _assert_trees_match(pair, f"rmdir_m_{dname}")


@pytest.mark.parametrize("trial", [0, 1, 2])
def test_rmdir_nonempty_fails_no_dataloss(pair, trial):
    """rmdir on a non-empty dir must fail; children must survive on both."""
    sub = _mk_scratch(pair, f"rmdir_ne_{trial}", _dir_with_child)
    for tag, url, data in _both(pair):
        st, _ = _fs(url).rmdir(f"{sub}/victim")
        assert not st.ok, f"{tag} rmdir of non-empty unexpectedly ok"
        child = os.path.join(data, f"rmdir_ne_{trial}", "victim", "child.txt")
        assert os.path.exists(child), f"{tag} DATA LOSS via rmdir non-empty"
    _assert_trees_match(pair, f"rmdir_ne_{trial}")


@pytest.mark.parametrize("trial", [0, 1])
def test_rmdir_nonempty_errno_parity(pair, trial):
    """rmdir on non-empty dir error code.

    DIVERGENCE: stock maps ENOTEMPTY->kXR_ItExists(3018), ours returns
    kXR_FSError(3005). Citation: XProtocol.hh:1425-1427. Suspected src:
    src/protocols/root/write/rm.c (rmdir error mapping).
    """
    sub = _mk_scratch(pair, f"rmdir_ne_err_{trial}", _dir_with_child)
    errs = {}
    for tag, url, _ in _both(pair):
        st, _ = _fs(url).rmdir(f"{sub}/victim")
        errs[tag] = st.errno
    assert errs["off"] == kXR_ItExists
    if errs["our"] != errs["off"]:
        pytest.xfail(
            f"DIVERGENCE rmdir-nonempty errno: stock={errs['off']}(ItExists) "
            f"ours={errs['our']}; suspected src/protocols/root/write/rm.c"
        )
    assert errs["our"] == errs["off"]


# --------------------------------------------------------------------------- #
# 9. mv / rename — file / onto-existing / into-missing-parent / missing-source
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("pairnames", [("a.txt", "b.txt"), ("src", "dst"), ("x.bin", "y.bin")])
def test_mv_file_ok(pair, pairnames):
    src, dst = pairnames
    tag_dir = f"mv_ok_{src.replace('.', '_')}"
    sub = _mk_scratch(
        pair, tag_dir, lambda d: open(os.path.join(d, src), "w").write("renmeE")
    )
    res = {}
    for tag, url, _ in _both(pair):
        st, _ = _fs(url).mv(f"{sub}/{src}", f"{sub}/{dst}")
        res[tag] = st.ok
    assert res["our"] == res["off"] is True
    _assert_trees_match(pair, tag_dir)


@pytest.mark.parametrize("trial", [0, 1])
def test_mv_missing_source_errno_parity(pair, trial):
    sub = _mk_scratch(pair, f"mv_miss_{trial}", lambda d: None)
    errs = {}
    for tag, url, _ in _both(pair):
        st, _ = _fs(url).mv(f"{sub}/nope.txt", f"{sub}/dst.txt")
        assert not st.ok
        errs[tag] = st.errno
    assert errs["our"] == errs["off"] == kXR_NotFound
    _assert_trees_match(pair, f"mv_miss_{trial}")


@pytest.mark.parametrize("trial", [0, 1])
def test_mv_onto_existing_status_parity(pair, trial):
    """mv onto an existing destination file — status + resulting tree parity."""

    def build(d):
        open(os.path.join(d, "a.txt"), "w").write("AAAA")
        open(os.path.join(d, "b.txt"), "w").write("BB")

    sub = _mk_scratch(pair, f"mv_onto_{trial}", build)
    res = {}
    for tag, url, _ in _both(pair):
        st, _ = _fs(url).mv(f"{sub}/a.txt", f"{sub}/b.txt")
        res[tag] = (st.ok, st.errno)
    assert res["our"] == res["off"]
    _assert_trees_match(pair, f"mv_onto_{trial}")


@pytest.mark.parametrize("trial", [0, 1])
def test_mv_into_missing_parent_status_parity(pair, trial):
    """mv into a non-existent destination directory — status + tree parity."""
    sub = _mk_scratch(
        pair,
        f"mv_noparent_{trial}",
        lambda d: open(os.path.join(d, "s.txt"), "w").write("S"),
    )
    res = {}
    for tag, url, _ in _both(pair):
        st, _ = _fs(url).mv(f"{sub}/s.txt", f"{sub}/nodir/d.txt")
        res[tag] = (st.ok, st.errno)
    assert res["our"] == res["off"]
    _assert_trees_match(pair, f"mv_noparent_{trial}")


def test_mv_dir_ok(pair):
    """mv (rename) of a directory."""
    sub = _mk_scratch(
        pair, "mv_dir", lambda d: os.makedirs(os.path.join(d, "olddir"))
    )
    res = {}
    for tag, url, _ in _both(pair):
        st, _ = _fs(url).mv(f"{sub}/olddir", f"{sub}/newdir")
        res[tag] = st.ok
    assert res["our"] == res["off"]
    _assert_trees_match(pair, "mv_dir")


# --------------------------------------------------------------------------- #
# 10. truncate
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("newsize", [0, 1, 5, 100, 4096])
def test_truncate_status_and_size_parity(pair, newsize):
    sub = _mk_scratch(
        pair,
        f"trunc_{newsize}",
        lambda d: open(os.path.join(d, "f.bin"), "wb").write(b"Z" * 4096),
    )
    res = {}
    for tag, url, _ in _both(pair):
        fs = _fs(url)
        st, _ = fs.truncate(f"{sub}/f.bin", newsize)
        sst, si = fs.stat(f"{sub}/f.bin")
        res[tag] = (st.ok, si.size if (sst.ok and si) else None)
    assert res["our"] == res["off"]
    if res["off"][0]:
        assert res["off"][1] == newsize
    _assert_trees_match(pair, f"trunc_{newsize}")


def test_truncate_missing_errno_parity(pair):
    """truncate of a missing file — error code parity.

    DIVERGENCE: stock returns kXR_NotFound(3011) (ENOENT), ours returns
    kXR_IOError(3007). Citation: XProtocol.hh:1407 (ENOENT->kXR_NotFound).
    Both fail (no file created), only the error code diverges.
    Suspected src: src/protocols/root/write/* truncate handler error mapping.
    """
    sub = _mk_scratch(pair, "trunc_miss", lambda d: None)
    errs = {}
    for tag, url, _ in _both(pair):
        st, _ = _fs(url).truncate(f"{sub}/nope.bin", 10)
        assert not st.ok
        errs[tag] = st.errno
    assert errs["off"] == kXR_NotFound
    if errs["our"] != errs["off"]:
        pytest.xfail(
            f"DIVERGENCE truncate-missing errno: stock={errs['off']}(NotFound) "
            f"ours={errs['our']}(IOError); suspected truncate handler mapping"
        )
    assert errs["our"] == errs["off"]


# --------------------------------------------------------------------------- #
# 11. simple query codes + statvfs — status parity (values are config-dependent)
# --------------------------------------------------------------------------- #
QUERY_CASES = [
    (QueryCode.CONFIG, "version"),
    (QueryCode.CONFIG, "bind_max"),
    (QueryCode.CONFIG, "chksum"),
    (QueryCode.SPACE, "/"),
    (QueryCode.SPACE, "/sub"),
    (QueryCode.STATS, "a"),
]


@pytest.mark.parametrize(
    "code,arg",
    QUERY_CASES,
    ids=[f"{c}_{a}".replace('/', 'root') for c, a in QUERY_CASES],
)
def test_query_status_parity(pair, code, arg):
    """The simple query codes must succeed (or fail) identically on both.
    Return *values* are config-dependent (version string, space numbers,
    cgroup names) so we compare status.ok only, not the payload."""
    res = {}
    for tag, url, _ in _both(pair):
        st, _ = _fs(url).query(code, arg)
        res[tag] = st.ok
    assert res["our"] == res["off"]


def test_query_space_nonempty_both(pair):
    """Qspace must return a non-empty payload on both (gfal df relies on it)."""
    for tag, url, _ in _both(pair):
        st, data = _fs(url).query(QueryCode.SPACE, "/")
        assert st.ok, f"{tag} Qspace failed: {st.message}"
        assert data, f"{tag} Qspace empty"


@pytest.mark.parametrize("path", ["/", "/sub", "/many"])
def test_statvfs_status_parity(pair, path):
    res = {}
    for tag, url, _ in _both(pair):
        st, _ = _fs(url).statvfs(path)
        res[tag] = st.ok
    assert res["our"] == res["off"]


def test_query_config_version_format(pair):
    """Both Qconfig version replies must be a non-empty 'vX.Y.Z'-ish string
    (the exact version differs, but the shape must parse for clients)."""
    for tag, url, _ in _both(pair):
        st, data = _fs(url).query(QueryCode.CONFIG, "version")
        assert st.ok, f"{tag} {st.message}"
        s = (data or b"").decode("ascii", "replace").strip()
        assert s.startswith("v"), f"{tag} version not v-prefixed: {s!r}"


# --------------------------------------------------------------------------- #
# 12. stat — direct file/dir stat parity (size + flags + isdir) per path
# --------------------------------------------------------------------------- #
STAT_PATHS = [
    "/hello.txt",
    "/data.bin",
    "/empty.txt",
    "/sub",
    "/sub/nested.txt",
    "/deep/a/b/c/leaf.txt",
    "/sz_4096.bin",
    "/big1m.bin",
    "/many/f00.txt",
]


@pytest.mark.parametrize("path", STAT_PATHS)
def test_stat_size_parity(pair, path):
    sizes = {}
    for tag, url, _ in _both(pair):
        st, si = _fs(url).stat(path)
        assert st.ok, f"{tag} stat {path}: {st.message}"
        sizes[tag] = si.size
    assert sizes["our"] == sizes["off"]


@pytest.mark.parametrize("path", STAT_PATHS)
def test_stat_flags_parity(pair, path):
    flags = {}
    for tag, url, _ in _both(pair):
        st, si = _fs(url).stat(path)
        assert st.ok, f"{tag} {st.message}"
        flags[tag] = si.flags
    assert flags["our"] == flags["off"]


@pytest.mark.parametrize("path", ["/missing.txt", "/sub/missing", "/no/such/path"])
def test_stat_missing_errno_parity(pair, path):
    errs = {}
    for tag, url, _ in _both(pair):
        st, _ = _fs(url).stat(path)
        assert not st.ok
        errs[tag] = st.errno
    assert errs["our"] == errs["off"] == kXR_NotFound
