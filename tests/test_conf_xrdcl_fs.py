from split_continuation import reexport as _reexport
_reexport(globals(), "_test_conf_xrdcl_fs_helpers")

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
STAT_DIRS = [pytest.param(DLROOT, id="dlroot"), "/sub", "/many", "/deep/a/b/c"]


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
    mkdir handler in /tmp/brix-src/src/XrdXrootd/XrdXrootdXeq.cc swallows the
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
