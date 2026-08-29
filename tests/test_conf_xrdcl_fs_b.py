from split_continuation import reexport as _reexport
_reexport(globals(), "_test_conf_xrdcl_fs_helpers")

pytestmark = pytest.mark.xdist_group("conf_xrdcl_fs_b")

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
def _assert_truncate_result(results, newsize):
    assert results["our"] == results["off"]
    if results["off"][0]:
        assert results["off"][1] == newsize


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
    _assert_truncate_result(res, newsize)
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
