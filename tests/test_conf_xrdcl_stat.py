from split_continuation import reexport as _reexport
_reexport(globals(), "_test_conf_xrdcl_stat_helpers")

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
def _assert_same_successful_stat(trailing, canonical):
    if not (trailing[0].ok and canonical[0].ok):
        return
    assert (trailing[1].flags, trailing[1].size) == \
        (canonical[1].flags, canonical[1].size)


def test_stat_dir_trailing_matches_canonical(fs_our, fs_off, path):
    # Stat of "/x/" must equal stat of "/x" within the SAME server (size+flags).
    canon = path.rstrip("/") or "/"
    so_t, sio_t = _stat(fs_our, path)
    so_c, sio_c = _stat(fs_our, canon)
    sf_t, sif_t = _stat(fs_off, path)
    sf_c, sif_c = _stat(fs_off, canon)
    _assert_same_successful_stat((so_t, sio_t), (so_c, sio_c))
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
    assert so.ok and sf.ok, "statvfs must be supported by both servers"
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
    assert so.ok and sf.ok, "statvfs must be supported by both servers"
    assert vo.nodes_rw == vf.nodes_rw, "nodes_rw diverges for %r" % path
    assert vo.nodes_staging == vf.nodes_staging
