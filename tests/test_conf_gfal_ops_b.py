from split_continuation import reexport as _reexport
_reexport(globals(), "_test_conf_gfal_ops_helpers")

pytestmark = pytest.mark.xdist_group("conf_gfal_ops_b")

def test_rm_file(ctx):
    """gfal-rm of an uploaded file: rc match stock; file gone afterward."""
    _both(ctx, lambda s: ("gfal-mkdir", "-p", _scratch(ctx, s, "rmf")))
    tmp = tempfile.NamedTemporaryFile(delete=False)
    tmp.write(b"to-be-removed"); tmp.close()
    try:
        _both(ctx, lambda s: ("gfal-copy", "-f", tmp.name,
                              _scratch(ctx, s, "rmf") + "/x.bin"))
        our, off = _both(ctx, lambda s: ("gfal-rm",
                                         _scratch(ctx, s, "rmf") + "/x.bin"))
        _assert_rc_and_errcat(our, off, "rm file")
        assert our[0] == 0
        gour, goff = _both(ctx, lambda s: ("gfal-stat",
                                           _scratch(ctx, s, "rmf") + "/x.bin"))
        _assert_rc_and_errcat(gour, goff, "stat after rm")
        assert gour[0] != 0
    finally:
        os.unlink(tmp.name)
        _both(ctx, lambda s: ("gfal-rm", "-r", _scratch(ctx, s, "rmf")))


def test_rm_dir_recursive(ctx):
    """gfal-rm -r of a populated dir tree: rc + category match stock; gone after."""
    _both(ctx, lambda s: ("gfal-mkdir", "-p", _scratch(ctx, s, "rmr") + "/a/b"))
    tmp = tempfile.NamedTemporaryFile(delete=False)
    tmp.write(b"deep-file"); tmp.close()
    try:
        _both(ctx, lambda s: ("gfal-copy", "-f", tmp.name,
                              _scratch(ctx, s, "rmr") + "/a/b/f.bin"))
        our, off = _both(ctx, lambda s: ("gfal-rm", "-r", _scratch(ctx, s, "rmr")))
        _assert_rc_and_errcat(our, off, "rm -r tree")
        assert our[0] == 0
        gour, goff = _both(ctx, lambda s: ("gfal-stat", _scratch(ctx, s, "rmr")))
        _assert_rc_and_errcat(gour, goff, "stat after rm -r")
        assert gour[0] != 0
    finally:
        os.unlink(tmp.name)
        _both(ctx, lambda s: ("gfal-rm", "-r", _scratch(ctx, s, "rmr")))


@pytest.mark.parametrize("path", MISSING)
def test_rm_missing(ctx, path):
    """gfal-rm of a missing file: rc + error category match stock."""
    our, off = _both(ctx, lambda s: ("gfal-rm", _url(ctx, s, path)))
    _assert_rc_and_errcat(our, off, f"rm missing {path}")
    assert our[0] != 0


# --------------------------------------------------------------------------- #
# gfal-xattr — listing.  Our server exposes xroot.cksum; stock (no checksum
# config) returns FAILED for that one attr but the common attrs (xroot.space,
# xroot.xattr) are present on both.  Compare the set of attr KEYS, not the
# cksum value.
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("path", ["hello.txt", "data.bin", "sub/nested.txt"])
def test_xattr_lists_common_keys(ctx, path):
    """gfal-xattr (list) succeeds on both; the common attribute keys
    (xroot.space, xroot.xattr) are present on both servers."""
    our, off = _both(ctx, lambda s: ("gfal-xattr", _url(ctx, s, path)))
    assert our[0] == 0, f"xattr our failed: {our[2]}"
    assert off[0] == 0, f"xattr off failed: {off[2]}"
    for key in ("xroot.space", "xroot.xattr"):
        assert key in our[1], f"xattr {path}: our missing {key}\n{our[1]}"
        assert key in off[1], f"xattr {path}: off missing {key}\n{off[1]}"


# DIVERGENCE (config, not bug): our server serves xroot.cksum via gfal-xattr
# (computed checksum), stock server — launched without checksum config —
# returns 'FAILED ... (Operation not supported)' for that single attribute.
# Same root cause as test_sum_rc_matches_stock; XrdCl QueryCode::XAttr +
# Checksum.  Suspected/relevant: our cksum dispatch (src/ checksum path);
# stock side is purely config.
@pytest.mark.xfail(reason="DIVERGENCE: xroot.cksum present on our server, "
                          "'Operation not supported' on stock (checksum config "
                          "gap); our cksum value verified correct elsewhere",
                   strict=False)
def test_xattr_cksum_parity(ctx, path):
    """Pinned: xroot.cksum availability differs (stock config exposes none)."""
    our, off = _both(ctx, lambda s: ("gfal-xattr", _url(ctx, s, path), "xroot.cksum"))
    assert our[0] == off[0], f"xattr xroot.cksum rc our={our[0]} off={off[0]}"


@pytest.mark.parametrize("path", MISSING)
def test_xattr_missing(ctx, path):
    """gfal-xattr (list) of a missing path: the gfal command itself succeeds on
    both servers (rc 0) — it enumerates the known attribute names and marks each
    one 'FAILED ... (No such file or directory)' inline rather than failing the
    process.  So the conformance check is rc-equality plus the per-attr ENOENT
    marker appearing on both."""
    our, off = _both(ctx, lambda s: ("gfal-xattr", _url(ctx, s, path)))
    assert our[0] == off[0], (
        f"xattr missing {path}: rc our={our[0]} off={off[0]}\n"
        f"our:{our[1]}{our[2]}\noff:{off[1]}{off[2]}")
    if our[0] == 0:
        assert "FAILED" in our[1] and "FAILED" in off[1], (
            f"xattr missing {path}: expected inline FAILED markers on both")
