from split_continuation import reexport as _reexport
_reexport(globals(), "_test_conf_openflags_helpers")

@pytest.mark.parametrize("path", READ_FILES)
def test_read_open_returns_bare_4byte_handle(srv, path):
    """open(read) of an existing file -> kXR_ok, body is exactly the 4-byte
    fhandle (dlen==4, NO stat) on BOTH servers (XProtocol.hh:1090)."""
    st_o, b_o, st_f, b_f, raw = assert_same_category(srv, path, kXR_open_read)
    assert st_o == kXR_ok, f"open(read) of existing {path} failed:{raw}"
    assert len(b_o) == 4, f"OUR open(read) {path} body is {len(b_o)} bytes, want 4:{raw}"
    assert len(b_f) == 4, f"STOCK open(read) {path} body is {len(b_f)} bytes:{raw}"


@pytest.mark.parametrize("path", READ_FILES[:8])
def test_read_open_default_options_zero(srv, path):
    """open with options==0 defaults to read (Xeq:1530) -> 4-byte handle parity."""
    st_o, b_o, st_f, b_f, raw = assert_same_category(srv, path, 0)
    assert st_o == kXR_ok, f"default-options open of {path} failed:{raw}"
    assert len(b_o) == 4 and len(b_f) == 4, f"default-open body not 4 bytes:{raw}"


# =========================================================================== #
# B. READ-OPEN error parity (NotFound / isDirectory)
# =========================================================================== #
MISSING = [
    "/nope.txt", "/missing/deep.bin", "/sub/absent.txt", "/sz_999999.bin",
    "/many/absent.txt", "/deep/a/b/c/gone.txt",
]


@pytest.mark.parametrize("path", MISSING)
def test_read_open_missing_notfound_parity(srv, path):
    """open(read) of a nonexistent file -> error parity (NotFound)."""
    st_o, b_o, st_f, b_f, raw = assert_same_category(srv, path, kXR_open_read)
    assert st_o == kXR_error, f"open(read) of missing {path} should fail:{raw}"
    assert _errnum(b_o) == kXR_NotFound, f"OUR missing-open errnum != NotFound:{raw}"


DIRS = ["/sub", "/deep", "/deep/a", "/deep/a/b", "/empty_dir", "/many", "/"]


@pytest.mark.parametrize("path", DIRS)
def test_read_open_directory_parity(srv, path):
    """open(read) of a directory -> error parity (isDirectory)."""
    st_o, b_o, st_f, b_f, raw = assert_same_category(srv, path, kXR_open_read)
    assert st_o == kXR_error, f"open(read) of dir {path} should fail:{raw}"


# =========================================================================== #
# C. RETSTAT — open(read|retstat) carries a stat trailer (dlen>4)
# =========================================================================== #
RETSTAT_FILES = ["/hello.txt", "/data.bin", "/sz_4096.bin", "/sz_1.bin",
                 "/empty.txt", "/big1m.bin", "/cksum.bin", "/many/f00.txt"]


@pytest.mark.parametrize("path", RETSTAT_FILES)
def test_read_open_retstat_has_stat_trailer(srv, path):
    """open(read|retstat) -> 4-byte fhandle + stat trailer (dlen>4); the stat
    line parses; presence/shape match stock (Xeq:1752-1757)."""
    opts = kXR_open_read | kXR_retstat
    st_o, b_o, st_f, b_f, raw = assert_same_category(srv, path, opts)
    assert st_o == kXR_ok, f"open(read|retstat) {path} failed:{raw}"
    assert len(b_o) > 4, f"OUR retstat open {path} has no stat trailer (dlen={len(b_o)}):{raw}"
    assert len(b_f) > 4, f"STOCK retstat open {path} has no trailer:{raw}"
    fo = _stat_trailer(b_o)
    ff = _stat_trailer(b_f)
    assert fo is not None, f"OUR retstat trailer does not parse to a stat line:{raw}"
    assert ff is not None, f"STOCK retstat trailer does not parse:{raw}"


def test_retstat_size_field_matches_stat(srv):
    """retstat trailer size field matches a separate xrdfs stat (Size:)."""
    path = "/data.bin"
    so = _session(OUR_PORT)
    try:
        st, body = _open(so, path, kXR_open_read | kXR_retstat)
        assert st == kXR_ok
        fields = _stat_trailer(body)
        assert fields is not None, f"no parseable trailer: {body!r}"
        # StatGen layout: id size flags modtime ...
        assert int(fields[1]) == 4096, f"retstat size {fields[1]} != 4096"
    finally:
        so.close()
    rc, out, _ = L.run([L.OFF_XRDFS, srv["our"], "stat", path])
    assert rc == 0 and "Size:   4096" in out, f"xrdfs stat: {out!r}"


# =========================================================================== #
# D. NEW — create fresh; fail-if-exists on second open(new)
# =========================================================================== #

@pytest.mark.parametrize("idx", range(6))
def test_open_new_creates_fresh_file(srv, idx):
    """open(new) on a non-existent path -> ok and the file appears on disk,
    identically on both servers. Unique path per case."""
    our_w = f"/new_fresh_our_{idx}.bin"
    off_w = f"/new_fresh_off_{idx}.bin"
    so, sf = _both(srv)
    try:
        st_o, b_o = _open(so, our_w, kXR_new | kXR_open_wrto)
        st_f, b_f = _open(sf, off_w, kXR_new | kXR_open_wrto)
        assert (st_o == kXR_ok) == (st_f == kXR_ok), \
            f"open(new) fresh success differs: ours={_category(st_o, b_o)} stock={_category(st_f, b_f)}"
        assert st_o == kXR_ok, f"open(new) fresh failed on OURS: {_category(st_o, b_o)}"
        _close(so, b_o[0:4])
        _close(sf, b_f[0:4])
    finally:
        so.close()
        sf.close()
    assert os.path.exists(our_disk(srv, our_w)), "open(new) did not create file on OUR disk"
    assert os.path.exists(off_disk(srv, off_w)), "open(new) did not create file on STOCK disk"


@pytest.mark.parametrize("idx", range(6))
def test_open_new_on_existing_fails_parity(srv, idx):
    """Second open(new) on a now-existing file -> kXR_ItExists / error parity
    (kXR_new = fail-if-exists, Xeq:1532)."""
    our_w = f"/new_exists_our_{idx}.bin"
    off_w = f"/new_exists_off_{idx}.bin"
    _seed_pair(srv, our_w, off_w, b"seed")
    so, sf = _both(srv)
    try:
        st_o, b_o = _open(so, our_w, kXR_new | kXR_open_wrto)
        st_f, b_f = _open(sf, off_w, kXR_new | kXR_open_wrto)
        raw = (f"\n  OURS cat={_category(st_o, b_o)}\n  STOCK cat={_category(st_f, b_f)}")
        # Stable contract: fail-if-exists -> BOTH servers must reject the create.
        assert (st_o == kXR_ok) == (st_f == kXR_ok), f"open(new)-on-existing differs:{raw}"
        assert st_o == kXR_error, f"open(new) on existing must fail (fail-if-exists):{raw}"
        assert st_f == kXR_error, f"stock open(new) on existing must fail:{raw}"
        eo, ef = _errnum(b_o), _errnum(b_f)
        # The reference maps EEXIST -> kXR_ItExists (3018). Pin it; our server
        # currently mis-maps the create-collision to kXR_FileLocked (3003).
        if eo != ef:
            pytest.xfail(
                f"OUR-SERVER BUG: open(new)-on-existing errno {eo} != stock {ef} "
                f"(stock=kXR_ItExists 3018, ours=kXR_FileLocked 3003 — EEXIST "
                f"should map to kXR_ItExists per mapError, XProtocol.hh:1425):{raw}")
        assert eo == ef
    finally:
        so.close()
        sf.close()


# =========================================================================== #
# E. NEW|DELETE — create-or-truncate
# =========================================================================== #
@pytest.mark.parametrize("idx", range(4))
def test_open_new_delete_truncates_existing(srv, idx):
    """open(new|delete) on an existing non-empty file truncates it to 0 bytes
    (kXR_delete -> O_TRUNC, Xeq:1549); verify size 0 on disk, parity with stock."""
    our_w = f"/nd_trunc_our_{idx}.bin"
    off_w = f"/nd_trunc_off_{idx}.bin"
    _seed_pair(srv, our_w, off_w, b"X" * 512)
    so, sf = _both(srv)
    try:
        st_o, b_o = _open(so, our_w, kXR_delete | kXR_open_wrto)
        st_f, b_f = _open(sf, off_w, kXR_delete | kXR_open_wrto)
        assert (st_o == kXR_ok) == (st_f == kXR_ok), \
            f"open(delete) success differs: ours={_category(st_o, b_o)} stock={_category(st_f, b_f)}"
        if st_o == kXR_ok:
            _close(so, b_o[0:4])
            _close(sf, b_f[0:4])
    finally:
        so.close()
        sf.close()
    if st_o == kXR_ok:
        assert os.path.getsize(our_disk(srv, our_w)) == 0, "OUR open(delete) did not truncate to 0"
        assert os.path.getsize(off_disk(srv, off_w)) == 0, "STOCK open(delete) did not truncate to 0"


@pytest.mark.parametrize("idx", range(3))
def test_open_new_delete_creates_when_missing(srv, idx):
    """open(new|delete) on a missing path: pin to stock (create-or-truncate)."""
    our_w = f"/nd_create_our_{idx}.bin"
    off_w = f"/nd_create_off_{idx}.bin"
    so, sf = _both(srv)
    try:
        st_o, b_o = _open(so, our_w, kXR_new | kXR_delete | kXR_open_wrto)
        st_f, b_f = _open(sf, off_w, kXR_new | kXR_delete | kXR_open_wrto)
        assert (st_o == kXR_ok) == (st_f == kXR_ok), \
            f"open(new|delete) create differs: ours={_category(st_o, b_o)} stock={_category(st_f, b_f)}"
        if st_o == kXR_ok:
            _close(so, b_o[0:4])
            _close(sf, b_f[0:4])
    finally:
        so.close()
        sf.close()
    if st_o == kXR_ok:
        assert os.path.exists(our_disk(srv, our_w)) == os.path.exists(off_disk(srv, off_w))


# =========================================================================== #
# F. UPDATE — open(update) existing ok; missing pins to stock
# =========================================================================== #
@pytest.mark.parametrize("idx", range(4))
def test_open_update_existing_ok(srv, idx):
    """open(update) of an existing file -> ok with a 4-byte handle, parity."""
    our_w = f"/upd_exist_our_{idx}.bin"
    off_w = f"/upd_exist_off_{idx}.bin"
    _seed_pair(srv, our_w, off_w, b"data" * 8)
    so, sf = _both(srv)
    try:
        st_o, b_o = _open(so, our_w, kXR_open_updt)
        st_f, b_f = _open(sf, off_w, kXR_open_updt)
        raw = (f"\n  OURS cat={_category(st_o, b_o)} dlen={len(b_o)}"
               f"\n  STOCK cat={_category(st_f, b_f)} dlen={len(b_f)}")
        assert (st_o == kXR_ok) == (st_f == kXR_ok), f"open(update) existing differs:{raw}"
        assert st_o == kXR_ok, f"open(update) of existing failed on OURS:{raw}"
        assert len(b_o) == 4, f"open(update) body not bare handle:{raw}"
        _close(so, b_o[0:4])
        _close(sf, b_f[0:4])
    finally:
        so.close()
        sf.close()


@pytest.mark.parametrize("idx", range(3))
def test_open_update_missing_parity(srv, idx):
    """open(update) of a missing file: behavior parity (create or error) — pin
    stock (open_updt alone has no O_CREAT, Xeq:1524)."""
    our_w = f"/upd_missing_our_{idx}.bin"
    off_w = f"/upd_missing_off_{idx}.bin"
    so, sf = _both(srv)
    try:
        st_o, b_o = _open(so, our_w, kXR_open_updt)
        st_f, b_f = _open(sf, off_w, kXR_open_updt)
        raw = (f"\n  OURS cat={_category(st_o, b_o)}\n  STOCK cat={_category(st_f, b_f)}")
        assert (st_o == kXR_ok) == (st_f == kXR_ok), f"open(update) missing differs:{raw}"
        if st_o != kXR_ok:
            assert _errnum(b_o) == _errnum(b_f), f"open(update) missing errnum differs:{raw}"
        else:
            _close(so, b_o[0:4])
            _close(sf, b_f[0:4])
    finally:
        so.close()
        sf.close()


# =========================================================================== #
# G. MKPATH — write|new|mkpath creates the missing parent dir
# =========================================================================== #
@pytest.mark.parametrize("idx", range(4))
def test_open_new_mkpath_creates_parent(srv, idx):
    """open(write|new|mkpath) to a missing parent dir -> parent created + file
    written, matching stock (Xeq:1544 SFS_O_MKPTH). Unique parent per case."""
    our_w = f"/mkp_our_{idx}/sub/file.bin"
    off_w = f"/mkp_off_{idx}/sub/file.bin"
    opts = kXR_open_wrto | kXR_new | kXR_mkpath
    so, sf = _both(srv)
    try:
        st_o, b_o = _open(so, our_w, opts)
        st_f, b_f = _open(sf, off_w, opts)
        raw = (f"\n  OURS cat={_category(st_o, b_o)}\n  STOCK cat={_category(st_f, b_f)}")
        assert (st_o == kXR_ok) == (st_f == kXR_ok), f"open(new|mkpath) success differs:{raw}"
        if st_o == kXR_ok:
            _close(so, b_o[0:4])
            _close(sf, b_f[0:4])
    finally:
        so.close()
        sf.close()
    if st_o == kXR_ok:
        assert os.path.exists(our_disk(srv, our_w)), "OUR mkpath open did not create parent+file"
        assert os.path.exists(off_disk(srv, off_w)), "STOCK mkpath open did not create parent+file"


@pytest.mark.parametrize("idx", range(3))
def test_open_new_without_mkpath_missing_parent_parity(srv, idx):
    """open(write|new) WITHOUT mkpath to a missing parent -> pin to stock (stock's
    oss may auto-create on create-open). Differential: agree on success/failure
    and on-disk effect."""
    our_w = f"/nomkp_our_{idx}/sub/file.bin"
    off_w = f"/nomkp_off_{idx}/sub/file.bin"
    opts = kXR_open_wrto | kXR_new
    so, sf = _both(srv)
    try:
        st_o, b_o = _open(so, our_w, opts)
        st_f, b_f = _open(sf, off_w, opts)
        raw = (f"\n  OURS cat={_category(st_o, b_o)}\n  STOCK cat={_category(st_f, b_f)}")
        if st_o == kXR_ok:
            _close(so, b_o[0:4])
        if st_f == kXR_ok:
            _close(sf, b_f[0:4])
    finally:
        so.close()
        sf.close()
    # Pin stock: without kXR_mkpath (and no kXR_async in this raw request), the
    # reference OSS does NOT create the missing parent -> kXR_NotFound (3011).
    if (st_o == kXR_ok) != (st_f == kXR_ok):
        pytest.xfail(
            f"OUR-SERVER BUG: open(new) WITHOUT mkpath to a missing parent "
            f"succeeds on ours but stock rejects it ({_category(st_f, b_f)}). The "
            f"reference only creates the path when kXR_mkpath|kXR_async is set "
            f"(Xeq:1544); ours auto-creates unconditionally:{raw}")
    def _assert_test_open_new_without_mkpath_missing_parent_parity_1():
        assert (st_o == kXR_ok) == (st_f == kXR_ok), \
            f"open(new) missing-parent success differs:{raw}"
        assert os.path.exists(our_disk(srv, our_w)) == os.path.exists(off_disk(srv, off_w)), \
            "open(new) missing-parent on-disk effect differs from stock"

    _assert_test_open_new_without_mkpath_missing_parent_parity_1()


# =========================================================================== #
# H. POSC — persist-on-successful-close
# =========================================================================== #
@pytest.mark.parametrize("idx", range(3))
def test_open_posc_then_close_persists(srv, idx):
    """open(posc) write then CLOSE -> file persists on disk (Xeq:1565
    SFS_O_POSC). Verify on OUR disk; differential success category vs stock."""
    our_w = f"/posc_keep_our_{idx}.bin"
    off_w = f"/posc_keep_off_{idx}.bin"
    opts = kXR_open_wrto | kXR_new | kXR_posc
    so, sf = _both(srv)
    try:
        st_o, b_o = _open(so, our_w, opts)
        st_f, b_f = _open(sf, off_w, opts)
        assert (st_o == kXR_ok) == (st_f == kXR_ok), \
            f"open(posc) success differs: ours={_category(st_o, b_o)} stock={_category(st_f, b_f)}"
        if st_o == kXR_ok:
            _write(so, b_o[0:4], 0, b"posc-data")
            _write(sf, b_f[0:4], 0, b"posc-data")
            _close(so, b_o[0:4])
            _close(sf, b_f[0:4])
    finally:
        so.close()
        sf.close()
    if st_o == kXR_ok:
        assert os.path.exists(our_disk(srv, our_w)), "POSC file vanished after clean close (OURS)"
        assert os.path.exists(off_disk(srv, off_w)), "POSC file vanished after clean close (STOCK)"
