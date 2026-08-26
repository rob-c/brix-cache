from split_continuation import reexport as _reexport
def _check_test_truncate_sparse_huge_1(rc_o, rc_f):
    assert (rc_o == 0) == (rc_f == 0), f"sparse truncate success differs ours={rc_o} off={rc_f}"

def _check_test_truncate_sparse_huge_2(huge, stt, url):
    assert stt.st_size == huge, f"{url} apparent size {stt.st_size} != {huge}"

def _check_test_truncate_sparse_huge_3(allocated, huge, url):
    assert allocated < huge // 2, \
        f"{url} file is not sparse: {allocated} bytes allocated for {huge}"

def _check_test_truncate_sparse_huge_4(st, data):
    assert st == kXR_ok and data == b"\x00", \
        f"far sparse byte not zero: st={st} data={data!r}"


_reexport(globals(), "_test_conf_truncate_sync_helpers")

pytestmark = pytest.mark.xdist_group("conf_truncate_sync")

@pytest.mark.parametrize("n,s,label", _TRUNC_NS)
def test_truncate_path_size_and_zerofill(srv, n, s, label):
    """xrdfs truncate /f S (path-based): on-disk size becomes S exactly; any
    extended region reads back as zeros."""
    wire = uniq(f"trp_{n}_{label}.bin")
    disk = our_disk(srv, wire)
    with open(disk, "wb") as f:
        f.write(det_bytes(n, seed=n))
    rc, o, e = fs(srv["our"], "truncate", wire, str(s))
    assert rc == 0, f"truncate N={n} -> S={s}: {o}{e}"
    assert os.path.getsize(disk) == s, f"on-disk size {os.path.getsize(disk)} != {s}"
    with open(disk, "rb") as f:
        got = f.read()
    if s <= n:
        assert got == det_bytes(n, seed=n)[:s], "kept-prefix bytes corrupted on shrink"
    else:
        assert got[:n] == det_bytes(n, seed=n), "original bytes corrupted on extend"
        assert got[n:] == b"\x00" * (s - n), "extended region is not zero-filled"


# DIFFERENTIAL: extend must succeed identically and be zero-filled on BOTH.
@pytest.mark.parametrize("n,extra", [(100, 900), (4096, 4096), (1, 99999)])
def test_truncate_path_extend_differential(srv, n, extra):
    s = n + extra
    our_w = uniq(f"trpx_our_{n}_{extra}.bin")
    off_w = uniq(f"trpx_off_{n}_{extra}.bin")
    for url, w in ((srv["our"], our_w), (srv["off"], off_w)):
        with open(disk_for(srv, url, w), "wb") as f:
            f.write(det_bytes(n, seed=1))
    rc_o, o_o, e_o = fs(srv["our"], "truncate", our_w, str(s))
    rc_f, o_f, e_f = fs(srv["off"], "truncate", off_w, str(s))
    assert (rc_o == 0) == (rc_f == 0), \
        f"extend success differs: ours={rc_o} stock={rc_f} {o_o}{e_o}|{o_f}{e_f}"
    if rc_o == 0:
        for url, w in ((srv["our"], our_w), (srv["off"], off_w)):
            with open(disk_for(srv, url, w), "rb") as f:
                b = f.read()
            assert len(b) == s, f"{url} extend size {len(b)} != {s}"
            assert b[:n] == det_bytes(n, seed=1), f"{url} extend corrupted prefix"
            assert b[n:] == b"\x00" * extra, f"{url} extend hole not zero"


# =========================================================================== #
# 2. TRUNCATE via OPEN HANDLE (raw-wire kXR_truncate on an open fhandle), and
#    compare the resulting size to the path-based route.
# =========================================================================== #
@pytest.mark.parametrize("n,s", [(1000, 0), (1000, 1), (1000, 500),
                                 (1000, 1000), (1000, 3000)])
def test_truncate_handle_raw_wire(srv, n, s):
    wire = uniq(f"trh_{n}_{s}.bin")
    disk = our_disk(srv, wire)
    with open(disk, "wb") as f:
        f.write(det_bytes(n, seed=5))
    s_sock = _session(srv["our"])
    try:
        fh = _open_handle(s_sock, wire, kXR_open_updt)
        st, body = _truncate_handle(s_sock, fh, s)
        assert st == kXR_ok, f"handle truncate failed: st={st} err={_err(body)}"
        _close(s_sock, fh)
    finally:
        s_sock.close()
    assert os.path.getsize(disk) == s, f"handle-truncate size {os.path.getsize(disk)} != {s}"
    with open(disk, "rb") as f:
        got = f.read()
    if s <= n:
        assert got == det_bytes(n, seed=5)[:s], "handle-truncate corrupted kept prefix"
    else:
        assert got[n:] == b"\x00" * (s - n), "handle-truncate extend not zero-filled"


def test_truncate_handle_matches_path_route(srv):
    """The OPEN-HANDLE truncate and the PATH truncate must land identical bytes."""
    n, s = 2048, 777
    seed = 9
    h_wire = uniq("trh_cmp_handle.bin")
    p_wire = uniq("trh_cmp_path.bin")
    for w in (h_wire, p_wire):
        with open(our_disk(srv, w), "wb") as f:
            f.write(det_bytes(n, seed=seed))
    # handle route
    s_sock = _session(srv["our"])
    try:
        fh = _open_handle(s_sock, h_wire, kXR_open_updt)
        st, body = _truncate_handle(s_sock, fh, s)
        assert st == kXR_ok, f"handle truncate failed: err={_err(body)}"
        _close(s_sock, fh)
    finally:
        s_sock.close()
    # path route
    assert fs(srv["our"], "truncate", p_wire, str(s))[0] == 0
    with open(our_disk(srv, h_wire), "rb") as a, open(our_disk(srv, p_wire), "rb") as b:
        assert a.read() == b.read(), "handle-route and path-route truncate diverge"


# =========================================================================== #
# 3. TRUNCATE of a nonexistent file -> error category parity vs stock.
# =========================================================================== #
def test_truncate_nonexistent_category(srv):
    def do(url):
        return fs(url, "truncate", uniq("tr_missing_xyz.bin"), "10")
    rc_o, rc_f, cat_o, cat_f, raw = diff_fail(srv, do)
    assert rc_o != 0 and rc_f != 0, f"truncate of missing file must fail:{raw}"
    assert cat_o == cat_f, f"truncate-missing error category differs:{raw}"


def test_truncate_handle_missing_fhandle_rejected(srv):
    """Raw-wire handle truncate on a never-opened fhandle -> kXR_error on both."""
    bogus = b"\x7f\x7f\x7f\x7f"
    cats = {}
    for who, url in (("our", srv["our"]), ("off", srv["off"])):
        s_sock = _session(url)
        try:
            st, body = _truncate_handle(s_sock, bogus, 10)
            cats[who] = (st, _err(body))
        finally:
            s_sock.close()
    assert cats["our"][0] == kXR_error, f"our server accepted bogus fhandle: {cats}"
    assert cats["off"][0] == kXR_error, f"stock accepted bogus fhandle: {cats}"


# =========================================================================== #
# 4. TRUNCATE to a HUGE size -> sparse: apparent size correct, allocated blocks
#    small; the far byte reads as zero. Parity vs stock.
# =========================================================================== #
@pytest.mark.parametrize("huge", [16 * 1024 * 1024, 64 * 1024 * 1024])
def test_truncate_sparse_huge(srv, huge):
    our_w = uniq(f"sparse_our_{huge}.bin")
    off_w = uniq(f"sparse_off_{huge}.bin")
    for url, w in ((srv["our"], our_w), (srv["off"], off_w)):
        with open(disk_for(srv, url, w), "wb") as f:
            f.write(b"AB")        # 2 real bytes, then a giant hole
    rc_o = fs(srv["our"], "truncate", our_w, str(huge))[0]
    rc_f = fs(srv["off"], "truncate", off_w, str(huge))[0]
    _check_test_truncate_sparse_huge_1(rc_o, rc_f)
    if rc_o != 0:
        return
    for url, w in ((srv["our"], our_w), (srv["off"], off_w)):
        disk = disk_for(srv, url, w)
        stt = os.stat(disk)
        _check_test_truncate_sparse_huge_2(huge, stt, url)
        # sparse: allocated blocks must be far smaller than the apparent size.
        allocated = stt.st_blocks * 512
        _check_test_truncate_sparse_huge_3(allocated, huge, url)
    # the far byte reads as zero through the wire
    s_sock = _session(srv["our"])
    try:
        fh = _open_handle(s_sock, our_w, kXR_open_read)
        st, data = _read(s_sock, fh, huge - 1, 1)
        _check_test_truncate_sparse_huge_4(st, data)
        _close(s_sock, fh)
    finally:
        s_sock.close()


# =========================================================================== #
# 5. SPARSE WRITE: write at a large offset into a fresh file -> size==offset+len,
#    bytes before are zero, written bytes correct. Differential vs stock.
# =========================================================================== #
@pytest.mark.parametrize("offset,wlen", [(4096, 16), (100000, 32), (1 << 20, 64)])
def test_sparse_write_at_offset(srv, offset, wlen):
    payload = det_bytes(wlen, seed=42)
    our_w = uniq(f"spw_our_{offset}.bin")
    off_w = uniq(f"spw_off_{offset}.bin")
    for url, w in ((srv["our"], our_w), (srv["off"], off_w)):
        s_sock = _session(url)
        try:
            fh = _open_handle(s_sock, w, kXR_new | kXR_open_updt | kXR_delete)
            st, body = _write(s_sock, fh, offset, payload)
            assert st == kXR_ok, f"{url} sparse write failed: err={_err(body)}"
            st, body = _close(s_sock, fh)
            assert st == kXR_ok, f"{url} close failed: err={_err(body)}"
        finally:
            s_sock.close()
    for url, w in ((srv["our"], our_w), (srv["off"], off_w)):
        with open(disk_for(srv, url, w), "rb") as f:
            b = f.read()
        def _assert_test_sparse_write_at_offset_1():
            assert len(b) == offset + wlen, f"{url} size {len(b)} != {offset + wlen}"
            assert b[:offset] == b"\x00" * offset, f"{url} sparse hole before write not zero"

        _assert_test_sparse_write_at_offset_1()
        assert b[offset:] == payload, f"{url} written bytes wrong"
    # cross-check both servers produced identical files
    with open(our_disk(srv, our_w), "rb") as a, open(off_disk(srv, off_w), "rb") as b:
        assert md5(a.read()) == md5(b.read()), "sparse-write files diverge our vs stock"


# =========================================================================== #
# 6. PARTIAL WRITES: open(new), 3 non-contiguous regions, close -> read back;
#    holes zero, regions correct (md5 vs independently constructed buffer).
# =========================================================================== #

@pytest.mark.parametrize("idx,regions,total", [
    (0, [(0, det_bytes(10, 1)), (100, det_bytes(20, 2)), (500, det_bytes(30, 3))], 530),
    (1, [(50, det_bytes(64, 4)), (4096, det_bytes(64, 5)), (9000, det_bytes(100, 6))], 9100),
    (2, [(0, det_bytes(1, 7)), (1, det_bytes(1, 8)), (4095, det_bytes(2, 9))], 4097),
])
def test_partial_noncontiguous_writes(srv, idx, regions, total):
    expected = _build_expected(regions, total)
    for who, url in (("our", srv["our"]), ("off", srv["off"])):
        wire = uniq(f"partial_{who}_{idx}.bin")
        s_sock = _session(url)
        try:
            fh = _open_handle(s_sock, wire, kXR_new | kXR_open_updt | kXR_delete)
            for off, data in regions:
                st, body = _write(s_sock, fh, off, data)
                assert st == kXR_ok, f"{who} write @{off} failed: err={_err(body)}"
            st, body = _close(s_sock, fh)
            assert st == kXR_ok, f"{who} close failed: err={_err(body)}"
        finally:
            s_sock.close()
        with open(disk_for(srv, url, wire), "rb") as f:
            got = f.read()
        assert len(got) == total, f"{who} partial size {len(got)} != {total}"
        assert md5(got) == md5(expected), f"{who} partial-write content mismatch"


# =========================================================================== #
# 7. OVERLAPPING WRITES: write region A then overwrite part of it -> final bytes.
# =========================================================================== #
@pytest.mark.parametrize("idx,a_off,a,b_off,b", [
    (0, 0, det_bytes(100, 1), 40, det_bytes(40, 2)),
    (1, 10, det_bytes(50, 3), 0, det_bytes(30, 4)),
    (2, 4090, det_bytes(20, 5), 4096, det_bytes(20, 6)),
])
def test_overlapping_writes(srv, idx, a_off, a, b_off, b):
    total = max(a_off + len(a), b_off + len(b))
    expected = bytearray(total)
    expected[a_off:a_off + len(a)] = a
    expected[b_off:b_off + len(b)] = b
    expected = bytes(expected)
    for who, url in (("our", srv["our"]), ("off", srv["off"])):
        wire = uniq(f"overlap_{who}_{idx}.bin")
        s_sock = _session(url)
        try:
            fh = _open_handle(s_sock, wire, kXR_new | kXR_open_updt | kXR_delete)
            assert _write(s_sock, fh, a_off, a)[0] == kXR_ok, f"{who} write A"
            assert _write(s_sock, fh, b_off, b)[0] == kXR_ok, f"{who} write B"
            assert _close(s_sock, fh)[0] == kXR_ok, f"{who} close"
        finally:
            s_sock.close()
        with open(disk_for(srv, url, wire), "rb") as f:
            got = f.read()
        assert got == expected, f"{who} overlapping-write final bytes wrong"


# =========================================================================== #
# 8. kXR_sync on an open write handle -> rc ok; data durable (read-back on a
#    SECOND handle). Parity vs stock.
# =========================================================================== #
def test_sync_makes_data_durable(srv):
    """write -> sync -> read-back (same handle) proves the synced bytes are
    persisted; then close and a SECOND fresh session must still see them. The
    second reader opens only AFTER the writer closes (stock enforces a single
    writer lock, so a read while the writer holds the file is correctly denied)."""
    payload = det_bytes(8192, seed=11)
    for who, url in (("our", srv["our"]), ("off", srv["off"])):
        wire = uniq(f"sync_durable_{who}.bin")
        s_sock = _session(url)
        try:
            fh = _open_handle(s_sock, wire, kXR_new | kXR_open_updt | kXR_delete)
            assert _write(s_sock, fh, 0, payload)[0] == kXR_ok, f"{who} write"
            st, body = _sync(s_sock, fh)
            assert st == kXR_ok, f"{who} sync rc not ok: err={_err(body)}"
            # read-back on the same (writer) handle after the sync
            st, data = _read(s_sock, fh, 0, len(payload))
            assert st == kXR_ok, f"{who} read-after-sync failed"
            assert data == payload, f"{who} sync not durable: same-handle read differs"
            assert _close(s_sock, fh)[0] == kXR_ok
        finally:
            s_sock.close()
        # writer is closed; a brand-new session must still see the synced bytes
        s2 = _session(url)
        try:
            fh2 = _open_handle(s2, wire, kXR_open_read)
            st, data = _read(s2, fh2, 0, len(payload))
            assert st == kXR_ok, f"{who} reopen-after-close read failed"
            assert data == payload, f"{who} synced data lost after close+reopen"
            _close(s2, fh2)
        finally:
            s2.close()


def test_sync_then_write_then_close_final_content(srv):
    """write -> sync -> write -> close -> final content is the union, correct."""
    a = det_bytes(4096, seed=21)
    b = det_bytes(4096, seed=22)
    for who, url in (("our", srv["our"]), ("off", srv["off"])):
        wire = uniq(f"sync_seq_{who}.bin")
        s_sock = _session(url)
        try:
            fh = _open_handle(s_sock, wire, kXR_new | kXR_open_updt | kXR_delete)
            assert _write(s_sock, fh, 0, a)[0] == kXR_ok
            assert _sync(s_sock, fh)[0] == kXR_ok, f"{who} sync"
            assert _write(s_sock, fh, 4096, b)[0] == kXR_ok
            assert _close(s_sock, fh)[0] == kXR_ok
        finally:
            s_sock.close()
        with open(disk_for(srv, url, wire), "rb") as f:
            got = f.read()
        assert got == a + b, f"{who} write-sync-write-close final content wrong"


def test_sync_missing_fhandle_rejected(srv):
    """Raw-wire sync on a never-opened fhandle -> kXR_error on both servers."""
    bogus = b"\x6f\x6f\x6f\x6f"
    res = {}
    for who, url in (("our", srv["our"]), ("off", srv["off"])):
        s_sock = _session(url)
        try:
            res[who] = _sync(s_sock, bogus)[0]
        finally:
            s_sock.close()
    assert res["our"] == kXR_error, f"our server accepted sync on bogus fhandle: {res}"
    assert res["off"] == kXR_error, f"stock accepted sync on bogus fhandle: {res}"


# =========================================================================== #
# 9. LARGE-FILE SIZE MATRIX: upload (xrdcp) sizes -> read back byte-identical,
#    on-disk size exact. Parametrized across both servers.
# =========================================================================== #
_SIZES = [0, 1, 512, 4095, 4096, 4097, 1 << 16, 1 << 20, 5 << 20]


@pytest.mark.parametrize("n", _SIZES)
def test_size_matrix_upload_roundtrip_our(srv, tmp_path, n):
    src = make_local(str(tmp_path / f"sm_our_{n}.bin"), n, seed=(n & 0xff))
    wire = uniq(f"sizematrix_our_{n}.bin")
    rc, o, e = cp("-f", src, f"{srv['our']}/{wire}")
    assert rc == 0, f"upload N={n} -> OUR failed: {o}{e}"
    disk = our_disk(srv, wire)
    assert os.path.getsize(disk) == n, f"on-disk size {os.path.getsize(disk)} != {n}"
    dl = str(tmp_path / f"sm_our_dl_{n}.bin")
    rc, o, e = cp("-f", f"{srv['our']}/{wire}", dl)
    assert rc == 0, f"download N={n} from OUR failed: {o}{e}"
    with open(src, "rb") as a, open(dl, "rb") as b:
        assert md5(a.read()) == md5(b.read()), f"N={n} roundtrip integrity mismatch"


@pytest.mark.parametrize("n", _SIZES)
def test_size_matrix_differential_our_vs_stock(srv, tmp_path, n):
    """Same source uploaded to BOTH servers; downloaded copies must be identical
    and match the source byte-for-byte."""
    src = make_local(str(tmp_path / f"sm_diff_{n}.bin"), n, seed=((n + 1) & 0xff))
    our_w = uniq(f"sizematrix_diff_our_{n}.bin")
    off_w = uniq(f"sizematrix_diff_off_{n}.bin")
    assert cp("-f", src, f"{srv['our']}/{our_w}")[0] == 0, f"upload our N={n}"
    assert cp("-f", src, f"{srv['off']}/{off_w}")[0] == 0, f"upload off N={n}"
    assert os.path.getsize(our_disk(srv, our_w)) == n
    assert os.path.getsize(off_disk(srv, off_w)) == n
    a = str(tmp_path / f"sm_diff_dl_our_{n}.bin")
    b = str(tmp_path / f"sm_diff_dl_off_{n}.bin")
    assert cp("-f", f"{srv['our']}/{our_w}", a)[0] == 0
    assert cp("-f", f"{srv['off']}/{off_w}", b)[0] == 0
    with open(src, "rb") as fs_, open(a, "rb") as fa, open(b, "rb") as fb:
        want, ga, gb = md5(fs_.read()), md5(fa.read()), md5(fb.read())
    assert ga == want, f"N={n}: OUR roundtrip differs from source"
    assert gb == want, f"N={n}: STOCK roundtrip differs from source"
    assert ga == gb, f"N={n}: OUR vs STOCK downloads differ"


# =========================================================================== #
# 10. TRUNCATE big1m down to a small prefix -> only the kept prefix remains.
# =========================================================================== #
