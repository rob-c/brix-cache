from split_continuation import reexport as _reexport
_reexport(globals(), "_test_conf_write_helpers")

@pytest.mark.parametrize("chunk,count", _SEQ)
def test_sequential_contiguous_writes(srv, chunk, count):
    chunks = [det_bytes(chunk, seed=(chunk + i) & 0xff) for i in range(count)]
    expected = b"".join(chunks)
    for who, url in both(srv):
        wire = uniq(f"seq_{who}_{chunk}_{count}.bin")
        s = _session(url)
        try:
            fh = _new_handle(s, wire)
            off = 0
            for c in chunks:
                st, body = _write(s, fh, off, c)
                assert st == kXR_ok, \
                    f"{who} seq write @{off} (cs={chunk}) failed: err={_err(body)}"
                off += len(c)
            assert _close(s, fh)[0] == kXR_ok, f"{who} close"
        finally:
            s.close()
        got = read_disk(srv, url, wire)
        assert len(got) == len(expected), \
            f"{who} seq size {len(got)} != {len(expected)} (cs={chunk} n={count})"
        assert md5(got) == md5(expected), \
            f"{who} seq content mismatch (cs={chunk} n={count})"


# =========================================================================== #
# 2. SINGLE WRITE @ offset 0 of various sizes -> file == data, size exact.
# =========================================================================== #
_SINGLE = [0, 1, 2, 511, 512, 513, 4095, 4096, 4097, 65535, 65536, 131072]


@pytest.mark.parametrize("n", _SINGLE)
def test_single_write_at_zero(srv, n):
    payload = det_bytes(n, seed=(n + 3) & 0xff)
    for who, url in both(srv):
        wire = uniq(f"single_{who}_{n}.bin")
        s = _session(url)
        try:
            fh = _new_handle(s, wire)
            st, body = _write(s, fh, 0, payload)
            assert st == kXR_ok, f"{who} single write n={n}: err={_err(body)}"
            assert _close(s, fh)[0] == kXR_ok
        finally:
            s.close()
        got = read_disk(srv, url, wire)
        assert len(got) == n, f"{who} single size {len(got)} != {n}"
        assert got == payload, f"{who} single content wrong n={n}"


# =========================================================================== #
# 3. RANDOM / OUT-OF-ORDER WRITES -> final file correct (md5 vs expected).
#    Write the regions in a scrambled order; result must equal in-order.
# =========================================================================== #
_RANDOM = [
    (0, [(8192, det_bytes(256, 1)), (0, det_bytes(256, 2)),
         (4096, det_bytes(256, 3))]),
    (1, [(1000, det_bytes(500, 4)), (0, det_bytes(100, 5)),
         (5000, det_bytes(123, 6)), (300, det_bytes(50, 7))]),
    (2, [(4097, det_bytes(4097, 8)), (0, det_bytes(1, 9)),
         (9000, det_bytes(7, 10))]),
]


@pytest.mark.parametrize("idx,regions", _RANDOM)
def test_random_out_of_order_writes(srv, idx, regions):
    total = max(off + len(d) for off, d in regions)
    expected = _build_expected(regions, total)
    for who, url in both(srv):
        wire = uniq(f"rand_{who}_{idx}.bin")
        s = _session(url)
        try:
            fh = _new_handle(s, wire)
            for off, data in regions:
                st, body = _write(s, fh, off, data)
                assert st == kXR_ok, \
                    f"{who} ooo write @{off} failed: err={_err(body)}"
            assert _close(s, fh)[0] == kXR_ok
        finally:
            s.close()
        got = read_disk(srv, url, wire)
        assert len(got) == total, f"{who} ooo size {len(got)} != {total}"
        assert md5(got) == md5(expected), f"{who} ooo content mismatch idx={idx}"


# =========================================================================== #
# 4. OVERLAPPING WRITES — last-writer-wins region correct.
# =========================================================================== #
_OVERLAP = [
    (0, 0, det_bytes(100, 1), 50, det_bytes(100, 2)),
    (1, 0, det_bytes(100, 3), 0, det_bytes(40, 4)),
    (2, 4090, det_bytes(20, 5), 4096, det_bytes(20, 6)),
    (3, 100, det_bytes(200, 7), 150, det_bytes(50, 8)),
]


@pytest.mark.parametrize("idx,a_off,a,b_off,b", _OVERLAP)
def test_overlapping_writes_last_wins(srv, idx, a_off, a, b_off, b):
    total = max(a_off + len(a), b_off + len(b))
    expected = bytearray(total)
    expected[a_off:a_off + len(a)] = a
    expected[b_off:b_off + len(b)] = b      # B applied second -> wins overlap
    expected = bytes(expected)
    for who, url in both(srv):
        wire = uniq(f"overlap_{who}_{idx}.bin")
        s = _session(url)
        try:
            fh = _new_handle(s, wire)
            assert _write(s, fh, a_off, a)[0] == kXR_ok, f"{who} write A"
            assert _write(s, fh, b_off, b)[0] == kXR_ok, f"{who} write B"
            assert _close(s, fh)[0] == kXR_ok
        finally:
            s.close()
        got = read_disk(srv, url, wire)
        assert got == expected, f"{who} overlap final bytes wrong idx={idx}"


# =========================================================================== #
# 5. SPARSE WRITE past EOF -> size==offset+len, hole zero, bytes correct;
#    files identical across our vs stock.
# =========================================================================== #
@pytest.mark.parametrize("offset,wlen", [(4096, 16), (65536, 32),
                                         (100000, 48), (1 << 20, 64)])
def test_sparse_write_at_offset(srv, offset, wlen):
    payload = det_bytes(wlen, seed=42)
    paths = {}
    for who, url in both(srv):
        wire = uniq(f"sparse_{who}_{offset}.bin")
        paths[who] = wire
        s = _session(url)
        try:
            fh = _new_handle(s, wire)
            st, body = _write(s, fh, offset, payload)
            assert st == kXR_ok, f"{who} sparse write failed: err={_err(body)}"
            assert _close(s, fh)[0] == kXR_ok
        finally:
            s.close()
        got = read_disk(srv, url, wire)
        assert len(got) == offset + wlen, \
            f"{who} sparse size {len(got)} != {offset + wlen}"
        assert got[:offset] == b"\x00" * offset, f"{who} sparse hole not zero"
        assert got[offset:] == payload, f"{who} sparse written bytes wrong"
    assert md5(read_disk(srv, srv["our"], paths["our"])) == \
        md5(read_disk(srv, srv["off"], paths["off"])), \
        "sparse-write files diverge our vs stock"


# =========================================================================== #
# 6. APPEND past a small existing file -> grows correctly.
# =========================================================================== #
@pytest.mark.parametrize("base_n,app_off,app_n", [
    (100, 100, 50),       # contiguous append at EOF
    (100, 200, 50),       # gap append (hole 100..200)
    (4096, 4096, 4096),
    (1, 1, 9999),
])
def test_write_past_small_file_grows(srv, base_n, app_off, app_n):
    base = det_bytes(base_n, seed=31)
    app = det_bytes(app_n, seed=32)
    total = max(base_n, app_off + app_n)
    expected = bytearray(total)
    expected[:base_n] = base
    expected[app_off:app_off + app_n] = app
    expected = bytes(expected)
    for who, url in both(srv):
        wire = uniq(f"grow_{who}_{base_n}_{app_off}_{app_n}.bin")
        with open(disk_for(srv, url, wire), "wb") as f:
            f.write(base)
        s = _session(url)
        try:
            fh = _open_handle(s, wire, kXR_open_updt)
            st, body = _write(s, fh, app_off, app)
            assert st == kXR_ok, f"{who} grow write failed: err={_err(body)}"
            assert _close(s, fh)[0] == kXR_ok
        finally:
            s.close()
        got = read_disk(srv, url, wire)
        assert len(got) == total, f"{who} grow size {len(got)} != {total}"
        assert got == expected, f"{who} grow content wrong"


# =========================================================================== #
# 7. ZERO-LENGTH WRITE -> no-op; content/size unchanged; rc parity.
# =========================================================================== #
@pytest.mark.parametrize("at", [0, 64, 256])
def test_zero_length_write_is_noop(srv, at):
    base = det_bytes(256, seed=51)
    res = {}
    for who, url in both(srv):
        wire = uniq(f"zerow_{who}_{at}.bin")
        with open(disk_for(srv, url, wire), "wb") as f:
            f.write(base)
        s = _session(url)
        try:
            fh = _open_handle(s, wire, kXR_open_updt)
            st, _b = _write(s, fh, at, b"")
            res[who] = (st == kXR_ok)
            assert _close(s, fh)[0] == kXR_ok
        finally:
            s.close()
        assert read_disk(srv, url, wire) == base, \
            f"{who} zero-length write @{at} changed content/size"
    assert res["our"] == res["off"], \
        f"zero-length write rc parity differs at={at}: {res}"


# =========================================================================== #
# 8. WRITE to a READ-ONLY handle -> error parity (not silently accepted).
# =========================================================================== #
@pytest.mark.parametrize("at", [0, 4096])
def test_write_to_readonly_handle(srv, at):
    base = det_bytes(8192, seed=71)
    res = {}
    for who, url in both(srv):
        wire = uniq(f"rowrite_{who}_{at}.bin")
        with open(disk_for(srv, url, wire), "wb") as f:
            f.write(base)
        s = _session(url)
        try:
            fh = _open_handle(s, wire, kXR_open_read)
            st, body = _write(s, fh, at, det_bytes(64, 99))
            res[who] = (st, _err(body))
            # drain link cleanly if still up
            try:
                _close(s, fh)
            except EOFError:
                pass
        except EOFError:
            res[who] = ("dropped", None)
        finally:
            s.close()
        # on-disk bytes must be untouched regardless of how the error surfaced
        assert read_disk(srv, url, wire) == base, \
            f"{who} RO-handle write mutated file (data corruption) at={at}"
    assert res["our"][0] != kXR_ok, \
        f"OUR server ACCEPTED a write to a read-only handle: {res}"
    assert res["off"][0] != kXR_ok, f"sanity: stock accepted RO write: {res}"


# =========================================================================== #
# 9. WRITE to a BAD / never-opened fhandle -> error parity (FileNotOpen).
# =========================================================================== #
def test_write_bogus_fhandle(srv):
    bogus = b"\x7e\x7e\x7e\x7e"
    res = {}
    for who, url in both(srv):
        s = _session(url)
        try:
            st, body = _write(s, bogus, 0, det_bytes(32, 1))
            res[who] = (st, _err(body))
        except EOFError:
            res[who] = ("dropped", None)
        finally:
            s.close()
    assert res["our"][0] != kXR_ok, \
        f"OUR server accepted write to bogus fhandle: {res}"
    assert res["off"][0] != kXR_ok, f"sanity: stock accepted bogus fhandle: {res}"


# =========================================================================== #
# 10. WRITE to a CLOSED / STALE fhandle -> error parity.
# =========================================================================== #
def test_write_after_close_stale_handle(srv):
    res = {}
    for who, url in both(srv):
        wire = uniq(f"stale_{who}.bin")
        s = _session(url)
        try:
            fh = _new_handle(s, wire)
            assert _write(s, fh, 0, det_bytes(128, 2))[0] == kXR_ok
            assert _close(s, fh)[0] == kXR_ok
            # fh is now stale: a further write must be rejected
            try:
                st, body = _write(s, fh, 128, det_bytes(128, 3))
                res[who] = (st, _err(body))
            except EOFError:
                res[who] = ("dropped", None)
        finally:
            s.close()
        # the post-close write must not have extended the file
        assert len(read_disk(srv, url, wire)) == 128, \
            f"{who} write to stale handle mutated file"
    assert res["our"][0] != kXR_ok, \
        f"OUR server accepted write to closed handle: {res}"
    assert res["off"][0] != kXR_ok, f"sanity: stock accepted stale handle: {res}"


# =========================================================================== #
# 11. WRITE + READ-BACK on the SAME handle -> sees the just-written bytes
#     (handle coherence pinned to stock).
# =========================================================================== #
@pytest.mark.parametrize("off,n", [(0, 4096), (0, 100), (4096, 4096), (1234, 777)])
def test_write_then_read_same_handle(srv, off, n):
    payload = det_bytes(n, seed=81)
    for who, url in both(srv):
        wire = uniq(f"rbsame_{who}_{off}_{n}.bin")
        s = _session(url)
        try:
            fh = _new_handle(s, wire)
            assert _write(s, fh, off, payload)[0] == kXR_ok, f"{who} write"
            st, data = _read(s, fh, off, n)
            assert st == kXR_ok, f"{who} read-back same handle failed"
            assert data == payload, \
                f"{who} same-handle read does not see written bytes (off={off})"
            assert _close(s, fh)[0] == kXR_ok
        finally:
            s.close()


# =========================================================================== #
# 12. INTERLEAVE write/read/sync/write/close -> final content correct.
# =========================================================================== #
def test_interleave_write_read_sync_write(srv):
    a = det_bytes(4096, seed=91)
    b = det_bytes(2048, seed=92)
    c = det_bytes(1024, seed=93)
    expected = bytearray(4096 + 2048 + 1024)
    expected[0:4096] = a
    expected[4096:4096 + 2048] = b
    expected[4096 + 2048:] = c
    expected = bytes(expected)
    for who, url in both(srv):
        wire = uniq(f"interleave_{who}.bin")
        s = _session(url)
        try:
            fh = _new_handle(s, wire)
            assert _write(s, fh, 0, a)[0] == kXR_ok, f"{who} w1"
            st, got = _read(s, fh, 0, 4096)
            assert st == kXR_ok and got == a, f"{who} read1 wrong"
            assert _sync(s, fh)[0] == kXR_ok, f"{who} sync"
            assert _write(s, fh, 4096, b)[0] == kXR_ok, f"{who} w2"
            st, got = _read(s, fh, 4096, 2048)
            assert st == kXR_ok and got == b, f"{who} read2 wrong"
            assert _write(s, fh, 4096 + 2048, c)[0] == kXR_ok, f"{who} w3"
            assert _close(s, fh)[0] == kXR_ok
        finally:
            s.close()
        got = read_disk(srv, url, wire)
        assert got == expected, f"{who} interleave final content wrong"


# =========================================================================== #
# 13. LARGE write (multi-MB in chunks) -> md5 stable round-trip.
# =========================================================================== #
