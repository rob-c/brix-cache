from split_continuation import reexport as _reexport
_reexport(globals(), "_test_conf_readv_helpers")

@pytest.mark.parametrize("name,off,ln", _single_cases())
def test_readv_single_segment(srv, name, off, ln):
    our, off_h = _open_both(srv, name)
    try:
        _, st_o, body_o = _readv(our.sock, [_seg(our.fh, ln, off)])
        _, st_f, body_f = _readv(off_h.sock, [_seg(off_h.fh, ln, off)])
    finally:
        our.close()
        off_h.close()
    assert st_o == st_f == kXR_ok, (
        f"single readv {name}@{off}+{ln}: status ours={st_o} stock={st_f}")
    want = _local(srv, name)[off:off + ln]
    payload_o = _readv_payload(body_o, 1)
    payload_f = _readv_payload(body_f, 1)
    assert payload_o == want, (
        f"OUR readv {name}@{off}+{ln} returned wrong bytes "
        f"(got {len(payload_o)}, want {len(want)})")
    assert payload_o == payload_f, (
        f"readv {name}@{off}+{ln} diverges from stock "
        f"(ours={len(payload_o)}B stock={len(payload_f)}B)")


# ===========================================================================
# RAW single-segment readahead_list framing: the response header echoes the
# requested fhandle, the served rlen, and the requested offset (vs stock).
# ===========================================================================
@pytest.mark.parametrize("name,off,ln", [
    ("sz_65536.bin", 0, 256),
    ("sz_65536.bin", 4096, 4096),
    ("sz_65536.bin", 12345, 1000),
    ("data.bin", 0, 4096),
])
def test_readv_single_framing(srv, name, off, ln):
    our, off_h = _open_both(srv, name)
    try:
        _, st_o, body_o = _readv(our.sock, [_seg(our.fh, ln, off)])
        _, st_f, body_f = _readv(off_h.sock, [_seg(off_h.fh, ln, off)])
    finally:
        our.close()
        off_h.close()
    assert st_o == st_f == kXR_ok
    segs_o = _parse_segments(body_o)
    segs_f = _parse_segments(body_f)
    assert len(segs_o) == len(segs_f) == 1, (
        f"segment count ours={len(segs_o)} stock={len(segs_f)}")
    fh_o, rlen_o, roff_o, _ = segs_o[0]
    fh_f, rlen_f, roff_f, _ = segs_f[0]
    # The fhandle in the response header must equal the one we opened/requested.
    assert fh_o == our.fh, "OUR readv header fhandle mismatch vs request"
    assert rlen_o == ln == rlen_f, (
        f"readv header rlen ours={rlen_o} stock={rlen_f} want={ln}")
    assert roff_o == off == roff_f, (
        f"readv header offset ours={roff_o} stock={roff_f} want={off}")


# ===========================================================================
# RAW multi-segment readv: N segments on one handle. Each segment's bytes are
# correct, segment count + ordering + per-segment framing all match stock.
# ===========================================================================

@pytest.mark.parametrize("n", [2, 4, 8, 16])
def test_readv_multi_segment(srv, n):
    name = "sz_65536.bin"
    chunks = _multi_chunks(n)
    our, off_h = _open_both(srv, name)
    try:
        _, st_o, body_o = _readv(our.sock, [_seg(our.fh, ln, o) for o, ln in chunks])
        _, st_f, body_f = _readv(off_h.sock, [_seg(off_h.fh, ln, o) for o, ln in chunks])
    finally:
        our.close()
        off_h.close()
    assert st_o == st_f == kXR_ok, f"multi readv n={n}: ours={st_o} stock={st_f}"
    segs_o = _parse_segments(body_o)
    segs_f = _parse_segments(body_f)
    assert len(segs_o) == n, f"OUR segment count {len(segs_o)} != {n}"
    assert len(segs_f) == n, f"stock segment count {len(segs_f)} != {n}"
    src = _local(srv, name)
    # Per-segment: framing (rlen, offset) and bytes match request + stock.
    for i, (o, ln) in enumerate(chunks):
        fh_o, rlen_o, roff_o, pay_o = segs_o[i]
        fh_f, rlen_f, roff_f, pay_f = segs_f[i]
        assert roff_o == o == roff_f, (
            f"seg {i} offset ours={roff_o} stock={roff_f} want={o}")
        assert rlen_o == ln == rlen_f, (
            f"seg {i} rlen ours={rlen_o} stock={rlen_f} want={ln}")
        assert pay_o == src[o:o + ln], f"seg {i} OUR bytes wrong"
        assert pay_o == pay_f, f"seg {i} bytes diverge from stock"


# ===========================================================================
# RAW non-monotonic ordering: read [high..] then [low..]; the server MUST
# return segments in request order, with correct bytes (differential vs stock).
# ===========================================================================
@pytest.mark.parametrize("order", [
    [(4096, 128), (0, 128)],
    [(60000, 200), (100, 200), (30000, 200)],
    [(8192, 64), (4096, 64), (2048, 64), (0, 64)],
])
def test_readv_non_monotonic_order(srv, order):
    name = "sz_65536.bin"
    our, off_h = _open_both(srv, name)
    try:
        _, st_o, body_o = _readv(our.sock, [_seg(our.fh, ln, o) for o, ln in order])
        _, st_f, body_f = _readv(off_h.sock, [_seg(off_h.fh, ln, o) for o, ln in order])
    finally:
        our.close()
        off_h.close()
    assert st_o == st_f == kXR_ok
    segs_o = _parse_segments(body_o)
    segs_f = _parse_segments(body_f)
    src = _local(srv, name)
    # Response order must equal request order (NOT offset-sorted).
    req_offsets = [o for o, _ in order]
    assert [s[2] for s in segs_o] == req_offsets, (
        f"OUR server reordered readv segments: {[s[2] for s in segs_o]} "
        f"!= request order {req_offsets}")
    assert [s[2] for s in segs_f] == req_offsets, "stock reordered (tooling?)"
    for i, (o, ln) in enumerate(order):
        assert segs_o[i][3] == src[o:o + ln], f"seg {i} OUR bytes wrong"
        assert segs_o[i][3] == segs_f[i][3], f"seg {i} diverges from stock"


# ===========================================================================
# RAW readv across MULTIPLE file handles in one request. do_ReadV switches the
# active file when info (fhandle) changes, so a request mixing two open handles
# must serve each from its own file. Pin against stock.
# ===========================================================================

@pytest.mark.parametrize("plan", [
    [(0, 0, 100), (1, 0, 100)],
    [(0, 10, 200), (1, 50, 200), (0, 1000, 64)],
    [(1, 0, 4096), (0, 0, 4096)],
])
def test_readv_multiple_handles(srv, plan):
    name_a, name_b = "data.bin", "sz_8192.bin"
    src_a = _local(srv, name_a)
    src_b = _local(srv, name_b)
    sources = (src_a, src_b)

    st_o, segs_o, _ = _readv_two_handles(*srv["our_hp"], name_a, name_b, plan)
    st_f, segs_f, _ = _readv_two_handles(*srv["off_hp"], name_a, name_b, plan)
    assert st_o == st_f, (
        f"multi-handle readv status diverges: ours={st_o} stock={st_f}")
    if st_o != kXR_ok:
        # Stock may not support cross-handle readv; just pin parity of refusal.
        return
    assert len(segs_o) == len(plan), f"OUR segment count {len(segs_o)} != {len(plan)}"
    for i, (w, o, ln) in enumerate(plan):
        want = sources[w][o:o + ln]
        assert segs_o[i][3] == want, (
            f"seg {i} (handle {w}) OUR bytes wrong: from wrong file?")
        assert segs_o[i][3] == segs_f[i][3], f"seg {i} diverges from stock"


# ===========================================================================
# RAW zero-length segment: pin stock behaviour (skipped/empty, not error).
# ===========================================================================
@pytest.mark.parametrize("segs_plan", [
    [(0, 0)],                       # lone zero-length
    [(0, 0), (100, 32)],            # zero-length followed by valid
    [(100, 32), (0, 0)],            # valid then zero-length
    [(100, 32), (0, 0), (200, 16)],  # zero in the middle
])
def test_readv_zero_length_segment(srv, segs_plan):
    name = "data.bin"
    our, off_h = _open_both(srv, name)
    try:
        _, st_o, body_o = _readv(our.sock, [_seg(our.fh, ln, o) for o, ln in segs_plan])
        _, st_f, body_f = _readv(off_h.sock, [_seg(off_h.fh, ln, o) for o, ln in segs_plan])
    finally:
        our.close()
        off_h.close()
    assert st_o == st_f, (
        f"zero-length readv status diverges: ours={st_o} stock={st_f}")
    if st_o != kXR_ok:
        return
    src = _local(srv, name)
    want = b"".join(src[o:o + ln] for o, ln in segs_plan if ln > 0)
    pay_o = b"".join(p for (_f, _r, _o, p) in _parse_segments(body_o))
    pay_f = b"".join(p for (_f, _r, _o, p) in _parse_segments(body_f))
    assert pay_o == want, f"OUR zero-length-mixed payload wrong for {segs_plan}"
    assert pay_o == pay_f, "zero-length-mixed payload diverges from stock"


# ===========================================================================
# RAW readv at / just past EOF: error parity vs stock (do_ReadV -> ENODATA).
# ===========================================================================
@pytest.mark.parametrize("name,off,ln", [
    ("data.bin", DATA_SIZE, 10),           # start exactly at EOF
    ("data.bin", DATA_SIZE - 1, 10),       # straddles EOF
    ("data.bin", DATA_SIZE - 50, 200),     # tail crosses EOF
    ("sz_4096.bin", 4096, 4096),           # at EOF on page-aligned file
    ("sz_4097.bin", 4097, 1),              # at EOF on +1 file
    ("data.bin", 1 << 40, 4096),           # way past EOF
])
def test_readv_eof_parity(srv, name, off, ln):
    our, off_h = _open_both(srv, name)
    try:
        _, st_o, _ = _readv(our.sock, [_seg(our.fh, ln, off)])
        _, st_f, _ = _readv(off_h.sock, [_seg(off_h.fh, ln, off)])
    finally:
        our.close()
        off_h.close()
    assert st_o == st_f, (
        f"readv EOF behaviour diverges for {name}@{off}+{ln}: "
        f"ours={st_o} stock={st_f} (stock reads past EOF as an error)")


# ===========================================================================
# RAW segment-count cap (readv_iov_max): exactly the cap is OK, over the cap is
# an error — parity with stock at the boundary.
# ===========================================================================

def test_readv_iov_max_advertised_matches_stock(srv):
    vo, vf = _iov_max(srv)
    assert vo == vf == READV_MAXSEGS, (
        f"readv_iov_max differs: ours={vo} stock={vf} (expected {READV_MAXSEGS})")


def test_readv_at_segment_cap_ok(srv):
    name = "sz_65536.bin"
    n = READV_MAXSEGS  # exactly at the cap
    chunks = [((i * 16) % (65536 - 16), 16) for i in range(n)]
    our, off_h = _open_both(srv, name)
    try:
        st_o, body_o = _readv_drain(our.sock, [_seg(our.fh, ln, o) for o, ln in chunks])
        st_f, body_f = _readv_drain(off_h.sock, [_seg(off_h.fh, ln, o) for o, ln in chunks])
    finally:
        our.close()
        off_h.close()
    assert st_o == st_f == kXR_ok, f"cap readv: ours={st_o} stock={st_f}"
    src = _local(srv, name)
    want = b"".join(src[o:o + ln] for o, ln in chunks)
    pay_o = b"".join(p for (_f, _r, _o, p) in _parse_segments(body_o))
    pay_f = b"".join(p for (_f, _r, _o, p) in _parse_segments(body_f))
    assert pay_o == want, "OUR readv at the segment cap returned wrong bytes"
    assert pay_o == pay_f, "readv at the segment cap diverges from stock"


def test_readv_over_segment_cap_error_parity(srv):
    name = "sz_65536.bin"
    n = READV_MAXSEGS + 1  # one over the cap
    chunks = [(i % 1000, 1) for i in range(n)]
    our, off_h = _open_both(srv, name)
    try:
        try:
            _, st_o, _ = _readv(our.sock, [_seg(our.fh, ln, o) for o, ln in chunks])
        except ConnectionError:
            st_o = kXR_error
        try:
            _, st_f, _ = _readv(off_h.sock, [_seg(off_h.fh, ln, o) for o, ln in chunks])
        except ConnectionError:
            st_f = kXR_error
    finally:
        our.close()
        off_h.close()
    assert st_o == kXR_error, "OUR server accepted a readv over readv_iov_max"
    assert st_f == kXR_error, "stock accepted over-cap readv (tooling?)"


# ===========================================================================
# RAW large whole-file readv reassembly: read all of big1m in N segments and
# verify the reassembled bytes md5 == source. Differential vs stock too.
# ===========================================================================

@pytest.mark.parametrize("n", [8, 16, 64])
def test_readv_big_reassembly(srv, n):
    name = BIG_BIN
    plan = _equal_segments(BIG_SIZE, n)
    our, off_h = _open_both(srv, name)
    try:
        st_o, body_o = _readv_drain(our.sock, [_seg(our.fh, ln, o) for o, ln in plan])
        st_f, body_f = _readv_drain(off_h.sock, [_seg(off_h.fh, ln, o) for o, ln in plan])
    finally:
        our.close()
        off_h.close()
    assert st_o == st_f == kXR_ok, f"big readv n={n}: ours={st_o} stock={st_f}"
    src = _local(srv, name)
    pay_o = b"".join(p for (_f, _r, _o, p) in _parse_segments(body_o))
    pay_f = b"".join(p for (_f, _r, _o, p) in _parse_segments(body_f))
    assert len(pay_o) == BIG_SIZE, f"OUR big readv reassembled {len(pay_o)} bytes"
    assert hashlib.md5(pay_o).digest() == hashlib.md5(src).digest(), (
        f"OUR big1m readv reassembly (n={n}) md5 mismatch vs source")
    assert pay_o == pay_f, f"big1m readv (n={n}) diverges from stock"


# ===========================================================================
# RAW plain kXR_read offset/len matrix on the sz_* files: bytes == slice,
# differential vs stock.
# ===========================================================================

@pytest.mark.parametrize("name,off,ln", _read_cases())
def test_plain_read_matrix(srv, name, off, ln):
    our, off_h = _open_both(srv, name)
    try:
        st_o, body_o = _read_drain(our.sock, our.fh, off, ln)
        st_f, body_f = _read_drain(off_h.sock, off_h.fh, off, ln)
    finally:
        our.close()
        off_h.close()
    assert st_o == st_f == kXR_ok, (
        f"plain read {name}@{off}+{ln}: ours={st_o} stock={st_f}")
    want = _local(srv, name)[off:off + ln]
    assert body_o == want, (
        f"OUR plain read {name}@{off}+{ln} wrong bytes "
        f"(got {len(body_o)}, want {len(want)})")
    assert body_o == body_f, f"plain read {name}@{off}+{ln} diverges from stock"


# ===========================================================================
# RAW plain kXR_read EOF / short-read parity vs stock.
# ===========================================================================
@pytest.mark.parametrize("name,off,ln,wantlen", [
    ("data.bin", DATA_SIZE, 10, 0),        # at EOF -> 0 bytes
    ("data.bin", DATA_SIZE - 4, 10, 4),    # straddle EOF -> short read (4)
    ("data.bin", DATA_SIZE + 100, 10, 0),  # past EOF -> 0 bytes
    ("sz_4097.bin", 4096, 10, 1),          # 1 byte left on +1 file
    ("sz_1.bin", 0, 10, 1),                # over-read a 1-byte file -> 1
    ("sz_1.bin", 1, 10, 0),                # at EOF of 1-byte file -> 0
])
def test_plain_read_eof_parity(srv, name, off, ln, wantlen):
    our, off_h = _open_both(srv, name)
    try:
        st_o, body_o = _read_drain(our.sock, our.fh, off, ln)
        st_f, body_f = _read_drain(off_h.sock, off_h.fh, off, ln)
    finally:
        our.close()
        off_h.close()
    # The reference serves short/zero reads as a success (no error past EOF),
    # possibly chunked as kXR_oksofar then kXR_ok; _read_drain normalises that to
    # the final kXR_ok plus the reassembled bytes. The byte COUNT and content
    # are the conformance contract, not the chunk framing.
    assert st_o == st_f, (
        f"plain read EOF status diverges {name}@{off}+{ln}: "
        f"ours={st_o} stock={st_f}")
    if st_o == kXR_ok:
        assert len(body_o) == wantlen, (
            f"OUR short read {name}@{off}+{ln} returned {len(body_o)} "
            f"bytes (want {wantlen})")
        assert body_o == body_f, "short-read bytes diverge from stock"
        want = _local(srv, name)[off:off + ln]
        assert body_o == want, "OUR short read bytes != source slice"


# ===========================================================================
# RAW plain read with len == 0: pin stock behaviour (0 bytes, kXR_ok).
# ===========================================================================
@pytest.mark.parametrize("name", ["data.bin", "sz_4096.bin", "empty.txt"])
def test_plain_read_zero_length(srv, name):
    our, off_h = _open_both(srv, name)
    try:
        _, st_o, body_o = _read(our.sock, our.fh, 0, 0)
        _, st_f, body_f = _read(off_h.sock, off_h.fh, 0, 0)
    finally:
        our.close()
        off_h.close()
    assert st_o == st_f, f"zero-length read status diverges: ours={st_o} stock={st_f}"
    if st_o == kXR_ok:
        assert body_o == b"" == body_f, "zero-length read should yield no bytes"


# ===========================================================================
# RAW read of empty.txt: 0 bytes, rc OK on both.
# ===========================================================================
def test_plain_read_empty_file(srv):
    name = "empty.txt"
    our, off_h = _open_both(srv, name)
    try:
        _, st_o, body_o = _read(our.sock, our.fh, 0, 4096)
        _, st_f, body_f = _read(off_h.sock, off_h.fh, 0, 4096)
    finally:
        our.close()
        off_h.close()
    assert st_o == st_f == kXR_ok, f"empty read: ours={st_o} stock={st_f}"
    assert body_o == b"" == body_f, "empty.txt read returned bytes"


# ===========================================================================
# RAW readv of empty.txt: pin stock behaviour for a zero-byte file.
# ===========================================================================
