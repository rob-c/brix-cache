from split_continuation import reexport as _reexport
_reexport(globals(), "_test_conf_write_helpers")

@pytest.mark.parametrize("total,chunk", [(1 << 20, 65536), (5 << 20, 1 << 20),
                                         (3 << 20, 4096)])
def test_large_chunked_write(srv, total, chunk):
    src = det_bytes(total, seed=7)
    for who, url in both(srv):
        wire = uniq(f"large_{who}_{total}_{chunk}.bin")
        s = _session(url)
        try:
            fh = _new_handle(s, wire)
            off = 0
            while off < total:
                seg = src[off:off + chunk]
                st, body = _write(s, fh, off, seg)
                assert st == kXR_ok, \
                    f"{who} large write @{off} failed: err={_err(body)}"
                off += len(seg)
            assert _close(s, fh)[0] == kXR_ok
        finally:
            s.close()
        got = read_disk(srv, url, wire)
        assert len(got) == total, f"{who} large size {len(got)} != {total}"
        assert md5(got) == md5(src), \
            f"{who} large write md5 mismatch (total={total} chunk={chunk})"


# =========================================================================== #
# 14. PIPELINED WRITES — send several kXR_write frames before draining ANY
#     acks, then read all acks; every byte must land. Exercises our write
#     pipelining (wr_inflight) without corruption.
# =========================================================================== #
@pytest.mark.parametrize("nchunks,chunk", [(8, 4096), (16, 65536),
                                           (32, 4096), (5, 1 << 20)])
def test_pipelined_writes(srv, nchunks, chunk):
    chunks = [det_bytes(chunk, seed=(i * 13 + 1) & 0xff) for i in range(nchunks)]
    expected = b"".join(chunks)
    for who, url in both(srv):
        wire = uniq(f"pipe_{who}_{nchunks}_{chunk}.bin")
        s = _session(url)
        try:
            fh = _new_handle(s, wire)
            # fire ALL writes back-to-back without reading replies yet
            off = 0
            for c in chunks:
                s.sendall(_write_frame(fh, off, len(c)) + c)
                off += len(c)
            # now drain exactly nchunks acks
            for i in range(nchunks):
                _, st, body = _resp(s)
                assert st == kXR_ok, \
                    f"{who} pipelined ack #{i} not ok: st={st} err={_err(body)}"
            assert _close(s, fh)[0] == kXR_ok
        finally:
            s.close()
        got = read_disk(srv, url, wire)
        assert len(got) == len(expected), \
            f"{who} pipelined size {len(got)} != {len(expected)}"
        assert md5(got) == md5(expected), \
            f"{who} pipelined write CORRUPTION (n={nchunks} cs={chunk})"


def test_pipelined_writes_out_of_order_offsets(srv):
    """Pipeline writes whose offsets are scrambled; bytes must still land at the
    declared offsets (proves offset is honoured per-frame under pipelining)."""
    regions = [(16384, det_bytes(4096, 1)), (0, det_bytes(4096, 2)),
               (8192, det_bytes(4096, 3)), (4096, det_bytes(4096, 4)),
               (12288, det_bytes(4096, 5))]
    total = max(o + len(d) for o, d in regions)
    expected = _build_expected(regions, total)
    for who, url in both(srv):
        wire = uniq(f"pipeooo_{who}.bin")
        s = _session(url)
        try:
            fh = _new_handle(s, wire)
            for off, data in regions:
                s.sendall(_write_frame(fh, off, len(data)) + data)
            for i in range(len(regions)):
                _, st, body = _resp(s)
                assert st == kXR_ok, \
                    f"{who} pipe-ooo ack #{i} not ok: err={_err(body)}"
            assert _close(s, fh)[0] == kXR_ok
        finally:
            s.close()
        got = read_disk(srv, url, wire)
        assert md5(got) == md5(expected), \
            f"{who} pipelined out-of-order write corruption"


# =========================================================================== #
# 15. MALFORMED WRITE — declared dlen does not match the actual payload, or is
#     absurdly large. The server must reject cleanly (error / link drop), never
#     silently accept it as a valid write. Pinned to stock behaviour.
#     A fresh session per case (a malformed frame may poison the link).
# =========================================================================== #
@pytest.mark.parametrize("kind", ["short_payload", "oversized_dlen"])
def test_malformed_write_rejected(srv, kind):
    res = {}
    for who, url in both(srv):
        wire = uniq(f"malformed_{who}_{kind}.bin")
        s = _session(url)
        try:
            fh = _new_handle(s, wire)
            if kind == "short_payload":
                # declare 4096 bytes but send only 100, then a close request.
                # The server must NOT treat the close bytes as write payload.
                hdr = _write_frame(fh, 0, 4096)
                s.sendall(hdr + det_bytes(100, 1))
                # follow with a close frame; a correct server reading 4096 bytes
                # would consume these bytes and the link state diverges -> we
                # simply observe that the eventual response is not a clean ok
                # for a 4096-byte write that never arrived.
                s.sendall(struct.pack("!2sH4s12sI", b"\x00\x0e", kXR_close,
                                      fh, b"\x00" * 12, 0))
                try:
                    _, st, _b = _resp(s)
                    res[who] = st
                except EOFError:
                    res[who] = "dropped"
            else:  # oversized_dlen: declare 1 GiB, send nothing more
                s.sendall(_write_frame(fh, 0, 1 << 30))
                try:
                    s.settimeout(8)
                    _, st, _b = _resp(s)
                    res[who] = st
                except (EOFError, socket.timeout):
                    res[who] = "dropped_or_timeout"
        finally:
            s.close()
    # The two servers should agree on *category*: neither returns a clean ok
    # acknowledging a well-formed 4096B / 1GiB write that never happened.
    assert res["our"] != kXR_ok, \
        f"OUR server returned clean ok for a malformed write ({kind}): {res}"
    assert res["off"] != kXR_ok, \
        f"sanity: stock returned clean ok for malformed write ({kind}): {res}"


# =========================================================================== #
# 16. END-TO-END xrdcp upload at many sizes -> read back byte-exact (our &
#     stock), differential. (write path exercised through the official client)
# =========================================================================== #
_E2E_SIZES = [0, 1, 512, 4095, 4096, 4097, 65536, 1 << 20, 5 << 20]


@pytest.mark.parametrize("n", _E2E_SIZES)
def test_e2e_upload_roundtrip_our(srv, tmp_path, n):
    src = make_local(str(tmp_path / f"e2e_our_{n}.bin"), n, seed=(n & 0xff))
    wire = uniq(f"e2e_our_{n}.bin")
    rc, o, e = cp("-f", src, f"{srv['our']}/{wire}")
    assert rc == 0, f"upload N={n} -> OUR failed: {o}{e}"
    assert os.path.getsize(our_disk(srv, wire)) == n, \
        f"on-disk size {os.path.getsize(our_disk(srv, wire))} != {n}"
    dl = str(tmp_path / f"e2e_our_dl_{n}.bin")
    rc, o, e = cp("-f", f"{srv['our']}/{wire}", dl)
    assert rc == 0, f"download N={n} from OUR failed: {o}{e}"
    with open(src, "rb") as a, open(dl, "rb") as b:
        assert md5(a.read()) == md5(b.read()), f"N={n} roundtrip integrity mismatch"


@pytest.mark.parametrize("n", _E2E_SIZES)
def test_e2e_upload_differential(srv, tmp_path, n):
    src = make_local(str(tmp_path / f"e2e_diff_{n}.bin"), n, seed=((n + 1) & 0xff))
    our_w = uniq(f"e2e_diff_our_{n}.bin")
    off_w = uniq(f"e2e_diff_off_{n}.bin")
    assert cp("-f", src, f"{srv['our']}/{our_w}")[0] == 0, f"upload our N={n}"
    assert cp("-f", src, f"{srv['off']}/{off_w}")[0] == 0, f"upload off N={n}"
    assert os.path.getsize(our_disk(srv, our_w)) == n
    assert os.path.getsize(off_disk(srv, off_w)) == n
    with open(src, "rb") as fsrc:
        want = md5(fsrc.read())
    assert md5(read_disk(srv, srv["our"], our_w)) == want, \
        f"N={n}: OUR uploaded bytes differ from source"
    assert md5(read_disk(srv, srv["off"], off_w)) == want, \
        f"N={n}: STOCK uploaded bytes differ from source"


# =========================================================================== #
# 17. WRITE then TRUNCATE-SHRINK then READ -> only the kept prefix remains.
# =========================================================================== #
@pytest.mark.parametrize("write_n,keep", [(4096, 0), (4096, 1), (4096, 2048),
                                          (65536, 4096), (10000, 9999)])
def test_write_then_shrink_then_read(srv, write_n, keep):
    payload = det_bytes(write_n, seed=61)
    for who, url in both(srv):
        wire = uniq(f"wshrink_{who}_{write_n}_{keep}.bin")
        s = _session(url)
        try:
            fh = _new_handle(s, wire)
            assert _write(s, fh, 0, payload)[0] == kXR_ok, f"{who} write"
            st, body = _truncate_handle(s, fh, keep)
            assert st == kXR_ok, f"{who} shrink failed: err={_err(body)}"
            st, data = _read(s, fh, 0, write_n)
            assert st == kXR_ok, f"{who} read-after-shrink failed"
            assert data == payload[:keep], \
                f"{who} read-after-shrink sees wrong prefix (keep={keep})"
            assert _close(s, fh)[0] == kXR_ok
        finally:
            s.close()
        got = read_disk(srv, url, wire)
        assert len(got) == keep, f"{who} shrink size {len(got)} != {keep}"
        assert got == payload[:keep], f"{who} shrink kept wrong prefix"


# =========================================================================== #
# 18. CONCURRENT — two open-write handles to DIFFERENT files in ONE session;
#     both must be written correctly and independently.
# =========================================================================== #
@pytest.mark.parametrize("n1,n2", [(4096, 8192), (1, 65536), (100, 100)])
def test_two_handles_one_session(srv, n1, n2):
    d1 = det_bytes(n1, seed=111)
    d2 = det_bytes(n2, seed=222)
    for who, url in both(srv):
        w1 = uniq(f"two_{who}_{n1}_{n2}_a.bin")
        w2 = uniq(f"two_{who}_{n1}_{n2}_b.bin")
        s = _session(url)
        try:
            fh1 = _open_handle(s, w1, kXR_new | kXR_open_updt | kXR_delete)
            fh2 = _open_handle(s, w2, kXR_new | kXR_open_updt | kXR_delete)
            assert fh1 != fh2, f"{who} server reused fhandle for two opens"
            # interleave the two streams
            assert _write(s, fh1, 0, d1[:n1 // 2 or n1])[0] == kXR_ok
            assert _write(s, fh2, 0, d2[:n2 // 2 or n2])[0] == kXR_ok
            if n1 // 2:
                assert _write(s, fh1, n1 // 2, d1[n1 // 2:])[0] == kXR_ok
            if n2 // 2:
                assert _write(s, fh2, n2 // 2, d2[n2 // 2:])[0] == kXR_ok
            assert _close(s, fh1)[0] == kXR_ok
            assert _close(s, fh2)[0] == kXR_ok
        finally:
            s.close()
        g1 = read_disk(srv, url, w1)
        g2 = read_disk(srv, url, w2)
        assert g1 == d1, f"{who} two-handle file1 wrong"
        assert g2 == d2, f"{who} two-handle file2 wrong"


# =========================================================================== #
# 19. WRITE with kXR_open_wrto (write-to / write-only create) -> sequential
#     writes land correctly (covers the alternate write-open option).
# =========================================================================== #
@pytest.mark.parametrize("n", [100, 4096, 65536])
def test_write_with_wrto_open(srv, n):
    payload = det_bytes(n, seed=131)
    for who, url in both(srv):
        wire = uniq(f"wrto_{who}_{n}.bin")
        s = _session(url)
        try:
            fh = _open_handle(s, wire, kXR_new | kXR_open_wrto | kXR_delete)
            assert _write(s, fh, 0, payload)[0] == kXR_ok, f"{who} wrto write"
            assert _close(s, fh)[0] == kXR_ok
        finally:
            s.close()
        got = read_disk(srv, url, wire)
        assert got == payload, f"{who} wrto write content wrong n={n}"


# =========================================================================== #
# 20. OVERWRITE existing region in an UPDATE-opened file -> in-place modify,
#     size unchanged, untouched bytes preserved.
# =========================================================================== #
@pytest.mark.parametrize("base_n,at,wn", [(4096, 0, 100), (4096, 2000, 96),
                                          (65536, 32768, 4096), (200, 100, 100)])
def test_inplace_overwrite_update_open(srv, base_n, at, wn):
    base = det_bytes(base_n, seed=141)
    patch = det_bytes(wn, seed=142)
    expected = bytearray(base)
    expected[at:at + wn] = patch
    expected = bytes(expected)
    for who, url in both(srv):
        wire = uniq(f"inplace_{who}_{base_n}_{at}_{wn}.bin")
        with open(disk_for(srv, url, wire), "wb") as f:
            f.write(base)
        s = _session(url)
        try:
            fh = _open_handle(s, wire, kXR_open_updt)
            assert _write(s, fh, at, patch)[0] == kXR_ok, f"{who} in-place write"
            assert _close(s, fh)[0] == kXR_ok
        finally:
            s.close()
        got = read_disk(srv, url, wire)
        assert len(got) == base_n, \
            f"{who} in-place overwrite changed size {len(got)} != {base_n}"
        assert got == expected, f"{who} in-place overwrite content wrong"
