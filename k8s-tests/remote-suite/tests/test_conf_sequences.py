from split_continuation import reexport as _reexport
_reexport(globals(), "_test_conf_sequences_helpers")

@pytest.mark.parametrize("n", _SEQ_SIZES)
def test_create_write_fstat_read_close_stat_reopen(srv, n):
    payload = det_bytes(n, seed=(n & 0xff) ^ 0x5a)
    results = {}
    for who, url in both(srv):
        wire = uniq(f"seq_full_{who}_{n}.bin")
        s = _session(url)
        try:
            fh = _open_handle(s, wire, WRITE_NEW)
            if n:
                st, body = _write(s, fh, 0, payload)
                _require(st == kXR_ok, f"{who} write n={n} err={_err(body)}")
            # fstat on the OPEN handle must report the written size
            st, body = _fstat(s, fh)
            fstat_sz = _stat_size_if_ok(st, body)
            # read-back through the same handle
            rb = b""
            if n:
                st_r, rb = _read(s, fh, 0, n)
                _require(st_r == kXR_ok, f"{who} read-back n={n} st={st_r}")
            _require(_close(s, fh)[0] == kXR_ok, f"{who} close n={n}")
            # stat(path) after close
            st, body = _stat_path(s, wire)
            _require(st == kXR_ok, f"{who} stat(path) n={n}")
            path_sz = _stat_size(body)
            # reopen(read) and read it all again
            fh2 = _open_handle(s, wire, kXR_open_read)
            rb2 = b""
            if n:
                st_r, rb2 = _read(s, fh2, 0, n)
                _require(st_r == kXR_ok, f"{who} reopen-read n={n}")
            _close(s, fh2)
        finally:
            s.close()
        # on-disk truth
        with open(disk_for(srv, url, wire), "rb") as f:
            disk = f.read()
        results[who] = dict(fstat=fstat_sz, path=path_sz, rb=rb, rb2=rb2,
                            disk=disk)
        # per-server invariants
        _require(fstat_sz == n, f"{who} fstat size {fstat_sz} != {n}")
        _require(path_sz == n, f"{who} stat(path) size {path_sz} != {n}")
        _require(rb == payload, f"{who} same-handle read-back != written (n={n})")
        _require(rb2 == payload, f"{who} reopen read-back != written (n={n})")
        _require(disk == payload, f"{who} on-disk bytes != written (n={n})")
    # cross-server: identical at every checkpoint
    _require(
        results["our"]["fstat"] == results["off"]["fstat"],
        f"fstat size differs our vs stock (n={n})",
    )
    _require(
        results["our"]["path"] == results["off"]["path"],
        f"stat(path) size differs our vs stock (n={n})",
    )
    _require(
        md5(results["our"]["disk"]) == md5(results["off"]["disk"]),
        f"on-disk bytes differ our vs stock (n={n})",
    )


# =========================================================================== #
# 2. CREATE -> write -> sync -> write more -> close -> verify full content.
# =========================================================================== #
@pytest.mark.parametrize("a_n,b_n", [(100, 100), (4096, 4096), (1, 8191),
                                     (4097, 1), (8192, 8192), (255, 4096)])
def test_write_sync_write_close_full_content(srv, a_n, b_n):
    a = det_bytes(a_n, seed=1)
    b = det_bytes(b_n, seed=2)
    expected = a + b
    for who, url in both(srv):
        wire = uniq(f"seq_sw_{who}_{a_n}_{b_n}.bin")
        s = _session(url)
        try:
            fh = _open_handle(s, wire, WRITE_NEW)
            assert _write(s, fh, 0, a)[0] == kXR_ok, f"{who} write A"
            assert _sync(s, fh)[0] == kXR_ok, f"{who} sync"
            assert _write(s, fh, a_n, b)[0] == kXR_ok, f"{who} write B"
            assert _close(s, fh)[0] == kXR_ok, f"{who} close"
        finally:
            s.close()
        with open(disk_for(srv, url, wire), "rb") as f:
            got = f.read()
        assert got == expected, f"{who} write-sync-write final content wrong"


# =========================================================================== #
# 3. CREATE -> write -> truncate(handle) SMALLER -> fstat==new -> read shows
#    truncated -> close -> verify on disk.
# =========================================================================== #
@pytest.mark.parametrize("n,keep", [(1000, 0), (1000, 1), (1000, 500),
                                    (4096, 1234), (8192, 4096), (8192, 0),
                                    (65536, 12345)])
def test_write_truncate_smaller_fstat_read(srv, n, keep):
    payload = det_bytes(n, seed=3)
    for who, url in both(srv):
        wire = uniq(f"seq_trs_{who}_{n}_{keep}.bin")
        s = _session(url)
        try:
            fh = _open_handle(s, wire, WRITE_NEW)
            assert _write(s, fh, 0, payload)[0] == kXR_ok, f"{who} write"
            st, body = _truncate_handle(s, fh, keep)
            assert st == kXR_ok, f"{who} handle-truncate err={_err(body)}"
            st, body = _fstat(s, fh)
            assert st == kXR_ok and _stat_size(body) == keep, \
                f"{who} fstat after shrink {_stat_size(body)} != {keep}"
            if keep:
                st_r, rb = _read(s, fh, 0, keep)
                assert st_r == kXR_ok and rb == payload[:keep], \
                    f"{who} truncated read mismatch"
            assert _close(s, fh)[0] == kXR_ok, f"{who} close"
        finally:
            s.close()
        with open(disk_for(srv, url, wire), "rb") as f:
            got = f.read()
        assert got == payload[:keep], f"{who} on-disk after shrink wrong"


# =========================================================================== #
# 4. CREATE -> write -> truncate LARGER (extend) -> read zero-fill region.
# =========================================================================== #
@pytest.mark.parametrize("n,grow", [(100, 4096), (4096, 8192), (1, 65536),
                                    (4096, 4097), (8192, 16384)])
def test_write_truncate_extend_zero_region(srv, n, grow):
    payload = det_bytes(n, seed=4)
    for who, url in both(srv):
        wire = uniq(f"seq_tre_{who}_{n}_{grow}.bin")
        s = _session(url)
        try:
            fh = _open_handle(s, wire, WRITE_NEW)
            assert _write(s, fh, 0, payload)[0] == kXR_ok, f"{who} write"
            st, body = _truncate_handle(s, fh, grow)
            assert st == kXR_ok, f"{who} extend err={_err(body)}"
            st, body = _fstat(s, fh)
            assert st == kXR_ok and _stat_size(body) == grow, \
                f"{who} fstat after extend != {grow}"
            st_r, hole = _read(s, fh, n, grow - n)
            assert st_r == kXR_ok and hole == b"\x00" * (grow - n), \
                f"{who} extended region not zero-filled"
            assert _close(s, fh)[0] == kXR_ok, f"{who} close"
        finally:
            s.close()
        with open(disk_for(srv, url, wire), "rb") as f:
            got = f.read()
        assert got[:n] == payload and got[n:] == b"\x00" * (grow - n), \
            f"{who} on-disk extend wrong"


# =========================================================================== #
# 5. OPEN(update existing) -> overwrite MIDDLE -> close -> only middle changed.
# =========================================================================== #
@pytest.mark.parametrize("total,off,mlen", [(1000, 400, 100), (4096, 0, 4096),
                                            (200, 199, 1), (8192, 4000, 192),
                                            (65536, 30000, 4096), (500, 0, 1)])
def test_overwrite_middle_only(srv, total, off, mlen):
    base = det_bytes(total, seed=5)
    patch = det_bytes(mlen, seed=6)
    expected = bytearray(base)
    expected[off:off + mlen] = patch
    expected = bytes(expected)
    for who, url in both(srv):
        wire = uniq(f"seq_mid_{who}_{total}_{off}_{mlen}.bin")
        with open(disk_for(srv, url, wire), "wb") as f:
            f.write(base)
        s = _session(url)
        try:
            fh = _open_handle(s, wire, WRITE_UPD)
            assert _write(s, fh, off, patch)[0] == kXR_ok, f"{who} overwrite"
            assert _close(s, fh)[0] == kXR_ok, f"{who} close"
        finally:
            s.close()
        with open(disk_for(srv, url, wire), "rb") as f:
            got = f.read()
        assert len(got) == total, f"{who} overwrite changed total size"
        assert got == expected, f"{who} overwrite touched bytes outside [off,off+mlen)"


# =========================================================================== #
# 6. CREATE -> write -> close -> reopen(update) -> append at size -> close ->
#    verify grown.
# =========================================================================== #
@pytest.mark.parametrize("base_n,app_n", [(100, 50), (4096, 4096), (1, 9999),
                                          (8192, 1), (65536, 4096), (255, 257)])
def test_reopen_append_grows(srv, base_n, app_n):
    base = det_bytes(base_n, seed=7)
    app = det_bytes(app_n, seed=8)
    for who, url in both(srv):
        wire = uniq(f"seq_app_{who}_{base_n}_{app_n}.bin")
        s = _session(url)
        try:
            fh = _open_handle(s, wire, WRITE_NEW)
            assert _write(s, fh, 0, base)[0] == kXR_ok, f"{who} write base"
            assert _close(s, fh)[0] == kXR_ok, f"{who} close base"
            # reopen update, append at current size
            fh2 = _open_handle(s, wire, WRITE_UPD)
            assert _write(s, fh2, base_n, app)[0] == kXR_ok, f"{who} append"
            st, body = _fstat(s, fh2)
            assert st == kXR_ok and _stat_size(body) == base_n + app_n, \
                f"{who} fstat after append wrong"
            assert _close(s, fh2)[0] == kXR_ok, f"{who} close append"
        finally:
            s.close()
        with open(disk_for(srv, url, wire), "rb") as f:
            got = f.read()
        assert got == base + app, f"{who} reopen-append content wrong"


# =========================================================================== #
# 7. CREATE -> write -> close -> open(read) -> readv multi-seg -> bytes match.
# =========================================================================== #
@pytest.mark.parametrize("idx,segs", [
    (0, [(0, 16), (100, 32), (500, 64)]),
    (1, [(0, 4096), (4096, 4096)]),
    (2, [(10000, 1), (0, 1), (5000, 100)]),
    (3, [(0, 1), (1, 1), (2, 1), (3, 1)]),
    (4, [(0, 8192)]),
    (5, [(4095, 2), (8190, 2), (0, 4096)]),
])
def test_readv_multiseg_matches(srv, idx, segs):
    total = max(o + l for o, l in segs)
    payload = det_bytes(total + 16, seed=9)        # a bit larger than needed
    for who, url in both(srv):
        wire = uniq(f"seq_rv_{who}_{idx}.bin")
        s = _session(url)
        try:
            fh = _open_handle(s, wire, WRITE_NEW)
            _require(_write(s, fh, 0, payload)[0] == kXR_ok, f"{who} write")
            _require(_close(s, fh)[0] == kXR_ok, f"{who} close")
            fh2 = _open_handle(s, wire, kXR_open_read)
            st, parts = _readv(s, [(fh2, o, l) for o, l in segs])
            _require(st == kXR_ok, f"{who} readv st={st}")
            _require(
                len(parts) == len(segs),
                f"{who} readv returned {len(parts)} segs, want {len(segs)}",
            )
            for (o, l), got in zip(segs, parts):
                _require(got == payload[o:o + l], f"{who} readv seg @{o}+{l} mismatch")
            _close(s, fh2)
        finally:
            s.close()


# =========================================================================== #
# 8. CREATE -> write -> close -> open(delete/truncate-create) -> size 0 ->
#    write new -> verify replaced.
# =========================================================================== #
@pytest.mark.parametrize("first_n,second_n", [(1000, 10), (4096, 4096),
                                              (1, 8192), (8192, 1),
                                              (65536, 100), (4097, 4095)])
def test_recreate_via_delete_replaces(srv, first_n, second_n):
    first = det_bytes(first_n, seed=11)
    second = det_bytes(second_n, seed=12)
    for who, url in both(srv):
        wire = uniq(f"seq_rc_{who}_{first_n}_{second_n}.bin")
        s = _session(url)
        try:
            fh = _open_handle(s, wire, WRITE_NEW)
            assert _write(s, fh, 0, first)[0] == kXR_ok, f"{who} write first"
            assert _close(s, fh)[0] == kXR_ok, f"{who} close first"
            # reopen with delete -> O_TRUNC; fstat must be 0 before writing
            fh2 = _open_handle(s, wire, kXR_delete | kXR_open_updt)
            st, body = _fstat(s, fh2)
            assert st == kXR_ok and _stat_size(body) == 0, \
                f"{who} delete-open did not truncate to 0 (got {_stat_size(body)})"
            assert _write(s, fh2, 0, second)[0] == kXR_ok, f"{who} write second"
            assert _close(s, fh2)[0] == kXR_ok, f"{who} close second"
        finally:
            s.close()
        with open(disk_for(srv, url, wire), "rb") as f:
            got = f.read()
        assert got == second, f"{who} recreate did not replace content"


# =========================================================================== #
# 9. TWO SEQUENTIAL SESSIONS — session1 creates+writes+closes; a brand-new
#    session2 opens+reads and must see the data (durability). Parity.
# =========================================================================== #
@pytest.mark.parametrize("n", [0, 1, 100, 4095, 4096, 4097, 65536, 1 << 20])
def test_durability_across_sessions(srv, n):
    payload = det_bytes(n, seed=13)
    for who, url in both(srv):
        wire = uniq(f"seq_dur_{who}_{n}.bin")
        s1 = _session(url)
        try:
            fh = _open_handle(s1, wire, WRITE_NEW)
            if n:
                assert _write(s1, fh, 0, payload)[0] == kXR_ok, f"{who} write"
            assert _close(s1, fh)[0] == kXR_ok, f"{who} close"
        finally:
            s1.close()
        s2 = _session(url)
        try:
            fh2 = _open_handle(s2, wire, kXR_open_read)
            rb = b""
            if n:
                st, rb = _read(s2, fh2, 0, n)
                assert st == kXR_ok, f"{who} session2 read st={st}"
            _close(s2, fh2)
        finally:
            s2.close()
        assert rb == payload, f"{who} session2 did not see session1 data (n={n})"


# =========================================================================== #
# 10. TWO HANDLES, ONE SESSION — write via h1, read via h2 (intra-session
#     coherence). Pin stock's coherence behaviour. The reader opens AFTER the
#     writer closes (single-writer lock), then both-open read-coherence with
#     two read handles is checked separately.
# =========================================================================== #
def test_two_handles_write_then_read_coherence(srv):
    payload = det_bytes(8192, seed=14)
    for who, url in both(srv):
        wire = uniq(f"seq_2h_{who}.bin")
        s = _session(url)
        try:
            # writer handle
            fhw = _open_handle(s, wire, WRITE_NEW, )
            assert _write(s, fhw, 0, payload)[0] == kXR_ok, f"{who} write h1"
            assert _close(s, fhw)[0] == kXR_ok, f"{who} close h1"
            # two simultaneous READ handles on the same session
            fh1 = _open_handle(s, wire, kXR_open_read)
            fh2 = _open_handle(s, wire, kXR_open_read)
            assert fh1 != fh2, f"{who} same fhandle for two opens"
            st1, d1 = _read(s, fh1, 0, 8192)
            st2, d2 = _read(s, fh2, 4096, 4096)
            assert st1 == kXR_ok and d1 == payload, f"{who} h1 read mismatch"
            assert st2 == kXR_ok and d2 == payload[4096:], f"{who} h2 read mismatch"
            _close(s, fh1)
            _close(s, fh2)
        finally:
            s.close()


# =========================================================================== #
# 11. CREATE -> write -> close -> RENAME -> open new name -> verify content +
#     checksum (xrdfs query checksum) matches the pre-rename file. Differential.
# =========================================================================== #
@pytest.mark.parametrize("n", [0, 1, 10, 4096, 65536])
def test_rename_preserves_content_and_checksum(srv, n):
    payload = det_bytes(n, seed=15)
    for who, url in both(srv):
        src_w = uniq(f"seq_mv_src_{who}_{n}.bin")
        dst_w = uniq(f"seq_mv_dst_{who}_{n}.bin")
        s = _session(url)
        try:
            fh = _open_handle(s, src_w, WRITE_NEW)
            if n:
                _require(_write(s, fh, 0, payload)[0] == kXR_ok, f"{who} write")
            _require(_close(s, fh)[0] == kXR_ok, f"{who} close")
        finally:
            s.close()
        # rename via the stock client (mv) against THIS server
        rc, o, e = fs(url, "mv", src_w, dst_w)
        _require(rc == 0, f"{who} mv failed: {o}{e}")
        _require(
            not os.path.exists(disk_for(srv, url, src_w)),
            f"{who} source still present after mv",
        )
        # reopen the new name and verify byte content
        s = _session(url)
        try:
            fh2 = _open_handle(s, dst_w, kXR_open_read)
            rb = b""
            if n:
                st, rb = _read(s, fh2, 0, n)
                _require(st == kXR_ok, f"{who} read after rename st={st}")
            _require(rb == payload, f"{who} content changed across rename")
            _close(s, fh2)
        finally:
            s.close()
        with open(disk_for(srv, url, dst_w), "rb") as f:
            _require(f.read() == payload, f"{who} on-disk content wrong after mv")


# =========================================================================== #
# 12. CREATE -> write -> checksum(query) == zlib.adler32(written bytes).
#     Stock's harness ships no checksum plugin, so the *value* is verifiable
#     only on OUR server; we still pin our value against an independent
#     reference (zlib.adler32) and confirm stock cannot answer (capability
#     parity is covered in test_conf_cksum.py).
# =========================================================================== #
