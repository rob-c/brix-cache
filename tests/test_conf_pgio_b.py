from _test_conf_pgio_helpers import *  # noqa: F401,F403  (Phase-38 split shared header)

# ===========================================================================
# 12) pgwrite with a WRONG CRC32c: the server MUST detect the corrupt page.
#     Stock returns a kXR_status carrying a ServerResponseBody_pgWrCSE list
#     (cseCRC[4] dlFirst[2] dlLast[2] then offsets) -- i.e. non-empty CSE
#     data. Both servers must flag (not silently accept) the bad page.
# ===========================================================================
@pytest.mark.parametrize("size,bad", [
    (4096, 0),       # single page corrupt
    (8192, 0),       # first of two corrupt
    (8192, 1),       # second of two corrupt
    (10000, 2),      # short final page corrupt
])
def test_pgwrite_corrupt_page_rejected(srv, size, bad):
    data = bytes((i * 13 + 5) & 0xFF for i in range(size))
    rel = f"pgw_bad_{size}_{bad}.bin"
    our = _our_writer(srv, rel, WR_NEW)
    off_h = _off_writer(srv, rel, WR_NEW)
    try:
        st_o, _ofo, cse_o = pgwrite(our.sock, our.fh, 0, data, corrupt_index=bad)
        st_f, _off, cse_f = pgwrite(off_h.sock, off_h.fh, 0, data, corrupt_index=bad)
    finally:
        our.close()
        off_h.close()
    # The corrupt page MUST be detected: either an error status OR a non-empty
    # CSE retransmit list in the kXR_status response. Silent acceptance (kXR_ok
    # with empty CSE) is a server bug.
    detected_o = (st_o == kXR_error) or (st_o == kXR_ok and len(cse_o) > 0)
    detected_f = (st_f == kXR_error) or (st_f == kXR_ok and len(cse_f) > 0)
    assert detected_f, "stock did not flag a corrupt page (tooling/assumption?)"
    assert detected_o, (
        f"OUR server ACCEPTED a corrupt pgwrite page (size={size} bad={bad}) "
        f"without flagging it -- silent data corruption")
    # The detection SHAPE must match stock (both error, or both CSE-list).
    assert (st_o == kXR_error) == (st_f == kXR_error), (
        f"corrupt-page rejection diverges from stock: ours st={st_o} "
        f"stock st={st_f}")
    if st_o == kXR_ok and st_f == kXR_ok:
        # Both report via CSE list: the bad-page offset must be present. The
        # CSE body is cseCRC[4] dlFirst[2] dlLast[2] then int64 offsets.
        assert len(cse_o) >= 8 and len(cse_f) >= 8, "CSE list too short"
        bad_off = sum(page_lengths(0, size)[:bad])
        offs_o = _cse_offsets(cse_o)
        assert bad_off in offs_o, (
            f"OUR CSE list {offs_o} missing corrupt page offset {bad_off}")


# ===========================================================================
# 12b) Differential CSE parity: the FULL retransmit list (offsets + dlFirst/
#      dlLast), the close gate, and retry-correction must match stock exactly.
# ===========================================================================
@pytest.mark.parametrize("size,bad", [
    (4096 * 3, [0, 2]),         # two full-page corruptions
    (4096 * 2 + 500, [0, 1, 2]),  # all three incl short final
    (4096 * 4, [1, 3]),
])
def test_pgwrite_cse_list_matches_stock(srv, size, bad):
    data = bytes((i * 7 + 3) & 0xFF for i in range(size))
    rel = f"pgw_cselist_{size}_{'_'.join(map(str, bad))}.bin"
    our = _our_writer(srv, rel, WR_NEW)
    off_h = _off_writer(srv, rel, WR_NEW)
    try:
        # Corrupt the same pages on both by issuing per-page flips through the
        # builder: build a payload that corrupts the first listed page, then
        # patch the rest. Simplest: corrupt each independently via repeated XOR.
        payload_o = _corrupt_pages(data, 0, bad)
        payload_f = payload_o
        st_o, _o, cse_o = _send_raw_pgwrite(our.sock, our.fh, 0, payload_o)
        st_f, _f, cse_f = _send_raw_pgwrite(off_h.sock, off_h.fh, 0, payload_f)
    finally:
        our.close()
        off_h.close()
    assert st_o == kXR_ok and st_f == kXR_ok, (st_o, st_f)
    assert _cse_offsets(cse_o) == _cse_offsets(cse_f), "CSE offset list diverges"
    assert _cse_lengths(cse_o) == _cse_lengths(cse_f), "dlFirst/dlLast diverge"


def test_pgwrite_cse_close_gate_matches_stock(srv):
    data = bytes((i * 11 + 1) & 0xFF for i in range(4096))
    rel = "pgw_cse_closegate.bin"
    our = _our_writer(srv, rel, WR_NEW)
    off_h = _off_writer(srv, rel, WR_NEW)
    try:
        _send_raw_pgwrite(our.sock, our.fh, 0, _corrupt_pages(data, 0, [0]))
        _send_raw_pgwrite(off_h.sock, off_h.fh, 0, _corrupt_pages(data, 0, [0]))
        _so, st_o, _bo = _close(our.sock, our.fh)
        _sf, st_f, _bf = _close(off_h.sock, off_h.fh)
    finally:
        our.sock.close()
        off_h.sock.close()
    assert st_o == st_f == kXR_error, (st_o, st_f)


def test_pgwrite_cse_retry_then_close_matches_stock(srv):
    data = bytes((i * 5 + 9) & 0xFF for i in range(4096 * 2))
    rel = "pgw_cse_retry_close.bin"
    our = _our_writer(srv, rel, WR_NEW)
    off_h = _off_writer(srv, rel, WR_NEW)
    try:
        for h in (our, off_h):
            _send_raw_pgwrite(h.sock, h.fh, 0, _corrupt_pages(data, 0, [1]))
            # Resend page 1 correctly.
            st, _o, cse = _retry_one_page(h.sock, h.fh, 0, data, 1)
            assert st == kXR_ok and len(cse) == 0, "retry should verify clean"
        _so, st_o, _bo = _close(our.sock, our.fh)
        _sf, st_f, _bf = _close(off_h.sock, off_h.fh)
    finally:
        our.sock.close()
        off_h.sock.close()
    assert st_o == st_f == kXR_ok, (st_o, st_f)


# ===========================================================================
# 13) pgwrite at OFFSET (sparse): hole reads back as zero, the written page is
#     correct, on-disk size == offset+len. Parity vs stock's file.
# ===========================================================================
@pytest.mark.parametrize("offset,size", [
    (4096, 4096),     # one-page hole then a page
    (8192, 100),      # two-page hole then short page
    (4096, 8192),     # hole then two pages
    (100, 4096),      # unaligned write past a small hole
])
def test_pgwrite_sparse_offset(srv, offset, size):
    data = bytes((i * 7 + 1) & 0xFF for i in range(size))
    rel = f"pgw_sparse_{offset}_{size}.bin"
    our = _our_writer(srv, rel, WR_NEW)
    off_h = _off_writer(srv, rel, WR_NEW)
    try:
        st_o, ofo, cse_o = pgwrite(our.sock, our.fh, offset, data)
        st_f, off2, cse_f = pgwrite(off_h.sock, off_h.fh, offset, data)
    finally:
        our.close()
        off_h.close()
    assert st_o == st_f == kXR_ok, (
        f"sparse pgwrite @{offset}+{size}: ours={st_o} stock={st_f}")
    assert cse_o == b"" == cse_f, "clean sparse pgwrite reported CRC errors"
    assert ofo == off2, (
        f"sparse pgwrite info offset diverges from stock: ours={ofo} stock={off2}")
    expect = b"\x00" * offset + data
    our_path = os.path.join(srv["our_data"], rel)
    off_path = os.path.join(srv["off_data"], rel)
    assert os.path.getsize(our_path) == offset + size, "OUR sparse size wrong"
    with open(our_path, "rb") as f:
        got = f.read()
    assert got[:offset] == b"\x00" * offset, "OUR sparse hole not zero-filled"
    assert got[offset:] == data, "OUR sparse written page wrong"
    with open(off_path, "rb") as f:
        assert f.read() == expect, "stock sparse pgwrite content diverges"


# ===========================================================================
# 14) pgwrite then pgread round-trip: write a multi-page buffer, read it back
#     via pgread, and verify every per-page CRC + bytes. End-to-end on OUR
#     server, with the source buffer as the oracle.
# ===========================================================================
@pytest.mark.parametrize("size", [4096, 4097, 8192, 10000, 20000])
def test_pgwrite_then_pgread_roundtrip(srv, size):
    data = bytes((i * 19 + 11) & 0xFF for i in range(size))
    rel = f"pgw_rt_{size}.bin"
    w = _our_writer(srv, rel, WR_NEW)
    try:
        st, _ofo, cse = pgwrite(w.sock, w.fh, 0, data)
    finally:
        w.close()
    assert st == kXR_ok and cse == b"", f"pgwrite roundtrip {size} failed"
    r = _Handle(*srv["our_hp"], rel, options=kXR_open_read)
    try:
        st_r, pages = pgread(r.sock, r.fh, 0, size)
    finally:
        r.close()
    assert st_r == kXR_ok, "pgread of written file failed"
    want_pages = page_slices(data, 0, size)
    assert len(pages) == len(want_pages), "roundtrip page count wrong"
    for i, (wo, wbytes) in enumerate(want_pages):
        po, page, crc = pages[i]
        assert (po, page) == (wo, wbytes), f"roundtrip page {i} bytes/offset wrong"
        assert crc == crc32c(wbytes), f"roundtrip page {i} CRC32c wrong"
    assert pgread_bytes(pages) == data, "roundtrip reassembly != source"


# ===========================================================================
# 15) pgwrite OVERWRITE of an existing file region (open updt, write at offset
#     0 over data): content matches and parity vs stock.
# ===========================================================================
@pytest.mark.parametrize("size", [4096, 8192])
def test_pgwrite_overwrite_region(srv, size):
    init = bytes((i * 3) & 0xFF for i in range(size))
    new = bytes((255 - (i & 0xFF)) for i in range(size))
    rel = f"pgw_ovr_{size}.bin"
    # Create both files with identical initial content.
    for writer in (_our_writer, _off_writer):
        h = writer(srv, rel, WR_NEW)
        try:
            st, _o, c = pgwrite(h.sock, h.fh, 0, init)
            assert st == kXR_ok and c == b""
        finally:
            h.close()
    # Reopen for update and overwrite.
    our = _our_writer(srv, rel, kXR_open_updt)
    off_h = _off_writer(srv, rel, kXR_open_updt)
    try:
        st_o, _o, cse_o = pgwrite(our.sock, our.fh, 0, new)
        st_f, _f, cse_f = pgwrite(off_h.sock, off_h.fh, 0, new)
    finally:
        our.close()
        off_h.close()
    assert st_o == st_f == kXR_ok, f"overwrite {size}: ours={st_o} stock={st_f}"
    assert cse_o == b"" == cse_f
    with open(os.path.join(srv["our_data"], rel), "rb") as f:
        assert f.read() == new, "OUR overwrite content wrong"
    with open(os.path.join(srv["off_data"], rel), "rb") as f:
        assert f.read() == new, "stock overwrite content diverges"


# ===========================================================================
# 16) INTEGRITY: pgwrite a buffer, then download via stock xrdcp -> bytes
#     match. The raw pgwrite path and the high-level read path must agree.
# ===========================================================================
@pytest.mark.parametrize("size", [4096, 10000, 65536])
def test_pgwrite_then_xrdcp_download(srv, tmp_path, size):
    data = bytes((i * 23 + 9) & 0xFF for i in range(size))
    rel = f"pgw_dl_{size}.bin"
    w = _our_writer(srv, rel, WR_NEW)
    try:
        st, _o, cse = pgwrite(w.sock, w.fh, 0, data)
    finally:
        w.close()
    assert st == kXR_ok and cse == b"", "pgwrite for xrdcp download failed"
    dst = str(tmp_path / f"dl_{rel}")
    rc, out, err = L.run([L.OFF_XRDCP, "-f", f"{srv['our']}//{rel}", dst],
                         timeout=90)
    assert rc == 0, f"xrdcp download of pgwritten {rel} failed: {out}{err}"
    with open(dst, "rb") as f:
        assert f.read() == data, "xrdcp download != pgwritten bytes"


# ===========================================================================
# 17) INTEGRITY: stock xrdcp UPLOAD a file, then pgread it back -> every CRC
#     valid and bytes match the uploaded source. End-to-end the other way.
# ===========================================================================
@pytest.mark.parametrize("size", [4096, 10000, 65536])
def test_xrdcp_upload_then_pgread(srv, tmp_path, size):
    data = bytes((i * 29 + 4) & 0xFF for i in range(size))
    src_path = str(tmp_path / f"up_{size}.bin")
    with open(src_path, "wb") as f:
        f.write(data)
    rel = f"pgup_{size}.bin"
    rc, out, err = L.run([L.OFF_XRDCP, "-f", src_path, f"{srv['our']}//{rel}"],
                         timeout=90)
    assert rc == 0, f"xrdcp upload to OUR server failed: {out}{err}"
    r = _Handle(*srv["our_hp"], rel, options=kXR_open_read)
    try:
        st, pages = pgread(r.sock, r.fh, 0, size)
    finally:
        r.close()
    assert st == kXR_ok, "pgread of xrdcp-uploaded file failed"
    for (_po, page, crc) in pages:
        assert crc == crc32c(page), "pgread of uploaded file has wrong CRC32c"
    assert pgread_bytes(pages) == data, "pgread of uploaded file != source"


# ===========================================================================
# 18) pgread with kXR_pgRetry flag set (verify): a normal read should still
#     return correct bytes + CRCs and match stock. Pins the reqflags path.
# ===========================================================================
@pytest.mark.parametrize("name,off,rlen", [
    ("sz_65536.bin", 0, 8192),
    ("sz_65536.bin", 100, 5000),
    ("data.bin", 0, 4096),
])
def test_pgread_retry_flag(srv, name, off, rlen):
    our, off_h = _open_both_read(srv, name)
    try:
        st_o, pg_o = pgread(our.sock, our.fh, off, rlen, reqflags=kXR_pgRetry)
        st_f, pg_f = pgread(off_h.sock, off_h.fh, off, rlen, reqflags=kXR_pgRetry)
    finally:
        our.close()
        off_h.close()
    assert st_o == st_f, f"pgread retry-flag status diverges: ours={st_o} stock={st_f}"
    if st_o != kXR_ok:
        return
    src = _local(srv, name)
    assert pgread_bytes(pg_o) == src[off:off + rlen], "OUR retry-flag pgread bytes wrong"
    for (_po, page, crc) in pg_o:
        assert crc == crc32c(page), "OUR retry-flag pgread CRC32c wrong"
    assert pgread_bytes(pg_o) == pgread_bytes(pg_f), "retry-flag pgread vs stock"


# ===========================================================================
# 19) pgread rlen invalid (negative): error parity vs stock.
# ===========================================================================
@pytest.mark.parametrize("rlen", [-1, -4096])
def test_pgread_negative_len_parity(srv, rlen):
    name = "sz_65536.bin"
    our, off_h = _open_both_read(srv, name)
    try:
        try:
            st_o, _ = pgread(our.sock, our.fh, 0, rlen)
        except ConnectionError:
            st_o = kXR_error
        try:
            st_f, _ = pgread(off_h.sock, off_h.fh, 0, rlen)
        except ConnectionError:
            st_f = kXR_error
    finally:
        our.close()
        off_h.close()
    assert st_o == st_f, (
        f"pgread negative-len status diverges: ours={st_o} stock={st_f}")


# ===========================================================================
# Oracle: stock xrdcp stock->stock on a multi-page file, proving the tooling
# is sound (a failure here is environmental, not ours).
# ===========================================================================
def test_oracle_stock_to_stock(srv, tmp_path):
    dst = str(tmp_path / "oracle.bin")
    rc, out, err = L.run([L.OFF_XRDCP, "-f", f"{srv['off']}//cksum.bin", dst])
    assert rc == 0, f"oracle stock->stock failed (tooling broken): {out}{err}"
    with open(dst, "rb") as f:
        assert f.read() == _local(srv, "cksum.bin")
