import time

from split_continuation import reexport as _reexport
_reexport(globals(), "_test_conf_pgio_helpers")


def _corruption_detected(status, cse):
    if status == kXR_error:
        return True
    return status == kXR_ok and bool(cse)


def _assert_corruption_detected(our_result, stock_result, size, bad):
    st_o, cse_o = our_result
    st_f, cse_f = stock_result
    assert _corruption_detected(st_f, cse_f), (
        "stock did not flag a corrupt page (tooling/assumption?)")
    assert _corruption_detected(st_o, cse_o), (
        f"OUR server ACCEPTED a corrupt pgwrite page (size={size} bad={bad}) "
        "without flagging it -- silent data corruption")


def _assert_rejection_shape(our_status, stock_status):
    assert (our_status == kXR_error) == (stock_status == kXR_error), (
        f"corrupt-page rejection diverges from stock: ours st={our_status} "
        f"stock st={stock_status}")


def _assert_cse_page_if_reported(our_result, stock_result, size, bad):
    st_o, cse_o = our_result
    st_f, cse_f = stock_result
    if st_o != kXR_ok or st_f != kXR_ok:
        return
    assert len(cse_o) >= 8 and len(cse_f) >= 8, "CSE list too short"
    bad_off = sum(page_lengths(0, size)[:bad])
    offs_o = _cse_offsets(cse_o)
    assert bad_off in offs_o, (
        f"OUR CSE list {offs_o} missing corrupt page offset {bad_off}")


def _assert_sparse_status(our_result, stock_result, offset, size):
    st_o, ofo, cse_o = our_result
    st_f, off2, cse_f = stock_result
    assert st_o == st_f == kXR_ok, (
        f"sparse pgwrite @{offset}+{size}: ours={st_o} stock={st_f}")
    assert cse_o == b"" == cse_f, "clean sparse pgwrite reported CRC errors"
    assert ofo == off2, (
        f"sparse pgwrite info offset diverges from stock: ours={ofo} stock={off2}")


def _assert_sparse_our_file(path, offset, size, data):
    assert os.path.getsize(path) == offset + size, "OUR sparse size wrong"
    with open(path, "rb") as stream:
        got = stream.read()
    assert got[:offset] == b"\x00" * offset, "OUR sparse hole not zero-filled"
    assert got[offset:] == data, "OUR sparse written page wrong"


def _assert_file_bytes(path, expected, message):
    with open(path, "rb") as stream:
        assert stream.read() == expected, message


def _assert_roundtrip_pages(pages, expected_pages):
    assert len(pages) == len(expected_pages), "roundtrip page count wrong"
    for index, (offset, expected) in enumerate(expected_pages):
        page_offset, page, crc = pages[index]
        assert (page_offset, page) == (offset, expected), (
            f"roundtrip page {index} bytes/offset wrong")
        assert crc == crc32c(expected), f"roundtrip page {index} CRC32c wrong"


def _write_initial_file(writer, srv, rel, content):
    handle = writer(srv, rel, WR_NEW)
    try:
        status, _offset, cse = pgwrite(handle.sock, handle.fh, 0, content)
    finally:
        handle.close()
    assert status == kXR_ok and cse == b""


def _overwrite_pair(srv, rel, content):
    our = _our_writer(srv, rel, kXR_open_updt)
    stock = _off_writer(srv, rel, kXR_open_updt)
    try:
        our_result = pgwrite(our.sock, our.fh, 0, content)
        stock_result = pgwrite(stock.sock, stock.fh, 0, content)
    finally:
        our.close()
        stock.close()
    return our_result, stock_result


def _assert_overwrite_status(our_result, stock_result, size):
    st_o, _offset_o, cse_o = our_result
    st_f, _offset_f, cse_f = stock_result
    assert st_o == st_f == kXR_ok, f"overwrite {size}: ours={st_o} stock={st_f}"
    assert cse_o == b"" == cse_f

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
    our_result = (st_o, cse_o)
    stock_result = (st_f, cse_f)
    _assert_corruption_detected(our_result, stock_result, size, bad)
    _assert_rejection_shape(st_o, st_f)
    _assert_cse_page_if_reported(our_result, stock_result, size, bad)


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
    _assert_sparse_status(
        (st_o, ofo, cse_o), (st_f, off2, cse_f), offset, size)
    expect = b"\x00" * offset + data
    our_path = os.path.join(srv["our_data"], rel)
    off_path = os.path.join(srv["off_data"], rel)
    _assert_sparse_our_file(our_path, offset, size, data)
    _assert_file_bytes(off_path, expect, "stock sparse pgwrite content diverges")


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
    _assert_roundtrip_pages(pages, want_pages)
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
    for writer in (_our_writer, _off_writer):
        _write_initial_file(writer, srv, rel, init)
    our_result, stock_result = _overwrite_pair(srv, rel, new)
    _assert_overwrite_status(our_result, stock_result, size)
    _assert_file_bytes(
        os.path.join(srv["our_data"], rel), new, "OUR overwrite content wrong")
    _assert_file_bytes(
        os.path.join(srv["off_data"], rel), new,
        "stock overwrite content diverges")


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
# 19) pgread request args (parity-audit §1.2): the OPTIONAL payload carries
#     pathid (byte 0, dlen >= 1) + reqflags (byte 1, dlen >= 2).  Stock
#     5.6.9, verified live: any payload length is tolerated, unknown flag
#     bits are ignored, and the ONE hard rule is that a nonzero pathid must
#     name a live kXR_bind path of this session — anything else is
#     kXR_ArgInvalid "invalid path ID".
# ===========================================================================
kXR_ArgInvalid_code = 3000
kXR_bind_req = 3024


def _pgread_payload(sock, fh, offset, rlen, payload, streamid=b"\x00\x17"):
    """pgread with an explicit raw args payload; returns (status, code_or_data).

    kXR_error → ("error", numeric code); kXR_status → ("status", data bytes,
    drained from this one message only — enough for the small reads here)."""
    req = struct.pack("!2sH4sqiI", streamid, kXR_pgread, fh,
                      offset, rlen, len(payload))
    sock.sendall(req + payload)
    _sid, status, hdrbody = _read_response(sock)
    if status == kXR_error:
        (code,) = struct.unpack("!i", hdrbody[:4])
        return ("error", code)
    assert status == kXR_status, f"expected kXR_status/kXR_error, got {status}"
    (data_dlen,) = struct.unpack("!i", hdrbody[12:16])
    data = _recv_exact(sock, data_dlen) if data_dlen > 0 else b""
    return ("status", data)


@pytest.mark.parametrize("payload", [
    b"\x00\x00",          # canonical args: pathid 0, no flags
    b"\x00",              # short payload: pathid only
    b"\x00\x00\x00",      # long payload: trailing byte tolerated
    b"\x00\x80",          # unknown flag bit: ignored
])
def test_pgread_args_pathid_zero_tolerated(srv, payload):
    """(success, differential) every stock-tolerated payload shape with
    pathid 0 serves normally on BOTH servers."""
    our, off_h = _open_both_read(srv, "data.bin")
    try:
        st_o = _pgread_payload(our.sock, our.fh, 0, 4096, payload)
        st_f = _pgread_payload(off_h.sock, off_h.fh, 0, 4096, payload)
    finally:
        our.close()
        off_h.close()
    assert st_o[0] == "status" and st_f[0] == "status", (payload, st_o, st_f)
    assert st_o[1] == st_f[1], f"payload {payload!r}: data diverges from stock"


def test_pgread_args_invalid_pathid_refused(srv):
    """(error, differential) a pathid that names no bound path of this
    session is kXR_ArgInvalid on BOTH servers — the request must not be
    served as if untagged (BriX used to ignore the payload entirely)."""
    our, off_h = _open_both_read(srv, "data.bin")
    try:
        st_o = _pgread_payload(our.sock, our.fh, 0, 4096, b"\x63\x00")
        st_f = _pgread_payload(off_h.sock, off_h.fh, 0, 4096, b"\x63\x00")
    finally:
        our.close()
        off_h.close()
    assert st_o == ("error", kXR_ArgInvalid_code), st_o
    assert st_f == ("error", kXR_ArgInvalid_code), st_f


def _login_sessid(sock):
    """kXR_login capturing the 16-byte sessid the server issued."""
    req = struct.pack("!2sHI8sBBBBI", b"\x00\x01", kXR_login,
                      os.getpid() & 0x7fffffff, b"pytest\x00\x00",
                      0, 0, 0, 0, 0)
    sock.sendall(req)
    _sid, status, body = _read_response(sock)
    assert status == kXR_ok, f"login failed: {status}"
    assert len(body) >= 16, f"login body too short for a sessid: {len(body)}"
    return body[:16]


def test_pgread_args_bound_pathid_lifecycle(srv):
    """(security-neg) a pathid is valid exactly while its bound secondary
    lives: accepted after kXR_bind, refused again after the secondary
    disconnects — a retired data path cannot be replayed.  OURS-only: stock
    answers a bound-path pgread on the BOUND socket (response offloading,
    audit §1.1) while BriX still answers on the control stream, so the
    response-read topology differs; the VALIDATION contract under test is
    identical on both."""
    host, port = srv["our_hp"]
    sock = _handshake(host, port)
    try:
        sessid = _login_sessid(sock)
        _sid, st, body = _open(sock, _wire_path("data.bin"))
        assert st == kXR_ok, f"open failed: {st}"
        fh = body[:4]

        sec = _handshake(host, port)
        try:
            sec.sendall(struct.pack("!2sH16sI", b"\x00\x24", kXR_bind_req,
                                    sessid, 0))
            _sid2, st2, body2 = _read_response(sec)
            if st2 != kXR_ok:
                pytest.skip(f"kXR_bind refused (substreams off?): {st2}")
            pathid = body2[0]
            assert 1 <= pathid <= 253

            st_tagged = _pgread_payload(sock, fh, 0, 4096,
                                        bytes([pathid, 0]))
            assert st_tagged[0] == "status", (
                f"live bound pathid {pathid} refused: {st_tagged}")
        finally:
            sec.close()

        # The secondary is gone: its pathid must be refused once the server
        # has processed the disconnect (poll briefly for determinism).
        deadline = time.monotonic() + 5.0
        verdict = None
        while time.monotonic() < deadline:
            verdict = _pgread_payload(sock, fh, 0, 4096, bytes([pathid, 0]))
            if verdict == ("error", kXR_ArgInvalid_code):
                break
            time.sleep(0.1)
        assert verdict == ("error", kXR_ArgInvalid_code), (
            f"retired pathid {pathid} still accepted: {verdict}")
    finally:
        sock.close()


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
