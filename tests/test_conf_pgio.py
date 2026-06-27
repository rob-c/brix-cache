from _test_conf_pgio_helpers import *  # noqa: F401,F403  (Phase-38 split shared header)

def test_crc32c_known_vector():
    """The headline integrity primitive must match the published test vector;
    every per-page CRC assertion in this file depends on it being correct."""
    assert crc32c(b"123456789") == 0xE3069283, (
        "software CRC-32C is wrong -- the whole pg-I/O CRC suite is invalid")


# ===========================================================================
# 1) pgread SINGLE PAGE at offset 0: bytes == file[0:4096] AND per-page CRC32c
#    == crc32c(file[0:4096]). On BOTH servers. Parametrised over many files.
# ===========================================================================
@pytest.mark.parametrize("name", list(SZ_FILES) + [DATA_BIN, CKSUM_BIN])
def test_pgread_single_page_off0(srv, name):
    size = len(_local(srv, name))
    rlen = min(PG_PAGE, size)
    if rlen == 0:
        pytest.skip("covered by empty-file test")
    our, off_h = _open_both_read(srv, name)
    try:
        st_o, pg_o = pgread(our.sock, our.fh, 0, rlen)
        st_f, pg_f = pgread(off_h.sock, off_h.fh, 0, rlen)
    finally:
        our.close()
        off_h.close()
    assert st_o == st_f == kXR_ok, f"pgread {name}@0+{rlen}: ours={st_o} stock={st_f}"
    want = _local(srv, name)[0:rlen]
    assert pgread_bytes(pg_o) == want, f"OUR pgread {name} bytes wrong"
    assert len(pg_o) == 1, f"OUR pgread {name}: expected 1 page, got {len(pg_o)}"
    off, page, crc = pg_o[0]
    assert off == 0, f"OUR pgread page offset {off} != 0"
    assert crc == crc32c(page), f"OUR pgread {name} per-page CRC32c wrong"
    assert crc == crc32c(want), "OUR pgread CRC32c != crc of source bytes"
    # Differential: stock must carry identical bytes + identical CRC.
    assert pgread_bytes(pg_f) == want, "stock pgread bytes diverge from source"
    assert pg_o == pg_f, f"pgread {name}@0 diverges from stock (page+CRC)"


@pytest.mark.parametrize("name,off,rlen", _multi_cases())
def test_pgread_multi_page(srv, name, off, rlen):
    our, off_h = _open_both_read(srv, name)
    try:
        st_o, pg_o = pgread(our.sock, our.fh, off, rlen)
        st_f, pg_f = pgread(off_h.sock, off_h.fh, off, rlen)
    finally:
        our.close()
        off_h.close()
    assert st_o == st_f == kXR_ok, (
        f"pgread {name}@{off}+{rlen}: ours={st_o} stock={st_f}")
    src = _local(srv, name)
    want_pages = page_slices(src, off, min(rlen, len(src) - off))
    # Page count + each page's offset/bytes/CRC.
    assert len(pg_o) == len(want_pages), (
        f"OUR pgread {name}@{off}+{rlen}: {len(pg_o)} pages, "
        f"want {len(want_pages)}")
    for i, (wo, wbytes) in enumerate(want_pages):
        po, page, crc = pg_o[i]
        assert po == wo, f"page {i} offset ours={po} want={wo}"
        assert page == wbytes, f"page {i} OUR bytes wrong"
        assert crc == crc32c(wbytes), (
            f"page {i} OUR CRC32c wrong (len {len(wbytes)} short-page CRC)")
    assert pgread_bytes(pg_o) == src[off:off + rlen], "OUR reassembly wrong"
    assert pg_o == pg_f, f"pgread {name}@{off}+{rlen} diverges from stock"


@pytest.mark.parametrize("name,off,rlen", _odd_offset_cases())
def test_pgread_unaligned_first_page(srv, name, off, rlen):
    our, off_h = _open_both_read(srv, name)
    try:
        st_o, pg_o = pgread(our.sock, our.fh, off, rlen)
        st_f, pg_f = pgread(off_h.sock, off_h.fh, off, rlen)
    finally:
        our.close()
        off_h.close()
    assert st_o == st_f == kXR_ok, (
        f"unaligned pgread {name}@{off}+{rlen}: ours={st_o} stock={st_f}")
    src = _local(srv, name)
    eff = min(rlen, len(src) - off)
    want_pages = page_slices(src, off, eff)
    assert len(pg_o) == len(want_pages), (
        f"OUR unaligned pgread {name}@{off}: {len(pg_o)} pages vs {len(want_pages)}")
    # The first page must be short to the next 4096 boundary.
    first_off, first_page, first_crc = pg_o[0]
    expect_first = min(PG_PAGE - (off % PG_PAGE), eff)
    assert first_off == off, f"first page offset {first_off} != requested {off}"
    assert len(first_page) == expect_first, (
        f"OUR first page len {len(first_page)} != short-to-boundary {expect_first}")
    assert first_crc == crc32c(first_page), "OUR short first-page CRC32c wrong"
    for i, (wo, wbytes) in enumerate(want_pages):
        po, page, crc = pg_o[i]
        assert (po, page) == (wo, wbytes), f"page {i} offset/bytes wrong"
        assert crc == crc32c(wbytes), f"page {i} CRC32c wrong"
    assert pg_o == pg_f, f"unaligned pgread {name}@{off} diverges from stock"


# ===========================================================================
# 4) pgread AT / PAST EOF: short/empty parity vs stock.
# ===========================================================================
@pytest.mark.parametrize("name,off,rlen", [
    ("data.bin", DATA_SIZE, 4096),         # start exactly at EOF
    ("data.bin", DATA_SIZE - 1, 4096),     # 1 byte then EOF
    ("data.bin", DATA_SIZE - 100, 4096),   # short tail page
    ("sz_4096.bin", 4096, 4096),           # at EOF, page-aligned file
    ("sz_4097.bin", 4096, 4096),           # 1 trailing byte
    ("sz_65536.bin", 65000, 4096),         # short tail crossing EOF
    ("data.bin", 1 << 30, 4096),           # far past EOF
])
def test_pgread_eof_parity(srv, name, off, rlen):
    our, off_h = _open_both_read(srv, name)
    try:
        st_o, pg_o = pgread(our.sock, our.fh, off, rlen)
        st_f, pg_f = pgread(off_h.sock, off_h.fh, off, rlen)
    finally:
        our.close()
        off_h.close()
    assert st_o == st_f, (
        f"pgread EOF status diverges {name}@{off}+{rlen}: ours={st_o} stock={st_f}")
    if st_o != kXR_ok:
        return
    src = _local(srv, name)
    avail = max(0, len(src) - off)
    want = src[off:off + rlen]
    assert pgread_bytes(pg_o) == want, (
        f"OUR pgread-at-EOF {name}@{off} returned {len(pgread_bytes(pg_o))}B "
        f"want {avail}B")
    for (_po, page, crc) in pg_o:
        assert crc == crc32c(page), "OUR pgread-at-EOF page CRC32c wrong"
    assert pgread_bytes(pg_o) == pgread_bytes(pg_f), "EOF pgread bytes vs stock"


# ===========================================================================
# 5) pgread of EMPTY file: parity vs stock.
# ===========================================================================
def test_pgread_empty_file(srv):
    name = "empty.txt"
    our, off_h = _open_both_read(srv, name)
    try:
        st_o, pg_o = pgread(our.sock, our.fh, 0, 4096)
        st_f, pg_f = pgread(off_h.sock, off_h.fh, 0, 4096)
    finally:
        our.close()
        off_h.close()
    assert st_o == st_f, f"pgread empty: ours={st_o} stock={st_f}"
    if st_o == kXR_ok:
        assert pgread_bytes(pg_o) == b"" == pgread_bytes(pg_f), (
            "empty-file pgread returned bytes")


# ===========================================================================
# 6) pgread REASSEMBLY of big1m -> md5 == source (and == stock). Multi-chunk
#    kXR_status response stitched back together.
# ===========================================================================
@pytest.mark.parametrize("off,rlen", [
    (0, BIG_SIZE),            # whole file
    (0, BIG_SIZE // 2),       # first half
    (BIG_SIZE // 2, BIG_SIZE // 2),  # second half
    (4096, BIG_SIZE - 4096),  # page-aligned tail
    (1, BIG_SIZE - 1),        # unaligned whole-ish
])
def test_pgread_big_reassembly(srv, off, rlen):
    name = BIG_BIN
    our, off_h = _open_both_read(srv, name)
    try:
        st_o, pg_o = pgread(our.sock, our.fh, off, rlen)
        st_f, pg_f = pgread(off_h.sock, off_h.fh, off, rlen)
    finally:
        our.close()
        off_h.close()
    assert st_o == st_f == kXR_ok, f"big pgread @{off}+{rlen}: ours={st_o} stock={st_f}"
    src = _local(srv, name)
    want = src[off:off + rlen]
    got = pgread_bytes(pg_o)
    assert len(got) == len(want), f"OUR big pgread {len(got)}B want {len(want)}B"
    assert hashlib.md5(got).digest() == hashlib.md5(want).digest(), (
        f"OUR big1m pgread @{off}+{rlen} md5 mismatch vs source")
    # Every per-page CRC must be self-consistent on our server.
    for (_po, page, crc) in pg_o:
        assert crc == crc32c(page), "OUR big pgread page CRC32c wrong"
    assert got == pgread_bytes(pg_f), f"big1m pgread @{off}+{rlen} diverges from stock"


@pytest.mark.parametrize("off,rlen", _crc_matrix())
def test_pgread_crc_self_consistent_both(srv, off, rlen):
    name = "sz_65536.bin"
    src = _local(srv, name)
    if off >= len(src):
        pytest.skip("offset past EOF handled by EOF parity test")
    our, off_h = _open_both_read(srv, name)
    try:
        st_o, pg_o = pgread(our.sock, our.fh, off, rlen)
        st_f, pg_f = pgread(off_h.sock, off_h.fh, off, rlen)
    finally:
        our.close()
        off_h.close()
    assert st_o == st_f == kXR_ok, f"crc matrix @{off}+{rlen}: ours={st_o} stock={st_f}"
    for (po, page, crc) in pg_o:
        assert crc == crc32c(page), (
            f"OUR pgread CRC32c WRONG @page {po} (len {len(page)})")
    for (po, page, crc) in pg_f:
        assert crc == crc32c(page), f"stock pgread CRC32c wrong @page {po}"
    assert pgread_bytes(pg_o) == src[off:off + rlen], "OUR bytes != source slice"
    assert pg_o == pg_f, f"pgread @{off}+{rlen} diverges from stock"


# ===========================================================================
# 8) pgread vs plain kXR_read of the SAME range: identical data bytes.
# ===========================================================================
@pytest.mark.parametrize("name,off,rlen", [
    ("sz_65536.bin", 0, 4096),
    ("sz_65536.bin", 0, 16384),
    ("sz_65536.bin", 100, 5000),
    ("sz_65536.bin", 4096, 8192),
    ("data.bin", 0, 4096),
    ("cksum.bin", 0, 10000),
    ("big1m.bin", 0, 65536),
    ("sz_4097.bin", 0, 4097),
])
def test_pgread_equals_plain_read(srv, name, off, rlen):
    our = _Handle(*srv["our_hp"], name)
    try:
        st_pg, pg = pgread(our.sock, our.fh, off, rlen)
        st_rd, rd = _read_drain(our.sock, our.fh, off, rlen)
    finally:
        our.close()
    assert st_pg == kXR_ok and st_rd == kXR_ok, (
        f"pgread/read {name}@{off}+{rlen}: pg={st_pg} read={st_rd}")
    assert pgread_bytes(pg) == rd, (
        f"OUR pgread bytes != plain read bytes for {name}@{off}+{rlen}")


# ===========================================================================
# 9) pgUnitSZ framing constant honoured: a full-page pgread carries exactly
#    4 CRC bytes + 4096 data bytes == kXR_pgUnitSZ (4100) per page.
# ===========================================================================
@pytest.mark.parametrize("npages", [1, 2, 4])
def test_pgread_unit_size_framing(srv, npages):
    name = "sz_65536.bin"
    rlen = PG_PAGE * npages
    our, off_h = _open_both_read(srv, name)
    try:
        st_o, pg_o = pgread(our.sock, our.fh, 0, rlen)
        st_f, pg_f = pgread(off_h.sock, off_h.fh, 0, rlen)
    finally:
        our.close()
        off_h.close()
    assert st_o == st_f == kXR_ok
    assert len(pg_o) == npages == len(pg_f)
    for (_po, page, _crc) in pg_o:
        # full page: data == 4096, the unit (crc+data) == 4100.
        assert len(page) == PG_PAGE, "OUR full page != 4096 data bytes"
        assert PG_CRC + len(page) == PG_UNIT, "pgUnitSZ (4100) framing wrong"
    assert pg_o == pg_f, "pgread unit framing diverges from stock"


# ===========================================================================
# 10) pgwrite SINGLE PAGE: open new, write one page with correct CRC, read
#     back == written; on-disk size correct. Parametrise page sizes incl short.
# ===========================================================================
@pytest.mark.parametrize("size", [1, 100, 4095, 4096])
def test_pgwrite_single_page(srv, size):
    data = bytes((i * 31 + 7) & 0xFF for i in range(size))
    rel = f"pgw_single_{size}.bin"
    our = _our_writer(srv, rel, WR_NEW)
    off_h = _off_writer(srv, rel, WR_NEW)
    try:
        st_o, ofo, cse_o = pgwrite(our.sock, our.fh, 0, data)
        st_f, off_off, cse_f = pgwrite(off_h.sock, off_h.fh, 0, data)
    finally:
        our.close()
        off_h.close()
    assert st_o == st_f == kXR_ok, (
        f"pgwrite single {size}: ours={st_o} stock={st_f}")
    assert cse_o == b"" == cse_f, "clean pgwrite must report no CRC errors"
    assert ofo == off_off, (
        f"pgwrite info offset diverges from stock: ours={ofo} stock={off_off}")
    # On-disk content + size, byte-exact on our server.
    our_path = os.path.join(srv["our_data"], rel)
    assert os.path.getsize(our_path) == size, "OUR pgwrite on-disk size wrong"
    with open(our_path, "rb") as f:
        assert f.read() == data, "OUR pgwrite on-disk content wrong"
    # Read it back over the wire too (and parity vs stock's file).
    back = _readback(*srv["our_hp"], rel, size)
    assert back == data, "OUR pgwrite read-back != written bytes"
    off_path = os.path.join(srv["off_data"], rel)
    with open(off_path, "rb") as f:
        assert f.read() == data, "stock pgwrite on-disk content diverges"


# ===========================================================================
# 11) pgwrite MULTI-PAGE + short final page: file content byte-exact vs an
#     independently built buffer (and vs stock's file). Parametrise sizes.
# ===========================================================================
@pytest.mark.parametrize("size", [4097, 8192, 8193, 10000, 65536, 100000])
def test_pgwrite_multi_page(srv, size):
    data = bytes((i * 17 + 3) & 0xFF for i in range(size))
    rel = f"pgw_multi_{size}.bin"
    our = _our_writer(srv, rel, WR_NEW)
    off_h = _off_writer(srv, rel, WR_NEW)
    try:
        st_o, _ofo, cse_o = pgwrite(our.sock, our.fh, 0, data)
        st_f, _off, cse_f = pgwrite(off_h.sock, off_h.fh, 0, data)
    finally:
        our.close()
        off_h.close()
    assert st_o == st_f == kXR_ok, f"pgwrite multi {size}: ours={st_o} stock={st_f}"
    assert cse_o == b"" == cse_f, "clean multi-page pgwrite reported CRC errors"
    our_path = os.path.join(srv["our_data"], rel)
    off_path = os.path.join(srv["off_data"], rel)
    assert os.path.getsize(our_path) == size, "OUR multi pgwrite size wrong"
    with open(our_path, "rb") as f:
        assert f.read() == data, "OUR multi-page pgwrite content wrong"
    with open(off_path, "rb") as f:
        assert f.read() == data, "stock multi-page pgwrite content diverges"
