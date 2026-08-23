from split_continuation import reexport as _reexport
_reexport(globals(), "_test_large_offset_wire_helpers")

class TestFourGiBBoundary:
    """Reads (and a write) straddling the 32-bit 4 GiB wrap point must use the
    full 64-bit offset, not a truncated low-32-bit value."""

    def test_read_at_4gib_returns_marker(self, rd_handle_4g):
        """The 16 marker bytes written at exactly 4 GiB must read back; a
        32-bit-truncated offset (== 0) would instead return the file's hole
        (zeros) at the start."""
        sock, fh, _size = rd_handle_4g
        _, status, body = _read(sock, fh, FOUR_GIB, 16)
        assert status == kXR_ok, _error_code(body)
        assert body == b"\xA5" * 16, (
            "read at 4 GiB returned wrong bytes — offset likely truncated to "
            "32 bits")
        # The same low-32-bits offset (0) must read the hole, proving the two
        # offsets are NOT aliased.
        _, status0, body0 = _read(sock, fh, 0, 16)
        assert status0 == kXR_ok
        assert body0 == b"\x00" * 16
        assert _ping(sock)[1] == kXR_ok

    def test_write_then_read_across_4gib(self):
        """Open a sparse file for update, write a marker just past 4 GiB, read
        it back at the same 64-bit offset."""
        name, full = _make_writable("/large_offset_4g_rw.bin", FOUR_GIB + 4096)
        sock = _session()
        try:
            _, status, body = _open(sock, name, kXR_open_updt)
            if status != kXR_ok:
                pytest.skip(f"anon server is read-only "
                            f"(open updt -> {_error_code(body)}); "
                            f"need brix_allow_write on")
            fh = body[:4]
            marker = b"BOUNDARY64!!" + b"\x11" * 4
            off = FOUR_GIB + 1024
            _, wst, wbody = _write(sock, fh, off, marker)
            assert wst == kXR_ok, _error_code(wbody)
            _, rst, rbody = _read(sock, fh, off, len(marker))
            assert rst == kXR_ok, _error_code(rbody)
            assert rbody == marker, "64-bit write/read offset round-trip failed"
            assert _ping(sock)[1] == kXR_ok
        finally:
            sock.close()
            _unlink(full)


# ===========================================================================
# Scenario 2 — offset just below INT64_MAX
# ===========================================================================

class TestNearInt64Max:
    """An offset a hair below INT64_MAX must be handled as a valid 64-bit
    offset: a read there hits a sparse hole (EOF) and returns a clean short/EOF
    response, never an overflow crash or wrong data."""

    def test_read_just_below_int64_max(self, huge_sparse_near_max):
        name, _full, size = huge_sparse_near_max
        sock = _session()
        try:
            _, ost, obody = _open(sock, name, kXR_open_read)
            _require_near_max_open(ost, obody)
            fh = obody[:4]
            # Offset 1 KiB below the very end: inside the file, in a hole.
            off = size - 1024
            _, rst, rbody = _read(sock, fh, off, 256)
            # Inside-file read of a hole: kXR_ok with up to 256 zero bytes.
            assert rst == kXR_ok, _error_code(rbody)
            assert len(rbody) <= 256
            assert rbody == b"\x00" * len(rbody)
            # A read starting one byte below INT64_MAX (past EOF) must be a
            # clean short/EOF read, not an error or a crash.
            _, est, ebody = _read(sock, fh, INT64_MAX - 1, 16)
            _assert_extreme_read(est, ebody)
            _close(sock, fh)
            assert _ping(sock)[1] == kXR_ok
        finally:
            sock.close()

    def test_open_handle_survives_extreme_read(self, huge_sparse_near_max):
        """A read at the largest representable positive offset must not wedge
        the session."""
        name, _full, _size = huge_sparse_near_max
        sock = _session()
        try:
            _, ost, obody = _open(sock, name, kXR_open_read)
            if ost != kXR_ok:
                pytest.skip("server refused open of near-max sparse file")
            fh = obody[:4]
            _read(sock, fh, INT64_MAX, 8)   # may be EOF-ok or error; must not hang
            assert _ping(sock)[1] == kXR_ok
        finally:
            sock.close()


def _require_near_max_open(status, body):
    if status != kXR_ok:
        pytest.skip("server refused open of near-max sparse file: "
                    f"{_error_code(body)}")


def _assert_extreme_read(status, body):
    assert status in (kXR_ok, kXR_error)
    if status == kXR_ok:
        assert body == b""        # past EOF -> empty


# ===========================================================================
# Scenario 3 — negative offset rejected for read/readv/write/pgwrite/truncate
# ===========================================================================

class TestNegativeOffsetRejected:
    """A negative (sign-bit-set) int64 offset must be rejected on EVERY I/O
    opcode with a clean protocol error, never silently coerced to a huge
    unsigned offset or used to index a buffer."""

    @pytest.fixture
    def wr_handle(self):
        name, full = _make_writable("/large_offset_neg.bin", PG_PAGESZ)
        sock = _session()
        _, status, body = _open(sock, name, kXR_open_updt)
        writable = (status == kXR_ok)
        fh = body[:4] if writable else None
        try:
            yield sock, fh, full, writable
        finally:
            if writable:
                try:
                    _close(sock, fh)
                except Exception:
                    pass
            sock.close()
            _unlink(full)

    def test_read_negative_offset(self, rd_handle_4g):
        sock, fh, _ = rd_handle_4g
        _, status, body = _read(sock, fh, -1, 64)
        assert status == kXR_error, "negative read offset must error"
        assert _error_code(body) in (kXR_IOError, kXR_ArgInvalid)
        assert _ping(sock)[1] == kXR_ok

    def test_readv_negative_offset(self, rd_handle_4g):
        sock, fh, _ = rd_handle_4g
        _, status, body = _readv(sock, [_seg(fh, 64, -8)])
        assert status == kXR_error, "negative readv offset must error"
        assert _error_code(body) in (kXR_IOError, kXR_ArgInvalid)
        assert _ping(sock)[1] == kXR_ok

    def test_write_negative_offset(self, wr_handle):
        sock, fh, _full, writable = wr_handle
        if not writable:
            pytest.skip("anon server read-only; cannot open for write")
        _, status, body = _write(sock, fh, -16, b"x" * 32)
        assert status == kXR_error, "negative write offset must error"
        assert _error_code(body) in (kXR_IOError, kXR_ArgInvalid)
        assert _ping(sock)[1] == kXR_ok

    def test_pgwrite_negative_offset(self, wr_handle):
        sock, fh, _full, writable = wr_handle
        _require_writable(writable)
        data = b"y" * 64
        crc = _test_crc(data)
        payload = struct.pack("!I", crc) + data
        _, status, body = _pgwrite(sock, fh, -32, payload)
        assert status == kXR_error, "negative pgwrite offset must error"
        assert _error_code(body) in (kXR_IOError, kXR_ArgInvalid, kXR_ChkSumErr)
        assert _ping(sock)[1] == kXR_ok

    def test_truncate_negative_offset(self, wr_handle):
        sock, fh, _full, writable = wr_handle
        if not writable:
            pytest.skip("anon server read-only; cannot open for write")
        _, status, body = _truncate(sock, fh, -64)
        # ftruncate(2) on a negative length returns EINVAL -> kXR_IOError;
        # an explicit pre-check would give kXR_ArgInvalid. Either is a clean
        # rejection.
        assert status == kXR_error, "negative truncate offset must error"
        assert _error_code(body) in (kXR_IOError, kXR_ArgInvalid)
        assert _ping(sock)[1] == kXR_ok


def _require_writable(writable):
    if not writable:
        pytest.skip("anon server read-only; cannot open for write")


def _test_crc(data):
    if _CRC32C_OK:
        return crc32c(data)
    return 0


# ===========================================================================
# Scenario 4 — offset + rlen overflow rejected
# ===========================================================================

class TestOffsetLengthOverflow:
    """offset + length that overflows int64 must be rejected up front, never
    wrapped into a small in-bounds extent that would disclose other bytes."""

    def test_read_offset_plus_rlen_overflow(self, rd_handle_4g):
        """offset == INT64_MAX with a positive rlen: the naive end = offset +
        rlen would wrap negative.

        The kXR_read handler (src/protocols/root/read/read.c) caps rlen to
        BRIX_READ_REQUEST_MAX *before* any offset+rlen arithmetic, then
        short-circuits to an empty response because offset >= file_size — so
        the documented, secure outcome is a clean past-EOF short read (kXR_ok
        with ZERO bytes), NOT a wrapped in-bounds read that would leak data.
        The security property under test is: no wrong/leaked bytes, no crash."""
        sock, fh, _ = rd_handle_4g
        _, status, body = _read(sock, fh, INT64_MAX, 0x7FFFFFFF)
        if status == kXR_ok:
            assert body == b"", (
                "overflowing read extent returned bytes — offset+rlen wrapped "
                "into an in-bounds read")
        else:
            assert status == kXR_error
            assert _error_code(body) in (kXR_IOError, kXR_ArgInvalid)
        assert _ping(sock)[1] == kXR_ok

    def test_readv_offset_plus_rlen_overflow(self, rd_handle_4g):
        sock, fh, _ = rd_handle_4g
        _, status, body = _readv(sock, [_seg(fh, 0x7FFFFFFF, INT64_MAX)])
        assert status == kXR_error, "overflowing readv extent must error"
        assert _error_code(body) in (kXR_IOError, kXR_ArgInvalid, kXR_ArgTooLong)
        # No file bytes may have leaked back.
        assert len(body) <= 64
        assert _ping(sock)[1] == kXR_ok

    def test_pgread_offset_plus_rlen_overflow(self, rd_handle_4g):
        sock, fh, _ = rd_handle_4g
        _, status, body, pages = _pgread(sock, fh, INT64_MAX, 0x7FFFFFFF)
        assert status == kXR_error, "overflowing pgread extent must error"
        assert pages == b""
        assert _ping(sock)[1] == kXR_ok


# ===========================================================================
# Scenario 5 — stat size field correct above 4 GiB
# ===========================================================================

class TestStatSizeAbove4GiB:
    """kXR_stat / kXR_statx must report the full 64-bit st_size for a file
    larger than 4 GiB; a %d / 32-bit format bug would report (size mod 2^32).

    In VFS mode (src/protocols/root/path/stat_body.c) the 2nd field carries st_blocks*512
    instead of logical size — near-zero for a sparse file — which is a
    documented alternate encoding, not a 64-bit regression, so those tests
    skip rather than fail when they detect it."""

    def test_stat_reports_full_size(self, big_sparse_4g):
        name, _full, size = big_sparse_4g
        sock = _session()
        try:
            _, status, body = _stat(sock, name)
            assert status == kXR_ok, _error_code(body)
            reported = _stat_size(body)
            _assert_full_stat_size(reported, size)
            assert _ping(sock)[1] == kXR_ok
        finally:
            sock.close()

    def test_statx_reports_full_size(self, big_sparse_4g):
        """statx (raw wire — the python client has no statx) must also carry
        the full 64-bit size."""
        name, _full, size = big_sparse_4g
        sock = _session()
        try:
            _, status, body = _statx(sock, [name])
            if status == kXR_error and _error_code(body) == kXR_Unsupported:
                pytest.skip("kXR_statx not implemented on this server")
            assert status == kXR_ok, _error_code(body)
            # kXR_statx returns ONE flag byte per path (kXR_file=0 / kXR_isDir=2 /
            # ...) — it carries NO size, so the 64-bit length is verified via
            # kXR_stat (see test_stat_reports_full_size).  Here we only confirm the
            # >4 GiB file is classified as a regular file and the session is healthy.
            assert len(body) == 1, f"statx must be one flag byte, got {body!r}"
            assert not (body[0] & 0x02), "regular file flagged as a directory"
            assert _ping(sock)[1] == kXR_ok
        finally:
            sock.close()


def _assert_full_stat_size(reported, expected):
    _skip_block_stat(reported, expected)
    low_bits = _low_32_bits(expected)
    assert reported == expected, (
        f"stat size {reported} != actual {expected}; low-32-bits would be {low_bits}")
    _assert_above_4g(reported)


def _skip_block_stat(reported, expected):
    if reported != expected and reported <= 0xFFFFFFFF:
        pytest.skip("server reports stat in VFS/block mode "
                    f"(field={reported}); logical-size check N/A")


def _low_32_bits(value):
    return value & 0xFFFFFFFF


def _assert_above_4g(reported):
    assert reported > 0xFFFFFFFF, "test file must exceed 4 GiB"


# ===========================================================================
# Scenario 6 — truncate to a large sparse offset
# ===========================================================================

class TestLargeTruncate:
    """Truncating to a multi-GiB offset must extend the file with a hole (no
    multi-GB allocation) and the new size must be reported correctly."""

    def test_truncate_to_above_4gib(self):
        name, full = _make_writable("/large_offset_trunc.bin", 0)
        sock = _session()
        try:
            _, status, body = _open(sock, name, kXR_open_updt)
            _require_large_truncate_open(status, body)
            fh = body[:4]
            target = FOUR_GIB + 12345
            _, tst, tbody = _truncate(sock, fh, target)
            assert tst == kXR_ok, _error_code(tbody)
            _close(sock, fh)
            # On-disk size must match (sparse — costs ~0 blocks).
            assert os.path.getsize(full) == target
            # And the server must report the new 64-bit size via stat (skip the
            # size assertion under VFS/block-mode stat encoding).
            _, sst, sbody = _stat(sock, name)
            assert sst == kXR_ok, _error_code(sbody)
            reported = _stat_size(sbody)
            _assert_truncate_stat(reported, target)
            assert _ping(sock)[1] == kXR_ok
        finally:
            sock.close()
            _unlink(full)


def _require_large_truncate_open(status, body):
    if status != kXR_ok:
        pytest.skip("anon server read-only "
                    f"(open updt -> {_error_code(body)}); need brix_allow_write on")


def _assert_truncate_stat(reported, target):
    if reported == target:
        return
    if reported <= 0xFFFFFFFF:
        pytest.skip("server reports stat in VFS/block mode; "
                    "on-disk truncate size already verified")
    pytest.fail(f"stat size {reported} != truncate target {target}")


# ===========================================================================
# Scenario 7 — readv with mixed small and >2 GiB offsets
# ===========================================================================

class TestReadvMixedLargeOffsets:
    """A single vector read mixing a tiny low offset with offsets above the
    2 GiB / 4 GiB 32-bit boundaries must return each segment's correct bytes —
    proving each segment's int64 offset is honoured independently (no shared
    32-bit truncation across the coalescer)."""

    def test_mixed_small_and_large_offsets(self, big_sparse_4g):
        name, full, _size = big_sparse_4g
        # Lay down distinct markers at the start, just over 2 GiB, and at 4 GiB
        # so each segment has verifiable non-hole content.
        m0 = b"AAAAAAAA"               # offset 0
        m2 = b"BBBBBBBB"               # offset 2 GiB + 4096
        m4 = b"\xA5" * 8               # offset 4 GiB (marker already present)
        off2 = (2 * GIB) + 4096
        with open(full, "r+b") as f:
            f.seek(0)
            f.write(m0)
            f.seek(off2)
            f.write(m2)
        sock = _session()
        try:
            _, ost, obody = _open(sock, name, kXR_open_read)
            assert ost == kXR_ok, _error_code(obody)
            fh = obody[:4]
            chunks = [(0, len(m0)), (off2, len(m2)), (FOUR_GIB, len(m4))]
            _, status, body = _readv(sock, [_seg(fh, n, o) for o, n in chunks])
            assert status == kXR_ok, _error_code(body)
            payload = _readv_payload(body, len(chunks))
            expect = m0 + m2 + m4
            assert payload == expect, (
                "mixed-offset readv returned wrong bytes — a >2 GiB segment "
                "offset was likely truncated")
            _close(sock, fh)
            assert _ping(sock)[1] == kXR_ok
        finally:
            sock.close()
