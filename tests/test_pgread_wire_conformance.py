from split_continuation import reexport as _reexport
_reexport(globals(), "_test_pgread_wire_conformance_helpers")

class TestPgreadWireConformance:
    """Frame, CRC, EOF, parity, cap, and error behaviour of kXR_pgread."""

    def test_status_4007_framing(self, rd_handle):
        """A successful pgread returns kXR_status (4007) with a status body
        whose embedded bdy.dlen equals the number of page-data bytes that
        actually follow on the wire.

        This is the core framing invariant: ServerResponseHeader.dlen covers
        the fixed status body; the CRC-interleaved page data is a SEPARATE
        network unit sized by bdy.dlen at body[12:16].
        """
        sock, fh = rd_handle
        want = PG_PAGESZ + 100          # one full page + part of a second
        sid, status, body, pages = _pgread(sock, fh, 0, want, streamid=b"\x00\x21")
        assert status == kXR_status, f"expected kXR_status(4007), got {status}"
        # Header dlen (= len(body)) must cover at least the fixed status body
        # (crc32c+streamID+requestid+resptype+reserved+dlen = 16 bytes).
        assert len(body) >= STATUS_BODY_MIN_LEN, "status body too short"
        bdy_dlen = struct.unpack(
            "!i", body[STATUS_BODY_DLEN_OFF:STATUS_BODY_DLEN_OFF + 4])[0]
        # The bytes we drained as page data must match the advertised count.
        assert bdy_dlen == len(pages), (
            f"bdy.dlen={bdy_dlen} but {len(pages)} page bytes followed")
        # Echoed stream id must match what we sent.
        assert sid == b"\x00\x21", f"stream id mismatch: {sid!r}"
        assert _ping(sock)[1] == kXR_ok

    @pytest.mark.skipif(not _CRC32C_OK, reason="local CRC32c self-test failed")
    def test_per_page_crc32c_matches_recompute(self, rd_handle):
        """Every per-page CRC32c on the wire recomputes to the same value with
        a local Castagnoli implementation, and the decoded payload is exactly
        the file bytes."""
        sock, fh = rd_handle
        want = 3 * PG_PAGESZ + 123       # 4 pages, last short
        _, status, body, pages = _pgread(sock, fh, 0, want, streamid=b"\x00\x22")
        assert status == kXR_status, f"expected kXR_status, got {status}"
        decoded = _decode_pages(pages, first_offset=0)
        assert decoded[:want] == PATTERN[:want]
        # Belt-and-braces: at least one full page must have been returned, so
        # the CRC check above was non-trivial.
        assert len(decoded) >= PG_PAGESZ

    @pytest.mark.skipif(not _CRC32C_OK, reason="local CRC32c self-test failed")
    def test_sub_page_unaligned_first_page_crc(self, rd_handle):
        """A read starting at a NON-page-aligned offset yields a short first
        page (only up to the next 4 KiB boundary) whose CRC32c still verifies.

        Per spec the CRC is computed over the actual page bytes, and page
        boundaries are absolute-file-offset based — so the first unit here is
        (PG_PAGESZ - 100) bytes, not a full page."""
        sock, fh = rd_handle
        off = 100                        # 100 bytes into page 0
        want = PG_PAGESZ                 # spills into page 1
        _, status, body, pages = _pgread(sock, fh, off, want, streamid=b"\x00\x23")
        assert status == kXR_status, f"expected kXR_status, got {status}"
        assert len(pages) >= 4, "no page unit returned for unaligned read"
        # First page unit must be the short remainder of page 0.
        first_crc = struct.unpack("!I", pages[:4])[0]
        first_cap = PG_PAGESZ - (off % PG_PAGESZ)
        first_page = pages[4:4 + first_cap]
        assert crc32c(first_page) == first_crc, "unaligned first-page CRC bad"
        decoded = _decode_pages(pages, first_offset=off)
        assert decoded[:want] == PATTERN[off:off + want]
        assert _ping(sock)[1] == kXR_ok

    @pytest.mark.skipif(not _CRC32C_OK, reason="local CRC32c self-test failed")
    def test_single_page_and_zero_length(self, rd_handle):
        """A single-page read returns exactly one CRC-prefixed page; a
        zero-length read returns a clean status with no page bytes (and never
        errors or hangs)."""
        sock, fh = rd_handle

        # --- single page ---
        _, status, body, pages = _pgread(sock, fh, 0, PG_PAGESZ, streamid=b"\x00\x24")
        assert status == kXR_status, f"single-page: expected status, got {status}"
        # One page unit = 4 CRC bytes + 4096 data bytes.
        assert len(pages) == 4 + PG_PAGESZ, f"single-page wire size {len(pages)}"
        decoded = _decode_pages(pages, first_offset=0)
        assert decoded == PATTERN[:PG_PAGESZ]

        # --- zero length ---
        _, status0, body0, pages0 = _pgread(sock, fh, 0, 0, streamid=b"\x00\x25")
        # A zero-length paged read must not be an error; no page data follows.
        assert status0 != kXR_error, "zero-length pgread must not error"
        assert pages0 == b"", "zero-length pgread returned page bytes"
        assert _ping(sock)[1] == kXR_ok

    @pytest.mark.skipif(not _CRC32C_OK, reason="local CRC32c self-test failed")
    def test_eof_short_final_page(self, rd_handle):
        """A read whose extent ends at EOF yields a correctly-sized short final
        page; reading exactly the file size returns all bytes and stops, never
        padding to a full page or over-reading."""
        sock, fh = rd_handle
        # Start two pages before EOF so we straddle the last full->short boundary.
        off = (DATA_SIZE // PG_PAGESZ - 1) * PG_PAGESZ
        want = DATA_SIZE - off           # to exactly EOF
        _, status, body, pages = _pgread(sock, fh, off, want, streamid=b"\x00\x26")
        assert status == kXR_status, f"expected kXR_status, got {status}"
        decoded = _decode_pages(pages, first_offset=off)
        assert decoded == PATTERN[off:DATA_SIZE], "EOF tail bytes wrong"
        # The decoded length must not exceed what the file holds from `off`.
        assert len(decoded) == DATA_SIZE - off
        assert _ping(sock)[1] == kXR_ok

    def test_pgread_at_eof_not_error(self, rd_handle):
        """A paged read starting exactly AT EOF returns a valid (empty/short)
        status response, NOT an error — unlike readv."""
        sock, fh = rd_handle
        _, status, body, pages = _pgread(sock, fh, DATA_SIZE, PG_PAGESZ,
                                         streamid=b"\x00\x27")
        assert status != kXR_error, "pgread at EOF must not be an error"
        assert pages == b"", "no data should follow at EOF"
        assert _ping(sock)[1] == kXR_ok

    @pytest.mark.skipif(not _CRC32C_OK, reason="local CRC32c self-test failed")
    def test_pgread_equals_plain_read(self, rd_handle):
        """The payload decoded from a pgread must be byte-exact with a plain
        kXR_read of the same (offset, length) — pgread only adds integrity
        framing, never alters the data."""
        sock, fh = rd_handle
        off, want = 8192, 2 * PG_PAGESZ + 777
        _, rs, rb = _read(sock, fh, off, want)
        assert rs == kXR_ok, f"plain read failed: {_error_code(rb)}"
        _, ps, _body, pages = _pgread(sock, fh, off, want, streamid=b"\x00\x28")
        assert ps == kXR_status, f"pgread failed: {ps}"
        decoded = _decode_pages(pages, first_offset=off)
        assert decoded == rb, "pgread payload != plain read payload"
        assert decoded == PATTERN[off:off + want]

    def test_huge_rlen_capped(self, rd_handle):
        """An enormous rlen (INT32_MAX) is capped server-side to the available
        file bytes — no crash, no over-read, no wild allocation."""
        sock, fh = rd_handle
        _, status, body, pages = _pgread(sock, fh, 0, 0x7FFFFFFF,
                                         streamid=b"\x00\x29")
        # pgread success is kXR_status; tolerate a plain status or a clean
        # error so an implementation choosing to reject the oversize request
        # is not hard-failed — the property under test is "no over-read".
        assert status in (kXR_status, kXR_ok, kXR_error)
        if status == kXR_status:
            # Page data <= file size + per-page CRC overhead (4 bytes/page).
            max_pages = DATA_SIZE // PG_PAGESZ + 1
            assert len(pages) <= DATA_SIZE + max_pages * 4, (
                f"capped pgread returned {len(pages)} bytes, over-read")
            if _CRC32C_OK and pages:
                decoded = _decode_pages(pages, first_offset=0)
                assert decoded == PATTERN[:len(decoded)]
        assert _ping(sock)[1] == kXR_ok

    def test_invalid_handle_rejected(self, rd_handle):
        """pgread on a never-opened handle (0xFE) must produce a clean protocol
        error and leave the session usable."""
        sock, _fh = rd_handle
        _, status, body, pages = _pgread(sock, b"\xfe\x00\x00\x00", 0, PG_PAGESZ,
                                         streamid=b"\x00\x2a")
        assert status == kXR_error, "invalid handle must error"
        assert pages == b"", "no page data on error"
        assert _ping(sock)[1] == kXR_ok

    def test_stale_handle_after_close(self, data_file):
        """pgread on a handle closed mid-session must error (no use-after-free),
        and the connection must stay alive for further requests."""
        sock = _session()
        try:
            _, status, body = _open(sock, data_file, kXR_open_read)
            assert status == kXR_ok
            fh = body[:4]
            _close(sock, fh)
            _, st, _b, pages = _pgread(sock, fh, 0, PG_PAGESZ, streamid=b"\x00\x2b")
            assert st == kXR_error, "pgread on closed handle must error"
            assert pages == b""
            assert _ping(sock)[1] == kXR_ok
        finally:
            sock.close()

    def test_negative_offset_ioerror(self, rd_handle):
        """A negative offset (sign bit set in the i64) must be rejected with a
        clean error — the documented mapping is kXR_IOError; we accept any
        clean protocol error but assert IOError/ArgInvalid when reported."""
        sock, fh = rd_handle
        _, status, body, pages = _pgread(sock, fh, -1, PG_PAGESZ,
                                         streamid=b"\x00\x2c")
        assert status == kXR_error, "negative offset must error"
        assert pages == b"", "no data should leak on negative offset"
        # Documented errno->kXR mapping: negative seek -> EINVAL/EIO -> IOError.
        code = _error_code(body)
        assert code in (kXR_IOError, kXR_ArgInvalid), (
            f"unexpected error code {code} for negative offset")
        assert _ping(sock)[1] == kXR_ok
