from split_continuation import reexport as _reexport
def _check_test_max_segments_ok_1(status, body):
    assert status == kXR_ok, _error_code(body)

def _check_test_max_segments_ok_2(payload, expect):
    assert payload == expect


_reexport(globals(), "_test_readv_security_helpers")

class TestReadvOOBRaw:
    """Hostile vector reads must error cleanly and never disclose data."""

    def test_baseline_valid_readv(self, rd_handle):
        """Positive control: in-bounds segments return exactly the file bytes."""
        sock, fh = rd_handle
        chunks = [(0, 64), (1000, 128), (4096, 256)]
        _, status, body = _readv(sock, [_seg(fh, n, o) for o, n in chunks])
        assert status == kXR_ok, _error_code(body)
        payload = _readv_payload_bytes(body, len(chunks))
        expect = b"".join(PATTERN[o:o + n] for o, n in chunks)
        assert payload == expect

    def test_negative_offset_rejected(self, rd_handle):
        """offset with the sign bit set (-> negative off_t) is rejected."""
        sock, fh = rd_handle
        # -1 as int64; the handler's `offset < 0` guard must fire.
        _, status, body = _readv(sock, [_seg(fh, 64, -1)])
        assert status == kXR_error
        assert _error_code(body) == kXR_IOError
        # Session still usable, no bytes leaked.
        assert _ping(sock)[1] == kXR_ok

    def test_offset_overflow_rejected(self, rd_handle):
        """offset near INT64_MAX + positive rlen overflows and is rejected."""
        sock, fh = rd_handle
        _, status, body = _readv(sock, [_seg(fh, 100, (1 << 63) - 1)])
        assert status == kXR_error
        assert _error_code(body) == kXR_IOError
        assert _ping(sock)[1] == kXR_ok

    def test_single_segment_past_eof(self, rd_handle):
        """A lone segment starting exactly at EOF errors (no zero-length OK)."""
        sock, fh = rd_handle
        _, status, body = _readv(sock, [_seg(fh, 100, DATA_SIZE)])
        assert status == kXR_error
        assert _error_code(body) == kXR_IOError

    def test_segment_straddles_eof(self, rd_handle):
        """A segment whose tail crosses EOF errors for the whole request."""
        sock, fh = rd_handle
        _, status, body = _readv(sock, [_seg(fh, 200, DATA_SIZE - 50)])
        assert status == kXR_error
        assert _error_code(body) == kXR_IOError

    def test_way_past_eof(self, rd_handle):
        """A 1 TiB offset is past EOF and must error, not allocate wildly."""
        sock, fh = rd_handle
        _, status, body = _readv(sock, [_seg(fh, 4096, 1 << 40)])
        assert status == kXR_error
        assert _error_code(body) == kXR_IOError

    def test_mixed_valid_and_oob_no_partial(self, rd_handle):
        """One valid + one past-EOF segment: the ENTIRE request must fail.

        A partial success would let a client probe EOF boundaries and could
        desync the client's response demultiplexer.
        """
        sock, fh = rd_handle
        segs = [_seg(fh, 64, 0), _seg(fh, 100, DATA_SIZE + 10)]
        _, status, body = _readv(sock, segs)
        assert status == kXR_error
        # No file bytes should have been returned at all.
        assert len(body) <= 64  # just the error errnum+message, never 64 data bytes
        assert _ping(sock)[1] == kXR_ok

    def test_coalesced_run_crosses_eof(self, rd_handle):
        """Two contiguous same-fd segments coalesced into one preadv whose
        combined extent crosses EOF must be caught by the short-read check."""
        sock, fh = rd_handle
        base = DATA_SIZE - 64
        segs = [_seg(fh, 64, base), _seg(fh, 64, base + 64)]  # 2nd is past EOF
        _, status, body = _readv(sock, segs)
        assert status == kXR_error
        assert _error_code(body) == kXR_IOError

    def test_zero_length_segment_among_valid(self, rd_handle):
        """A zero-length segment is skipped; the valid ones still return."""
        sock, fh = rd_handle
        segs = [_seg(fh, 0, 0), _seg(fh, 32, 100)]
        _, status, body = _readv(sock, segs)
        assert status == kXR_ok, _error_code(body)
        payload = _readv_payload_bytes(body, 2)
        assert payload == PATTERN[100:132]

    def test_malformed_dlen_not_multiple(self, rd_handle):
        """dlen not a multiple of the 16-byte segment size is rejected."""
        sock, fh = rd_handle
        # One valid segment but advertise dlen = 17 (16 + 1 stray byte).
        _, status, body = _readv(sock, [_seg(fh, 16, 0) + b"\x00"],
                                 raw_dlen=17)
        assert status == kXR_error
        assert _error_code(body) == kXR_ArgInvalid
        # Server may keep the stray byte buffered; a fresh session must work.
        sock2 = _session()
        assert _ping(sock2)[1] == kXR_ok
        sock2.close()

    def test_too_many_segments_rejected(self, rd_handle):
        """1025 segments (over READV_MAXSEGS=1024) is rejected, not processed."""
        sock, fh = rd_handle
        segs = [_seg(fh, 1, (i % 100)) for i in range(READV_MAXSEGS + 1)]
        try:
            _, status, body = _readv(sock, segs)
        except ConnectionError:
            return  # acceptable: recv-layer cap closed the connection
        assert status == kXR_error
        assert _error_code(body) in (kXR_ArgTooLong, kXR_ArgInvalid)

    def test_max_segments_ok(self, rd_handle):
        """Exactly 1024 in-bounds 16-byte segments all return correctly."""
        sock, fh = rd_handle
        seg = 16
        chunks = [((i * 64) % (DATA_SIZE - seg), seg)
                  for i in range(READV_MAXSEGS)]
        _, status, body = _readv(sock, [_seg(fh, n, o) for o, n in chunks])
        _check_test_max_segments_ok_1(status, body)
        payload = _readv_payload_bytes(body, READV_MAXSEGS)
        expect = b"".join(PATTERN[o:o + n] for o, n in chunks)
        _check_test_max_segments_ok_2(payload, expect)

    def test_total_response_size_cap(self, rd_handle):
        """Requested total over 256 MiB is rejected before any I/O.

        (MAX_READV_TOTAL // READ_MAX) + 1 segments each requesting the per-segment
        cap sums to just over MAX_READV_TOTAL, so the two-phase validator must
        reject up front (the data file is tiny, so this proves the size check
        happens BEFORE the read, not after EOF).
        """
        sock, fh = rd_handle
        n_segs = (MAX_READV_TOTAL // READ_MAX) + 1
        segs = [_seg(fh, READ_MAX, 0) for _ in range(n_segs)]
        try:
            _, status, body = _readv(sock, segs)
        except ConnectionError:
            return
        assert status == kXR_error
        assert _error_code(body) == kXR_ArgTooLong

    def test_invalid_handle_rejected(self, rd_handle):
        """A segment naming an unopened handle (0xFF) is rejected."""
        sock, _fh = rd_handle
        _, status, body = _readv(sock, [_seg(b"\xff\x00\x00\x00", 16, 0)])
        assert status == kXR_error
        assert _ping(sock)[1] == kXR_ok

    def test_stale_handle_after_close(self, data_file):
        """readv on a handle that was already closed must error (no UAF)."""
        sock = _session()
        _, status, body = _open(sock, data_file, kXR_open_read)
        assert status == kXR_ok
        fh = body[:4]
        _close(sock, fh)
        _, status, body = _readv(sock, [_seg(fh, 16, 0)])
        assert status == kXR_error
        sock.close()


# ===========================================================================
# Class 2 — kXR_pgread (chunked / paged read) security + integrity
# ===========================================================================

class TestPgreadSecurity:
    """Paged reads: integrity of the CRC-interleaved chunked response and
    correct EOF / bounds behaviour."""

    def _decode_pages(self, pages):
        """Split a pgread page stream [crc4][<=4096 data]... verifying each
        CRC32c.  Returns the concatenated data; raises on CRC mismatch."""
        out = bytearray()
        pos = 0
        while pos < len(pages):
            crc = struct.unpack("!I", pages[pos:pos + 4])[0]
            pos += 4
            page = pages[pos:pos + PG_PAGESZ]
            pos += len(page)
            assert crc32c(page) == crc, "pgread per-page CRC32c mismatch"
            out.extend(page)
            if len(page) < PG_PAGESZ:
                break
        return bytes(out)

    def test_negative_offset_rejected(self, rd_handle):
        sock, fh = rd_handle
        _, status, body, _ = _pgread(sock, fh, -1, 4096)
        assert status == kXR_error
        assert _error_code(body) == kXR_IOError
        assert _ping(sock)[1] == kXR_ok

    @pytest.mark.skipif(not _CRC32C_OK, reason="local CRC32c self-test failed")
    def test_valid_pgread_crc_integrity(self, rd_handle):
        """A normal paged read returns kXR_status framing and every page's
        CRC32c must verify against the data — and match the raw bytes."""
        sock, fh = rd_handle
        want = 3 * PG_PAGESZ + 123   # spans 4 pages, last one short
        _, status, body, pages = _pgread(sock, fh, 0, want)
        assert status == kXR_status, f"expected kXR_status, got {status}"
        decoded = self._decode_pages(pages)
        assert decoded[:want] == PATTERN[:want]

    def test_pgread_at_eof_not_error(self, rd_handle):
        """Unlike readv, a paged read AT EOF returns a valid short/empty
        response (next-offset status), NOT an error."""
        sock, fh = rd_handle
        _, status, body, _ = _pgread(sock, fh, DATA_SIZE, 4096)
        assert status != kXR_error, "pgread at EOF must not be an error"
        assert _ping(sock)[1] == kXR_ok

    def test_pgread_huge_rlen_capped(self, rd_handle):
        """An enormous rlen is capped server-side; no crash, no over-read."""
        sock, fh = rd_handle
        _, status, body, pages = _pgread(sock, fh, 0, 0x7FFFFFFF)
        assert status in (kXR_status, kXR_ok, kXR_error)
        # Capped read must not exceed the file size (plus per-page CRC overhead).
        if status == kXR_status:
            assert len(pages) <= DATA_SIZE + (DATA_SIZE // PG_PAGESZ + 1) * 4
        assert _ping(sock)[1] == kXR_ok

    def test_pgread_invalid_handle(self, rd_handle):
        sock, _fh = rd_handle
        _, status, body, _ = _pgread(sock, b"\xfe\x00\x00\x00", 0, 4096)
        assert status == kXR_error


# ===========================================================================
# Class 3 — kXR_pgwrite (chunked / paged write) integrity
# ===========================================================================

class TestPgwriteSecurity:
    """Paged writes must verify each page's CRC32c before touching the file."""

    @pytest.fixture
    def wr_handle(self):
        sock = _session()
        path = "/test_pgwrite_security.bin"
        full = os.path.join(DATA_ROOT, path.lstrip("/"))
        with open(full, "wb") as f:
            f.write(b"\x00" * PG_PAGESZ)
        _, status, body = _open(sock, path, kXR_open_updt)
        assert status == kXR_ok, "write-open failed"
        fh = body[:4]
        try:
            yield sock, fh, full
        finally:
            try:
                _close(sock, fh)
            except Exception:
                pass
            sock.close()

    def test_bad_crc_reported_via_cse(self, wr_handle):
        """A page whose CRC32c does not match its data is accepted-and-reported
        via a CSE retransmit list (success kXR_status), not silently accepted.
        The corrupt bytes land on disk (accept-then-correct) and the page is
        flagged for retransmission; the close gate (covered elsewhere) refuses
        to commit until corrected."""
        sock, fh, full = wr_handle
        data = b"CORRUPTME" + b"x" * 1000
        bad_payload = struct.pack("!I", 0xDEADBEEF) + data  # wrong CRC
        _, status, body = _pgwrite(sock, fh, 0, bad_payload)
        assert status == kXR_status, f"expected CSE kXR_status, got {status}"
        # Drain the CSE trailer (bdy.dlen bytes, not in hdr.dlen) so the socket
        # stays aligned for the ping below; it must list page offset 0.
        cse_len = struct.unpack("!i", body[12:16])[0]
        assert cse_len >= 8, "CSE trailer must be present for a bad page"
        cse = _recv_exact(sock, cse_len)
        offs = list(struct.unpack("!" + "q" * ((cse_len - 8) // 8), cse[8:]))
        assert offs == [0], f"CSE must flag the corrupt page offset: {offs}"
        # The page is reported, not silently dropped; the connection stays sane.
        assert _ping(sock)[1] == kXR_ok

    @pytest.mark.skipif(not _CRC32C_OK, reason="local CRC32c self-test failed")
    def test_valid_pgwrite_roundtrip(self, wr_handle):
        """A correctly-checksummed page is accepted and lands on disk."""
        sock, fh, full = wr_handle
        data = bytes((i * 13 + 1) & 0xFF for i in range(2000))
        payload = struct.pack("!I", crc32c(data)) + data
        _, status, body = _pgwrite(sock, fh, 0, payload)
        assert status in (kXR_status, kXR_ok), _error_code(body)
        # Verify via a normal read on the same handle.
        _, rs, rb = _read(sock, fh, 0, len(data))
        assert rs == kXR_ok
        assert rb == data

    @pytest.mark.skipif(not _CRC32C_OK, reason="local CRC32c self-test failed")
    def test_pgwrite_negative_offset(self, wr_handle):
        sock, fh, _full = wr_handle
        data = b"y" * 64
        payload = struct.pack("!I", crc32c(data)) + data
        _, status, body = _pgwrite(sock, fh, -8, payload)
        assert status == kXR_error
        assert _ping(sock)[1] == kXR_ok

    def test_pgwrite_truncated_page_framing(self, wr_handle):
        """A payload with a CRC header but no/short data (malformed framing)
        must be rejected cleanly, not crash or partially write."""
        sock, fh, _full = wr_handle
        # 4-byte CRC then only 1 data byte but claim it's a page — the decoder
        # must handle the short final fragment without over-reading.
        payload = struct.pack("!I", crc32c(b"Z")) + b"Z"
        _, status, body = _pgwrite(sock, fh, 0, payload)
        # Either accepted as a legitimate 1-byte final page, or a clean error;
        # never a crash — prove the session survives.
        assert status in (kXR_status, kXR_ok, kXR_error)
        assert _ping(sock)[1] == kXR_ok


# ===========================================================================
# Class 4 — cross-protocol OOB vector reads via the XRootD client
# ===========================================================================


@bindings_required
class TestCrossProtocolReadvOOB:
    """The same out-of-bounds vector reads, exercised through the authenticated
    endpoints so the per-protocol auth + client demux paths are covered."""

    def _upload(self, url_base, remote, data):
        from XRootD import client
        from XRootD.client.flags import OpenFlags
        f = client.File()
        st, _ = f.open(f"{url_base}//{remote.lstrip('/')}",
                       OpenFlags.DELETE | OpenFlags.NEW)
        assert st.ok, f"upload open failed: {st.message}"
        st, _ = f.write(data)
        assert st.ok
        f.close()

    def test_anon_client_oob(self, data_file):
        url = f"root://{SERVER_HOST}:{NGINX_ANON_PORT}"
        past, huge = _client_oob(url, data_file)
        assert not past.ok, "past-EOF vector_read should fail"
        assert not huge.ok, "huge-offset vector_read should fail"

    def test_gsi_client_oob(self):
        if not CA_DIR or not PROXY_STD or not os.path.exists(PROXY_STD):
            pytest.skip("GSI proxy assets unavailable")
        os.environ["X509_CERT_DIR"] = CA_DIR
        os.environ["X509_USER_PROXY"] = PROXY_STD
        try:
            url = f"root://{SERVER_HOST}:{NGINX_GSI_PORT}"
            remote = "/test_readv_security_gsi.bin"
            self._upload(url, remote, PATTERN)
            past, huge = _client_oob(url, remote)
            def _assert_test_gsi_client_oob_1():
                assert not past.ok
                assert not huge.ok

            _assert_test_gsi_client_oob_1()
        finally:
            for k in ("X509_CERT_DIR", "X509_USER_PROXY"):
                os.environ.pop(k, None)


# ===========================================================================
# Class 5 — slice-cache handle vs vector/paged reads (executable spec)
# ===========================================================================

@pytest.mark.skip(reason="needs a live XRootD origin + brix_cache_slice env")
class TestSliceHandleVectorReads:
    """Phase 26 slice-mode handles park their fd on /dev/null; only kXR_read is
    wired into slice serving.  readv/pgread guard against such handles and must
    return kXR_Unsupported rather than reading /dev/null (empty/wrong data).

    Requires a server configured with brix_cache_slice + brix_cache_origin,
    so it stays skipped until that env is available.
    """

    def test_readv_on_slice_handle_unsupported(self):
        """Open a file on a slice-cache server, then kXR_readv -> kXR_Unsupported."""

    def test_pgread_on_slice_handle_unsupported(self):
        """Open a file on a slice-cache server, then kXR_pgread -> kXR_Unsupported."""

    def test_plain_read_on_slice_handle_serves_data(self):
        """kXR_read on the same handle still serves correct bytes from slices."""
