from split_continuation import reexport as _reexport
_reexport(globals(), "_test_compression_root_edge_helpers")

class TestIncompressible:
    """Random 2 MiB data downloaded WITH --compress for several codecs must stay
    byte-exact even though every codec frame is >= its plaintext input.  Proves
    the server never corrupts or truncates incompressible data when the frame
    expands past the plaintext size (brix_codec_max_out bound + cmp_scratch)."""

    @pytest.mark.parametrize("codec", INCOMPRESSIBLE_CODECS)
    def test_random_download_byte_exact(self, random_uploaded, tmp_path, codec):
        remote, payload = random_uploaded
        out = str(tmp_path / f"rand_{codec}.out")
        r = _download(remote, out, codec=codec)
        assert r.returncode == 0, (
            f"--compress {codec} download of random data failed: {r.stderr[:300]}")
        with open(out, "rb") as fh:
            got = fh.read()
        assert len(got) == len(payload), (
            f"--compress {codec}: length mismatch "
            f"(got {len(got)}, want {len(payload)}) — truncation on the "
            "worst-case expansion path")
        assert got == payload, (
            f"--compress {codec}: incompressible 2 MiB download not byte-exact "
            "— corruption on the worst-case expansion path")

    def test_random_plain_download_byte_exact(self, random_uploaded, tmp_path):
        """Control: the same random file WITHOUT --compress is byte-exact (the
        uncompressed hot path is untouched)."""
        remote, payload = random_uploaded
        out = str(tmp_path / "rand_plain.out")
        r = _download(remote, out)
        assert r.returncode == 0, f"plain download failed: {r.stderr[:300]}"
        with open(out, "rb") as fh:
            assert fh.read() == payload, "plain random download not byte-exact"


# ===========================================================================
# (2) EOF / EMPTY
# ===========================================================================

class TestEofEmpty:
    """A 0-byte file with --compress is byte-exact empty (empty frame inflates to
    nothing) and a small file read entirely + past EOF returns exactly the source
    (no extra bytes after the final short window)."""

    @pytest.mark.parametrize("codec", ["gzip", "zstd"])
    def test_empty_file_compressed_byte_exact(self, empty_uploaded, tmp_path, codec):
        remote, payload = empty_uploaded
        out = str(tmp_path / f"empty_{codec}.out")
        r = _download(remote, out, codec=codec)
        assert r.returncode == 0, (
            f"--compress {codec} download of empty file failed: {r.stderr[:300]}")
        with open(out, "rb") as fh:
            got = fh.read()
        assert got == payload == b"", (
            f"--compress {codec}: empty file not byte-exact empty (got "
            f"{len(got)} bytes)")

    def test_small_file_compressed_byte_exact(self, small_uploaded, tmp_path):
        """A small file fully read with --compress (the body is one short final
        window; the client reads to EOF and a read past EOF yields no extra
        bytes) is byte-exact."""
        remote, payload = small_uploaded
        out = str(tmp_path / "small.out")
        r = _download(remote, out, codec="gzip")
        assert r.returncode == 0, f"small --compress download failed: {r.stderr[:300]}"
        with open(out, "rb") as fh:
            assert fh.read() == payload, "small --compress download not byte-exact"

    def test_read_past_eof_returns_no_extra_bytes(self, small_uploaded):
        """Raw wire: on a compression handle, a kXR_read whose offset is AT EOF
        returns an empty body (an empty frame inflating to zero bytes), proving
        the EOF/empty-range branch sends no spurious payload."""
        remote, payload = small_uploaded
        sock = _session()
        try:
            _, status, body = _open(sock, f"{remote}?xrootd.compress=gzip",
                                    kXR_open_read)
            assert status == kXR_ok, f"compressed open failed (status={status})"
            fh, cpsize, cptype = _parse_open_body(body)
            assert cpsize == INLINE_CMP_MAGIC and cptype[0] == CODEC_GZIP, (
                "compression not negotiated; is brix_read_compress on?")
            # Read AT EOF: offset == filesize.
            _, rstatus, rbody = _read(sock, fh, len(payload), 65536)
            assert rstatus == kXR_ok, f"read-at-EOF failed (status={rstatus})"
            assert rbody == b"", (
                f"read at EOF returned {len(rbody)} bytes; expected an empty "
                "frame/body")
        finally:
            try:
                _close(sock, fh)
            except Exception:
                pass
            sock.close()


# ===========================================================================
# (3) OFFSET-RESUME (raw wire) — frames are offset-addressable
# ===========================================================================

class TestOffsetResume:
    """Each kXR_read is an independent whole-range frame, so a read at a non-zero
    offset inflates to the source slice STARTING at that offset (resumable)."""

    def test_read_at_offset_matches_source_slice(self, small_uploaded):
        remote, payload = small_uploaded
        offset = len(payload) // 2
        want = 4096
        sock = _session()
        try:
            _, status, body = _open(sock, f"{remote}?xrootd.compress=gzip",
                                    kXR_open_read)
            assert status == kXR_ok, f"compressed open failed (status={status})"
            fh, cpsize, cptype = _parse_open_body(body)
            assert cpsize == INLINE_CMP_MAGIC and cptype[0] == CODEC_GZIP, (
                "compression not negotiated; is brix_read_compress on?")

            _, rstatus, rbody = _read(sock, fh, offset, want)
            assert rstatus == kXR_ok, f"offset read failed (status={rstatus})"
            assert _looks_gzip(rbody), (
                "offset read body is not a gzip frame — compression did not "
                f"engage (first bytes: {rbody[:4].hex()})")
            inflated = _gunzip(rbody)
            expect = payload[offset:offset + want]
            assert inflated == expect, (
                "inflated offset frame != source slice at that offset "
                f"(offset={offset}, got {len(inflated)} bytes)")
        finally:
            try:
                _close(sock, fh)
            except Exception:
                pass
            sock.close()

    def test_offset_zero_and_nonaligned_offset_differ(self, small_uploaded):
        """Two reads on the SAME handle at different offsets yield DIFFERENT
        plaintext slices — proving the frame really is keyed on the requested
        offset, not always serving from byte 0.

        The payload is a 54-byte line repeated, so an offset must be chosen that
        is NOT a multiple of 54 (otherwise both slices begin at the same phase of
        the repeating pattern and are legitimately identical — a property of the
        DATA, not the server).  37 is coprime with 54, so payload[37:] is phase-
        shifted relative to payload[0:]."""
        remote, payload = small_uploaded
        want = 4096
        off = 37  # not a multiple of the 54-byte line → genuinely different slice
        sock = _session()
        try:
            _, status, body = _open(sock, f"{remote}?xrootd.compress=gzip",
                                    kXR_open_read)
            assert status == kXR_ok, f"compressed open failed (status={status})"
            fh, cpsize, _cptype = _parse_open_body(body)
            assert cpsize == INLINE_CMP_MAGIC, "compression not negotiated"

            _, s0, b0 = _read(sock, fh, 0, want)
            _, s1, b1 = _read(sock, fh, off, want)
            assert s0 == kXR_ok and s1 == kXR_ok
            assert _gunzip(b0) == payload[:want]
            assert _gunzip(b1) == payload[off:off + want]
            assert _gunzip(b0) != _gunzip(b1), (
                "offset-0 and offset-37 frames inflate to identical bytes — "
                "frames are not offset-addressable")
        finally:
            try:
                _close(sock, fh)
            except Exception:
                pass
            sock.close()


# ===========================================================================
# (4) INVISIBILITY (raw wire) — a stock open sees no compression signal
# ===========================================================================

class TestInvisibilityWire:
    """Opening the SAME file WITHOUT the opaque (a stock kXR_open) yields cpsize
    == 0 and cptype[0] == 0 — a stock client sees no compression signal (opt-in
    invisibility) — and a plain kXR_read returns the raw plaintext."""

    def test_plain_open_reply_has_no_compression_signal(self, small_uploaded):
        remote, _payload = small_uploaded
        sock = _session()
        try:
            _, status, body = _open(sock, remote, kXR_open_read)
            assert status == kXR_ok, f"plain open failed (status={status})"
            fh, cpsize, cptype = _parse_open_body(body)
            assert cpsize == 0, (
                f"stock open reply leaked a compression signal: cpsize={cpsize:#x} "
                f"(expected 0) — invisibility violated")
            assert cptype[0] == 0, (
                f"stock open reply cptype[0]={cptype[0]} (expected 0) — "
                "invisibility violated")
        finally:
            try:
                _close(sock, fh)
            except Exception:
                pass
            sock.close()

    def test_plain_read_returns_raw_plaintext(self, small_uploaded):
        remote, payload = small_uploaded
        want = 4096
        sock = _session()
        try:
            _, status, body = _open(sock, remote, kXR_open_read)
            assert status == kXR_ok, f"plain open failed (status={status})"
            fh, cpsize, _cptype = _parse_open_body(body)
            assert cpsize == 0, "stock open unexpectedly negotiated compression"

            _, rstatus, rbody = _read(sock, fh, 0, want)
            assert rstatus == kXR_ok, f"plain read failed (status={rstatus})"
            assert not _looks_gzip(rbody), (
                "plain read body begins with gzip magic — a stock read was "
                "compressed, violating opt-in invisibility")
            assert rbody == payload[:want], (
                "plain read body is not raw plaintext")
        finally:
            try:
                _close(sock, fh)
            except Exception:
                pass
            sock.close()

    def test_same_file_plain_vs_compressed_open_diverge(self, small_uploaded):
        """End-to-end contrast: the SAME file opened plain reports cpsize==0,
        opened '?xrootd.compress=gzip' reports the magic + gzip ordinal — the
        compression signal is strictly opt-in per open."""
        remote, _payload = small_uploaded

        sock_p = _session()
        sock_c = _session()
        fh_p = fh_c = None
        try:
            _, sp, bp = _open(sock_p, remote, kXR_open_read)
            assert sp == kXR_ok
            fh_p, cpsize_p, cptype_p = _parse_open_body(bp)

            _, sc, bc = _open(sock_c, f"{remote}?xrootd.compress=gzip",
                              kXR_open_read)
            assert sc == kXR_ok
            fh_c, cpsize_c, cptype_c = _parse_open_body(bc)

            assert cpsize_p == 0 and cptype_p[0] == 0, "plain open leaked signal"
            assert cpsize_c == INLINE_CMP_MAGIC and cptype_c[0] == CODEC_GZIP, (
                "compressed open did not negotiate; is brix_read_compress on?")
        finally:
            for s, fhh in ((sock_p, fh_p), (sock_c, fh_c)):
                try:
                    if fhh is not None:
                        _close(s, fhh)
                except Exception:
                    pass
                s.close()
