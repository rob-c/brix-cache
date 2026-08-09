from split_continuation import reexport as _reexport
_reexport(globals(), "_test_compression_write_adversarial_helpers")

class TestCompressedWriteOkControl:

    def test_correct_zstd_frame_stores_exact_plaintext(self):
        """A single zstd frame written to a compression-mode handle is stored as
        its decompressed PLAINTEXT, byte-exact on readback."""
        remote = f"/wcmp_ok_{uuid.uuid4().hex}.bin"
        # Highly compressible so the wire frame is dramatically smaller than the
        # stored plaintext (proves a real codec frame, not a stored copy).
        plaintext = b"the quick brown fox jumps over the lazy dog 0123456789\n" * 400
        frame = _zstd_frame(plaintext)
        assert len(frame) < len(plaintext), "zstd frame not smaller than plaintext"

        sock = _session()
        try:
            fh = _open_write_compressed(sock, remote, "zstd")
            _, wstatus, wbody = _write(sock, fh, 0, frame)
            assert wstatus == kXR_ok, (
                f"correct compressed write rejected (status={wstatus}, "
                f"body={_err_fields(wbody)})")
            _close(sock, fh)
        finally:
            sock.close()

        rstatus, content = _readback(remote)
        try:
            assert rstatus == kXR_ok, f"readback open/read failed (status={rstatus})"
            assert content == plaintext, (
                "stored content is not the byte-exact decompressed plaintext")
            assert len(content) == len(plaintext)
        finally:
            _rm(remote)

    def test_compressed_write_at_offset_addresses_plaintext(self):
        """Each kXR_write is an independent whole frame, so writes stay offset-
        addressable: two frames at 0 and len(p0) reconstruct p0+p1 contiguously."""
        remote = f"/wcmp_off_{uuid.uuid4().hex}.bin"
        p0 = b"AAAA-block-zero-" * 64
        p1 = b"BBBB-block-one--" * 64

        sock = _session()
        try:
            fh = _open_write_compressed(sock, remote, "zstd")
            _, w0, b0 = _write(sock, fh, 0, _zstd_frame(p0))
            assert w0 == kXR_ok, f"frame@0 rejected ({_err_fields(b0)})"
            _, w1, b1 = _write(sock, fh, len(p0), _zstd_frame(p1),
                               streamid=b"\x00\x05")
            assert w1 == kXR_ok, f"frame@len(p0) rejected ({_err_fields(b1)})"
            _close(sock, fh)
        finally:
            sock.close()

        rstatus, content = _readback(remote)
        try:
            assert rstatus == kXR_ok
            assert content == p0 + p1, "offset-addressed frames did not reassemble"
        finally:
            _rm(remote)


# ===========================================================================
# (1) WCMP-CORRUPT — a truncated/garbage codec frame is rejected and leaves no
#     partial garbage on disk.
# ===========================================================================

class TestCompressedWriteCorrupt:

    def _assert_rejected(self, wstatus, wbody):
        assert wstatus == kXR_error, (
            f"corrupt compressed write was NOT rejected (status={wstatus}); "
            "the server accepted a malformed codec frame")
        errnum, msg = _err_fields(wbody)
        # The decode failure maps to the corrupt/oversized error message; assert
        # on the message (stable) rather than the numeric ordinal alone.
        assert msg == CORRUPT_WRITE_MSG, (
            f"unexpected error message for corrupt write: {msg!r} "
            f"(errnum={errnum})")

    def _assert_no_partial_garbage(self, remote):
        """Pinned contract (verified against the live harness): the corrupt frame
        is rejected BEFORE any decompressed prefix is committed, so the file is
        either not present OR present and 0 bytes — never holding partial garbage.

        We accept both 'not created' and '0 bytes' so the test is robust to the
        kXR_new-created-empty-file detail, but it MUST NOT contain any bytes."""
        rstatus, content = _readback(remote)
        if rstatus == kXR_ok:
            assert content == b"", (
                f"corrupt write left {len(content)} bytes of partial data on "
                f"disk: {content[:32]!r}... — partial-garbage commit is a bug")
        else:
            # Not openable as a regular readable file (e.g. not found) is also an
            # acceptable 'no garbage committed' outcome.
            assert rstatus != kXR_ok

    def test_truncated_zstd_frame_rejected_no_garbage(self):
        """A zstd frame chopped mid-stream: server must reply kXR_error and leave
        no partial plaintext on disk."""
        remote = f"/wcmp_trunc_{uuid.uuid4().hex}.bin"
        plaintext = b"this plaintext is long enough to span a real zstd frame " * 80
        full = _zstd_frame(plaintext)
        truncated = full[: max(4, len(full) // 2)]  # keep magic, drop the tail

        sock = _session()
        try:
            fh = _open_write_compressed(sock, remote, "zstd")
            _, wstatus, wbody = _write(sock, fh, 0, truncated)
            self._assert_rejected(wstatus, wbody)
            _close(sock, fh)
        finally:
            sock.close()

        try:
            self._assert_no_partial_garbage(remote)
        finally:
            _rm(remote)

    def test_garbage_after_magic_rejected_no_garbage(self):
        """Valid zstd magic followed by random bytes (a hostile/garbage frame):
        rejected, nothing committed."""
        remote = f"/wcmp_garb_{uuid.uuid4().hex}.bin"
        garbage = b"\x28\xb5\x2f\xfd" + os.urandom(64)  # zstd magic + junk

        sock = _session()
        try:
            fh = _open_write_compressed(sock, remote, "zstd")
            _, wstatus, wbody = _write(sock, fh, 0, garbage)
            self._assert_rejected(wstatus, wbody)
            _close(sock, fh)
        finally:
            sock.close()

        try:
            self._assert_no_partial_garbage(remote)
        finally:
            _rm(remote)

    def test_pure_random_rejected_no_garbage(self):
        """Payload with no valid codec magic at all: rejected, nothing committed."""
        remote = f"/wcmp_rand_{uuid.uuid4().hex}.bin"
        junk = os.urandom(128)

        sock = _session()
        try:
            fh = _open_write_compressed(sock, remote, "zstd")
            _, wstatus, wbody = _write(sock, fh, 0, junk)
            self._assert_rejected(wstatus, wbody)
            _close(sock, fh)
        finally:
            sock.close()

        try:
            self._assert_no_partial_garbage(remote)
        finally:
            _rm(remote)


# ===========================================================================
# (2) WCMP-INVARIANT — pgwrite on a compression-negotiated WRITE handle is
#     treated as PLAINTEXT (the W5 invariant excludes pgwrite/writev).
# ===========================================================================

class TestPgwritePlaintextInvariant:

    @pytest.mark.skipif(not _CRC32C_OK, reason="local CRC32c self-test failed")
    def test_pgwrite_on_compressed_handle_is_plaintext(self):
        """THE INVARIANT: a kXR_pgwrite on a handle opened '?xrootd.compress=zstd'
        is NOT decompressed — its page data is written verbatim and reads back
        byte-exact as plaintext, with pgwrite's kXR_status(4007) framing intact.

        If pgwrite were (incorrectly) routed through the write_codec decompressor,
        this PLAINTEXT page would be interpreted as a codec frame and either be
        rejected (kXR_error) or stored as decode garbage — so a byte-exact
        plaintext readback proves the opt-out."""
        remote = f"/wcmp_pg_{uuid.uuid4().hex}.bin"
        plaintext = b"pgwrite plaintext invariant on a compress handle " * 28
        assert len(plaintext) <= XRD_PGWRITE_PAGESZ, "single-page assumption broke"

        sock = _session()
        try:
            fh = _open_write_compressed(sock, remote, "zstd")
            _, pstatus, pbody = _pgwrite_single_page(sock, fh, 0, plaintext)
            assert pstatus == kXR_status, (
                f"pgwrite did not use kXR_status(4007) framing (status={pstatus}, "
                f"body={_err_fields(pbody)}) — pgwrite may have been routed through "
                "the compression decoder, violating the W5 invariant")
            _close(sock, fh)
        finally:
            sock.close()

        rstatus, content = _readback(remote)
        try:
            assert rstatus == kXR_ok, f"readback failed (status={rstatus})"
            assert content == plaintext, (
                "pgwrite on a compression-mode handle was NOT stored as verbatim "
                "plaintext — the compression invariant excludes pgwrite")
        finally:
            _rm(remote)

    @pytest.mark.skipif(not _CRC32C_OK, reason="local CRC32c self-test failed")
    def test_pgwrite_rejects_a_compressed_frame_as_plaintext(self):
        """Negative-control of the invariant: because pgwrite is plaintext, sending
        a *compressed* zstd frame through pgwrite stores the COMPRESSED BYTES
        verbatim (it is NOT decompressed).  Readback equals the frame bytes, never
        the underlying plaintext — confirming pgwrite never engages the codec."""
        remote = f"/wcmp_pg_neg_{uuid.uuid4().hex}.bin"
        plaintext = b"X" * 512
        frame = _zstd_frame(plaintext)
        assert len(frame) <= XRD_PGWRITE_PAGESZ
        assert frame != plaintext

        sock = _session()
        try:
            fh = _open_write_compressed(sock, remote, "zstd")
            _, pstatus, pbody = _pgwrite_single_page(sock, fh, 0, frame)
            assert pstatus == kXR_status, (
                f"pgwrite of a frame did not return kXR_status (status={pstatus}, "
                f"body={_err_fields(pbody)})")
            _close(sock, fh)
        finally:
            sock.close()

        rstatus, content = _readback(remote)
        try:
            assert rstatus == kXR_ok, f"readback failed (status={rstatus})"
            assert content == frame, (
                "pgwrite stored something other than the verbatim frame bytes")
            assert content != plaintext, (
                "pgwrite DECOMPRESSED a frame — it must treat input as plaintext, "
                "violating the W5 compression invariant")
        finally:
            _rm(remote)
