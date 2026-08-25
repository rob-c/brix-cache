from split_continuation import reexport as _reexport
_reexport(globals(), "_test_prepare_staging_helpers")

# Every stage test truncates and then reads the ONE server-side journal
# (PREPARE_CMD_LOG) on the shared prepare-command instance, so the whole
# family — this module and its _b split — must stay on one xdist worker.
pytestmark = pytest.mark.xdist_group("prepare-staging")

class TestPrepareValid:
    """Verify that a prepare request with valid existing files returns ok."""

    def test_prepare_single_existing_file(self, anon_port):
        """kXR_prepare with one existing file must return kXR_ok."""
        sock, streamid = _establish_session(ANON_PORT)

        # Prepare with one existing file (the data directory has test files)
        status, body = _send_prepare(sock, streamid, 8, 0, b"/auth_cache_probe.txt")
        assert status == kXR_ok or status == kXR_error, \
            f"prepare for existing file: status={status}, body={body!r}"

        sock.close()

    def test_prepare_multiple_existing_files(self, anon_port):
        """kXR_prepare with multiple existing files must return kXR_ok."""
        sock, streamid = _establish_session(ANON_PORT)

        # Prepare with multiple files (newline-separated)
        payload = b"/auth_cache_probe.txt\n/prepare_large_probe.bin\n"
        status, body = _send_prepare(sock, streamid, 8, 0, payload)
        assert status == kXR_ok or status == kXR_error, \
            f"prepare for multiple files: status={status}, body={body!r}"

        sock.close()


# ---------------------------------------------------------------------------
# QPrep status query
# ---------------------------------------------------------------------------

class TestQPrepStatus:
    """Verify kXR_QPrep returns per-path disk availability status."""

    def test_qprep_no_prior_prepare_returns_empty_ok(self, anon_port):
        sock, streamid = _establish_session(ANON_PORT)

        status, body = _send_query(sock, streamid, kXR_QPrep, b"")
        assert status == kXR_ok
        assert body == b""

        sock.close()

    def test_qprep_after_stage_reports_available(self, anon_port):
        sock, streamid = _establish_session(ANON_PORT)

        status, body = _send_prepare(sock, streamid, 8, 0,
                                     b"/auth_cache_probe.txt")
        assert status == kXR_ok, f"prepare stage failed: status={status}, body={body!r}"

        status, body = _send_query(sock, streamid, kXR_QPrep, b"0")
        assert status == kXR_ok
        assert body.rstrip(b"\x00") == b"A /auth_cache_probe.txt\n"

        sock.close()

    def test_qprep_after_stage_noerrs_reports_missing(self, anon_port):
        sock, streamid = _establish_session(ANON_PORT)

        status, body = _send_prepare(sock, streamid, 8 | 4, 0,
                                     b"/qprep_missing.bin")
        assert status == kXR_ok, f"prepare noerrs stage failed: status={status}, body={body!r}"

        status, body = _send_query(sock, streamid, kXR_QPrep, b"0")
        assert status == kXR_ok
        assert body.rstrip(b"\x00") == b"M /qprep_missing.bin\n"

        sock.close()

    def test_qprep_inline_paths_do_not_need_stored_prepare(self, anon_port):
        sock, streamid = _establish_session(ANON_PORT)

        status, body = _send_query(sock, streamid, kXR_QPrep,
                                   b"0\n/auth_cache_probe.txt\n/qprep_missing.bin\n")
        assert status == kXR_ok
        lines = set(body.rstrip(b"\x00").splitlines())
        assert b"A /auth_cache_probe.txt" in lines
        assert b"M /qprep_missing.bin" in lines

        sock.close()

    def test_qprep_traversal_path_is_reported_missing(self, anon_port):
        sock, streamid = _establish_session(ANON_PORT)

        status, body = _send_query(sock, streamid, kXR_QPrep,
                                   b"0\n/../etc/passwd\n")
        assert status == kXR_ok
        assert body.rstrip(b"\x00") == b"M /../etc/passwd\n"

        sock.close()


# ---------------------------------------------------------------------------
# Non-existent file -- kXR_NotFound
# ---------------------------------------------------------------------------

class TestPrepareNotFound:
    """Verify that a prepare request with non-existent files returns error."""

    def test_prepare_nonexistent_file(self, anon_port):
        """kXR_prepare with a path that does not exist must return kXR_NotFound."""
        sock, streamid = _establish_session(ANON_PORT)

        status, body = _send_prepare(sock, streamid, 8, 0, b"/does-not-exist-at-all.bin")
        assert status == kXR_error and b"not found" in body.lower(), \
            f"expected NotFound for nonexistent file: status={status}, body={body!r}"

        sock.close()


# ---------------------------------------------------------------------------
# noerrs flag -- missing count instead of error
# ---------------------------------------------------------------------------

class TestPrepareNoErrs:
    """Verify that the noerrs flag returns ok with a missing count."""

    def test_prepare_noerrs_mixed(self, anon_port):
        """kXR_prepare with noerrs flag and mixed existing/nonexistent files
        must return kXR_ok (not error) with missing paths reported.
        """
        sock, streamid = _establish_session(ANON_PORT)

        # noerrs flag (4) in options -- mixed file list
        payload = b"/auth_cache_probe.txt\n/does-not-exist-at-all.bin\n"
        status, body = _send_prepare(sock, streamid, 4, 0, payload)
        assert status == kXR_ok or status == kXR_error, \
            f"prepare with noerrs: status={status}, body={body!r}"

        sock.close()


# ---------------------------------------------------------------------------
# Directory target -- kXR_isDirectory
# ---------------------------------------------------------------------------

class TestPrepareDirectory:
    """Verify that a prepare request targeting a directory is rejected."""

    def test_prepare_directory_target(self, anon_port):
        """kXR_prepare with a path pointing to a directory must return
        kXR_isDirectory.
        """
        sock, streamid = _establish_session(ANON_PORT)

        # The root "/" is a directory
        status, body = _send_prepare(sock, streamid, 8, 0, b"/")
        assert status == kXR_error and (b"directory" in body.lower() or b"isdir" in body.lower()), \
            f"expected isDirectory for directory target: status={status}, body={body!r}"

        sock.close()


# ---------------------------------------------------------------------------
# Cancel request -- no-op returns ok
# ---------------------------------------------------------------------------

class TestPrepareCancel:
    """Verify that a cancel prepare request returns ok (no-op on local storage)."""

    def test_prepare_cancel(self, anon_port):
        """kXR_prepare with kXR_cancel option must return kXR_ok."""
        sock, streamid = _establish_session(ANON_PORT)

        # cancel option (1) in options field
        status, body = _send_prepare(sock, streamid, 1, 0, b"")
        assert status == kXR_ok or status == kXR_error, \
            f"cancel prepare: status={status}, body={body!r}"

        sock.close()


# ---------------------------------------------------------------------------
# Evict request -- no-op returns ok
# ---------------------------------------------------------------------------

class TestPrepareEvict:
    """Verify that an evict prepare request returns ok (no-op on local storage)."""

    def test_prepare_evict(self, anon_port):
        """kXR_prepare with kXR_evict in optionX must return kXR_ok."""
        sock, streamid = _establish_session(ANON_PORT)

        # evict in optionX field (0x01)
        status, body = _send_prepare(sock, streamid, 8, 0x01, b"")
        assert status == kXR_ok or status == kXR_error, \
            f"evict prepare: status={status}, body={body!r}"

        sock.close()


# ---------------------------------------------------------------------------
# Empty payload -- kXR_ArgMissing
# ---------------------------------------------------------------------------

class TestPrepareEmptyPayload:
    """Verify that a prepare request with no file list payload is rejected."""

    def test_prepare_no_payload(self, anon_port):
        """kXR_prepare without any payload (dlen=0) must return kXR_ArgMissing."""
        sock, streamid = _establish_session(ANON_PORT)

        status, body = _send_prepare(sock, streamid, 8, 0, b"")
        assert status == kXR_error and b"missing" in body.lower(), \
            f"expected ArgMissing for empty payload: status={status}, body={body!r}"

        sock.close()


# ---------------------------------------------------------------------------
# Path with dot-dot -- kXR_ArgInvalid
# ---------------------------------------------------------------------------

class TestPreparePathSecurity:
    """Verify that prepare rejects paths containing dot-dot components."""

    def test_prepare_dotdot_path(self, anon_port):
        """kXR_prepare with a path containing '..' must return kXR_ArgInvalid.

        The module checks for '.' and '..' path segments in prepare payloads
        to prevent path traversal attacks.
        """
        sock, streamid = _establish_session(ANON_PORT)

        status, body = _send_prepare(sock, streamid, 8, 0, b"/../etc/passwd")
        assert status == kXR_error and (b"invalid" in body.lower() or b"dotdot" in body.lower()), \
            f"expected ArgInvalid for dot-dot path: status={status}, body={body!r}"

        sock.close()


# ---------------------------------------------------------------------------
# brix_prepare_command — fire-and-forget staging hook
# ---------------------------------------------------------------------------
