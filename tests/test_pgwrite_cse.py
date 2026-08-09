from split_continuation import reexport as _reexport
_reexport(globals(), "_test_pgwrite_cse_helpers")

class TestCSEReplyShape:
    def test_clean_write_has_empty_cse(self):
        sock = _handshake_login()
        try:
            fh = _open(sock, b"/_cse_clean.bin")
            st, _off, cse = send_pgwrite(sock, fh, 0, build_payload(b"x" * 500, 0))
            assert st == kXR_status
            assert cse == b"", "clean write must carry no CSE trailer"
            _close(sock, fh)
        finally:
            sock.close()

    def test_single_corrupt_page_lists_offset(self):
        sock = _handshake_login()
        try:
            fh = _open(sock, b"/_cse_single.bin")
            data = b"A" * 1000
            st, _off, cse = send_pgwrite(sock, fh, 0,
                                         build_payload(data, 0, corrupt_crc=[0]))
            assert st == kXR_status, f"want success+CSE, got {st}"
            crc, dl_first, dl_last, offs, crc_ok = parse_cse(cse)
            assert crc_ok, "cseCRC mismatch"
            assert offs == [0], offs
            assert dl_first == dl_last == 1000
        finally:
            sock.close()

    @pytest.mark.parametrize("bad", [0, 1, 2])
    def test_corrupt_position_in_three_pages(self, bad):
        sock = _handshake_login()
        try:
            fh = _open(sock, f"/_cse_3p_{bad}.bin".encode())
            data = os.urandom(kXR_pgPageSZ * 2 + 512)   # 3 pages (last short)
            st, _off, cse = send_pgwrite(sock, fh, 0,
                                         build_payload(data, 0, corrupt_crc=[bad]))
            assert st == kXR_status
            _crc, _f, _l, offs, crc_ok = parse_cse(cse)
            assert crc_ok
            assert offs == [page_offset(0, len(data), bad)], offs
        finally:
            sock.close()

    def test_multiple_corrupt_pages_ordered(self):
        sock = _handshake_login()
        try:
            fh = _open(sock, b"/_cse_multi.bin")
            data = os.urandom(kXR_pgPageSZ * 4)         # 4 full pages
            st, _off, cse = send_pgwrite(sock, fh, 0,
                                         build_payload(data, 0, corrupt_crc=[0, 2, 3]))
            assert st == kXR_status
            _crc, dl_first, dl_last, offs, crc_ok = parse_cse(cse)
            assert crc_ok
            assert offs == [page_offset(0, len(data), i) for i in (0, 2, 3)], offs
            assert dl_first == kXR_pgPageSZ and dl_last == kXR_pgPageSZ
        finally:
            sock.close()

    def test_all_pages_corrupt(self):
        sock = _handshake_login()
        try:
            fh = _open(sock, b"/_cse_all.bin")
            data = os.urandom(kXR_pgPageSZ * 3 + 10)
            npages = len(page_lengths(0, len(data)))
            st, _off, cse = send_pgwrite(sock, fh, 0,
                                         build_payload(data, 0, corrupt_crc=range(npages)))
            assert st == kXR_status
            _crc, _f, dl_last, offs, crc_ok = parse_cse(cse)
            assert crc_ok
            assert offs == [page_offset(0, len(data), i) for i in range(npages)]
            assert dl_last == 10, "last page is a short final fragment"
        finally:
            sock.close()

    def test_unaligned_start_offset(self):
        sock = _handshake_login()
        try:
            fh = _open(sock, b"/_cse_unaligned.bin")
            data = os.urandom(300)
            st, _off, cse = send_pgwrite(sock, fh, 100,
                                         build_payload(data, 100, corrupt_crc=[0]))
            assert st == kXR_status
            _crc, dl_first, _l, offs, crc_ok = parse_cse(cse)
            assert crc_ok
            assert offs == [100], offs
            assert dl_first == 300
        finally:
            sock.close()

    def test_too_many_errors_per_request(self):
        """>128 corrupt pages in one request → kXR_TooManyErrs (no CSE list)."""
        sock = _handshake_login()
        try:
            fh = _open(sock, b"/_cse_toomany.bin")
            npages = kXR_pgMaxEpr + 1
            data = os.urandom(kXR_pgPageSZ * npages)
            st, err, _msg = send_pgwrite(sock, fh, 0,
                                         build_payload(data, 0, corrupt_crc=range(npages)))
            assert st == "error", f"expected error, got {st}"
            assert err == kXR_TooManyErrs, f"expected kXR_TooManyErrs, got {err}"
        finally:
            sock.close()

    def test_malformed_payload_still_arginvalid(self):
        """A truncated payload (no room for a page after the CRC) → kXR_ArgInvalid."""
        sock = _handshake_login()
        try:
            fh = _open(sock, b"/_cse_malformed.bin")
            st, err, _msg = send_pgwrite(sock, fh, 0, b"\x00\x00\x00\x00")  # 4B = CRC only
            assert st == "error"
            assert err == kXR_ArgInvalid, f"expected kXR_ArgInvalid, got {err}"
        finally:
            sock.close()


# --------------------------------------------------------------------------- #
# 2) Write-then-correct on disk
# --------------------------------------------------------------------------- #
class TestWriteThenCorrect:
    """Accept-then-correct ON DISK (stock direct-to-disk semantics).

    These inspect the final object out-of-band MID-write, so they run against
    the upload_resume=OFF endpoint where pgwrite lands bytes on the final file
    immediately.  The resume=ON commit path is covered by
    TestWriteThenCorrectResumeOn below.
    """

    def test_corrupt_bytes_land_on_disk_then_fixed(self):
        remote = "_cse_disk_fix.bin"
        sock = _handshake_login(port=_RESUME_OFF_PORT)
        try:
            fh = _open(sock, f"/{remote}".encode())
            good = os.urandom(2000)
            # Page 0 data arrives mutated (CRC of the original) → server writes
            # the wrong bytes and reports the page.
            st, _off, cse = send_pgwrite(sock, fh, 0,
                                         build_payload(good, 0, corrupt_data=[0]))
            assert st == kXR_status
            _c, _f, _l, offs, ok = parse_cse(cse)
            assert ok and offs == [0]

            # The corrupt bytes are on disk (accept-then-correct, not hold-back).
            on_disk = open(disk_path(remote), "rb").read()
            assert on_disk != good, "corrupt page should be on disk before retry"

            # Resend page 0 with correct data → clean status, Fob cleared.
            retry, pgoff = single_page_retry_payload(good, 0, len(good), 0)
            st, _off, cse = send_pgwrite(sock, fh, pgoff, retry, reqflags=kXR_pgRetry)
            assert st == kXR_status and cse == b"", "retry should verify clean"

            st, _err = _close(sock, fh)
            assert st == kXR_ok, "close should succeed once corrected"
        finally:
            sock.close()
        assert open(disk_path(remote), "rb").read() == good, "disk not fixed by retry"
        os.unlink(disk_path(remote))

    def test_good_pages_intact_alongside_bad(self):
        remote = "_cse_good_intact.bin"
        sock = _handshake_login(port=_RESUME_OFF_PORT)
        try:
            fh = _open(sock, f"/{remote}".encode())
            data = os.urandom(kXR_pgPageSZ * 3)
            # Corrupt only page 1's data; pages 0 and 2 must be correct on disk.
            st, _off, cse = send_pgwrite(sock, fh, 0,
                                         build_payload(data, 0, corrupt_data=[1]))
            assert st == kXR_status
            on_disk = open(disk_path(remote), "rb").read()
            assert on_disk[0:kXR_pgPageSZ] == data[0:kXR_pgPageSZ]
            assert on_disk[2 * kXR_pgPageSZ:] == data[2 * kXR_pgPageSZ:]
            # correct page 1
            retry, pgoff = single_page_retry_payload(data, 0, len(data), 1)
            st, _o, cse = send_pgwrite(sock, fh, pgoff, retry, reqflags=kXR_pgRetry)
            assert st == kXR_status and cse == b""
            _close(sock, fh)
        finally:
            sock.close()
        assert open(disk_path(remote), "rb").read() == data
        os.unlink(disk_path(remote))


class TestWriteThenCorrectResumeOn:
    """Same accept-then-correct flow, but on the upload_resume=ON endpoint.

    With staging, the in-flight (and corrected) bytes live in a
    .xrdresume.*.part until close — they are NOT visible at the final path
    out-of-band mid-write — so the on-config contract is verified through the
    wire (the CSE status + close gate) and the FINAL committed object AFTER a
    clean close.  This proves pgwrite + upload_resume are compatible: the
    corrected bytes are what gets committed.
    """

    def test_corrupt_then_correct_commits_fixed_bytes(self):
        remote = "_cse_resume_on_fix.bin"
        sock = _handshake_login(port=_PORT)
        try:
            fh = _open(sock, f"/{remote}".encode())
            good = os.urandom(2000)
            # Page 0 arrives corrupt → reported via CSE.  Bytes are staged in the
            # .part (not the final path), so we do NOT inspect disk mid-write.
            st, _off, cse = send_pgwrite(sock, fh, 0,
                                         build_payload(good, 0, corrupt_data=[0]))
            assert st == kXR_status
            _c, _f, _l, offs, ok = parse_cse(cse)
            assert ok and offs == [0]
            assert not os.path.exists(disk_path(remote)), \
                "resume=ON must stage writes, not touch the final path mid-write"

            # Correct page 0 → clean status, close gate opens.
            retry, pgoff = single_page_retry_payload(good, 0, len(good), 0)
            st, _off, cse = send_pgwrite(sock, fh, pgoff, retry, reqflags=kXR_pgRetry)
            assert st == kXR_status and cse == b"", "retry should verify clean"

            st, _err = _close(sock, fh)
            assert st == kXR_ok, "close should succeed once corrected"
        finally:
            sock.close()
        # The staged partial was synchronously committed onto the final path on
        # close, carrying the CORRECTED bytes (not the corrupt ones).
        assert open(disk_path(remote), "rb").read() == good, \
            "resume=ON commit must publish the corrected bytes"
        assert not glob.glob(disk_path(remote) + "*.xrdresume.*.part"), \
            "no resume partial should survive a clean close"
        os.unlink(disk_path(remote))


# --------------------------------------------------------------------------- #
# 3) Fob / retry state machine
# --------------------------------------------------------------------------- #
class TestFobRetry:
    def test_retry_clears_one_of_two(self):
        sock = _handshake_login()
        try:
            fh = _open(sock, b"/_cse_two_clear_one.bin")
            data = os.urandom(kXR_pgPageSZ * 2)
            st, _o, cse = send_pgwrite(sock, fh, 0,
                                       build_payload(data, 0, corrupt_data=[0, 1]))
            assert st == kXR_status
            _c, _f, _l, offs, ok = parse_cse(cse)
            assert ok and len(offs) == 2

            # Correct page 1 only; page 0 stays uncorrected → close still gated.
            retry, pgoff = single_page_retry_payload(data, 0, len(data), 1)
            st, _o, cse = send_pgwrite(sock, fh, pgoff, retry, reqflags=kXR_pgRetry)
            assert st == kXR_status and cse == b""

            st, err = _close(sock, fh)
            assert st == kXR_error and err == kXR_ChkSumErr, \
                "one page still uncorrected → close must fail"

            # Now correct page 0 and close cleanly.
            retry0, pg0 = single_page_retry_payload(data, 0, len(data), 0)
            st, _o, cse = send_pgwrite(sock, fh, pg0, retry0, reqflags=kXR_pgRetry)
            assert st == kXR_status and cse == b""
            st, _err = _close(sock, fh)
            assert st == kXR_ok
        finally:
            sock.close()

    def test_retry_of_unregistered_offset_is_normal_write(self):
        """A pgRetry for a page that was never bad is treated as a normal write
        (succeeds, no error, Fob untouched) — a forged/stale retry can't poison
        the registry or the close gate."""
        remote = "_cse_stray_retry.bin"
        sock = _handshake_login()
        try:
            fh = _open(sock, f"/{remote}".encode())
            data = os.urandom(1000)
            # Stray retry on a clean handle (no prior CSE).
            st, _o, cse = send_pgwrite(sock, fh, 0,
                                       build_payload(data, 0), reqflags=kXR_pgRetry)
            assert st == kXR_status and cse == b"", "stray retry should just write"
            st, _err = _close(sock, fh)
            assert st == kXR_ok, "stray retry must not register a Fob entry"
        finally:
            sock.close()
        assert open(disk_path(remote), "rb").read() == data
        os.unlink(disk_path(remote))

    def test_retry_spanning_two_pages_rejected(self):
        sock = _handshake_login()
        try:
            fh = _open(sock, b"/_cse_retry_2page.bin")
            data = os.urandom(kXR_pgPageSZ + 100)   # spans two pages
            st, err, _msg = send_pgwrite(sock, fh, 0, build_payload(data, 0),
                                         reqflags=kXR_pgRetry)
            assert st == "error", f"expected error, got {st}"
            assert err == kXR_ArgInvalid, f"expected kXR_ArgInvalid, got {err}"
        finally:
            sock.close()

    def test_retry_still_bad_keeps_offset(self):
        sock = _handshake_login()
        try:
            fh = _open(sock, b"/_cse_retry_stillbad.bin")
            data = os.urandom(900)
            st, _o, cse = send_pgwrite(sock, fh, 0,
                                       build_payload(data, 0, corrupt_data=[0]))
            assert st == kXR_status
            # Retry but STILL corrupt → CSE again, same offset stays registered.
            st, _o, cse = send_pgwrite(sock, fh, 0,
                                       build_payload(data, 0, corrupt_data=[0]),
                                       reqflags=kXR_pgRetry)
            assert st == kXR_status
            _c, _f, _l, offs, ok = parse_cse(cse)
            assert ok and offs == [0]
            st, err = _close(sock, fh)
            assert st == kXR_error and err == kXR_ChkSumErr
        finally:
            sock.close()


# --------------------------------------------------------------------------- #
# 4) Close gate (integrity core)
# --------------------------------------------------------------------------- #
class TestCloseGate:
    def test_close_blocked_with_uncorrected(self):
        sock = _handshake_login()
        try:
            fh = _open(sock, b"/_cse_close_block.bin")
            data = os.urandom(1000)
            st, _o, _cse = send_pgwrite(sock, fh, 0,
                                        build_payload(data, 0, corrupt_crc=[0]))
            assert st == kXR_status
            st, err = _close(sock, fh)
            assert st == kXR_error and err == kXR_ChkSumErr, (st, err)
        finally:
            sock.close()

    def test_close_message_reports_count(self):
        sock = _handshake_login()
        try:
            fh = _open(sock, b"/_cse_close_count.bin")
            data = os.urandom(kXR_pgPageSZ * 3)
            st, _o, _cse = send_pgwrite(sock, fh, 0,
                                        build_payload(data, 0, corrupt_crc=[0, 1, 2]))
            assert st == kXR_status
            # Inspect the close error message text for the count "3".
            sock.sendall(struct.pack("!2sH4s12sI",
                                     b"\x00\x09", kXR_close, fh, b"\x00" * 12, 0))
            status, body = _read_response(sock)
            assert status == kXR_error
            msg = body[4:].split(b"\x00", 1)[0]
            assert b"3" in msg, f"close message should report 3 errors: {msg!r}"
        finally:
            sock.close()

    def test_clean_write_closes_ok(self):
        sock = _handshake_login()
        try:
            fh = _open(sock, b"/_cse_clean_close.bin")
            st, _o, cse = send_pgwrite(sock, fh, 0, build_payload(b"z" * 4096, 0))
            assert st == kXR_status and cse == b""
            st, _err = _close(sock, fh)
            assert st == kXR_ok
        finally:
            sock.close()


# --------------------------------------------------------------------------- #
# 5) Proxy passthrough — the CSE frame and close gate must survive the proxy's
#    two-phase kXR_status expansion unchanged.
# --------------------------------------------------------------------------- #
