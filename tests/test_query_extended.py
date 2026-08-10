from split_continuation import reexport as _reexport
_reexport(globals(), "_test_query_extended_helpers")

class TestQconfigKnownKeys:
    """kXR_Qconfig (infotype=7) — src/protocols/root/query/config.c"""

    def test_qconfig_chksum_returns_adler32(self):
        sock = _session()
        status, body = _query(sock, kXR_Qconfig, b"chksum")
        sock.close()
        assert status == kXR_ok
        # Reference do_Qconf returns the bare checksum cslist (no "chksum=" prefix);
        # adler32 leads (xrdcp default).  Cf. test_qconfig_key_without_newline.
        assert b"adler32" in body

    def test_qconfig_readv_returns_1(self):
        sock = _session()
        status, body = _query(sock, kXR_Qconfig, b"readv")
        sock.close()
        assert status == kXR_ok
        assert b"readv=1" in body

    def test_qconfig_unknown_key_returns_zero(self):
        sock = _session()
        status, body = _query(sock, kXR_Qconfig, b"nosuchfeature")
        sock.close()
        assert status == kXR_ok
        # Reference do_Qconf echoes an unrecognised key name verbatim (no "=0").
        assert b"nosuchfeature" in body

    def test_qconfig_multiple_keys_single_req(self):
        sock = _session()
        payload = b"chksum\nreadv\nnosuch"
        status, body = _query(sock, kXR_Qconfig, payload)
        sock.close()
        assert status == kXR_ok
        assert b"adler32" in body
        assert b"readv=1" in body
        assert b"nosuch" in body

    def test_qconfig_empty_payload_rejected(self):
        # An empty kXR_Qconfig payload (no keys requested) is rejected by both our
        # server and stock xrootd (kXR_error "Required argument not present").
        # Verified differentially against stock.
        sock = _session()
        status, body = _query(sock, kXR_Qconfig, b"")
        sock.close()
        assert status == kXR_error

    def test_qconfig_key_without_newline(self):
        sock = _session()
        status, body = _query(sock, kXR_Qconfig, b"chksum")
        sock.close()
        assert status == kXR_ok
        assert b"adler32" in body

    def test_qconfig_response_ends_with_newline(self):
        sock = _session()
        status, body = _query(sock, kXR_Qconfig, b"chksum")
        sock.close()
        assert status == kXR_ok
        # Response ends with \n or \0
        assert body.endswith(b"\n") or body.endswith(b"\x00")

    def test_qconfig_two_consecutive_requests(self):
        sock = _session()
        s1, b1 = _query(sock, kXR_Qconfig, b"chksum", streamid=b"\x00\x10")
        s2, b2 = _query(sock, kXR_Qconfig, b"readv", streamid=b"\x00\x11")
        sock.close()
        assert s1 == kXR_ok and b"adler32" in b1
        assert s2 == kXR_ok and b"readv=1" in b2


# =========================================================================
# Class 2 — Qvisa
# =========================================================================

class TestQueryVisa:
    """kXR_Qvisa (infotype=8) — completely untested."""

    def test_qvisa_no_path_no_crash(self):
        # Qvisa with dlen=0 — server handles it
        sock = _session()
        status, body = _query(sock, kXR_Qvisa, b"")
        sock.close()
        # Any response is acceptable (ok, error, unsupported) — just must not hang
        assert status in (kXR_ok, kXR_error)

    def test_qvisa_with_path_returns_error(self):
        # Qvisa dispatch: dlen != 0 → returns kXR_ArgInvalid
        sock = _session()
        status, body = _query(sock, kXR_Qvisa, b"/test.txt\x00")
        sock.close()
        assert status == kXR_error
        assert _error_code(body) == kXR_ArgInvalid

    def test_qvisa_two_consecutive_requests(self):
        sock = _session()
        s1, b1 = _query(sock, kXR_Qvisa, b"", streamid=b"\x00\x10")
        s2, b2 = _query(sock, kXR_Qvisa, b"", streamid=b"\x00\x11")
        sock.close()
        # Server must not stall after first Qvisa
        assert s1 in (kXR_ok, kXR_error)
        assert s2 in (kXR_ok, kXR_error)

    def test_qvisa_then_ping(self):
        sock = _session()
        s1, b1 = _query(sock, kXR_Qvisa, b"")
        # Ping must still work after Qvisa
        req = struct.pack("!2sH16sI", b"\x00\x02", kXR_ping, b"\x00"*16, 0)
        sock.sendall(req)
        s2, b2 = _read_response(sock)
        sock.close()
        assert s2 == kXR_ok

    def test_qvisa_ok_body_is_bytes(self):
        sock = _session()
        status, body = _query(sock, kXR_Qvisa, b"")
        sock.close()
        assert isinstance(body, bytes)


# =========================================================================
# Class 3 — Qopaque
# =========================================================================

class TestQueryOpaque:
    """kXR_Qopaque (infotype=16) — completely untested."""

    def test_qopaque_plain_path_no_crash(self):
        sock = _session()
        status, body = _query(sock, kXR_Qopaque, b"/test.txt\x00")
        sock.close()
        assert status in (kXR_ok, kXR_error)

    def test_qopaque_with_opaque_string(self):
        sock = _session()
        status, body = _query(sock, kXR_Qopaque, b"/test.txt?key=val\x00")
        sock.close()
        assert status in (kXR_ok, kXR_error)

    def test_qopaque_large_payload_no_crash(self):
        # Large opaque string — must not crash
        payload = b"/test?" + b"k=v&" * 512 + b"\x00"
        # Trim to avoid dlen limit
        payload = payload[:512]
        sock = _session()
        status, body = _query(sock, kXR_Qopaque, payload)
        sock.close()
        assert status in (kXR_ok, kXR_error)

    def test_qopaque_response_is_bytes(self):
        sock = _session()
        status, body = _query(sock, kXR_Qopaque, b"")
        sock.close()
        assert isinstance(body, bytes)

    def test_qopaque_then_ping(self):
        sock = _session()
        _query(sock, kXR_Qopaque, b"/test.txt\x00")
        req = struct.pack("!2sH16sI", b"\x00\x02", kXR_ping, b"\x00"*16, 0)
        sock.sendall(req)
        s2, b2 = _read_response(sock)
        sock.close()
        assert s2 == kXR_ok


# =========================================================================
# Class 4 — Dirlist Edge Cases
# =========================================================================

class TestDirlistEdgeCases:

    def test_dirlist_empty_directory(self):
        _make_dir("/qdl_empty_dir")
        sock = _session()
        status, body = _dirlist(sock, "/qdl_empty_dir")
        sock.close()
        assert status == kXR_ok

    def test_dirlist_dstat_flag(self):
        _make_dir("/qdl_dstat_dir")
        _make_file("/qdl_dstat_dir/file.txt", b"x" * 100)
        sock = _session()
        status, body = _dirlist(sock, "/qdl_dstat_dir", flags=kXR_dstat)
        sock.close()
        assert status == kXR_ok
        assert b"file.txt" in body

    def test_dirlist_nonexistent_path_error(self):
        sock = _session()
        status, body = _dirlist(sock, "/nonexistent_dir_xyz_abc")
        sock.close()
        assert status == kXR_error

    def test_dirlist_on_file_is_error(self):
        _make_file("/qdl_a_file.txt", b"content")
        sock = _session()
        status, body = _dirlist(sock, "/qdl_a_file.txt")
        sock.close()
        assert status == kXR_error

    def test_dirlist_dstat_size_correct(self):
        content = b"X" * 512
        _make_dir("/qdl_sz_dir")
        _make_file("/qdl_sz_dir/sized.txt", content)
        sock = _session()
        status, body = _dirlist(sock, "/qdl_sz_dir", flags=kXR_dstat)
        sock.close()
        assert status == kXR_ok
        # body contains "sized.txt" and stat info including size 512
        assert b"sized.txt" in body
        assert b"512" in body

    def test_dirlist_body_newline_delimited(self):
        _make_dir("/qdl_nl_dir")
        _make_file("/qdl_nl_dir/a.txt", b"a")
        _make_file("/qdl_nl_dir/b.txt", b"b")
        sock = _session()
        status, body = _dirlist(sock, "/qdl_nl_dir")
        sock.close()
        assert status == kXR_ok
        # Entries separated by newlines
        assert b"\n" in body

    def test_dirlist_trailing_slash_ok(self):
        _make_dir("/qdl_slash_dir")
        _make_file("/qdl_slash_dir/x.txt", b"x")
        sock = _session()
        s1, b1 = _dirlist(sock, "/qdl_slash_dir", streamid=b"\x00\x10")
        s2, b2 = _dirlist(sock, "/qdl_slash_dir/", streamid=b"\x00\x11")
        sock.close()
        assert s1 == kXR_ok
        assert s2 == kXR_ok

    def test_dirlist_root_has_test_files(self):
        sock = _session()
        status, body = _dirlist(sock, "/")
        sock.close()
        assert status == kXR_ok
        assert b"test.txt" in body

    def test_dirlist_multiple_files(self):
        _make_dir("/qdl_multi")
        for i in range(5):
            _make_file(f"/qdl_multi/file{i}.txt", bytes([i]))
        sock = _session()
        status, body = _dirlist(sock, "/qdl_multi")
        sock.close()
        assert status == kXR_ok
        for i in range(5):
            assert f"file{i}.txt".encode() in body

    def test_dirlist_subdir_no_cross_dir(self):
        _make_dir("/qdl_isolated/subA")
        _make_dir("/qdl_isolated/subB")
        _make_file("/qdl_isolated/subA/inA.txt", b"a")
        _make_file("/qdl_isolated/subB/inB.txt", b"b")
        sock = _session()
        status, body = _dirlist(sock, "/qdl_isolated/subA")
        sock.close()
        assert status == kXR_ok
        assert b"inA.txt" in body
        assert b"inB.txt" not in body


# =========================================================================
# Class 5 — Checksum Query Coverage
# =========================================================================

class TestChecksumQueries:

    def test_qcksum_crc32_known_file(self):
        """kXR_Qcksum crc32 (ISO-3309) must return the zlib CRC32 as 8 hex chars."""
        import zlib
        payload = b"123456789"
        _make_file("/qcrc32_known.bin", payload)
        expected = zlib.crc32(payload) & 0xFFFFFFFF
        sock = _session()
        status, body = _query(sock, kXR_Qcksum, b"crc32:/qcrc32_known.bin\x00")
        sock.close()
        assert status == kXR_ok
        text = body.rstrip(b"\x00").decode("ascii")
        algo, hexval = text.split()
        assert algo == "crc32"
        assert int(hexval, 16) == expected

    def test_qcksum_crc32_response_shape(self):
        """crc32 response is 'crc32 XXXXXXXX' (8 lower-hex digits)."""
        _make_file("/qcrc32_shape.bin", b"shape-test-crc32")
        sock = _session()
        status, body = _query(sock, kXR_Qcksum, b"crc32:/qcrc32_shape.bin\x00")
        sock.close()
        assert status == kXR_ok
        text = body.rstrip(b"\x00").decode("ascii")
        algo, hexval = text.split()
        assert algo == "crc32"
        assert len(hexval) == 8
        int(hexval, 16)  # must be valid hex

    def test_qcksum_crc32c_known_file(self):
        _make_file("/qcrc32c_known.bin", b"123456789")
        sock = _session()
        status, body = _query(sock, kXR_Qcksum, b"crc32c:/qcrc32c_known.bin\x00")
        sock.close()
        assert status == kXR_ok
        assert body.rstrip(b"\x00") == b"crc32c e3069283"

    def test_qcksum_crc32c_response_shape(self):
        _make_file("/qcrc32c_shape.bin", b"shape-test")
        sock = _session()
        status, body = _query(sock, kXR_Qcksum, b"crc32c:/qcrc32c_shape.bin\x00")
        sock.close()
        assert status == kXR_ok
        text = body.rstrip(b"\x00").decode("ascii")
        algo, hexval = text.split()
        assert algo == "crc32c"
        assert len(hexval) == 8
        int(hexval, 16)

    def test_qcksum_unknown_algorithm_still_errors(self):
        _make_file("/qcrc32c_unknown_alg.bin", b"alg-test")
        sock = _session()
        status, body = _query(sock, kXR_Qcksum, b"bogus:/qcrc32c_unknown_alg.bin\x00")
        sock.close()
        assert status == kXR_error
        assert _error_code(body) == kXR_ArgInvalid


class TestQconfigStockKeyParity:
    """kXR_Qconfig residual keys from parity-audit §1.14 — semantics verified
    live against the fleet's stock XRootD reference server (5.6.9, default
    config): `window` answers a bare positive integer (the TCP window in use);
    sysid/wan_port/wan_window/sitename/cid ECHO their key name when the
    feature is unconfigured — which on BriX (no directive sets them) is the
    permanent, reference-faithful answer."""

    def test_qconfig_window_returns_positive_int(self):
        """(success) `window` emits the session's receive window as a bare
        integer — never the echoed key name."""
        sock = _session()
        status, body = _query(sock, kXR_Qconfig, b"window")
        sock.close()
        assert status == kXR_ok
        text = body.rstrip(b"\x00").decode("ascii").strip()
        assert text != "window", "window key was echoed, not answered"
        assert int(text) > 0, f"window not a positive integer: {text!r}"

    def test_qconfig_unset_stock_keys_echo(self):
        """(error-shape parity) keys stock answers only when configured —
        sysid/wan_port/wan_window/sitename/cid — echo verbatim, matching the
        stock 5.6.9 default-config behavior byte-for-byte."""
        sock = _session()
        status, body = _query(sock, kXR_Qconfig,
                              b"sysid wan_port wan_window sitename cid")
        sock.close()
        assert status == kXR_ok
        lines = body.rstrip(b"\x00").decode("ascii").split("\n")
        assert lines[:5] == ["sysid", "wan_port", "wan_window",
                             "sitename", "cid"], lines

    def test_qconfig_window_flood_stays_bounded(self):
        """(security-neg) a hostile query repeating `window` far past the
        512-byte response buffer must neither overflow nor error — the
        capacity-tracked append truncates and the reply stays well-formed."""
        sock = _session()
        status, body = _query(sock, kXR_Qconfig, b" ".join([b"window"] * 80))
        sock.close()
        assert status == kXR_ok
        assert len(body) <= 512
        first = body.rstrip(b"\x00").decode("ascii").split("\n")[0].strip()
        assert int(first) > 0


# =========================================================================
# Class 6 — Qckscan
# =========================================================================
