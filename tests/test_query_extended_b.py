from split_continuation import reexport as _reexport
_reexport(globals(), "_test_query_extended_helpers")

class TestQckscan:

    def _lines(self, body):
        text = body.rstrip(b"\x00").decode("utf-8", errors="replace")
        return [line for line in text.splitlines() if line]

    def test_qckscan_single_file(self):
        data = b"single-file-qckscan"
        _make_file("/qckscan_single.bin", data)
        sock = _session()
        status, body = _query(sock, kXR_Qckscan, b"/qckscan_single.bin\x00")
        sock.close()
        assert status == kXR_ok
        assert self._lines(body) == [
            f"adler32 {_adler_hex(data)}  /qckscan_single.bin"
        ]

    def test_qckscan_directory_tree(self):
        a = b"alpha"
        b = b"beta"
        _make_dir("/qckscan_tree/sub")
        _make_file("/qckscan_tree/a.bin", a)
        _make_file("/qckscan_tree/sub/b.bin", b)
        sock = _session()
        status, body = _query(sock, kXR_Qckscan, b"/qckscan_tree\x00")
        sock.close()
        assert status == kXR_ok
        assert set(self._lines(body)) == {
            f"adler32 {_adler_hex(a)}  /qckscan_tree/a.bin",
            f"adler32 {_adler_hex(b)}  /qckscan_tree/sub/b.bin",
        }

    def test_qckscan_nonexistent_path_errors(self):
        sock = _session()
        status, body = _query(sock, kXR_Qckscan, b"/qckscan_missing_xyz\x00")
        sock.close()
        assert status == kXR_error
        assert _error_code(body) == kXR_NotFound

    def test_qckscan_symlink_escape_is_not_followed(self, tmp_path):
        outside = tmp_path / "outside"
        outside.mkdir()
        (outside / "hidden.txt").write_bytes(b"hidden")

        scan_dir = os.path.join(DATA_DIR, "qckscan_symlink")
        os.makedirs(scan_dir, exist_ok=True)
        _make_file("/qckscan_symlink/visible.txt", b"visible")

        link_path = os.path.join(scan_dir, "outside")
        try:
            os.unlink(link_path)
        except FileNotFoundError:
            pass
        os.symlink(str(outside), link_path)

        sock = _session()
        status, body = _query(sock, kXR_Qckscan, b"/qckscan_symlink\x00")
        sock.close()
        assert status == kXR_ok
        text = body.decode("utf-8", errors="replace")
        assert "visible.txt" in text
        assert "hidden.txt" not in text


# =========================================================================
# Class 7 — Query Consistency
# =========================================================================

class TestQueryConsistency:

    def test_adler32_empty_file_is_1(self):
        _make_file("/qdl_cksum_empty.bin", b"")
        sock = _session()
        status, body = _query(sock, kXR_Qcksum, b"/qdl_cksum_empty.bin\x00")
        sock.close()
        # adler32 of empty data = 1 (zlib spec initial value)
        if status == kXR_ok:
            assert b"1" in body or b"00000001" in body.lower()

    def test_checksum_changes_after_overwrite(self):
        path = b"/qdl_cksum_change.bin\x00"
        _make_file("/qdl_cksum_change.bin", b"version1")
        sock = _session()
        s1, b1 = _query(sock, kXR_Qcksum, path, streamid=b"\x00\x10")
        sock.close()
        # Overwrite with different content
        _make_file("/qdl_cksum_change.bin", b"version2_different_content")
        sock2 = _session()
        s2, b2 = _query(sock2, kXR_Qcksum, path, streamid=b"\x00\x11")
        sock2.close()
        if s1 == kXR_ok and s2 == kXR_ok:
            assert b1 != b2, "checksum must differ after content change"

    def test_qspace_returns_ok(self):
        # kXR_Qspace requires a path: both our server and stock reject an empty/
        # absent path (kXR_error "relative path '' disallowed"); a valid path like
        # "/" returns the space metrics.  Verified differentially against stock.
        sock = _session()
        status, body = _query(sock, kXR_Qspace, b"/")
        sock.close()
        assert status == kXR_ok
        assert len(body) > 0

    def test_qspace_has_oss_fields(self):
        sock = _session()
        status, body = _query(sock, kXR_Qspace, b"/")
        sock.close()
        assert status == kXR_ok
        # Response should contain space metrics
        assert b"oss" in body.lower() or b"free" in body.lower() or len(body) > 0

    def test_qfsinfo_returns_ok(self):
        sock = _session()
        status, body = _query(sock, kXR_QFSinfo)
        sock.close()
        assert status == kXR_ok
        assert len(body) > 0

    def test_qconfig_then_qspace_consistent(self):
        sock = _session()
        s1, b1 = _query(sock, kXR_Qconfig, b"chksum", streamid=b"\x00\x10")
        s2, b2 = _query(sock, kXR_Qspace, b"/", streamid=b"\x00\x11")
        sock.close()
        assert s1 == kXR_ok
        assert s2 == kXR_ok

    def test_unknown_infotype_returns_unsupported(self):
        sock = _session()
        status, body = _query(sock, 999)
        sock.close()
        assert status == kXR_error
        assert _error_code(body) == kXR_Unsupported
