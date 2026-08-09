from split_continuation import reexport as _reexport
_reexport(globals(), "_test_gsi_security_helpers")

class TestGSIClientWrite:
    """Write operations through the GSI port."""

    def test_write_read_roundtrip(self):
        content = b"gsi write test content 12345"
        path = "/gsi_sec_write.txt"
        f = xrd_client.File()
        status, _ = f.open(f"{GSI_URL}/{path}", OpenFlags.NEW | OpenFlags.DELETE)
        assert status.ok, f"open for write failed: {status.message}"
        status, _ = f.write(content)
        assert status.ok
        f.close()
        data = _xrd_read_all(f"{GSI_URL}/{path}")
        assert data == content

    def test_write_then_stat_size_correct(self):
        content = b"X" * 256
        path = "/gsi_sec_stat_check.txt"
        f = xrd_client.File()
        f.open(f"{GSI_URL}/{path}", OpenFlags.NEW | OpenFlags.DELETE)
        f.write(content)
        f.close()
        fs = _gsi_fs()
        status, info = fs.stat(path)
        assert status.ok
        assert info.size == len(content)

    def test_write_via_gsi_readable_via_anon(self):
        content = b"cross-auth content"
        path = "/gsi_sec_cross.txt"
        f = xrd_client.File()
        f.open(f"{GSI_URL}/{path}", OpenFlags.NEW | OpenFlags.DELETE)
        f.write(content)
        f.close()
        anon_data = _xrd_read_all(f"{ANON_URL}/{path}")
        assert anon_data == content

    def test_write_to_new_directory(self):
        _make_file("/gsi_sec_dir/placeholder.txt", b"")
        content = b"inside subdir"
        path = "/gsi_sec_dir/new_file.txt"
        f = xrd_client.File()
        status, _ = f.open(f"{GSI_URL}/{path}", OpenFlags.NEW | OpenFlags.DELETE)
        assert status.ok
        f.write(content)
        f.close()
        data = _xrd_read_all(f"{GSI_URL}/{path}")
        assert data == content


# ---------------------------------------------------------------------------
# TestGSITLSPort
# (GSI + in-protocol TLS port 11096)
# ---------------------------------------------------------------------------

class TestGSITLSPort:
    """Functional tests on the GSI+TLS port (brix_tls on)."""

    def test_stat_root_via_tls(self):
        fs = _gsi_tls_fs()
        status, info = fs.stat("/")
        assert status.ok, f"TLS stat('/') failed: {status.message}"

    def test_stat_test_file_via_tls(self):
        fs = _gsi_tls_fs()
        status, info = fs.stat("/test.txt")
        assert status.ok
        assert info.size == 24

    def test_read_via_tls_matches_plain(self):
        tls_data  = _xrd_read_all(f"{GSI_TLS_URL}//test.txt")
        plain_data = _xrd_read_all(f"{GSI_URL}//test.txt")
        assert tls_data == plain_data

    def test_stat_nonexistent_via_tls(self):
        fs = _gsi_tls_fs()
        status, _ = fs.stat("/tls_no_such_file_xyz.txt")
        assert not status.ok

    def test_dirlist_via_tls_has_test_txt(self):
        fs = _gsi_tls_fs()
        status, listing = fs.dirlist("/")
        assert status.ok
        names = [e.name for e in listing]
        assert "test.txt" in names

    def test_qconfig_via_tls_ok(self):
        fs = _gsi_tls_fs()
        status, resp = fs.query(QueryCode.CONFIG, "chksum")
        assert status.ok
        assert b"adler32" in resp

    def test_write_read_roundtrip_via_tls(self):
        content = b"tls port write test"
        path = "/gsi_tls_sec_write.txt"
        f = xrd_client.File()
        status, _ = f.open(f"{GSI_TLS_URL}/{path}", OpenFlags.NEW | OpenFlags.DELETE)
        assert status.ok
        f.write(content)
        f.close()
        data = _xrd_read_all(f"{GSI_TLS_URL}/{path}")
        assert data == content

    def test_adler32_tls_matches_plain_gsi(self):
        fs_tls   = _gsi_tls_fs()
        fs_plain = _gsi_fs()
        s1, r1 = fs_tls.query(QueryCode.CHECKSUM, "/test.txt")
        s2, r2 = fs_plain.query(QueryCode.CHECKSUM, "/test.txt")
        if s1.ok and s2.ok:
            assert r1 == r2

    def test_two_consecutive_reads_via_tls(self):
        d1 = _xrd_read_all(f"{GSI_TLS_URL}//test.txt")
        d2 = _xrd_read_all(f"{GSI_TLS_URL}//test.txt")
        assert d1 == d2

    def test_tls_stat_size_matches_anon(self):
        fs_tls  = _gsi_tls_fs()
        fs_anon = _anon_fs()
        s1, i1 = fs_tls.stat("/test.txt")
        s2, i2 = fs_anon.stat("/test.txt")
        assert s1.ok and s2.ok
        assert i1.size == i2.size
