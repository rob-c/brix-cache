from split_continuation import reexport as _reexport
_reexport(globals(), "_test_gsi_tls_helpers")

class TestGSITLSWrite:
    """Verify writes over GSI+TLS (xrdcp and File API)."""

    def test_write_small_file_api(self, cleanup_gsi_tls_writes):
        """Write a small file via File API and verify on disk."""
        content = b"GSI+TLS write test small file\n"
        remote = f"{WRITE_PREFIX}small.txt"

        f = client.File()
        status, _ = f.open(
            f"{GSI_TLS_URL}//{remote}",
            OpenFlags.DELETE | OpenFlags.NEW,
        )
        assert status.ok, f"open for write failed: {status.message}"
        status, _ = f.write(content)
        assert status.ok, f"write failed: {status.message}"
        f.close()

        disk_path = os.path.join(DATA_ROOT, remote)
        assert os.path.exists(disk_path), "file not created on disk"
        assert open(disk_path, "rb").read() == content

    def test_write_then_read_back(self, cleanup_gsi_tls_writes):
        """Write via File API, then read back on the same endpoint."""
        content = b"round-trip: " + os.urandom(128)
        remote = f"{WRITE_PREFIX}roundtrip.bin"

        # Write
        f = client.File()
        status, _ = f.open(
            f"{GSI_TLS_URL}//{remote}",
            OpenFlags.DELETE | OpenFlags.NEW,
        )
        assert status.ok, f"open for write failed: {status.message}"
        status, _ = f.write(content)
        assert status.ok
        f.close()

        # Read back
        data = xrd_read_all(f"{GSI_TLS_URL}//{remote}")
        assert data == content

    def test_write_medium_file_integrity(self, cleanup_gsi_tls_writes):
        """Write a 1 MB file and verify MD5 on disk."""
        size = 1024 * 1024
        content = os.urandom(size)
        expected_md5 = md5_of_bytes(content)
        remote = f"{WRITE_PREFIX}medium.bin"

        f = client.File()
        status, _ = f.open(
            f"{GSI_TLS_URL}//{remote}",
            OpenFlags.DELETE | OpenFlags.NEW,
        )
        assert status.ok, f"open for write failed: {status.message}"
        status, _ = f.write(content)
        assert status.ok
        f.close()

        disk_path = os.path.join(DATA_ROOT, remote)
        assert os.path.getsize(disk_path) == size
        assert md5_of_file(disk_path) == expected_md5

    def test_xrdcp_upload(self, cleanup_gsi_tls_writes):
        """Upload a file via xrdcp to the GSI+TLS endpoint."""
        content = b"xrdcp GSI+TLS upload test\n"
        remote = f"{WRITE_PREFIX}xrdcp.txt"
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(content)
            local = tmp.name
        try:
            env = (
                f"X509_CERT_DIR={CA_DIR} "
                f"X509_USER_PROXY={PROXY_PEM}"
            )
            cmd = f"{env} xrdcp -f {local} {GSI_TLS_URL}//{remote} 2>&1"
            rc = os.system(cmd)
            assert rc == 0, "xrdcp upload failed"

            disk_path = os.path.join(DATA_ROOT, remote)
            assert os.path.exists(disk_path)
            assert open(disk_path, "rb").read() == content
        finally:
            os.unlink(local)

    def test_xrdcp_large_upload_integrity(self, cleanup_gsi_tls_writes):
        """Upload a 10 MB file via xrdcp and verify MD5."""
        size = 10 * 1024 * 1024
        content = os.urandom(size)
        expected_md5 = md5_of_bytes(content)
        remote = f"{WRITE_PREFIX}xrdcp_large.bin"

        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(content)
            local = tmp.name
        try:
            env = (
                f"X509_CERT_DIR={CA_DIR} "
                f"X509_USER_PROXY={PROXY_PEM}"
            )
            cmd = f"{env} xrdcp -f {local} {GSI_TLS_URL}//{remote} 2>&1"
            rc = os.system(cmd)
            assert rc == 0, "xrdcp large upload failed"

            disk_path = os.path.join(DATA_ROOT, remote)
            assert os.path.getsize(disk_path) == size
            assert md5_of_file(disk_path) == expected_md5
        finally:
            os.unlink(local)

    def test_overwrite_existing_file(self, cleanup_gsi_tls_writes):
        """Overwrite an existing file and verify new content."""
        remote = f"{WRITE_PREFIX}overwrite.txt"

        # Write original
        f = client.File()
        status, _ = f.open(
            f"{GSI_TLS_URL}//{remote}",
            OpenFlags.DELETE | OpenFlags.NEW,
        )
        assert status.ok
        status, _ = f.write(b"original\n")
        assert status.ok
        f.close()

        # Overwrite
        f = client.File()
        status, _ = f.open(
            f"{GSI_TLS_URL}//{remote}",
            OpenFlags.DELETE | OpenFlags.NEW,
        )
        assert status.ok
        status, _ = f.write(b"replaced\n")
        assert status.ok
        f.close()

        disk_path = os.path.join(DATA_ROOT, remote)
        assert open(disk_path, "rb").read() == b"replaced\n"

    def test_write_read_cross_endpoint(self, cleanup_gsi_tls_writes):
        """Write via GSI+TLS, read back via plain GSI — data matches."""
        content = b"cross-endpoint: " + os.urandom(64)
        remote = f"{WRITE_PREFIX}cross.bin"

        f = client.File()
        status, _ = f.open(
            f"{GSI_TLS_URL}//{remote}",
            OpenFlags.DELETE | OpenFlags.NEW,
        )
        assert status.ok
        status, _ = f.write(content)
        assert status.ok
        f.close()

        data = xrd_read_all(f"{GSI_URL}//{remote}")
        assert data == content
