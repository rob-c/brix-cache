from split_continuation import reexport as _reexport
_reexport(globals(), "_test_gsi_bridge_helpers")

class TestXrootdToNginx:
    """Copy files from the official xrootd server to the nginx-xrootd endpoint."""

    def test_small_file_transfer(self, nginx_gsi_ready):
        """Copy a small file from xrootd to nginx; verify content is identical."""
        content = b"Hello from official xrootd server via GSI!\n" * 10
        filename = "bridge_small_xrd_to_nginx.txt"

        # Write source file into xrootd's data directory
        src_path = os.path.join(BRIDGE_DATA, filename)
        with open(src_path, "wb") as f:
            f.write(content)

        # Copy xrootd → nginx via xrdcp (GSI on both ends)
        rc = _xrdcp(
            f"{REF_URL}//{filename}",
            f"{NGINX_URL}//{filename}",
        )
        assert rc == 0, "xrdcp xrootd→nginx failed"

        # Verify on nginx side
        dst_path = os.path.join(NGINX_DATA, filename)
        assert os.path.exists(dst_path), "File not found in nginx data dir"
        with open(dst_path, "rb") as f:
            got = f.read()
        assert got == content, "File content mismatch after xrootd→nginx transfer"

    def test_large_file_transfer(self, nginx_gsi_ready):
        """Transfer a 10 MB file from xrootd to nginx and verify md5."""
        size = 10 * 1024 * 1024
        content = bytes(range(256)) * (size // 256)
        filename = "bridge_large_xrd_to_nginx.bin"

        src_path = os.path.join(BRIDGE_DATA, filename)
        with open(src_path, "wb") as f:
            f.write(content)
        expected_md5 = _md5(src_path)

        rc = _xrdcp(
            f"{REF_URL}//{filename}",
            f"{NGINX_URL}//{filename}",
        )
        assert rc == 0, "xrdcp large file xrootd→nginx failed"

        dst_path = os.path.join(NGINX_DATA, filename)
        assert os.path.exists(dst_path)
        assert _md5(dst_path) == expected_md5, "md5 mismatch after 10 MB xrootd→nginx"

    def test_checksum_preserved(self, nginx_gsi_ready):
        """Adler32 checksum returned by nginx must match the source file's checksum."""
        content = b"checksum integrity test " * 512
        filename = "bridge_cksum_xrd_to_nginx.txt"

        src_path = os.path.join(BRIDGE_DATA, filename)
        with open(src_path, "wb") as f:
            f.write(content)
        expected = _adler32(src_path)

        rc = _xrdcp(f"{REF_URL}//{filename}", f"{NGINX_URL}//{filename}")
        assert rc == 0

        # Query checksum from nginx via GSI
        os.environ["X509_CERT_DIR"]   = CA_DIR
        os.environ["X509_USER_PROXY"] = PROXY_PEM
        os.environ["XrdSecPROTOCOL"]  = "gsi"
        fs = client.FileSystem(NGINX_URL)
        st, resp = fs.query(QueryCode.CHECKSUM, f"/{filename}")
        assert st.ok, f"Checksum query failed: {st.message}"

        # Response: b"adler32 <hex>\x00"
        parts = resp.decode("ascii", errors="replace").strip("\x00").split()
        assert len(parts) == 2 and parts[0] == "adler32"
        got = int(parts[1], 16)
        assert got == expected, (
            f"Checksum mismatch: nginx returned {got:#010x}, expected {expected:#010x}"
        )


# ---------------------------------------------------------------------------
# Tests: nginx → xrootd (GSI on both ends)
# ---------------------------------------------------------------------------

class TestNginxToXrootd:
    """Copy files from the nginx-xrootd endpoint to the official xrootd server."""

    def test_small_file_transfer(self, nginx_gsi_ready):
        """Upload to nginx, then copy nginx → xrootd; verify content."""
        content = b"Hello from nginx-xrootd via GSI!\n" * 10
        filename = "bridge_small_nginx_to_xrd.txt"

        # Upload to nginx
        local = _write_local(content)
        try:
            rc = _xrdcp(local, f"{NGINX_URL}//{filename}")
            assert rc == 0, "Upload to nginx failed"

            # Copy nginx → xrootd
            rc = _xrdcp(
                f"{NGINX_URL}//{filename}",
                f"{REF_URL}//{filename}",
            )
            assert rc == 0, "xrdcp nginx→xrootd failed"

            # Verify on disk in xrootd data dir
            dst_path = os.path.join(BRIDGE_DATA, filename)
            assert os.path.exists(dst_path)
            with open(dst_path, "rb") as f:
                got = f.read()
            assert got == content
        finally:
            os.unlink(local)

    def test_large_file_transfer(self, nginx_gsi_ready):
        """Upload 10 MB to nginx, copy to xrootd, verify md5."""
        size = 10 * 1024 * 1024
        content = os.urandom(size)
        filename = "bridge_large_nginx_to_xrd.bin"

        local = _write_local(content)
        try:
            expected_md5 = _md5(local)

            rc = _xrdcp(local, f"{NGINX_URL}//{filename}")
            assert rc == 0, "Upload 10 MB to nginx failed"

            rc = _xrdcp(
                f"{NGINX_URL}//{filename}",
                f"{REF_URL}//{filename}",
            )
            assert rc == 0, "xrdcp 10 MB nginx→xrootd failed"

            dst_path = os.path.join(BRIDGE_DATA, filename)
            assert _md5(dst_path) == expected_md5
        finally:
            os.unlink(local)


# ---------------------------------------------------------------------------
# Tests: round-trip transfers
# ---------------------------------------------------------------------------

class TestRoundTrip:
    """Upload, bridge, and read back to verify end-to-end GSI transfer integrity."""

    def test_brix_to_nginx_and_back(self, nginx_gsi_ready):
        """
        Write a file on xrootd → copy to nginx → read back from nginx.
        Verifies the full path: xrootd GSI read + nginx GSI write + nginx GSI read.
        """
        content = b"round-trip: xrootd write, nginx read\n" * 200
        filename = "bridge_roundtrip_fwd.txt"

        src_path = os.path.join(BRIDGE_DATA, filename)
        with open(src_path, "wb") as f:
            f.write(content)

        # xrootd → nginx
        rc = _xrdcp(f"{REF_URL}//{filename}", f"{NGINX_URL}//{filename}")
        assert rc == 0, "xrootd→nginx copy failed"

        # Read back from nginx via Python client (GSI)
        os.environ["X509_CERT_DIR"]   = CA_DIR
        os.environ["X509_USER_PROXY"] = PROXY_PEM
        os.environ["XrdSecPROTOCOL"]  = "gsi"
        f_obj = client.File()
        st, _ = f_obj.open(f"{NGINX_URL}//{filename}", OpenFlags.READ)
        assert st.ok, f"nginx GSI open failed: {st.message}"
        st, data = f_obj.read()
        assert st.ok
        f_obj.close()
        assert data == content, "Round-trip content mismatch (xrootd write → nginx read)"

    def test_nginx_to_brix_and_back(self, nginx_gsi_ready):
        """
        Upload to nginx → copy to xrootd → read back from xrootd.
        Verifies: nginx GSI write + xrootd GSI read.
        """
        content = b"round-trip: nginx write, xrootd read\n" * 200
        filename = "bridge_roundtrip_rev.txt"

        local = _write_local(content)
        try:
            rc = _xrdcp(local, f"{NGINX_URL}//{filename}")
            assert rc == 0, "Upload to nginx failed"

            rc = _xrdcp(
                f"{NGINX_URL}//{filename}",
                f"{REF_URL}//{filename}",
            )
            assert rc == 0, "nginx→xrootd copy failed"

            # Read back via xrdcp to a local temp file
            local_out = _write_local(b"")  # empty placeholder
            os.unlink(local_out)
            rc = _xrdcp(f"{REF_URL}//{filename}", local_out)
            assert rc == 0, "xrootd read-back failed"
            with open(local_out, "rb") as fh:
                got = fh.read()
            os.unlink(local_out)
            assert got == content, "Round-trip content mismatch (nginx write → xrootd read)"
        finally:
            os.unlink(local)

    def test_integrity_across_multiple_chunks(self, nginx_gsi_ready):
        """
        Transfer a file large enough to require multiple xrdcp read chunks (>4 MB),
        verifying that chunked reassembly produces identical bytes on both ends.
        """
        size = 12 * 1024 * 1024   # 12 MB — forces at least 3 read chunks
        content = os.urandom(size)
        filename = "bridge_multichunk.bin"

        src_path = os.path.join(BRIDGE_DATA, filename)
        with open(src_path, "wb") as f:
            f.write(content)
        expected_md5 = _md5(src_path)

        # xrootd → nginx
        rc = _xrdcp(f"{REF_URL}//{filename}", f"{NGINX_URL}//{filename}")
        assert rc == 0, "Multi-chunk xrootd→nginx failed"

        # Read back from nginx
        local_out = src_path + ".verify"
        rc = _xrdcp(f"{NGINX_URL}//{filename}", local_out)
        assert rc == 0, "Multi-chunk nginx read-back failed"
        try:
            assert _md5(local_out) == expected_md5
        finally:
            os.unlink(local_out)


# ---------------------------------------------------------------------------
# Tests: authentication enforcement
# ---------------------------------------------------------------------------

class TestAuthEnforcement:
    """Verify that GSI authentication is required and rejected credentials fail."""

    def test_no_proxy_rejected_by_nginx(self, nginx_gsi_ready):
        """
        xrdcp to nginx GSI port without a proxy certificate must fail.
        The server should refuse the connection at the authentication stage.
        """
        local = _write_local(b"should not be written\n")
        try:
            rc = _xrdcp(
                local,
                f"{NGINX_URL}//bridge_auth_test_no_proxy.txt",
                gsi=False,   # no X509 env vars
            )
            assert rc != 0, (
                "xrdcp to GSI nginx port without credentials should have failed"
            )
        finally:
            os.unlink(local)

    def test_no_proxy_rejected_by_xrootd(self, nginx_gsi_ready):
        """
        xrdcp to reference xrootd GSI port without a proxy must also fail,
        confirming the test CA setup enforces authentication on the xrootd side too.
        """
        local = _write_local(b"should not be written\n")
        try:
            # Write a file into xrootd's data dir to try reading without a proxy
            src_path = os.path.join(BRIDGE_DATA, "bridge_no_proxy_src.txt")
            with open(src_path, "wb") as f:
                f.write(b"secret")

            local_out = local + ".out"
            rc = _xrdcp(
                f"{REF_URL}//bridge_no_proxy_src.txt",
                local_out,
                gsi=False,
            )
            assert rc != 0, (
                "xrdcp from GSI xrootd port without credentials should have failed"
            )
            assert not os.path.exists(local_out), (
                "Output file should not exist when auth fails"
            )
        finally:
            os.unlink(local)

    def test_valid_proxy_accepted_by_both(self, nginx_gsi_ready):
        """
        With a valid proxy, transfers to both servers must succeed.
        This is the positive control for the auth tests above.
        """
        content = b"valid proxy accepted\n"
        filename = "bridge_auth_valid.txt"

        # Write to xrootd
        src_path = os.path.join(BRIDGE_DATA, filename)
        with open(src_path, "wb") as f:
            f.write(content)

        # Read from xrootd — must succeed
        local_out = src_path + ".verify"
        rc = _xrdcp(f"{REF_URL}//{filename}", local_out, gsi=True)
        assert rc == 0, "Valid GSI proxy should be accepted by xrootd"
        os.unlink(local_out)

        # Write to nginx — must succeed
        local = _write_local(content)
        try:
            rc = _xrdcp(local, f"{NGINX_URL}//{filename}", gsi=True)
            assert rc == 0, "Valid GSI proxy should be accepted by nginx-xrootd"
        finally:
            os.unlink(local)


# ---------------------------------------------------------------------------
# Tests: directory listing via GSI
# ---------------------------------------------------------------------------

class TestDirlistGSI:
    """Verify directory listing works across both GSI endpoints."""

    def test_nginx_dirlist_after_bridge_transfer(self, nginx_gsi_ready):
        """
        Files copied from xrootd to nginx must appear in nginx's directory listing.
        """
        filename = "bridge_dirlist_test.txt"
        content  = b"dirlist test file\n"

        src_path = os.path.join(BRIDGE_DATA, filename)
        with open(src_path, "wb") as f:
            f.write(content)

        rc = _xrdcp(f"{REF_URL}//{filename}", f"{NGINX_URL}//{filename}")
        assert rc == 0

        os.environ["X509_CERT_DIR"]   = CA_DIR
        os.environ["X509_USER_PROXY"] = PROXY_PEM
        os.environ["XrdSecPROTOCOL"]  = "gsi"
        from XRootD.client.flags import DirListFlags
        fs = client.FileSystem(NGINX_URL)
        st, listing = fs.dirlist("/", DirListFlags.STAT)
        assert st.ok, f"nginx GSI dirlist failed: {st.message}"
        names = [e.name for e in listing]
        assert filename in names, (
            f"{filename!r} not found in nginx directory listing.\n"
            f"Got: {names}"
        )

    def test_brix_dirlist_after_bridge_transfer(self, nginx_gsi_ready):
        """
        Files copied from nginx to xrootd must appear in xrootd's directory listing.
        """
        filename = "bridge_dirlist_xrd.txt"
        content  = b"dirlist xrootd test file\n"

        local = _write_local(content)
        try:
            rc = _xrdcp(local, f"{NGINX_URL}//{filename}")
            assert rc == 0

            rc = _xrdcp(f"{NGINX_URL}//{filename}", f"{REF_URL}//{filename}")
            assert rc == 0
        finally:
            os.unlink(local)

        from XRootD.client.flags import DirListFlags
        os.environ["X509_CERT_DIR"]   = CA_DIR
        os.environ["X509_USER_PROXY"] = PROXY_PEM
        os.environ["XrdSecPROTOCOL"]  = "gsi"
        fs = client.FileSystem(REF_URL)
        st, listing = fs.dirlist("/", DirListFlags.STAT)
        assert st.ok, f"xrootd GSI dirlist failed: {st.message}"
        names = [e.name for e in listing]
        assert filename in names, (
            f"{filename!r} not found in xrootd directory listing.\n"
            f"Got: {names}"
        )
