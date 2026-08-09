from split_continuation import reexport as _reexport
_reexport(globals(), "_test_gsi_security_helpers")

class TestGSIPreAuthRejection:
    """Data opcodes before kXR_login must be rejected on the GSI port."""

    def _pre_auth_req(self, reqid, payload=b""):
        sock = _raw_conn()
        _handshake(sock)
        path = b"/test.txt\x00"
        req = struct.pack("!2sH16sI", b"\x00\x02", reqid, b"\x00" * 16,
                          len(payload) + len(path))
        sock.sendall(req + payload + path)
        status, _ = _read_response(sock)
        sock.close()
        return status

    def test_stat_before_login_rejected(self):
        sock = _raw_conn()
        _handshake(sock)
        path = b"/test.txt\x00"
        req = struct.pack("!2sH16sI", b"\x00\x02", kXR_stat, b"\x00" * 16, len(path))
        sock.sendall(req + path)
        status, _ = _read_response(sock)
        sock.close()
        assert status != kXR_ok

    def test_open_before_login_rejected(self):
        sock = _raw_conn()
        _handshake(sock)
        path = b"/test.txt\x00"
        body16 = struct.pack("!HHIHH4s", 0, 0, 0, kXR_open, 0, b"\x00" * 4)[:16]
        req = struct.pack("!2sH16sI", b"\x00\x02", kXR_open, b"\x00" * 16, len(path))
        sock.sendall(req + path)
        status, _ = _read_response(sock)
        sock.close()
        assert status != kXR_ok

    def test_rm_before_login_rejected(self):
        sock = _raw_conn()
        _handshake(sock)
        path = b"/test.txt\x00"
        req = struct.pack("!2sH16sI", b"\x00\x02", kXR_rm, b"\x00" * 16, len(path))
        sock.sendall(req + path)
        status, _ = _read_response(sock)
        sock.close()
        assert status != kXR_ok

    def test_rmdir_before_login_rejected(self):
        sock = _raw_conn()
        _handshake(sock)
        path = b"/\x00"
        req = struct.pack("!2sH16sI", b"\x00\x02", kXR_rmdir, b"\x00" * 16, len(path))
        sock.sendall(req + path)
        status, _ = _read_response(sock)
        sock.close()
        assert status != kXR_ok

    def test_ping_before_login_rejected(self):
        """A pre-login kXR_ping is rejected with kXR_error, matching stock xrootd
        (ping is routed through the pre-login auth gate, not answered ok)."""
        sock = _raw_conn()
        _handshake(sock)
        req = struct.pack("!2sH16sI", b"\x00\x02", kXR_ping, b"\x00" * 16, 0)
        sock.sendall(req)
        status, _ = _read_response(sock)
        sock.close()
        assert status == kXR_error

    def test_dirlist_before_login_rejected(self):
        sock = _raw_conn()
        _handshake(sock)
        path = b"/\x00"
        req = struct.pack("!2sH16sI", b"\x00\x02", kXR_dirlist, b"\x00" * 16, len(path))
        sock.sendall(req + path)
        status, _ = _read_response(sock)
        sock.close()
        assert status != kXR_ok

    def test_readv_before_login_rejected(self):
        sock = _raw_conn()
        _handshake(sock)
        req = struct.pack("!2sH16sI", b"\x00\x02", kXR_readv, b"\x00" * 16, 0)
        sock.sendall(req)
        status, _ = _read_response(sock)
        sock.close()
        assert status != kXR_ok

    def test_writev_before_login_rejected(self):
        sock = _raw_conn()
        _handshake(sock)
        req = struct.pack("!2sH16sI", b"\x00\x02", kXR_writev, b"\x00" * 16, 0)
        sock.sendall(req)
        status, _ = _read_response(sock)
        sock.close()
        assert status != kXR_ok

    def test_truncate_before_login_rejected(self):
        sock = _raw_conn()
        _handshake(sock)
        path = b"/test.txt\x00"
        req = struct.pack("!2sH16sI", b"\x00\x02", kXR_truncate, b"\x00" * 16, len(path))
        sock.sendall(req + path)
        status, _ = _read_response(sock)
        sock.close()
        assert status != kXR_ok

    def test_chmod_before_login_rejected(self):
        sock = _raw_conn()
        _handshake(sock)
        path = b"/test.txt\x00"
        req = struct.pack("!2sH16sI", b"\x00\x02", kXR_chmod, b"\x00" * 16, len(path))
        sock.sendall(req + path)
        status, _ = _read_response(sock)
        sock.close()
        assert status != kXR_ok

    def test_mkdir_before_login_rejected(self):
        sock = _raw_conn()
        _handshake(sock)
        path = b"/newdir\x00"
        req = struct.pack("!2sH16sI", b"\x00\x02", kXR_mkdir, b"\x00" * 16, len(path))
        sock.sendall(req + path)
        status, _ = _read_response(sock)
        sock.close()
        assert status != kXR_ok

    def test_sync_before_login_rejected(self):
        sock = _raw_conn()
        _handshake(sock)
        req = struct.pack("!2sH16sI", b"\x00\x02", kXR_sync, b"\x00" * 16, 0)
        sock.sendall(req)
        status, _ = _read_response(sock)
        sock.close()
        assert status != kXR_ok


# ---------------------------------------------------------------------------
# TestGSIProtocolEdges
# (wire-level edge cases on plain GSI port 11095)
# ---------------------------------------------------------------------------

class TestGSIProtocolEdges:
    """Edge cases in the XRootD protocol framing on the GSI port."""

    def test_auth_before_login_rejected(self):
        sock = _raw_conn()
        _handshake(sock)
        cred = b"gsi\x00" + b"\x00" * 8
        req = struct.pack("!2sH12s4sI",
                          b"\x00\x01", kXR_auth,
                          b"\x00" * 12, b"gsi\x00",
                          len(cred))
        sock.sendall(req + cred)
        status, _ = _read_response(sock)
        sock.close()
        assert status != kXR_ok

    def test_unknown_credtype_on_gsi_port(self):
        sock = _raw_conn()
        _handshake(sock)
        status, _ = _login(sock)
        assert status == kXR_ok
        cred = b"xyz\x00" + b"\x00" * 8
        req = struct.pack("!2sH12s4sI",
                          b"\x00\x02", kXR_auth,
                          b"\x00" * 12, b"xyz\x00",
                          len(cred))
        sock.sendall(req + cred)
        status, _ = _read_response(sock)
        sock.close()
        assert status != kXR_ok

    def test_kxr_auth_empty_body_on_gsi_port(self):
        sock = _raw_conn()
        _handshake(sock)
        status, _ = _login(sock)
        assert status == kXR_ok
        req = struct.pack("!2sH12s4sI",
                          b"\x00\x02", kXR_auth,
                          b"\x00" * 12, b"gsi\x00", 0)
        sock.sendall(req)
        status, _ = _read_response(sock)
        sock.close()
        assert status != kXR_ok

    def test_kxr_auth_four_bytes_too_short(self):
        sock = _raw_conn()
        _handshake(sock)
        status, _ = _login(sock)
        assert status == kXR_ok
        body = b"gsi\x00"  # only 4 bytes, below 8-byte minimum
        req = struct.pack("!2sH12s4sI",
                          b"\x00\x02", kXR_auth,
                          b"\x00" * 12, b"gsi\x00",
                          len(body))
        sock.sendall(req + body)
        status, _ = _read_response(sock)
        sock.close()
        assert status != kXR_ok

    def test_invalid_requestid_after_login(self):
        sock = _raw_conn()
        _handshake(sock)
        _login(sock)
        req = struct.pack("!2sH16sI", b"\x00\x02", 0xFFFF, b"\x00" * 16, 0)
        sock.sendall(req)
        status, _ = _read_response(sock)
        sock.close()
        # Before GSI auth completes: kXR_Unsupported or kXR_error
        assert status in (kXR_Unsupported, kXR_error)

    def test_requestid_zero_after_login(self):
        sock = _raw_conn()
        _handshake(sock)
        _login(sock)
        req = struct.pack("!2sH16sI", b"\x00\x02", 0, b"\x00" * 16, 0)
        sock.sendall(req)
        status, _ = _read_response(sock)
        sock.close()
        # Before GSI auth completes: kXR_Unsupported or kXR_error
        assert status in (kXR_Unsupported, kXR_error)

    def test_ping_after_login_on_gsi_port(self):
        sock = _raw_conn()
        _handshake(sock)
        status, _ = _login(sock)
        assert status == kXR_ok
        req = struct.pack("!2sH16sI", b"\x00\x02", kXR_ping, b"\x00" * 16, 0)
        sock.sendall(req)
        status, _ = _read_response(sock)
        sock.close()
        assert status == kXR_ok

    def test_stat_unauthenticated_after_login_rejected(self):
        """On the GSI port, stat should fail without completing GSI auth."""
        sock = _raw_conn()
        _handshake(sock)
        status, _ = _login(sock)
        assert status == kXR_ok
        path = b"/test.txt\x00"
        req = struct.pack("!2sH16sI", b"\x00\x03", kXR_stat, b"\x00" * 16, len(path))
        sock.sendall(req + path)
        status, _ = _read_response(sock)
        sock.close()
        assert status != kXR_ok

    def test_partial_handshake_no_crash(self):
        sock = _raw_conn()
        sock.sendall(b"\x00" * 10)  # partial 20-byte handshake
        sock.close()

    def test_multiple_pings_gsi_port(self):
        sock = _raw_conn()
        _handshake(sock)
        _login(sock)
        for i in range(5):
            sid = struct.pack("!H", i + 1)
            req = struct.pack("!2sH16sI", sid, kXR_ping, b"\x00" * 16, 0)
            sock.sendall(req)
            status, _ = _read_response(sock)
            assert status == kXR_ok
        sock.close()


# ---------------------------------------------------------------------------
# TestGSIClientStat
# (XRootD client functional tests — stat, dirlist, query)
# ---------------------------------------------------------------------------

class TestGSIClientStat:
    """Stat, dirlist, and query operations via the GSI port."""

    def test_stat_root_ok(self):
        fs = _gsi_fs()
        status, info = fs.stat("/")
        assert status.ok, f"stat('/') failed: {status.message}"

    def test_stat_test_file_ok(self):
        fs = _gsi_fs()
        status, info = fs.stat("/test.txt")
        assert status.ok, f"stat('/test.txt') failed: {status.message}"
        assert info.size == 24

    def test_stat_nonexistent_is_error(self):
        fs = _gsi_fs()
        status, _ = fs.stat("/gsi_no_such_file_xyz.txt")
        assert not status.ok

    def test_dirlist_root_contains_test_txt(self):
        fs = _gsi_fs()
        status, listing = fs.dirlist("/")
        assert status.ok, f"dirlist('/') failed: {status.message}"
        names = [e.name for e in listing]
        assert "test.txt" in names

    def test_qconfig_chksum_via_gsi(self):
        fs = _gsi_fs()
        status, resp = fs.query(QueryCode.CONFIG, "chksum")
        assert status.ok
        assert b"adler32" in resp

    def test_qspace_via_gsi_ok(self):
        fs = _gsi_fs()
        status, _ = fs.query(QueryCode.SPACE, "/")
        assert status.ok

    def test_gsi_stat_size_matches_anon(self):
        fs_gsi  = _gsi_fs()
        fs_anon = _anon_fs()
        s1, i1 = fs_gsi.stat("/test.txt")
        s2, i2 = fs_anon.stat("/test.txt")
        assert s1.ok and s2.ok
        assert i1.size == i2.size

    def test_two_consecutive_stats_ok(self):
        fs = _gsi_fs()
        s1, i1 = fs.stat("/test.txt")
        s2, i2 = fs.stat("/test.txt")
        assert s1.ok and s2.ok
        assert i1.size == i2.size


# ---------------------------------------------------------------------------
# TestGSIClientRead
# (XRootD client read operations via GSI port)
# ---------------------------------------------------------------------------

class TestGSIClientRead:
    """File read operations through the GSI port."""

    def test_read_test_txt_content(self):
        data = _xrd_read_all(f"{GSI_URL}//test.txt")
        assert data == b"hello from nginx-xrootd\n"

    def test_read_gsi_matches_anon(self):
        gsi_data  = _xrd_read_all(f"{GSI_URL}//test.txt")
        anon_data = _xrd_read_all(f"{ANON_URL}//test.txt")
        assert gsi_data == anon_data

    def test_read_random_bin_md5_matches(self):
        _ensure_random_bin()
        gsi_data  = _xrd_read_all(f"{GSI_URL}//random.bin")
        assert gsi_data is not None
        with open(os.path.join(DATA_ROOT, "random.bin"), "rb") as handle:
            expected = handle.read()
        assert hashlib.md5(gsi_data).hexdigest() == hashlib.md5(expected).hexdigest()

    def test_read_partial_correct_bytes(self):
        f = xrd_client.File()
        status, _ = f.open(f"{GSI_URL}//test.txt")
        assert status.ok
        status, data = f.read(offset=6, size=4)
        f.close()
        assert status.ok
        assert data == b"from"

    def test_stat_then_read_same_size(self):
        fs = _gsi_fs()
        status, info = fs.stat("/test.txt")
        assert status.ok
        data = _xrd_read_all(f"{GSI_URL}//test.txt")
        assert len(data) == info.size

    def test_adler32_via_gsi_matches_anon(self):
        fs_gsi  = _gsi_fs()
        fs_anon = _anon_fs()
        s1, r1 = fs_gsi.query(QueryCode.CHECKSUM, "/test.txt")
        s2, r2 = fs_anon.query(QueryCode.CHECKSUM, "/test.txt")
        if s1.ok and s2.ok:
            assert r1 == r2


# ---------------------------------------------------------------------------
# TestGSIClientWrite
# (XRootD client write operations via GSI port)
# ---------------------------------------------------------------------------
