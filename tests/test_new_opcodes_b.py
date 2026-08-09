from split_continuation import reexport as _reexport
_reexport(globals(), "_test_new_opcodes_helpers")

class TestChkpoint:
    """
    Wire-level tests for kXR_chkpoint (begin/commit/rollback/query) and
    kXR_ckpXeq — write sub-operations executed under checkpoint protection.

    Opcodes exercised: kXR_chkpoint (3012), kXR_ckpXeq (sub-opcode 4).
    """

    # ── low-level helpers ────────────────────────────────────────────────

    @staticmethod
    def _recvall(sock, n):
        buf = b""
        while len(buf) < n:
            chunk = sock.recv(n - len(buf))
            assert chunk, "connection closed unexpectedly"
            buf += chunk
        return buf

    def _recv_response(self, sock):
        hdr    = self._recvall(sock, 8)
        status = struct.unpack(">H", hdr[2:4])[0]
        dlen   = struct.unpack(">I", hdr[4:8])[0]
        body   = self._recvall(sock, dlen) if dlen else b""
        return status, body

    def _connect(self, host, port):
        """Handshake + kXR_login; return connected socket."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((host, port))
        sock.sendall(struct.pack("!IIIII", 0, 0, 0, 4, 2012))
        hdr = self._recvall(sock, 8)
        self._recvall(sock, struct.unpack("!I", hdr[4:8])[0])  # handshake body
        sock.sendall(struct.pack("!2sHI8sBBBBI",
                                 b"\x00\x01", 3007, 0,
                                 b"test\x00\x00\x00\x00",
                                 0, 0, 5, 0, 0))
        self._recv_response(sock)
        return sock

    def _open(self, sock, sid, path, options=0x0020):
        """kXR_open; return 4-byte fhandle. Default options=kXR_open_updt."""
        path_b = path.encode()
        req = struct.pack("!2sHHH2s6s4sI",
                          bytes([0, sid]), 3010,
                          0o644, options,
                          b"\x00\x00", b"\x00" * 6, b"\x00" * 4,
                          len(path_b))
        sock.sendall(req + path_b)
        status, body = self._recv_response(sock)
        assert status == 0, f"open({path!r}) failed: status={status} body={body!r}"
        return body[:4]

    def _write(self, sock, sid, fh, offset, data):
        req = struct.pack("!2sH4sqB3sI",
                          bytes([0, sid]), 3019, fh, offset, 0, b"\x00" * 3, len(data))
        sock.sendall(req + data)
        status, _ = self._recv_response(sock)
        assert status == 0, f"write failed: status={status}"

    def _read(self, sock, sid, fh, offset, rlen):
        req = struct.pack("!2sH4sqiI",
                          bytes([0, sid]), 3013, fh, offset, rlen, 0)
        sock.sendall(req)
        status, body = self._recv_response(sock)
        assert status == 0, f"read failed: status={status}"
        return body

    def _close(self, sock, sid, fh):
        req = struct.pack("!2sH4s12sI",
                          bytes([0, sid]), 3003, fh, b"\x00" * 12, 0)
        sock.sendall(req)
        self._recv_response(sock)

    def _chkpoint(self, sock, sid, fh, opcode, extra=b""):
        """Send kXR_chkpoint with the given sub-opcode; return (status, body)."""
        req = struct.pack("!2sH4s11sBI",
                          bytes([0, sid]), 3012, fh, b"\x00" * 11, opcode, len(extra))
        sock.sendall(req + extra)
        return self._recv_response(sock)

    def _ckpxeq_write(self, sock, sid, fh, offset, data):
        """kXR_ckpXeq carrying a kXR_write sub-request (stock framing: the
        chkpoint dlen covers only the embedded 24-byte sub-header — which must
        carry the outer streamid — and the write data streams after the
        frame, exactly like XrdCl sends it)."""
        sub = struct.pack("!2sH4sqB3sI",
                          bytes([0, sid]), 3019, fh, offset, 0, b"\x00" * 3,
                          len(data))
        req = struct.pack("!2sH4s11sBI",
                          bytes([0, sid]), 3012, fh, b"\x00" * 11, 4, len(sub))
        sock.sendall(req + sub + data)
        return self._recv_response(sock)

    # ── tests ────────────────────────────────────────────────────────────

    def test_chkpoint_begin_commit(self):
        """begin + write + commit: modified content is made permanent."""
        upload(ANON_URL, "ckp_commit.bin", b"original")
        sock = self._connect(HOST, ANON_PORT)
        try:
            fh = self._open(sock, 2, "/ckp_commit.bin")
            status, _ = self._chkpoint(sock, 3, fh, 0)   # kXR_ckpBegin
            assert status == 0, f"chkpoint begin failed: {status}"
            self._write(sock, 4, fh, 0, b"modified")
            status, _ = self._chkpoint(sock, 5, fh, 1)   # kXR_ckpCommit
            assert status == 0, f"chkpoint commit failed: {status}"
            data = self._read(sock, 6, fh, 0, 8)
            assert data == b"modified", f"commit did not persist data: {data!r}"
            self._close(sock, 7, fh)
        finally:
            sock.close()

    def test_chkpoint_begin_rollback(self):
        """begin + write + rollback: file reverts to the pre-checkpoint content."""
        upload(ANON_URL, "ckp_rollback.bin", b"before!!")
        sock = self._connect(HOST, ANON_PORT)
        try:
            fh = self._open(sock, 2, "/ckp_rollback.bin")
            status, _ = self._chkpoint(sock, 3, fh, 0)   # begin
            assert status == 0
            self._write(sock, 4, fh, 0, b"MODIFIED")
            status, _ = self._chkpoint(sock, 5, fh, 3)   # kXR_ckpRollback
            assert status == 0, f"chkpoint rollback failed: {status}"
            data = self._read(sock, 6, fh, 0, 8)
            assert data == b"before!!", f"rollback did not restore data: {data!r}"
            self._close(sock, 7, fh)
        finally:
            sock.close()

    def test_chkpoint_query(self):
        """kXR_ckpQuery returns a nonzero max capacity and zero initial usage."""
        upload(ANON_URL, "ckp_query.bin", b"querytest")
        sock = self._connect(HOST, ANON_PORT)
        try:
            fh = self._open(sock, 2, "/ckp_query.bin")
            status, body = self._chkpoint(sock, 3, fh, 2)   # kXR_ckpQuery
            assert status == 0
            assert len(body) >= 8
            max_sz, use_sz = struct.unpack(">II", body[:8])
            assert max_sz > 0, "maxCkpSize should be > 0"
            assert use_sz == 0, "useCkpSize should be 0 before any checkpoint"
            self._close(sock, 4, fh)
        finally:
            sock.close()

    def test_chkpoint_ckpXeq_write(self):
        """kXR_ckpXeq dispatches a kXR_write sub-request under an active checkpoint."""
        upload(ANON_URL, "ckp_xeq.bin", b"aaaaaaaaa")
        sock = self._connect(HOST, ANON_PORT)
        try:
            fh = self._open(sock, 2, "/ckp_xeq.bin")
            status, _ = self._chkpoint(sock, 3, fh, 0)   # begin
            assert status == 0
            status, _ = self._ckpxeq_write(sock, 4, fh, 0, b"bbbbbbbbb")
            assert status == 0, f"kXR_ckpXeq write failed: {status}"
            data = self._read(sock, 5, fh, 0, 9)
            assert data == b"bbbbbbbbb", f"ckpXeq data mismatch: {data!r}"
            self._chkpoint(sock, 6, fh, 1)   # commit to clean up
            self._close(sock, 7, fh)
        finally:
            sock.close()

    def test_chkpoint_double_begin_rejected(self):
        """A second kXR_ckpBegin while a checkpoint is active returns an error."""
        upload(ANON_URL, "ckp_double.bin", b"data")
        sock = self._connect(HOST, ANON_PORT)
        try:
            fh = self._open(sock, 2, "/ckp_double.bin")
            status, _ = self._chkpoint(sock, 3, fh, 0)   # first begin — ok
            assert status == 0
            status, _ = self._chkpoint(sock, 4, fh, 0)   # second begin — error
            assert status != 0, "expected kXR_inProgress on double begin"
            self._chkpoint(sock, 5, fh, 1)   # commit to clean up
            self._close(sock, 6, fh)
        finally:
            sock.close()

    def test_chkpoint_same_file_second_handle_rejected(self):
        """A checkpoint on one handle must block another handle to the same file."""
        upload(ANON_URL, "ckp_same_file.bin", b"data")
        sock = self._connect(HOST, ANON_PORT)
        try:
            fh1 = self._open(sock, 2, "/ckp_same_file.bin")
            fh2 = self._open(sock, 3, "/ckp_same_file.bin")

            status, _ = self._chkpoint(sock, 4, fh1, 0)
            assert status == 0

            status, _ = self._chkpoint(sock, 5, fh2, 0)
            assert status != 0, "second handle must not replace active checkpoint"

            self._chkpoint(sock, 6, fh1, 1)
            self._close(sock, 7, fh2)
            self._close(sock, 8, fh1)
        finally:
            sock.close()

    def test_chkpoint_startup_recovery_guardrails(self):
        """Startup recovery must rollback stale .ckp snapshots under a lock."""
        # phase-79 file-size split: the startup-recovery cluster
        # (brix_chkpoint_recover_root + its flock guard) moved from chkpoint.c
        # into the sibling chkpoint_recover.c; the live snapshot path
        # (brix_copy_range) stayed in chkpoint.c. Read both as one blob.
        _wdir = Path(__file__).resolve().parents[1] / "src" / "protocols" / "root" / "write"
        src = (
            (_wdir / "chkpoint.c").read_text(encoding="utf-8")
            + (_wdir / "chkpoint_recover.c").read_text(encoding="utf-8")
        )
        # The startup recovery call site lives in the process init path; that
        # path was split (pre-phase-79, commit 27c89e3) into process.c +
        # process_server_init.c, so read both.
        _cdir = Path(__file__).resolve().parents[1] / "src" / "core" / "config"
        process = (
            (_cdir / "process.c").read_text(encoding="utf-8")
            + (_cdir / "process_server_init.c").read_text(encoding="utf-8")
        )

        assert "brix_chkpoint_recover_root" in src
        assert "flock(lock_fd, LOCK_EX)" in src
        assert "brix_copy_range" in src
        assert "brix_staged_open" in src
        assert "brix_staged_commit" in src
        # Phase 62: confined unlink routes through the VFS seam
        # (brix_vfs_unlink_path) rather than calling the path helper directly.
        assert "brix_vfs_unlink_path" in src
        assert "O_DIRECTORY" in src
        assert "O_NOFOLLOW" in src
        assert "fstatat" in src
        assert "brix_chkpoint_recover_root" in process

    def test_chkpoint_rollback_without_begin_rejected(self):
        """kXR_ckpRollback without an active checkpoint returns an error."""
        upload(ANON_URL, "ckp_nobegin.bin", b"data")
        sock = self._connect(HOST, ANON_PORT)
        try:
            fh = self._open(sock, 2, "/ckp_nobegin.bin")
            status, _ = self._chkpoint(sock, 3, fh, 3)   # rollback without begin
            assert status != 0, "expected kXR_InvalidRequest on rollback without begin"
            self._close(sock, 4, fh)
        finally:
            sock.close()


# ---------------------------------------------------------------------------
# kXR_clone
# ---------------------------------------------------------------------------
