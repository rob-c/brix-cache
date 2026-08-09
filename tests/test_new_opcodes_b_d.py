from split_continuation import reexport as _reexport
_reexport(globals(), "_test_new_opcodes_helpers")

class TestChkpointExtended:
    """
    Checkpoint state invariants not covered by TestChkpoint:

      - Query after begin shows nonzero checkpoint file usage.
      - Multiple ckpXeq writes under one checkpoint — commit persists all.
      - Multiple ckpXeq writes under one checkpoint — rollback restores all.
      - ckpXeq before begin returns an error (no active checkpoint).
      - Query after commit shows zero checkpoint usage again.
    """

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
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((host, port))
        sock.sendall(struct.pack("!IIIII", 0, 0, 0, 4, 2012))
        hdr = self._recvall(sock, 8)
        self._recvall(sock, struct.unpack("!I", hdr[4:8])[0])
        sock.sendall(struct.pack("!2sHI8sBBBBI",
                                 b"\x00\x01", 3007, 0,
                                 b"test\x00\x00\x00\x00",
                                 0, 0, 5, 0, 0))
        self._recv_response(sock)
        return sock

    def _open(self, sock, sid, path, options=0x0020):
        path_b = path.encode()
        req = struct.pack("!2sHHH2s6s4sI",
                          bytes([0, sid]), 3010, 0o644, options,
                          b"\x00\x00", b"\x00"*6, b"\x00"*4, len(path_b))
        sock.sendall(req + path_b)
        status, body = self._recv_response(sock)
        assert status == 0, f"open({path!r}) failed: {status}"
        return body[:4]

    def _write(self, sock, sid, fh, offset, data):
        req = struct.pack("!2sH4sqB3sI",
                          bytes([0, sid]), 3019, fh, offset, 0, b"\x00"*3, len(data))
        sock.sendall(req + data)
        status, _ = self._recv_response(sock)
        assert status == 0, f"write failed: {status}"

    def _read(self, sock, sid, fh, offset, rlen):
        req = struct.pack("!2sH4sqiI",
                          bytes([0, sid]), 3013, fh, offset, rlen, 0)
        sock.sendall(req)
        status, body = self._recv_response(sock)
        assert status == 0, f"read failed: {status}"
        return body

    def _close(self, sock, sid, fh):
        req = struct.pack("!2sH4s12sI",
                          bytes([0, sid]), 3003, fh, b"\x00"*12, 0)
        sock.sendall(req)
        self._recv_response(sock)

    def _chkpoint(self, sock, sid, fh, opcode, extra=b""):
        req = struct.pack("!2sH4s11sBI",
                          bytes([0, sid]), 3012, fh, b"\x00"*11, opcode, len(extra))
        sock.sendall(req + extra)
        return self._recv_response(sock)

    def _ckpxeq_write(self, sock, sid, fh, offset, data):
        """Stock-framed ckpXeq write: the chkpoint dlen covers only the
        embedded 24-byte sub-header (carrying the outer streamid); the write
        data streams after the frame."""
        sub = struct.pack("!2sH4sqB3sI",
                          bytes([0, sid]), 3019, fh, offset, 0, b"\x00"*3,
                          len(data))
        req = struct.pack("!2sH4s11sBI",
                          bytes([0, sid]), 3012, fh, b"\x00"*11, 4, len(sub))
        sock.sendall(req + sub + data)
        return self._recv_response(sock)

    # ── tests ──────────────────────────────────────────────────────────────

    def test_query_after_begin_shows_nonzero_usage(self):
        """After kXR_ckpBegin the query response must show useCkpSize > 0."""
        upload(ANON_URL, "ext_query_begin.bin", b"some content")
        sock = self._connect(HOST, ANON_PORT)
        try:
            fh = self._open(sock, 2, "/ext_query_begin.bin")
            self._chkpoint(sock, 3, fh, 0)   # begin — snapshot taken
            status, body = self._chkpoint(sock, 4, fh, 2)   # query
            assert status == 0
            assert len(body) >= 8
            _max_sz, use_sz = struct.unpack(">II", body[:8])
            assert use_sz > 0, (
                f"useCkpSize should be >0 after begin, got {use_sz}"
            )
            self._chkpoint(sock, 5, fh, 1)   # commit to clean up
            self._close(sock, 6, fh)
        finally:
            sock.close()

    def test_multiple_xeq_then_commit_persists_all(self):
        """Multiple ckpXeq writes under one checkpoint all persist after commit."""
        upload(ANON_URL, "ext_multi_commit.bin", b"\x00" * 30)
        sock = self._connect(HOST, ANON_PORT)
        try:
            fh = self._open(sock, 2, "/ext_multi_commit.bin")
            self._chkpoint(sock, 3, fh, 0)   # begin
            self._ckpxeq_write(sock, 4, fh,  0, b"first")
            self._ckpxeq_write(sock, 5, fh, 10, b"second")
            self._ckpxeq_write(sock, 6, fh, 20, b"third!")
            self._chkpoint(sock, 7, fh, 1)   # commit
            assert self._read(sock,  8, fh,  0, 5) == b"first"
            assert self._read(sock,  9, fh, 10, 6) == b"second"
            assert self._read(sock, 10, fh, 20, 6) == b"third!"
            self._close(sock, 11, fh)
        finally:
            sock.close()

    def test_multiple_xeq_then_rollback_restores_all(self):
        """Multiple ckpXeq writes under one checkpoint are all undone by rollback."""
        original = b"XXXXXXXXXX" * 3
        upload(ANON_URL, "ext_multi_rb.bin", original)
        sock = self._connect(HOST, ANON_PORT)
        try:
            fh = self._open(sock, 2, "/ext_multi_rb.bin")
            self._chkpoint(sock, 3, fh, 0)
            self._ckpxeq_write(sock, 4, fh,  0, b"aaaaaa")
            self._ckpxeq_write(sock, 5, fh, 10, b"bbbbbb")
            self._ckpxeq_write(sock, 6, fh, 20, b"cccccc")
            self._chkpoint(sock, 7, fh, 3)   # rollback
            data = self._read(sock, 8, fh, 0, len(original))
            assert data == original, (
                f"rollback did not restore all three writes; got {data!r}"
            )
            self._close(sock, 9, fh)
        finally:
            sock.close()

    def test_xeq_without_active_checkpoint_fails(self):
        """ckpXeq before kXR_ckpBegin must return an error (no snapshot file)."""
        upload(ANON_URL, "ext_xeq_nobegin.bin", b"intact")
        sock = self._connect(HOST, ANON_PORT)
        try:
            fh = self._open(sock, 2, "/ext_xeq_nobegin.bin")
            # No begin — ckpXeq must fail.
            status, _ = self._ckpxeq_write(sock, 3, fh, 0, b"override")
            assert status != 0, "ckpXeq without begin should return an error"
            self._close(sock, 4, fh)
        finally:
            sock.close()

    def test_query_after_commit_shows_zero_usage(self):
        """After kXR_ckpCommit the query response must show useCkpSize == 0."""
        upload(ANON_URL, "ext_query_commit.bin", b"committed content")
        sock = self._connect(HOST, ANON_PORT)
        try:
            fh = self._open(sock, 2, "/ext_query_commit.bin")
            self._chkpoint(sock, 3, fh, 0)   # begin
            self._write(sock, 4, fh, 0, b"changed!")
            self._chkpoint(sock, 5, fh, 1)   # commit
            status, body = self._chkpoint(sock, 6, fh, 2)   # query
            assert status == 0
            assert len(body) >= 8
            _max_sz, use_sz = struct.unpack(">II", body[:8])
            assert use_sz == 0, (
                f"useCkpSize should be 0 after commit, got {use_sz}"
            )
            self._close(sock, 7, fh)
        finally:
            sock.close()
