from split_continuation import reexport as _reexport
_reexport(globals(), "_test_new_opcodes_helpers")

class TestClone:
    """Wire-level tests for kXR_clone — server-side range copy (protocol v5.2.0)."""

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
                          bytes([0, sid]), 3010,
                          0o644, options,
                          b"\x00\x00", b"\x00" * 6, b"\x00" * 4,
                          len(path_b))
        sock.sendall(req + path_b)
        status, body = self._recv_response(sock)
        assert status == 0, f"open({path!r}) failed: status={status}"
        return body[:4]

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

    def _clone(self, sock, sid, dst_fh, items):
        """Send kXR_clone; items = list of (src_fh, src_off, src_len, dst_off)."""
        payload = b"".join(
            struct.pack("!4s4sQQQ",
                        src_fh, b"\x00" * 4, src_off, src_len, dst_off)
            for src_fh, src_off, src_len, dst_off in items
        )
        req = struct.pack("!2sH4s12sI",
                          bytes([0, sid]), 3032, dst_fh, b"\x00" * 12, len(payload))
        sock.sendall(req + payload)
        return self._recv_response(sock)

    def test_clone_full_file(self):
        """clone copies the entire source file to the destination."""
        src_data = b"CLONE_FULL_DATA_" * 16   # 256 bytes
        upload(ANON_URL, "clone_full_src.bin", src_data)
        upload(ANON_URL, "clone_full_dst.bin", b"\x00" * len(src_data))

        sock = self._connect(HOST, ANON_PORT)
        try:
            src_fh = self._open(sock, 2, "/clone_full_src.bin", options=0x0010)  # read
            dst_fh = self._open(sock, 3, "/clone_full_dst.bin", options=0x0020)  # r/w

            status, body = self._clone(sock, 4, dst_fh, [(src_fh, 0, len(src_data), 0)])
            assert status == 0, f"clone failed: status={status} body={body!r}"

            result = self._read(sock, 5, dst_fh, 0, len(src_data))
            assert result == src_data, f"clone data mismatch"

            self._close(sock, 6, src_fh)
            self._close(sock, 7, dst_fh)
        finally:
            sock.close()

    def test_clone_partial_range(self):
        """clone copies only the specified byte range at the given dst offset."""
        src_data = bytes(range(100))
        upload(ANON_URL, "clone_range_src.bin", src_data)
        upload(ANON_URL, "clone_range_dst.bin", b"\x00" * 100)

        sock = self._connect(HOST, ANON_PORT)
        try:
            src_fh = self._open(sock, 2, "/clone_range_src.bin", options=0x0010)
            dst_fh = self._open(sock, 3, "/clone_range_dst.bin", options=0x0020)

            # copy src[20:50] → dst[0:30]
            status, _ = self._clone(sock, 4, dst_fh, [(src_fh, 20, 30, 0)])
            assert status == 0

            result = self._read(sock, 5, dst_fh, 0, 30)
            assert result == src_data[20:50], f"range clone mismatch: {result!r}"

            self._close(sock, 6, src_fh)
            self._close(sock, 7, dst_fh)
        finally:
            sock.close()

    def test_clone_to_read_only_handle_rejected(self):
        """clone to a read-only file handle returns an error."""
        upload(ANON_URL, "clone_ro_src.bin", b"x" * 50)
        upload(ANON_URL, "clone_ro_dst.bin", b"y" * 50)

        sock = self._connect(HOST, ANON_PORT)
        try:
            src_fh = self._open(sock, 2, "/clone_ro_src.bin", options=0x0010)
            ro_fh  = self._open(sock, 3, "/clone_ro_dst.bin", options=0x0010)

            status, _ = self._clone(sock, 4, ro_fh, [(src_fh, 0, 10, 0)])
            assert status != 0, "expected error: clone to read-only handle"

            self._close(sock, 5, src_fh)
            self._close(sock, 6, ro_fh)
        finally:
            sock.close()

    def test_clone_negative_offset_rejected(self):
        """A wire offset with the high bit set (negative off_t) is refused early
        with kXR_ArgInvalid (3000) — NOT handed to copy_file_range/pread where a
        negative off_t would round-trip to a kernel EINVAL (kXR_IOError, 3007).
        The specific code proves the new guard ran, and the worker survives to
        serve the next request."""
        KXR_ARGINVALID = 3000
        src_data = b"z" * 64
        upload(ANON_URL, "clone_neg_src.bin", src_data)
        upload(ANON_URL, "clone_neg_dst.bin", b"\x00" * 64)

        sock = self._connect(HOST, ANON_PORT)
        try:
            src_fh = self._open(sock, 2, "/clone_neg_src.bin", options=0x0010)
            dst_fh = self._open(sock, 3, "/clone_neg_dst.bin", options=0x0020)

            # src_off = 0xFFFFFFFFFFFFFFFF → negative off_t after the cast.
            huge = 0xFFFFFFFFFFFFFFFF
            status, body = self._clone(sock, 4, dst_fh, [(src_fh, huge, 16, 0)])
            assert status != 0, "expected error: clone with out-of-range offset"
            errnum = struct.unpack(">I", body[:4])[0]
            assert errnum == KXR_ARGINVALID, \
                f"expected kXR_ArgInvalid(3000), got {errnum}"

            # A dst_off that overflows off_t + len must also be refused early.
            status, body = self._clone(sock, 5, dst_fh, [(src_fh, 0, 16, huge)])
            assert status != 0, "expected error: clone with out-of-range dst offset"
            errnum = struct.unpack(">I", body[:4])[0]
            assert errnum == KXR_ARGINVALID, \
                f"expected kXR_ArgInvalid(3000) for dst overflow, got {errnum}"

            # Worker is still alive and serving: a valid clone now succeeds.
            status, _ = self._clone(sock, 6, dst_fh, [(src_fh, 0, len(src_data), 0)])
            assert status == 0, f"post-reject clone failed: status={status}"
            assert self._read(sock, 7, dst_fh, 0, len(src_data)) == src_data

            self._close(sock, 8, src_fh)
            self._close(sock, 9, dst_fh)
        finally:
            sock.close()


# ---------------------------------------------------------------------------
# kXR_ckpXeq — sub-operation variants (pgwrite, truncate, writev)
#
# chkpoint_xeq.c dispatches four sub-opcodes under an active checkpoint:
#   kXR_write (3019)    — tested in TestChkpoint.test_chkpoint_ckpXeq_write
#   kXR_pgwrite (3026)  — no existing test
#   kXR_truncate (3028) — no existing test
#   kXR_writev (3031)   — no existing test
# ---------------------------------------------------------------------------
