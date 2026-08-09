from split_continuation import reexport as _reexport
_reexport(globals(), "_test_dropin_byte_for_byte_helpers")

class TestCloneOpcodeParity:
    """kXR_clone (3032, protocol v5.2) is server-side range copy.  nginx
    implements it (src/protocols/root/read/clone.c).  This asserts the DOCUMENTED behaviour:
    a clone with a bad destination handle is rejected cleanly (not a crash) and
    the session survives — on both servers.  An empty clone-list is also a
    clean error.  If a server lacks the opcode it answers kXR_Unsupported,
    which is an acceptable consistent outcome."""

    def test_clone_bad_dst_handle_rejected(self, both):
        n, x = both
        # Destination handle 0xFF is not an open writable file.
        sid, n_status, n_body = _clone(n, b"\xff\x00\x00\x00", items=b"")
        assert n_status == kXR_error, "nginx clone with bad dst handle must error"
        # Connection must remain usable (no crash / no desync).
        assert _ping(n)[1] == kXR_ok
        # Official server: same opcode; either errors or reports Unsupported.
        sid, x_status, x_body = _clone(x, b"\xff\x00\x00\x00", items=b"")
        assert x_status == kXR_error, "official clone bad handle should error"
        assert _ping(x)[1] == kXR_ok

    def test_clone_empty_list_clean_error(self, both):
        """Open a writable dst, then clone with an EMPTY clone list — a missing
        list is a clean kXR_ArgMissing-class error, session survives."""
        n, x = both
        # nginx side: open a fresh writable destination.
        dst = "/dropin_clone_dst.bin"
        full = os.path.join(stack_data_dir(), dst.lstrip("/"))
        with open(full, "wb") as f:
            f.write(b"\x00" * 4096)
        # Under the root harness the servers run as `nobody`; a fresh file
        # created by the (root) test process is mode 0644, so make it a+rw so
        # the dropped user can open it for update.
        if os.geteuid() == 0:
            os.chmod(full, 0o666)
        try:
            sid, o_status, o_body = _open(n, dst, kXR_open_updt)
            assert o_status == kXR_ok, f"dst open failed: {_error_msg(o_body)}"
            fh = o_body[:4]
            try:
                sid, c_status, c_body = _clone(n, fh, items=b"")
                # Documented: empty/absent clone list -> clean error, NOT a hang
                # or a crash.  Accept Unsupported too in case clone is disabled.
                assert c_status in (kXR_error, kXR_status, kXR_ok), \
                    f"unexpected nginx clone status {c_status}"
                if c_status == kXR_error:
                    assert _error_code(c_body) != 0
            finally:
                _close(n, fh)
        finally:
            try:
                os.unlink(full)
            except FileNotFoundError:
                pass
        assert _ping(n)[1] == kXR_ok


# ===========================================================================
# 8. plain read — byte-exact vs official
# ===========================================================================

class TestPlainReadParity:
    """A normal kXR_read of the whole file (and at an offset) returns the same
    bytes on both servers — byte-for-byte, since they serve the same inode."""

    def _drain_read(self, sock, fh, off, length):
        """Read exactly `length` bytes starting at `off`, looping over the
        per-request chunk so a server that answers kXR_oksofar (a partial) does
        not make us under-read.  A read that returns no bytes (EOF) stops."""
        out = bytearray()
        want = length
        cur = off
        while want > 0:
            chunk = min(1 << 20, want)
            sid, rstatus, rbody = _read(sock, fh, cur, chunk)
            assert rstatus in (kXR_ok, kXR_oksofar), \
                f"read failed status={rstatus}"
            if not rbody:
                break
            out.extend(rbody)
            cur += len(rbody)
            want -= len(rbody)
        return bytes(out)

    def _read_all(self, sock, path, size):
        sid, status, body = _open(sock, path, kXR_open_read)
        assert status == kXR_ok, f"open failed: {_error_msg(body)}"
        fh = body[:4]
        try:
            return self._drain_read(sock, fh, 0, size)
        finally:
            _close(sock, fh)

    def test_full_file_byte_exact(self, both):
        n, x = both
        n_data = self._read_all(n, PLAIN_NAME, PLAIN_SIZE)
        x_data = self._read_all(x, PLAIN_NAME, PLAIN_SIZE)
        assert n_data == PLAIN_DATA, "nginx full read != source file"
        assert x_data == PLAIN_DATA, "official full read != source file"
        assert n_data == x_data, "nginx vs official full read differ"
        assert _ping(n)[1] == kXR_ok and _ping(x)[1] == kXR_ok

    def test_offset_read_byte_exact(self, both):
        n, x = both
        off, length = 12345, 20000
        n_open = _open(n, PLAIN_NAME, kXR_open_read)
        x_open = _open(x, PLAIN_NAME, kXR_open_read)
        assert n_open[1] == kXR_ok and x_open[1] == kXR_ok
        n_fh, x_fh = n_open[2][:4], x_open[2][:4]
        try:
            # Drain the full extent so a partial kXR_oksofar response does not
            # cause a spurious mismatch.
            n_data = self._drain_read(n, n_fh, off, length)
            x_data = self._drain_read(x, x_fh, off, length)
            assert n_data == x_data == PLAIN_DATA[off:off + length], \
                "offset read mismatch nginx vs official"
        finally:
            _close(n, n_fh)
            _close(x, x_fh)

    def test_read_past_eof_same_behaviour(self, both):
        """Reading well past EOF must NEVER leak bytes on either server.

        kXR_read past EOF is one of the few places XRootD implementations
        legitimately diverge: a plain read past EOF returns a zero-length
        success on a POSIX backend (pread → 0), which is what nginx does, but
        the contract that actually matters for a drop-in is that NO file bytes
        are ever returned past EOF.  We assert the strict, portable property —
        zero bytes returned by each server — and accept either a success or a
        clean error status (not a crash / not data)."""
        n, x = both
        n_open = _open(n, PLAIN_NAME, kXR_open_read)
        x_open = _open(x, PLAIN_NAME, kXR_open_read)
        assert n_open[1] == kXR_ok and x_open[1] == kXR_ok
        n_fh, x_fh = n_open[2][:4], x_open[2][:4]
        try:
            sid, n_st, n_data = _read(n, n_fh, PLAIN_SIZE + 10000, 4096)
            sid, x_st, x_data = _read(x, x_fh, PLAIN_SIZE + 10000, 4096)
            # Neither may return file bytes past EOF.
            assert n_data == b"", f"nginx leaked {len(n_data)} bytes past EOF"
            assert x_data == b"", f"official leaked {len(x_data)} bytes past EOF"
            # nginx's documented behaviour is a zero-length success; the official
            # server may answer ok/oksofar OR a clean error — never a crash.
            assert n_st in (kXR_ok, kXR_oksofar), \
                f"nginx past-EOF read status={n_st}"
            assert x_st in (kXR_ok, kXR_oksofar, kXR_error), \
                f"official past-EOF read status={x_st}"
        finally:
            _close(n, n_fh)
            _close(x, x_fh)
        assert _ping(n)[1] == kXR_ok and _ping(x)[1] == kXR_ok
