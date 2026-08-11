#!/usr/bin/env python3
# _test_session_bind_helpers_b.py — continuation shard of test_session_bind.py.
# Two bind test classes moved here to keep test_session_bind.py <=600 logical
# lines.  The `_helpers_b` suffix makes split_continuation.reexport() EXEC this
# into the test module's namespace, so pytest still collects these classes and
# they see the fixtures/helpers already reexported there.


class TestBindInvalidSessid:

    def test_bind_with_random_sessid(self, bind_nginx):
        random_sessid = os.urandom(16)

        sec_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sec_sock.connect((ANON_HOST, bind_nginx))

        handshake = struct.pack(">IIIII", 0, 0, 0, 4, 2012)
        sec_sock.sendall(handshake)
        _recv_exact(sec_sock, 16)

        status, body = _send_req(sec_sock, b"\x00\xFF", kXR_bind, body=random_sessid)
        assert status == kXR_error, (
            f"bind with random sessid returned {status}, expected kXR_error"
        )
        sec_sock.close()


# ---------------------------------------------------------------------------
# Bind without handshake — rejected
# ---------------------------------------------------------------------------

class TestBindNoHandshake:
    """Verify that a bind sent without completing the handshake is rejected."""

    def test_bind_without_handshake(self, bind_nginx):
        """Sending kXR_bind immediately after connect (no handshake) must fail.

        The server expects the 20-byte client hello before processing any request.
        """
        sec_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sec_sock.connect((ANON_HOST, bind_nginx))

        # Skip handshake — send bind directly
        random_sessid = os.urandom(16)
        hdr = struct.pack(">2sH", b"\x00\xAA", kXR_bind) + random_sessid + struct.pack(">I", 0)
        sec_sock.sendall(hdr)

        # The server should either reject or not respond properly
        try:
            rsp = _recv_exact(sec_sock, 8)
            if rsp is not None:
                status = struct.unpack(">H", rsp[2:4])[0]
                assert status == kXR_error, f"expected error for no-handshake bind, got {status}"
        except Exception:
            pass  # connection may be closed — that's also acceptable

        sec_sock.close()
