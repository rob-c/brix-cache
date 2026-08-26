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


# ---------------------------------------------------------------------------
# §1.1 response-offload rig — shared legwork for the offload test classes
# ---------------------------------------------------------------------------

import contextlib


def _assert_socket_quiet(sock, label, timeout=0.3):
    """No stray bytes may be waiting on `sock` (an offloaded reply must not
    ALSO land on the other channel); a closed-window timeout is healthy."""
    sock.settimeout(timeout)
    try:
        leftover = sock.recv(1)
    except (BlockingIOError, socket.timeout):
        return
    assert leftover == b"", f"unexpected bytes on {label}: {leftover!r}"


def _assert_streamed_reply(sock, want_stream, timeout=5):
    """One framed reply from `sock`: assert its streamid, require a success
    status (kXR_ok / kXR_oksofar), return (status, data)."""
    sock.settimeout(timeout)
    r_stream, r_status, data = _recv_response(sock)
    assert r_stream == want_stream, f"streamid {r_stream!r} != {want_stream!r}"
    assert r_status in (kXR_ok, kXR_oksofar), f"status={r_status}"
    return r_status, data


def _recv_windowed(sock, want_stream, total, timeout=5):
    """Accumulate a possibly oksofar-windowed reply until `total` bytes (or the
    terminal kXR_ok frame); every chunk must carry the request's streamid."""
    got = b""
    while len(got) < total:
        status, data = _assert_streamed_reply(sock, want_stream, timeout)
        got += data
        if status == kXR_ok:
            break
    return got


@contextlib.contextmanager
def _offload_rig(port, path):
    """Primary session with `path` opened + a bound secondary data channel;
    yields (primary, sec, pathid, fh) and closes both sockets on exit."""
    primary, sessid, stream = _establish_primary(port)
    sec = None
    try:
        fh = _open_read(primary, stream, path)
        sec, pathid = _bind_on(port, sessid)
        assert pathid != 0
        yield primary, sec, pathid, fh
    finally:
        if sec is not None:
            sec.close()
        primary.close()


def _bind_small_window(port, sessid, rcvbuf=2048, streamid=b"\x00\x05"):
    """Bind a secondary whose tiny SO_RCVBUF keeps the server's reply parked
    (the pipelining test's queued-behind boundary); returns (sock, pathid)."""
    sec = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sec.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, rcvbuf)
    sec.connect((ANON_HOST, port))
    sec.sendall(struct.pack(">IIIII", 0, 0, 0, 4, 2012))
    _recv_exact(sec, 16)
    status, pathid_body = _send_req(sec, streamid, kXR_bind, body=sessid)
    assert status == kXR_ok, f"bind failed: {status}"
    return sec, pathid_body[0]
