"""
tests/test_ssi_async.py — Phase-2 async server-push (kXR_attn) for SSI.

The `echo-async` service defers: the submit is acked with kXR_waitresp, and the
response is delivered later as an unsolicited kXR_attn + kXR_asynresp frame — what
a real libXrdSsi client awaits. Also exercises the use-after-free guard: a client
that closes mid-flight must not crash the worker.

Run:
    TEST_SKIP_SERVER_SETUP=1 PYTHONPATH=tests pytest tests/test_ssi_async.py -v
"""
import struct

from settings import HOST
from test_ssi_wire import (
    ssi_server,                # reused module-scoped nginx-with-ssi fixture
    _handshake_login, _open_ssi, _read_response, _parse_ssi_reply, _rrinfo,
    kXR_write, kXR_ok, SSI_CMD_RXQ,
)

kXR_attn      = 4001
kXR_waitresp  = 4006
kXR_asynresp  = 5008


def _submit(sock, fh, req_id, data):
    """Send the request via kXR_write; return the ack status (no assert)."""
    off = _rrinfo(SSI_CMD_RXQ, req_id, len(data))
    fhandle = bytes([fh, 0, 0, 0])
    sock.sendall(
        struct.pack(">BB H 4s 8s B 3x I", 0, 1, kXR_write, fhandle, off,
                    0, len(data)) + data
    )
    status, _ = _read_response(sock)
    return status


def _parse_asynresp(body):
    """Unwrap a kXR_attn asynresp outer body → (actnum, inner_status, inner_body).
    Layout: [actnum 4][reserved 4][inner ServerResponseHdr 8][inner body]."""
    actnum = struct.unpack(">I", body[0:4])[0]
    inner = body[8:]
    inner_status = struct.unpack(">H", inner[2:4])[0]
    inner_dlen = struct.unpack(">I", inner[4:8])[0]
    inner_body = inner[8:8 + inner_dlen]
    return actnum, inner_status, inner_body


class TestSsiAsync:
    def test_deferred_response_is_pushed(self, ssi_server):
        sock = _handshake_login(HOST, ssi_server)
        try:
            fh = _open_ssi(sock, "echo-async")
            # submit → server defers with kXR_waitresp
            assert _submit(sock, fh, 1, b"async-payload") == kXR_waitresp
            # the response arrives unsolicited as kXR_attn + kXR_asynresp
            status, body = _read_response(sock)
            assert status == kXR_attn, f"expected kXR_attn, got {status}"
            actnum, inner_status, inner_body = _parse_asynresp(body)
            assert actnum == kXR_asynresp, f"actnum {actnum}"
            assert inner_status == kXR_ok, f"inner status {inner_status}"
            tag, md, data = _parse_ssi_reply(inner_body)
            assert tag == b":", "expected fullResp tag"
            assert data == b"async-payload", f"echo mismatch: {data!r}"
        finally:
            sock.close()

    def test_close_mid_flight_does_not_crash(self, ssi_server):
        # Submit a deferred request then immediately close before the timer fires;
        # the worker must cancel the timer + unregister cleanly (no UAF).
        sock = _handshake_login(HOST, ssi_server)
        fh = _open_ssi(sock, "echo-async")
        assert _submit(sock, fh, 5, b"abandon-me") == kXR_waitresp
        sock.close()
        # the server is still healthy: a fresh sync request round-trips.
        sock2 = _handshake_login(HOST, ssi_server)
        try:
            fh2 = _open_ssi(sock2, "echo")
            off = _rrinfo(SSI_CMD_RXQ, 1, len(b"still-alive"))
            fhandle = bytes([fh2, 0, 0, 0])
            sock2.sendall(struct.pack(">BB H 4s 8s B 3x I", 0, 1, kXR_write,
                                      fhandle, off, 0, len(b"still-alive"))
                          + b"still-alive")
            assert _read_response(sock2)[0] == kXR_ok
        finally:
            sock2.close()

    def test_two_async_reqids_both_pushed(self, ssi_server):
        sock = _handshake_login(HOST, ssi_server)
        try:
            fh = _open_ssi(sock, "echo-async")
            assert _submit(sock, fh, 1, b"one") == kXR_waitresp
            assert _submit(sock, fh, 2, b"two") == kXR_waitresp
            # two pushed responses arrive (order not guaranteed); collect both.
            got = set()
            for _ in range(2):
                status, body = _read_response(sock)
                assert status == kXR_attn
                _, inner_status, inner_body = _parse_asynresp(body)
                assert inner_status == kXR_ok
                _, _, data = _parse_ssi_reply(inner_body)
                got.add(data)
            assert got == {b"one", b"two"}, f"got {got!r}"
        finally:
            sock.close()
