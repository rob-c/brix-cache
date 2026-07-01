"""
tests/test_ssi_multiplex.py — two (and more) concurrent reqIds on one open
/.ssi/ handle resolve independently (Phase-1 session/RRTable multiplex).

A single libXrdSsi resource handle pipelines several requests, each keyed by the
reqId carried in the XrdSsiRRInfo. This proves the session routes each reqId to
its own request slot, that an unknown reqId is rejected, and that the per-session
inflight cap (XROOTD_SSI_MAX_INFLIGHT = 8) is enforced.

Run:
    TEST_SKIP_SERVER_SETUP=1 PYTHONPATH=tests pytest tests/test_ssi_multiplex.py -v
"""
import struct

from settings import HOST
from test_ssi_wire import (
    ssi_server,                # module-scoped nginx-with-ssi fixture (reused)
    _handshake_login, _open_ssi, _write_request, _query_wait,
    _parse_ssi_reply, _read_response, _rrinfo,
    kXR_write, kXR_ok, SSI_CMD_RXQ,
)


def _write_request_status(sock, fh, req_id, data):
    """Like _write_request but returns the ack status instead of asserting ok."""
    off = _rrinfo(SSI_CMD_RXQ, req_id, len(data))
    fhandle = bytes([fh, 0, 0, 0])
    sock.sendall(
        struct.pack(">BB H 4s 8s B 3x I", 0, 1, kXR_write, fhandle, off,
                    0, len(data)) + data
    )
    status, _ = _read_response(sock)
    return status


class TestSsiMultiplex:
    def test_two_concurrent_reqids_resolve_independently(self, ssi_server):
        sock = _handshake_login(HOST, ssi_server)
        try:
            fh = _open_ssi(sock, "echo")
            # Submit both requests before draining either response.
            _write_request(sock, fh, 1, b"alpha")
            _write_request(sock, fh, 2, b"bravo")
            s1, b1 = _query_wait(sock, fh, 1)
            s2, b2 = _query_wait(sock, fh, 2)
            assert s1 == kXR_ok and s2 == kXR_ok
            _, _, d1 = _parse_ssi_reply(b1)
            _, _, d2 = _parse_ssi_reply(b2)
            assert d1 == b"alpha", f"reqId 1 got {d1!r}"
            assert d2 == b"bravo", f"reqId 2 got {d2!r}"
        finally:
            sock.close()

    def test_wait_unknown_reqid_errors(self, ssi_server):
        sock = _handshake_login(HOST, ssi_server)
        try:
            fh = _open_ssi(sock, "echo")
            status, _ = _query_wait(sock, fh, 777)   # never submitted
            assert status != kXR_ok, "wait on unknown reqId must error"
        finally:
            sock.close()

    def test_inflight_cap_rejects_overflow(self, ssi_server):
        # Eight distinct reqIds occupy all slots (each echo dispatches but the
        # slot stays in use until cancel/close); the ninth is rejected.
        sock = _handshake_login(HOST, ssi_server)
        try:
            fh = _open_ssi(sock, "echo")
            for i in range(8):
                _write_request(sock, fh, 10 + i, b"x")
            status = _write_request_status(sock, fh, 99, b"x")
            assert status != kXR_ok, "ninth concurrent reqId must be rejected"
        finally:
            sock.close()
