"""
tests/test_ssi_stream.py — Phase-3 streamed async responses for SSI.

The `stream-async` service defers, then produces a multi-chunk response. The
server acks kXR_waitresp, pushes a kXR_attn carrying a pendResp ('*') reply, and
the client drains the concatenated body via kXR_read.

Run:
    TEST_SKIP_SERVER_SETUP=1 PYTHONPATH=tests pytest tests/test_ssi_stream.py -v
"""
import struct

from settings import HOST
from test_ssi_wire import (
    ssi_server,
    _handshake_login, _open_ssi, _read_response, _parse_ssi_reply, _rrinfo,
    kXR_write, kXR_ok, SSI_CMD_RXQ,
)
from test_ssi_async import _submit, _parse_asynresp, kXR_attn, kXR_waitresp, kXR_asynresp

kXR_read = 3013


def _ssi_read(sock, fh, req_id, rlen=4096):
    """kXR_read on the SSI handle; the offset field carries the RRInfo."""
    off_bytes = _rrinfo(SSI_CMD_RXQ, req_id, 0)
    offset = int.from_bytes(off_bytes, "big")
    fhandle = bytes([fh, 0, 0, 0])
    sock.sendall(struct.pack(">2sH4sqII", b"\x00\x01", kXR_read, fhandle,
                             offset, rlen, 0))
    return _read_response(sock)


class TestSsiStream:
    def test_streamed_response_drained_via_read(self, ssi_server):
        sock = _handshake_login(HOST, ssi_server)
        try:
            fh = _open_ssi(sock, "stream-async")
            assert _submit(sock, fh, 1, b"go") == kXR_waitresp
            # pushed pendResp attn
            status, body = _read_response(sock)
            assert status == kXR_attn, f"expected attn, got {status}"
            actnum, inner_status, inner_body = _parse_asynresp(body)
            assert actnum == kXR_asynresp and inner_status == kXR_ok
            tag, _, data = _parse_ssi_reply(inner_body)
            assert tag == b"*", f"expected pendResp tag, got {tag!r}"
            assert data == b"", "pendResp carries no inline data"
            # drain the streamed body
            collected = b""
            for _ in range(8):
                st, chunk = _ssi_read(sock, fh, 1)
                assert st == kXR_ok
                if not chunk:
                    break          # EOF
                collected += chunk
            assert collected == b"part-A|part-B|part-C", f"got {collected!r}"
        finally:
            sock.close()
