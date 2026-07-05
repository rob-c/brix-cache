"""
tests/test_ssi_alerts.py — Phase-3 out-of-band alert delivery for SSI.

The `alert-async` service defers, pushes two progress alerts (alrtResp '!'), then
the terminal response (fullResp ':'). A real libXrdSsi client processes each alert
and keeps awaiting the response.

Run:
    TEST_SKIP_SERVER_SETUP=1 PYTHONPATH=tests pytest tests/test_ssi_alerts.py -v
"""
from settings import HOST
from test_ssi_wire import (
    ssi_server,
    _handshake_login, _open_ssi, _read_response, _parse_ssi_reply,
)
from test_ssi_async import _submit, _parse_asynresp, kXR_attn, kXR_waitresp, kXR_ok


def _next_ssi_frame(sock):
    """Read one pushed kXR_attn asynresp and return (tag, data)."""
    status, body = _read_response(sock)
    assert status == kXR_attn, f"expected attn, got {status}"
    _, inner_status, inner_body = _parse_asynresp(body)
    assert inner_status == kXR_ok, f"inner status {inner_status}"
    tag, _, data = _parse_ssi_reply(inner_body)
    return tag, data


class TestSsiAlerts:
    def test_alerts_precede_response(self, ssi_server):
        sock = _handshake_login(HOST, ssi_server)
        try:
            fh = _open_ssi(sock, "alert-async")
            assert _submit(sock, fh, 1, b"go") == kXR_waitresp
            # two alerts (tag '!') then the response (tag ':')
            tag1, d1 = _next_ssi_frame(sock)
            tag2, d2 = _next_ssi_frame(sock)
            tag3, d3 = _next_ssi_frame(sock)
            assert tag1 == b"!" and d1 == b"progress-1", (tag1, d1)
            assert tag2 == b"!" and d2 == b"progress-2", (tag2, d2)
            assert tag3 == b":" and d3 == b"done", (tag3, d3)
        finally:
            sock.close()
