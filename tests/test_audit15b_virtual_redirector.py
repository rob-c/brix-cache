"""
test_audit15b_virtual_redirector.py — live coverage for `brix_virtual_redirector`
(audit §A2, testsuite-combinatorial-coverage-audit 2026-08-15: a whole operating
mode never configured by any test; the 08-15 parse sweep proved only that the
name parses).

The directive's one runtime consumer is protocol_role_flags()
(src/protocols/root/session/protocol.c): with the flag on, the kXR_protocol
reply's flags word advertises kXR_isManager|kXR_attrVirtRdr, telling stock
clients this endpoint translates logical paths rather than owning them.  The
three cases:

  * subject (flag on)   -> both role bits advertised
  * control (flag off)  -> neither bit advertised (same template, same knobs
                           otherwise — the directive is the only variable)
  * subject still serves -> advertising the role must not break local serving
                            (there is no manager_map, so opens stay local)
"""

import socket
import struct

import pytest

from settings import HOST
from test_phase25_ratelimit import (_start_stream, _xrd_login, _xrd_open,
                                    _xrd_read, KXR_OK)

pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-audit15b-vrdr")]

KXR_ISMANAGER  = 0x00000002
KXR_ATTRVIRTRDR = 0x00000800

SEED = b"virtual-redirector-payload\n"


def _recv_exact(s, n):
    buf = b""
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("closed")
        buf += chunk
    return buf


def _protocol_flags(port):
    """Handshake + kXR_protocol; return the ServerProtocolBody flags word."""
    s = socket.create_connection((HOST, port), timeout=5)
    try:
        s.settimeout(5)
        s.sendall(struct.pack(">IIIII", 0, 0, 0, 4, 2012))
        _recv_exact(s, 16)
        s.sendall(struct.pack(">BB H I BB 10x I", 0, 1, 3006,
                              0x00000520, 0x00, 0x03, 0))
        hdr = _recv_exact(s, 8)
        status = struct.unpack(">H", hdr[2:4])[0]
        dlen = struct.unpack(">I", hdr[4:8])[0]
        body = _recv_exact(s, dlen) if dlen else b""
        assert status == KXR_OK, (status, body)
        assert len(body) >= 8, body
        # ServerProtocolBody = pval(4) + flags(4)
        return struct.unpack(">I", body[4:8])[0]
    finally:
        s.close()


def _boot(lifecycle, tmp_path, name, knobs):
    data = tmp_path / f"{name}-data"
    data.mkdir()
    (data / "seed.bin").write_bytes(SEED)
    return _start_stream(lifecycle, data, name, knobs, "")


@pytest.fixture()
def vrdr_port(lifecycle, tmp_path):
    return _boot(lifecycle, tmp_path, "lc-audit15b-vrdr-on",
                 "        brix_virtual_redirector on;\n")


def test_virtual_redirector_advertises_role_bits(vrdr_port):
    flags = _protocol_flags(vrdr_port)
    want = KXR_ISMANAGER | KXR_ATTRVIRTRDR
    assert flags & want == want, \
        f"flags {flags:#010x} missing kXR_isManager|kXR_attrVirtRdr"


def test_plain_server_does_not_advertise_role_bits(lifecycle, tmp_path):
    # Control: identical template with the directive absent — the bits must be
    # clear, so the subject's advertisement is attributable to the directive.
    port = _boot(lifecycle, tmp_path, "lc-audit15b-vrdr-off", "")
    flags = _protocol_flags(port)
    assert flags & (KXR_ISMANAGER | KXR_ATTRVIRTRDR) == 0, \
        f"flags {flags:#010x} advertise a redirector role without the directive"


def test_virtual_redirector_still_serves_locally(vrdr_port):
    # Without a manager_map there is nothing to redirect to; the advertised
    # role must not break plain local open+read.
    s = _xrd_login(HOST, vrdr_port)
    try:
        status, body = _xrd_open(s, "/seed.bin")
        assert status == KXR_OK, (status, body)
        status, data = _xrd_read(s, body[:4], 0, len(SEED))
        assert status == KXR_OK and data == SEED, (status, data)
    finally:
        s.close()
