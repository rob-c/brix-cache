"""
tests/test_ssi_config.py — Phase-6 SSI config directives.

Verifies the gating + caps directives: the CTA service is opt-in
(`brix_ssi_service cta`), an unknown service name is rejected by `nginx -t`, and
`brix_ssi_max_inflight` caps concurrent requests.

Run:
    TEST_SKIP_SERVER_SETUP=1 PYTHONPATH=tests pytest tests/test_ssi_config.py -v
"""
import os
import struct

import pytest

from settings import NGINX_BIN, BIND_HOST
from server_registry import NginxInstanceSpec
from server_launcher import RegistryCommandFailure
from test_ssi_wire import (
    _handshake_login, _read_response, _rrinfo, _write_request,
    kXR_open, kXR_ok, SSI_CMD_RXQ,
)

pytestmark = pytest.mark.uses_lifecycle_harness


def _directives(extra_ssi):
    """Assemble the SSI_DIRECTIVES block: `brix_ssi on` plus any extra lines."""
    return "        brix_ssi on;\n" + extra_ssi


def _start(lifecycle, name, extra_ssi):
    ep = lifecycle.start(NginxInstanceSpec(
        name=name,
        template="nginx_lc_ssi.conf",
        protocol="root",
        template_values={"BIND_HOST": BIND_HOST,
                         "SSI_DIRECTIVES": _directives(extra_ssi)},
        reason="SSI config-directive test server"))
    return ep.port


def _open_status(sock, service):
    path = ("/.ssi/" + service).encode() + b"\x00"
    sock.sendall(
        struct.pack(">BB H H H H 6x 4x I", 0, 1, kXR_open, 0, 0x20, 0, len(path))
        + path)
    return _read_response(sock)[0]


@pytest.mark.skipif(not os.path.exists(NGINX_BIN), reason="nginx binary not found")
class TestSsiConfig:
    def test_cta_gated_off_by_default(self, lifecycle):
        # brix_ssi on but no `brix_ssi_service cta` → cta must not resolve.
        port = _start(lifecycle, "lc-ssi-cfg-default", "")
        sock = _handshake_login(BIND_HOST, port)
        assert _open_status(sock, "cta") != kXR_ok   # NotFound
        # the built-in test service still resolves
        assert _open_status(_handshake_login(BIND_HOST, port), "echo") == kXR_ok
        sock.close()

    def test_cta_enabled_resolves(self, lifecycle):
        port = _start(lifecycle, "lc-ssi-cfg-cta", "  brix_ssi_service cta;\n")
        sock = _handshake_login(BIND_HOST, port)
        assert _open_status(sock, "cta") == kXR_ok
        sock.close()

    def test_unknown_service_rejected_by_nginx_t(self, lifecycle):
        with pytest.raises(RegistryCommandFailure) as exc:
            lifecycle.start(NginxInstanceSpec(
                name="lc-ssi-cfg-bogus",
                template="nginx_lc_ssi.conf",
                protocol="root",
                template_values={
                    "BIND_HOST": BIND_HOST,
                    "SSI_DIRECTIVES": _directives("  brix_ssi_service bogus;\n"),
                },
                reason="SSI unknown-service rejected by nginx -t"))
        assert "unknown SSI service" in str(exc.value)

    def test_max_inflight_caps_concurrency(self, lifecycle):
        port = _start(lifecycle, "lc-ssi-cfg-inflight", "  brix_ssi_max_inflight 2;\n")
        sock = _handshake_login(BIND_HOST, port)
        # open echo, fill 2 concurrent reqIds, the 3rd is rejected
        path = b"/.ssi/echo\x00"
        sock.sendall(struct.pack(">BB H H H H 6x 4x I", 0, 1, kXR_open, 0,
                                 0x20, 0, len(path)) + path)
        fh = _read_response(sock)[1][0]
        _write_request(sock, fh, 1, b"a")
        _write_request(sock, fh, 2, b"b")
        off = _rrinfo(SSI_CMD_RXQ, 3, 1)
        fhandle = bytes([fh, 0, 0, 0])
        sock.sendall(struct.pack(">BB H 4s 8s B 3x I", 0, 1, 3019, fhandle,
                                 off, 0, 1) + b"c")
        assert _read_response(sock)[0] != kXR_ok   # kXR_Overloaded
        sock.close()
