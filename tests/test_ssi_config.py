"""
tests/test_ssi_config.py — Phase-6 SSI config directives.

Verifies the gating + caps directives: the CTA service is opt-in
(`brix_ssi_service cta`), an unknown service name is rejected by `nginx -t`, and
`brix_ssi_max_inflight` caps concurrent requests.

Run:
    TEST_SKIP_SERVER_SETUP=1 PYTHONPATH=tests pytest tests/test_ssi_config.py -v
"""
import os
import socket
import struct
import subprocess
import time

import pytest

from config_templates import render_config
from settings import NGINX_BIN, BIND_HOST, free_port
from test_ssi_wire import (
    _handshake_login, _read_response, _rrinfo, _write_request,
    kXR_open, kXR_ok, SSI_CMD_RXQ,
)


def _write_config(base, extra_ssi):
    data = os.path.join(base, "data")
    os.makedirs(data, exist_ok=True)
    port = free_port()
    cfg = os.path.join(base, "ssi.conf")
    with open(cfg, "w") as f:
        f.write(render_config("nginx_ssi_config_extra.conf",
                              BASE_DIR=base,
                              BIND_HOST=BIND_HOST,
                              PORT=port,
                              DATA_DIR=data,
                              EXTRA_SSI=extra_ssi))
    return cfg, port


def _start(base, extra_ssi):
    cfg, port = _write_config(base, extra_ssi)
    chk = subprocess.run([NGINX_BIN, "-t", "-c", cfg], capture_output=True, text=True)
    if chk.returncode != 0:
        return None, port, chk.stderr
    p = subprocess.Popen([NGINX_BIN, "-c", cfg, "-p", base],
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    for _ in range(40):
        try:
            socket.create_connection((BIND_HOST, port), timeout=0.5).close()
            return p, port, ""
        except OSError:
            time.sleep(0.1)
    p.terminate()
    return None, port, "did not start"


def _open_status(sock, service):
    path = ("/.ssi/" + service).encode() + b"\x00"
    sock.sendall(
        struct.pack(">BB H H H H 6x 4x I", 0, 1, kXR_open, 0, 0x20, 0, len(path))
        + path)
    return _read_response(sock)[0]


@pytest.mark.skipif(not os.path.exists(NGINX_BIN), reason="nginx binary not found")
class TestSsiConfig:
    def test_cta_gated_off_by_default(self, tmp_path):
        # brix_ssi on but no `brix_ssi_service cta` → cta must not resolve.
        p, port, err = _start(str(tmp_path), "")
        assert p is not None, err
        try:
            sock = _handshake_login(BIND_HOST, port)
            assert _open_status(sock, "cta") != kXR_ok   # NotFound
            # the built-in test service still resolves
            assert _open_status(_handshake_login(BIND_HOST, port), "echo") == kXR_ok
            sock.close()
        finally:
            p.terminate()

    def test_cta_enabled_resolves(self, tmp_path):
        p, port, err = _start(str(tmp_path), "  brix_ssi_service cta;\n")
        assert p is not None, err
        try:
            sock = _handshake_login(BIND_HOST, port)
            assert _open_status(sock, "cta") == kXR_ok
            sock.close()
        finally:
            p.terminate()

    def test_unknown_service_rejected_by_nginx_t(self, tmp_path):
        cfg, _ = _write_config(str(tmp_path), "  brix_ssi_service bogus;\n")
        chk = subprocess.run([NGINX_BIN, "-t", "-c", cfg],
                             capture_output=True, text=True)
        assert chk.returncode != 0
        assert "unknown SSI service" in chk.stderr

    def test_max_inflight_caps_concurrency(self, tmp_path):
        p, port, err = _start(str(tmp_path), "  brix_ssi_max_inflight 2;\n")
        assert p is not None, err
        try:
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
        finally:
            p.terminate()
