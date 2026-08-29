"""brix_checksum_default — the configurable default checksum algorithm.

Stock XRootD's `xrootd.chksum` sets the server's default/preferred checksum
algorithm; BriX hard-coded adler32. This adds `brix_checksum_default <algo>`,
which drives two things:

  * a kXR_Qcksum that names NO algorithm (no "<algo>:" prefix, no "?cks.type="
    CGI) computes the configured algorithm instead of adler32, and
  * the Qconfig "chksum" cslist advertises it FIRST — the entry a client takes
    as this server's preference when intersecting preference lists.

An explicit per-request algorithm still wins, and an unset (or unrecognized)
value falls back to adler32 — byte-identical to the prior behaviour.

Coverage: default drives path-Qcksum + Qconfig order; explicit ?cks.type
overrides; unset ⇒ adler32 (regression); a bad value degrades to adler32; the
directive passes `nginx -t`. Self-contained (no shared fleet).
"""

import os
import socket
import struct
import subprocess
import time

import pytest

from settings import BIND_HOST, NGINX_BIN

import _test_session_bind_helpers as H
from ephemeral_port import free_port

kXR_query = 3001
kXR_Qcksum = 3
kXR_Qconfig = 7


def _free_port():
    s = socket.socket()
    s.bind((BIND_HOST, free_port()))  # leased mock-range port (never kernel-assigned)
    port = s.getsockname()[1]
    s.close()
    return port


def _write_conf(tmp_path, extra):
    ns = tmp_path / "ns"
    ns.mkdir(exist_ok=True)
    (ns / "f.bin").write_bytes(b"checksum default payload\n")
    logs = tmp_path / "logs"
    logs.mkdir(exist_ok=True)
    port = _free_port()
    conf = tmp_path / "nginx.conf"
    conf.write_text(
        "daemon on;\nworker_processes 1;\n"
        f"pid {logs}/nginx.pid;\nerror_log {logs}/error.log info;\n"
        "events { worker_connections 64; }\n"
        "stream {\n  server {\n"
        f"    listen {BIND_HOST}:{port};\n"
        "    brix_root on;\n"
        f"    brix_export {ns};\n"
        "    brix_auth none;\n"
        f"    {extra}\n"
        "  }\n}\n")
    return port, conf


def _launch(tmp_path, extra):
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx not executable: {NGINX_BIN}")
    port, conf = _write_conf(tmp_path, extra)
    t = subprocess.run([NGINX_BIN, "-p", str(tmp_path), "-c", str(conf), "-t"],
                       capture_output=True, text=True, timeout=30)
    assert t.returncode == 0, f"config rejected: {t.stderr}"
    r = subprocess.run([NGINX_BIN, "-p", str(tmp_path), "-c", str(conf)],
                       capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, f"nginx failed to start: {r.stderr}"
    for _ in range(50):
        try:
            socket.create_connection((BIND_HOST, port), timeout=0.5).close()
            break
        except OSError:
            time.sleep(0.1)
    return port, conf


def _stop(tmp_path, conf):
    subprocess.run([NGINX_BIN, "-p", str(tmp_path), "-c", str(conf),
                    "-s", "quit"], capture_output=True, timeout=30)
    time.sleep(0.2)


def _query(port, subcode, payload):
    H.ANON_HOST = BIND_HOST
    sock, sessid, stream = H._establish_primary(port)
    try:
        body = struct.pack(">H", subcode) + b"\x00" * 14
        status, resp = H._send_req(sock, stream, kXR_query, body=body,
                                   payload=payload)
        assert status == H.kXR_ok, f"query {subcode} failed: {status}"
        return resp.split(b"\x00", 1)[0]
    finally:
        sock.close()


def _cksum_algo(port, path):
    """The algorithm token from a kXR_Qcksum reply ('algo hexvalue')."""
    return _query(port, kXR_Qcksum, path).split(b" ", 1)[0]


def test_default_drives_qcksum_and_qconfig(tmp_path):
    """(success) crc32c default ⇒ path-Qcksum computes crc32c and Qconfig leads
    with it (once, not duplicated)."""
    port, conf = _launch(tmp_path, "brix_checksum_default crc32c;")
    try:
        assert _cksum_algo(port, b"/f.bin") == b"crc32c"
        chksum = _query(port, kXR_Qconfig, b"chksum")
        assert chksum.startswith(b"crc32c,"), f"chksum list: {chksum!r}"
        assert chksum.count(b"crc32c") == 1, "default duplicated in cslist"
        assert b"adler32" in chksum, "full algo set no longer advertised"
    finally:
        _stop(tmp_path, conf)


def test_explicit_request_algo_overrides_default(tmp_path):
    """(override) an explicit ?cks.type=md5 still wins over the default."""
    port, conf = _launch(tmp_path, "brix_checksum_default crc32c;")
    try:
        assert _cksum_algo(port, b"/f.bin?cks.type=md5") == b"md5"
    finally:
        _stop(tmp_path, conf)


def test_unset_defaults_to_adler32(tmp_path):
    """(regression) no directive ⇒ adler32 leads Qconfig and answers Qcksum."""
    port, conf = _launch(tmp_path, "")
    try:
        assert _cksum_algo(port, b"/f.bin") == b"adler32"
        assert _query(port, kXR_Qconfig, b"chksum").startswith(b"adler32,")
    finally:
        _stop(tmp_path, conf)


def test_bad_value_degrades_to_adler32(tmp_path):
    """(robustness) an unrecognized algo does not break checksums — it falls
    back to adler32 at use, never erroring the request."""
    port, conf = _launch(tmp_path, "brix_checksum_default not_an_algo;")
    try:
        assert _cksum_algo(port, b"/f.bin") == b"adler32"
        assert _query(port, kXR_Qconfig, b"chksum").startswith(b"adler32,")
    finally:
        _stop(tmp_path, conf)


def test_directive_accepted_by_config_test(tmp_path):
    """(config) brix_checksum_default passes `nginx -t`."""
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip("nginx not executable")
    _port, conf = _write_conf(tmp_path, "brix_checksum_default sha256;")
    r = subprocess.run([NGINX_BIN, "-p", str(tmp_path), "-c", str(conf), "-t"],
                       capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, f"rejected by -t: {r.stderr}"
    assert "unknown directive" not in r.stderr
