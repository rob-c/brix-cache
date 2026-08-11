"""kXR_locate `kXR_prefname` option — parity audit §2.18.

A data server answers kXR_locate with a location token `S<access><host>:<port>`.
Stock lets the client ask (option bit `kXR_prefname`, 0x0100) for the server's
DNS *hostname* in that token rather than its IP literal — the form a client
needs when a GSI host-cert CN must match, or when the name should re-resolve
through a different route. BriX previously hard-coded the IP (the option was
decoded-and-ignored, with a comment that wrongly claimed the hostname was the
default); it now honors the bit at the `locate_format_local` choke point.

Coverage:
  * default (option clear) ⇒ the IP literal, byte-identical to before;
  * prefname (option set)  ⇒ the server's gethostname(2) name, not a dotted IP;
  * the access char and port are preserved across both forms.
Self-contained (no shared fleet).
"""

import os
import re
import socket
import struct
import subprocess
import time

import pytest

from settings import BIND_HOST, NGINX_BIN

import _test_session_bind_helpers as H

kXR_locate = 3027
kXR_prefname = 0x0100
_IPV4 = re.compile(rb"^\d{1,3}(\.\d{1,3}){3}$")


def _free_port():
    s = socket.socket()
    s.bind((BIND_HOST, 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _launch(tmp_path):
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx not executable: {NGINX_BIN}")
    ns = tmp_path / "ns"
    ns.mkdir(exist_ok=True)
    (ns / "f.bin").write_bytes(b"L" * 4096)
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
        "  }\n}\n")
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


def _locate(sock, stream, path, options):
    """Send kXR_locate. Body: options[2] reserved[14]; payload = path+NUL."""
    body = struct.pack(">H", options) + b"\x00" * 14
    return H._send_req(sock, stream, kXR_locate, body=body,
                       payload=path.encode() + b"\x00")


def _split_token(tok):
    """'S' + access + host:port  →  (access, host, port). Handles [v6]:port."""
    assert tok[:1] == b"S", f"not a server token: {tok!r}"
    access = tok[1:2]
    rest = tok[2:]
    hostport = rest.rsplit(b":", 1)
    return access, hostport[0], hostport[1]


def test_default_locate_returns_ip(tmp_path):
    """(regression) option clear ⇒ the IP literal, exactly as before."""
    port, conf = _launch(tmp_path)
    sock = None
    try:
        H.ANON_HOST = BIND_HOST
        sock, sessid, stream = H._establish_primary(port)
        status, body = _locate(sock, stream, "/f.bin", 0)
        assert status == H.kXR_ok, f"locate failed: {status} {body!r}"
        tok = body.split(b"\x00", 1)[0]
        access, host, tport = _split_token(tok)
        assert access in (b"r", b"w"), f"bad access char: {access!r}"
        assert _IPV4.match(host), f"default locate host not an IP: {host!r}"
        assert host == BIND_HOST.encode()
        assert int(tport) == port
    finally:
        if sock is not None:
            sock.close()
        _stop(tmp_path, conf)


def test_prefname_returns_hostname(tmp_path):
    """(success) kXR_prefname set ⇒ gethostname(2), not a dotted IP; access +
    port preserved."""
    port, conf = _launch(tmp_path)
    sock = None
    try:
        H.ANON_HOST = BIND_HOST
        sock, sessid, stream = H._establish_primary(port)
        status, body = _locate(sock, stream, "/f.bin", kXR_prefname)
        assert status == H.kXR_ok, f"locate failed: {status} {body!r}"
        tok = body.split(b"\x00", 1)[0]
        access, host, tport = _split_token(tok)
        assert access in (b"r", b"w"), f"bad access char: {access!r}"
        assert not _IPV4.match(host), \
            f"prefname host is still an IP literal: {host!r}"
        assert host == socket.gethostname().encode(), \
            f"prefname host {host!r} != gethostname {socket.gethostname()!r}"
        assert int(tport) == port, "port not preserved under prefname"
    finally:
        if sock is not None:
            sock.close()
        _stop(tmp_path, conf)


def test_prefname_and_default_differ(tmp_path):
    """(discriminator) the two forms genuinely diverge — same server, one call
    each, host field IP vs name."""
    port, conf = _launch(tmp_path)
    sock = None
    try:
        H.ANON_HOST = BIND_HOST
        sock, sessid, stream = H._establish_primary(port)
        _, ip_body = _locate(sock, stream, "/f.bin", 0)
        _, nm_body = _locate(sock, stream, "/f.bin", kXR_prefname)
        _, ip_host, _ = _split_token(ip_body.split(b"\x00", 1)[0])
        _, nm_host, _ = _split_token(nm_body.split(b"\x00", 1)[0])
        assert ip_host != nm_host, (
            "prefname produced the same host as the default "
            f"({ip_host!r}) — the option had no effect")
    finally:
        if sock is not None:
            sock.close()
        _stop(tmp_path, conf)
