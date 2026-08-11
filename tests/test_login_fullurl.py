"""kXR_fullurl login ability — parity audit §1.3 (previously "decoded, ignored").

The client's XLoginAbility bitmask now persists on the session
(`ctx->login.ability`/`ability2`), and `kXR_fullurl` (bit 0) is honored at the
redirect emission choke point: a fullurl-capable client gets a SELF-CONTAINED
`root://host:port` URL in the redirect host field (the unambiguous cross-port
form), while clients that did not advertise it keep the classic host-only form
byte-identical. Unknown ability bits are stored untouched and change nothing.

The redirect is triggered deterministically via §1.10 fsoverload: a memory
budget smaller than one read admission makes the very first kXR_read take the
configured `brix_fsoverload_redirect` backoff.

Coverage: fullurl advertised ⇒ full URL; not advertised ⇒ host-only (regression);
garbage ability bits (0xFE, fullurl clear) ⇒ host-only and no misbehavior.
Self-contained (no shared fleet).
"""

import os
import socket
import struct
import subprocess
import time

import pytest

from settings import BIND_HOST, NGINX_BIN

import _test_session_bind_helpers as H

kXR_redirect = 4004


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
    (ns / "big.bin").write_bytes(b"R" * (8 * 1024 * 1024))
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
        "    brix_memory_budget 256k;\n"      # < one 2MiB streaming window
        "    brix_fsoverload_redirect sibling.example 2094;\n"
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


def _login_with_ability(port, ability):
    """Handshake + kXR_login carrying an explicit XLoginAbility byte.
    Body layout (oracle ClientLoginRequest): pid[4] username[8] ability2[1]
    ability[1] capver[1] reserved[1]."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((BIND_HOST, port))
    sock.sendall(struct.pack(">IIIII", 0, 0, 0, 4, 2012))
    assert H._recv_exact(sock, 16) is not None
    body = struct.pack(">I8sBBBB", 12345, b"anon\x00\x00\x00\x00",
                       0, ability, 0, 0)
    status, _ = H._send_req(sock, b"\x00\x01", H.kXR_login, body=body,
                            payload=b"anon\x00")
    assert status == H.kXR_ok, f"login failed: {status}"
    return sock


def _open_big(sock, sid):
    open_body = struct.pack(">HH", 0o644, 0x0010) + b"\x00" * 12
    status, body = H._send_req(sock, sid, H.kXR_open, body=open_body,
                               payload=b"/big.bin\x00")
    assert status == H.kXR_ok, f"open failed: {status}"
    return body[:4]


def _send_read(sock, sid, fh, rlen):
    body = fh + struct.pack(">q", 0) + struct.pack(">i", rlen)
    hdr = bytes(sid[:2]) + struct.pack(">H", H.kXR_read)
    hdr += body.ljust(16, b"\x00") + struct.pack(">I", 0)
    sock.sendall(hdr)


def _trigger_redirect(port, reader_b):
    """The §1.10 overload pattern: reader A (tiny RCVBUF) holds an undrained
    whole-file read whose windowed scratch charges the 256k budget; reader B's
    read is then deferred with the configured redirect. Returns (port, host)
    from B's kXR_redirect body."""
    a = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    a.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8192)
    a.connect((BIND_HOST, port))
    a.sendall(struct.pack(">IIIII", 0, 0, 0, 4, 2012))
    assert H._recv_exact(a, 16) is not None
    status, _ = H._send_req(a, b"\x00\x01", H.kXR_login,
                            body=struct.pack(">I8sBBBB", 1, b"anon\x00\x00\x00\x00",
                                             0, 0, 0, 0),
                            payload=b"anon\x00")
    assert status == H.kXR_ok
    try:
        fa = _open_big(a, b"\x00\x02")
        fb = _open_big(reader_b, b"\x00\x02")
        _send_read(a, b"\x00\x03", fa, 8 * 1024 * 1024)
        assert H._recv_exact(a, 8) is not None, "reader A got no first frame"

        deadline = time.time() + 8
        while time.time() < deadline:
            _send_read(reader_b, b"\x00\x05", fb, 4 * 1024 * 1024)
            hdr = H._recv_exact(reader_b, 8)
            status = struct.unpack(">H", hdr[2:4])[0]
            dlen = struct.unpack(">I", hdr[4:8])[0]
            body = H._recv_exact(reader_b, dlen) if dlen else b""
            if status == kXR_redirect:
                rport = struct.unpack(">i", body[:4])[0]
                host = body[4:].split(b"\x00", 1)[0].decode()
                return rport, host
            if status in (H.kXR_ok, H.kXR_oksofar):
                while status == H.kXR_oksofar:   # drain continuations
                    hdr = H._recv_exact(reader_b, 8)
                    status = struct.unpack(">H", hdr[2:4])[0]
                    dlen = struct.unpack(">I", hdr[4:8])[0]
                    if dlen:
                        H._recv_exact(reader_b, dlen)
                time.sleep(0.2)
                continue
            raise AssertionError(f"reader B unexpected status {status}")
        raise AssertionError("budget never deferred reader B")
    finally:
        a.close()


def test_fullurl_client_gets_full_url(tmp_path):
    """(success) ability kXR_fullurl=1 ⇒ the redirect host is a self-contained
    root:// URL; the numeric port field still carries the port."""
    port, conf = _launch(tmp_path)
    sock = None
    try:
        sock = _login_with_ability(port, 0x01 | 0x04)  # fullurl + readrdok
        rport, host = _trigger_redirect(port, sock)
        assert host == "root://sibling.example:2094", \
            f"fullurl client got {host!r}"
        assert rport == 2094
    finally:
        if sock is not None:
            sock.close()
        _stop(tmp_path, conf)


def test_plain_client_keeps_host_only(tmp_path):
    """(regression) readrdok but no fullurl ⇒ the classic host-only form."""
    port, conf = _launch(tmp_path)
    sock = None
    try:
        sock = _login_with_ability(port, 0x04)  # readrdok only (no fullurl)
        rport, host = _trigger_redirect(port, sock)
        assert host == "sibling.example", f"plain client got {host!r}"
        assert rport == 2094
    finally:
        if sock is not None:
            sock.close()
        _stop(tmp_path, conf)


def test_unknown_ability_bits_ignored(tmp_path):
    """(security-neg) garbage ability bits with fullurl CLEAR change nothing —
    stored untouched, host-only redirect, no misbehavior."""
    port, conf = _launch(tmp_path)
    sock = None
    try:
        sock = _login_with_ability(port, 0xFE)   # every bit except fullurl
        rport, host = _trigger_redirect(port, sock)
        assert host == "sibling.example", \
            f"unknown ability bits changed the redirect: {host!r}"
        assert rport == 2094
    finally:
        if sock is not None:
            sock.close()
        _stop(tmp_path, conf)
