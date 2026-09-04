"""kXR_fullurl login ability — parity audit §1.3 (previously "decoded, ignored").

The client's XLoginAbility bitmask now persists on the session
(`ctx->login.ability`/`ability2`), and `kXR_fullurl` (bit 0) is honored at the
redirect emission choke point: a fullurl-capable client gets a SELF-CONTAINED
`root://host:port` URL in the redirect host field (the unambiguous cross-port
form), while clients that did not advertise it keep the classic host-only form
byte-identical. Unknown ability bits are stored untouched and change nothing.

The redirect is triggered deterministically via §1.10 fsoverload: reader A
holds an undrained kXR_pgread whose windowed scratch exceeds the 256k budget,
so reader B's small buffered read takes the configured
`brix_fsoverload_redirect` backoff.  Reader A must use kXR_pgread — a large
cleartext kXR_read of a regular file is served zero-copy by sendfile and holds
NO heap, so it can never charge the memory budget; pgread's per-page CRC32c
forces the memory path.  Reader B stays a plain kXR_read below
BRIX_READ_SENDFILE_MIN (32k) so it takes the buffered path (the one that
consults brix_budget_admit) and its served response is a single kXR_ok frame.

Coverage: fullurl advertised ⇒ full URL; not advertised ⇒ host-only (regression);
garbage ability bits (0xFE, fullurl clear) ⇒ host-only and no misbehavior.
Self-contained (no shared fleet).
"""

import socket
import struct
import time
from pathlib import Path

import pytest

from settings import BIND_HOST
from server_registry import NginxInstanceSpec

import _test_session_bind_helpers as H

pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-login-fullurl")]

_SERVER = "lc-login-fullurl"

kXR_redirect = 4004


def _launch(lifecycle):
    endpoint = lifecycle.start(NginxInstanceSpec(
        name=_SERVER,
        template="nginx_lc_login_fullurl.conf",
        template_values={"BIND_HOST": BIND_HOST},
        reason="login fullurl redirect coverage"))
    Path(endpoint.data_root, "big.bin").write_bytes(b"R" * (8 * 1024 * 1024))
    return endpoint.port


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


kXR_pgread = 3030


def _send_read(sock, sid, fh, rlen, reqid=None):
    body = fh + struct.pack(">q", 0) + struct.pack(">i", rlen)
    hdr = bytes(sid[:2]) + struct.pack(">H", reqid if reqid else H.kXR_read)
    hdr += body.ljust(16, b"\x00") + struct.pack(">I", 0)
    sock.sendall(hdr)


def _trigger_redirect(port, reader_b):
    """The §1.10 overload pattern: reader A (tiny RCVBUF) holds an undrained
    whole-file kXR_pgread whose windowed scratch charges the 256k budget
    (pgread cannot sendfile, so it must buffer in heap); reader B's small
    buffered read is then deferred with the configured redirect. Returns
    (port, host) from B's kXR_redirect body."""
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
        _send_read(a, b"\x00\x03", fa, 8 * 1024 * 1024, reqid=kXR_pgread)
        assert H._recv_exact(a, 8) is not None, "reader A got no first frame"

        deadline = time.time() + 8
        while time.time() < deadline:
            redirect = _poll_reader_b_once(reader_b, fb)
            if redirect is not None:
                return redirect
        raise AssertionError("budget never deferred reader B")
    finally:
        a.close()


def _drain_oksofar(reader_b, status):
    """Drain kXR_oksofar continuation frames until a terminal status arrives."""
    while status == H.kXR_oksofar:
        hdr = H._recv_exact(reader_b, 8)
        status = struct.unpack(">H", hdr[2:4])[0]
        dlen = struct.unpack(">I", hdr[4:8])[0]
        if dlen:
            H._recv_exact(reader_b, dlen)
    return status


def _poll_reader_b_once(reader_b, fb):
    """One reader-B read: return (port, host) on kXR_redirect, None if the read
    was served (budget not yet exhausted); raise on an unexpected status."""
    # Below BRIX_READ_SENDFILE_MIN: buffered path, budget-admitted, one frame.
    _send_read(reader_b, b"\x00\x05", fb, 16 * 1024)
    hdr = H._recv_exact(reader_b, 8)
    status = struct.unpack(">H", hdr[2:4])[0]
    dlen = struct.unpack(">I", hdr[4:8])[0]
    body = H._recv_exact(reader_b, dlen) if dlen else b""
    if status == kXR_redirect:
        rport = struct.unpack(">i", body[:4])[0]
        host = body[4:].split(b"\x00", 1)[0].decode()
        return rport, host
    if status in (H.kXR_ok, H.kXR_oksofar):
        _drain_oksofar(reader_b, status)
        time.sleep(0.2)
        return None
    raise AssertionError(f"reader B unexpected status {status}")


def test_fullurl_client_gets_full_url(lifecycle):
    """(success) ability kXR_fullurl=1 ⇒ STILL the classic host-only form for a
    root:// target: with a positive numeric port the reference client appends
    ":port" to the host field, so a full URL here would parse as
    "root://h:p:p/" and fail errInvalidRedirectURL.  A full URL is only legal
    with a negative (flags) port, which this redirect path never sends."""
    port = _launch(lifecycle)
    sock = None
    try:
        sock = _login_with_ability(port, 0x01 | 0x04)  # fullurl + readrdok
        rport, host = _trigger_redirect(port, sock)
        assert host == "sibling.example", f"fullurl client got {host!r}"
        assert rport == 2094
    finally:
        if sock is not None:
            sock.close()


def test_plain_client_keeps_host_only(lifecycle):
    """(regression) readrdok but no fullurl ⇒ the classic host-only form."""
    port = _launch(lifecycle)
    sock = None
    try:
        sock = _login_with_ability(port, 0x04)  # readrdok only (no fullurl)
        rport, host = _trigger_redirect(port, sock)
        assert host == "sibling.example", f"plain client got {host!r}"
        assert rport == 2094
    finally:
        if sock is not None:
            sock.close()


def test_unknown_ability_bits_ignored(lifecycle):
    """(security-neg) garbage ability bits with fullurl CLEAR change nothing —
    stored untouched, host-only redirect, no misbehavior."""
    port = _launch(lifecycle)
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
