"""
tests/test_ssi_wire.py — byte-exact XrdSsi-over-xroot conformance for the nginx
module's SSI engine (src/protocols/ssi/).

A raw-wire client reproduces exactly what a real libXrdSsi client does
(XrdSsiTaskReal + XrdClFile): open "/.ssi/<svc>", submit the request via
kXR_write whose offset carries an XrdSsiRRInfo{Rxq,reqId,size}, then wait for the
response via kXR_query(infotype=kXR_Qopaqug, fhandle, body=RRInfo{Rwt,reqId}).
The reply is parsed the same way GetResp() does:
[XrdSsiRRInfoAttn 16][metadata mdLen][data dbL].

Run:
    TEST_SKIP_SERVER_SETUP=1 PYTHONPATH=tests pytest tests/test_ssi_wire.py -v
"""

import os
import socket
import struct
import subprocess
import time

import pytest

from settings import HOST, NGINX_BIN, free_port

_DIR = os.path.join(os.environ["TMPDIR"], "xrd_ssi_wire")
SSI_PORT = int(os.environ.get("TEST_SSI_PORT") or free_port())

# kXR opcodes / constants
kXR_query    = 3001
kXR_open     = 3010
kXR_write    = 3019
kXR_protocol = 3006
kXR_login    = 3007
kXR_ok       = 0
kXR_Qopaqug  = 64
SSI_CMD_RXQ  = 0
SSI_CMD_RWT  = 1
SSI_CMD_CAN  = 2


def _recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise RuntimeError(f"closed after {len(buf)}/{n}")
        buf += chunk
    return buf


def _read_response(sock):
    hdr = _recv_exact(sock, 8)
    status = struct.unpack(">H", hdr[2:4])[0]
    dlen = struct.unpack(">I", hdr[4:8])[0]
    body = _recv_exact(sock, dlen) if dlen else b""
    return status, body


def _rrinfo(cmd, req_id, size):
    """Encode an XrdSsiRRInfo into the 8 wire bytes, matching the real class:
    byte0 = reqCmd, bytes1-3 = reqId big-endian (24-bit), bytes4-7 = reqSize
    little-endian. (Verified against live libXrdSsi traffic.)"""
    return bytes([cmd & 0xff, (req_id >> 16) & 0xff, (req_id >> 8) & 0xff,
                  req_id & 0xff]) + struct.pack("<I", size)


def _handshake_login(host, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)
    sock.connect((host, port))
    sock.sendall(struct.pack(">IIIII", 0, 0, 0, 4, 2012))           # handshake
    sock.sendall(struct.pack(">BB H I BB 10x I",
                             0, 1, kXR_protocol, 0x00000520, 0x02, 0x03, 0))
    _recv_exact(sock, 16)                                           # hs reply
    _read_response(sock)                                           # protocol reply
    # ClientLoginRequest (24-byte header): streamid[2] requestid pid[4]
    # username[8] reserved ability capver role dlen
    sock.sendall(struct.pack(">BB H I 8s B B B B I",
                             0, 1, kXR_login, 0, b"anon\x00\x00\x00\x00",
                             0, 0, 5, 0, 0))
    _read_response(sock)                                           # login reply
    return sock


def _open_ssi(sock, service):
    path = ("/.ssi/" + service).encode() + b"\x00"
    # ClientOpenRequest: streamid[2] requestid mode options optiont reserved[6]
    # fhtemplt[4] dlen
    sock.sendall(
        struct.pack(">BB H H H H 6x 4x I", 0, 1, kXR_open, 0, 0x20, 0, len(path))
        + path
    )
    status, body = _read_response(sock)
    assert status == kXR_ok, f"SSI open failed: status {status} body={body!r}"
    return body[0]   # fhandle slot index


def _write_request(sock, fh, req_id, data):
    # ClientWriteRequest: streamid[2] requestid fhandle[4] offset(8) pathid
    # reserved[3] dlen ; offset = RRInfo{Rxq, req_id, size}
    off = _rrinfo(SSI_CMD_RXQ, req_id, len(data))
    fhandle = bytes([fh, 0, 0, 0])
    sock.sendall(
        struct.pack(">BB H 4s 8s B 3x I", 0, 1, kXR_write, fhandle, off,
                    0, len(data)) + data
    )
    status, _ = _read_response(sock)
    assert status == kXR_ok, f"SSI write ack failed: status {status}"


def _query_wait(sock, fh, req_id, cmd=SSI_CMD_RWT):
    # ClientQueryRequest: streamid[2] requestid infotype reserved1[2] fhandle[4]
    # reserved2[8] dlen ; body = RRInfo{cmd, req_id}
    body = _rrinfo(cmd, req_id, 0)
    fhandle = bytes([fh, 0, 0, 0])
    sock.sendall(
        struct.pack(">BB H H 2x 4s 8x I", 0, 1, kXR_query, kXR_Qopaqug,
                    fhandle, len(body)) + body
    )
    return _read_response(sock)


def _parse_ssi_reply(body):
    """Parse [XrdSsiRRInfoAttn 16][metadata][data] exactly like GetResp()."""
    assert len(body) >= 16, f"reply shorter than attn prefix: {len(body)}"
    tag = body[0:1]
    pfx = struct.unpack(">H", body[2:4])[0]
    md = struct.unpack(">I", body[4:8])[0]
    db = len(body) - md - pfx
    assert pfx == 16, f"pfxLen {pfx} != 16"
    assert db >= 0, f"negative data length {db}"
    metadata = body[pfx:pfx + md]
    data = body[pfx + md:pfx + md + db]
    return tag, metadata, data


# ---------------------------------------------------------------------------
# fixture: a dedicated nginx with brix_ssi on
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def ssi_server():
    if not os.path.exists(NGINX_BIN):
        pytest.skip(f"nginx binary not found: {NGINX_BIN}")
    base = os.path.join(_DIR, "srv")
    data = os.path.join(_DIR, "data")
    os.makedirs(os.path.join(base, "logs"), exist_ok=True)
    os.makedirs(data, exist_ok=True)
    conf = os.path.join(base, "nginx.conf")
    with open(conf, "w") as f:
        f.write(
            f"worker_processes 1;\n"
            f"error_log {base}/logs/error.log info;\n"
            f"pid {base}/logs/nginx.pid;\n"
            f"events {{ worker_connections 128; }}\n"
            f"stream {{\n"
            f"    server {{\n"
            f"        listen 0.0.0.0:{SSI_PORT};\n"
            f"        brix_root on; brix_storage_backend posix:{data}; brix_auth none;\n"
            f"        brix_allow_write on;\n"
            f"        brix_ssi on;\n"
            f"        brix_ssi_service cta;\n"
            f"    }}\n"
            f"}}\n")
    subprocess.run([NGINX_BIN, "-c", conf, "-s", "stop"], capture_output=True)
    time.sleep(0.3)
    chk = subprocess.run([NGINX_BIN, "-t", "-c", conf], capture_output=True, text=True)
    if chk.returncode != 0:
        pytest.skip(f"ssi nginx config rejected: {chk.stderr[-300:]}")
    started = subprocess.run([NGINX_BIN, "-c", conf], capture_output=True, text=True)
    if started.returncode != 0:
        pytest.skip(f"ssi nginx failed to start: {started.stderr[-300:]}")
    # wait for the port
    for _ in range(40):
        try:
            socket.create_connection((HOST, SSI_PORT), timeout=1).close()
            break
        except OSError:
            time.sleep(0.25)
    else:
        subprocess.run([NGINX_BIN, "-c", conf, "-s", "stop"], capture_output=True)
        pytest.skip("ssi nginx did not come up")
    yield SSI_PORT
    subprocess.run([NGINX_BIN, "-c", conf, "-s", "stop"], capture_output=True)


class TestSsiUnary:
    def test_echo_roundtrip(self, ssi_server):
        sock = _handshake_login(HOST, ssi_server)
        try:
            fh = _open_ssi(sock, "echo")
            _write_request(sock, fh, 7, b"hello ssi world")
            status, body = _query_wait(sock, fh, 7)
            assert status == kXR_ok, f"query-wait status {status}"
            tag, md, data = _parse_ssi_reply(body)
            assert tag == b":", "expected fullResp tag"
            assert data == b"hello ssi world", f"echo mismatch: {data!r}"
        finally:
            sock.close()

    def test_meta_service_sets_metadata(self, ssi_server):
        sock = _handshake_login(HOST, ssi_server)
        try:
            fh = _open_ssi(sock, "meta")
            _write_request(sock, fh, 3, b"payload")
            status, body = _query_wait(sock, fh, 3)
            assert status == kXR_ok
            tag, md, data = _parse_ssi_reply(body)
            assert md == b"ssi-meta", f"metadata mismatch: {md!r}"
            assert data == b"payload", f"data mismatch: {data!r}"
        finally:
            sock.close()

    def test_unknown_service_rejected(self, ssi_server):
        sock = _handshake_login(HOST, ssi_server)
        try:
            path = b"/.ssi/nosuch\x00"
            sock.sendall(
                struct.pack(">BB H H H H 6x 4x I", 0, 1, kXR_open, 0, 0x20, 0,
                            len(path)) + path
            )
            status, _ = _read_response(sock)
            assert status != kXR_ok, "unknown SSI service must be rejected"
        finally:
            sock.close()

    def test_cancel_is_accepted(self, ssi_server):
        sock = _handshake_login(HOST, ssi_server)
        try:
            fh = _open_ssi(sock, "echo")
            _write_request(sock, fh, 9, b"to-cancel")
            status, _ = _query_wait(sock, fh, 9, cmd=SSI_CMD_CAN)
            assert status == kXR_ok, f"cancel status {status}"
        finally:
            sock.close()


# ===========================================================================
# Real libXrdSsi client interop — the gold-standard proof: stock XRootD's own
# SSI client stack drives the module. Skips cleanly when the SSI client
# tooling (source-tree headers + libXrdSsiLib) is unavailable.
# ===========================================================================

import shutil

_BRIX_SRC = "/tmp/brix-src/src"
_SSI_CLIENT_SRC = os.path.join(os.path.dirname(__file__), "ssi_client.cc")


def _build_ssi_client():
    """Compile the real libXrdSsi C++ client; return its path or None."""
    if not os.path.isdir(os.path.join(_BRIX_SRC, "XrdSsi")):
        return None
    if shutil.which("g++") is None:
        return None
    out = os.path.join(os.environ["TMPDIR"], "ssi_client_bin")
    r = subprocess.run(
        ["g++", "-std=c++17", "-I", _BRIX_SRC, "-o", out, _SSI_CLIENT_SRC,
         "-lXrdSsiLib", "-lXrdCl", "-lXrdUtils"],
        capture_output=True, text=True)
    return out if r.returncode == 0 else None


@pytest.fixture(scope="module")
def ssi_client_bin():
    b = _build_ssi_client()
    if b is None:
        pytest.skip("libXrdSsi client tooling unavailable (no headers/lib/g++)")
    return b


class TestSsiRealClient:
    """A real libXrdSsi client (stock XRootD client stack) round-trips against
    the nginx module — the definitive interop proof."""

    def _run(self, client_bin, port, resource, request):
        r = subprocess.run([client_bin, f"{HOST}:{port}", resource, request],
                           capture_output=True, text=True, timeout=30,
                           env={**os.environ, "XRD_LOGLEVEL": "Error"})
        return r.returncode, r.stdout.strip(), r.stderr.strip()

    def test_real_client_echo(self, ssi_server, ssi_client_bin):
        rc, out, err = self._run(ssi_client_bin, ssi_server, "/.ssi/echo",
                                 "hello from real client")
        assert rc == 0, f"real SSI client failed: {out} {err}"
        assert "resp=hello from real client" in out, f"unexpected: {out!r}"

    def test_real_client_metadata(self, ssi_server, ssi_client_bin):
        rc, out, err = self._run(ssi_client_bin, ssi_server, "/.ssi/meta",
                                 "payload-xyz")
        assert rc == 0, f"real SSI client failed: {out} {err}"
        assert "resp=payload-xyz" in out, f"unexpected resp: {out!r}"
        assert "meta=ssi-meta" in out, f"metadata not delivered: {out!r}"

    def test_real_client_stream(self, ssi_server, ssi_client_bin):
        rc, out, err = self._run(ssi_client_bin, ssi_server, "/.ssi/stream",
                                 "go")
        assert rc == 0, f"real SSI stream client failed: {out} {err}"
        assert "resp=part-A|part-B|part-C" in out, f"stream mismatch: {out!r}"

    def test_real_client_error(self, ssi_server, ssi_client_bin):
        rc, out, err = self._run(ssi_client_bin, ssi_server, "/.ssi/err", "x")
        assert rc != 0, f"err service should fail the request: {out}"
        assert "rejected" in out, f"error text not delivered: {out!r}"
