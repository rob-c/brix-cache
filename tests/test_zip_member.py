"""Server-side root:// ZIP member access (phase-57 W2): ?xrdcl.unzip=<member>.

Self-contained: starts its own nginx (xrootd_zip_access on) over an export dir
containing a real ZIP archive.

IMPORTANT: the native/stock XrdCl client handles xrdcl.unzip CLIENT-SIDE (it
reads the archive's central directory + member bytes and inflates locally), so a
native xrdcp never exercises the SERVER member path. These tests therefore drive
the server with a raw wire client (kXR_open with the opaque + kXR_read), which is
exactly the path a non-plugin client / HTTP gateway reuse needs. Stored members
are served by offset translation; deflate members are rejected for now
(kXR_Unsupported) pending the streaming-inflate follow-up.
"""
import os
import socket
import struct
import subprocess
import time
import zipfile
from pathlib import Path

import pytest
import requests

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NGINX_BIN = "/tmp/nginx-1.28.3/objs/nginx"
XRDCP = os.path.join(REPO, "client", "bin", "xrdcp")

STORED = b"hello stored member\n"
DEFL = bytes((i * 31 + 7) & 0xFF for i in range(100000))

kXR_login, kXR_open, kXR_read, kXR_close = 3007, 3010, 3013, 3003
kXR_ok, kXR_open_read = 0, 0x0010
PORT = 21196        # root:// stream
HTTP_PORT = 21198   # WebDAV/HTTP
S3_PORT = 21199     # S3 REST
S3_BUCKET = "zipbucket"


def _run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=60, **kw)


def _wait_listen(port, tries=80):
    for _ in range(tries):
        if _run(["bash", "-c", f"ss -tln | grep -q ':{port} '"]).returncode == 0:
            return True
        time.sleep(0.1)
    return False


# ---- compact raw-wire client (parameterised by port) ----

def _recv_exact(sock, n):
    buf = bytearray()
    while len(buf) < n:
        c = sock.recv(n - len(buf))
        if not c:
            raise ConnectionError("closed")
        buf.extend(c)
    return bytes(buf)


def _resp(sock):
    sid, status, dlen = struct.unpack("!2sHI", _recv_exact(sock, 8))
    return status, (_recv_exact(sock, dlen) if dlen else b"")


def _session(port):
    s = socket.create_connection(("127.0.0.1", port), timeout=8)
    s.settimeout(8)
    s.sendall(struct.pack("!IIIII", 0, 0, 0, 4, 2012))   # handshake
    assert _resp(s)[0] == kXR_ok
    login = struct.pack("!2sHI8sBBBBI", b"\x00\x01", kXR_login,
                        os.getpid() & 0xFFFFFFFF, b"pytest\x00\x00", 0, 0, 5, 0, 0)
    s.sendall(login)
    assert _resp(s)[0] == kXR_ok
    return s


def _open(sock, path):
    p = path.encode() + b"\x00"
    req = struct.pack("!2sHHH2s6s4sI", b"\x00\x02", kXR_open, 0o644,
                      kXR_open_read, b"\x00\x00", b"\x00" * 6, b"\x00" * 4, len(p))
    sock.sendall(req + p)
    return _resp(sock)


def _read(sock, fhandle, offset, rlen):
    req = struct.pack("!2sH4sqiI", b"\x00\x06", kXR_read, fhandle,
                      offset, rlen, 0)
    sock.sendall(req)
    return _resp(sock)


def _read_all(sock, fhandle, total):
    out = bytearray()
    off = 0
    while off < total:
        st, data = _read(sock, fhandle, off, 65536)
        if st != kXR_ok:
            return st, bytes(out)
        if not data:
            break
        out.extend(data)
        off += len(data)
    return kXR_ok, bytes(out)


@pytest.fixture(scope="module")
def zipsrv(tmp_path_factory):
    if not os.path.exists(NGINX_BIN):
        pytest.skip("nginx binary not built")
    base = tmp_path_factory.mktemp("zipmember")
    data, logs = base / "data", base / "logs"
    data.mkdir(); logs.mkdir()
    with zipfile.ZipFile(data / "a.zip", "w") as z:
        z.writestr("stored.txt", STORED, compress_type=zipfile.ZIP_STORED)
        zi = zipfile.ZipInfo("sub/defl.bin"); zi.compress_type = zipfile.ZIP_DEFLATED
        z.writestr(zi, DEFL)
    cfg = base / "nginx.conf"
    cfg.write_text(
        "daemon off;\nworker_processes 1;\n"
        f"error_log {logs}/err.log info;\npid {base}/nginx.pid;\n"
        "events { worker_connections 64; }\n"
        f"stream {{ server {{ listen 127.0.0.1:{PORT}; xrootd on; "
        f"xrootd_storage_backend posix:{data}; xrootd_auth none; xrootd_zip_access on; "
        f"xrootd_access_log {logs}/access.log; }} }}\n"
        "http {\n"
        f"  server {{ listen 127.0.0.1:{HTTP_PORT};\n"
        "    location / {\n"
        "      xrootd_webdav on;\n"
        f"      xrootd_webdav_storage_backend posix:{data};\n"
        "      xrootd_webdav_auth none;\n"
        "      xrootd_webdav_zip_access on;\n"
        "    }\n  }\n"
        f"  server {{ listen 127.0.0.1:{S3_PORT};\n"
        "    location / {\n"
        "      xrootd_s3 on;\n"
        f"      xrootd_s3_storage_backend posix:{data};\n"
        f"      xrootd_s3_bucket {S3_BUCKET};\n"
        "      xrootd_s3_zip_access on;\n"
        "    }\n  }\n}\n")
    _run(["bash", "-c", f"fuser -k {PORT}/tcp 2>/dev/null"])
    proc = subprocess.Popen([NGINX_BIN, "-c", str(cfg), "-p", str(base)],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if (not _wait_listen(PORT) or not _wait_listen(HTTP_PORT)
            or not _wait_listen(S3_PORT)):
        proc.terminate(); pytest.skip("zip nginx did not come up")
    yield {"base": str(base), "data": str(data)}
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()


# ---- raw-wire tests: exercise the SERVER member path ----

def test_server_stored_member_read(zipsrv):
    s = _session(PORT)
    st, body = _open(s, "/a.zip?xrdcl.unzip=stored.txt")
    assert st == kXR_ok, f"open failed status={st}"
    fh = body[:4]
    st, data = _read(s, fh, 0, 65536)
    assert st == kXR_ok
    assert data == STORED
    s.close()


def test_server_stored_member_offset_read(zipsrv):
    s = _session(PORT)
    st, body = _open(s, "/a.zip?xrdcl.unzip=stored.txt")
    assert st == kXR_ok
    st, data = _read(s, body[:4], 6, 6)        # "stored" at offset 6
    assert st == kXR_ok and data == STORED[6:12]
    s.close()


def test_server_missing_member_rejected(zipsrv):
    s = _session(PORT)
    st, _ = _open(s, "/a.zip?xrdcl.unzip=nope.txt")
    assert st != kXR_ok               # kXR_NotFound
    s.close()


@pytest.mark.parametrize("evil", ["../../etc/passwd", "/etc/passwd", "a/../../x"])
def test_server_member_traversal_rejected(zipsrv, evil):
    s = _session(PORT)
    st, _ = _open(s, f"/a.zip?xrdcl.unzip={evil}")
    assert st != kXR_ok
    s.close()


def test_server_deflate_member_full_read(zipsrv):
    # Streaming raw inflate: the whole deflate member round-trips byte-exact.
    s = _session(PORT)
    st, body = _open(s, "/a.zip?xrdcl.unzip=sub/defl.bin")
    assert st == kXR_ok, "deflate member open should succeed"
    st, data = _read_all(s, body[:4], len(DEFL))
    assert st == kXR_ok
    assert data == DEFL
    s.close()


def test_server_deflate_member_seeks(zipsrv):
    # Forward seek then backward seek (forces re-inflate from start).
    s = _session(PORT)
    st, body = _open(s, "/a.zip?xrdcl.unzip=sub/defl.bin")
    assert st == kXR_ok
    fh = body[:4]
    st, d1 = _read(s, fh, 50000, 1000)        # forward seek
    assert st == kXR_ok and d1 == DEFL[50000:51000]
    st, d2 = _read(s, fh, 10, 20)             # backward seek
    assert st == kXR_ok and d2 == DEFL[10:30]
    s.close()


# ---- HTTP/WebDAV GET member tests (server MUST extract — no client-side unzip) ----

def _http(member, **kw):
    return requests.get(f"http://127.0.0.1:{HTTP_PORT}/a.zip",
                        params={"xrdcl.unzip": member}, timeout=15, **kw)


def test_http_stored_member(zipsrv):
    r = _http("stored.txt")
    assert r.status_code == 200
    assert r.content == STORED


def test_http_deflate_member(zipsrv):
    r = _http("sub/defl.bin")
    assert r.status_code == 200
    assert r.content == DEFL


def test_http_missing_member_404(zipsrv):
    assert _http("nope.txt").status_code == 404


@pytest.mark.parametrize("evil", ["../../etc/passwd", "/etc/passwd"])
def test_http_member_traversal_rejected(zipsrv, evil):
    assert _http(evil).status_code in (400, 404)


def test_http_stored_member_range(zipsrv):
    r = _http("stored.txt", headers={"Range": "bytes=6-11"})
    assert r.status_code == 206
    assert r.content == STORED[6:12]
    assert r.headers.get("Content-Range") == f"bytes 6-11/{len(STORED)}"


def test_http_deflate_member_range(zipsrv):
    r = _http("sub/defl.bin", headers={"Range": "bytes=50000-50999"})
    assert r.status_code == 206
    assert r.content == DEFL[50000:51000]


# ---- S3 GetObject member tests (server MUST extract) ----

def _s3(member, **kw):
    return requests.get(f"http://127.0.0.1:{S3_PORT}/{S3_BUCKET}/a.zip",
                        params={"xrdcl.unzip": member}, timeout=15, **kw)


def test_s3_stored_member(zipsrv):
    r = _s3("stored.txt")
    assert r.status_code == 200
    assert r.content == STORED


def test_s3_deflate_member(zipsrv):
    r = _s3("sub/defl.bin")
    assert r.status_code == 200
    assert r.content == DEFL


def test_s3_missing_member_404(zipsrv):
    assert _s3("nope.txt").status_code == 404


def test_s3_stored_member_range(zipsrv):
    r = _s3("stored.txt", headers={"Range": "bytes=6-11"})
    assert r.status_code == 206
    assert r.content == STORED[6:12]


def test_native_client_does_clientside_unzip(zipsrv, tmp_path):
    """Interop: the native client inflates the member locally (server serves the
    archive bytes), so a deflate member round-trips even though the server-side
    deflate read is not yet implemented. Documents the client-side behavior."""
    if not os.path.exists(XRDCP):
        pytest.skip("native xrdcp not built")
    out = str(tmp_path / "got")
    r = _run([XRDCP, "-f", "-s",
              f"root://127.0.0.1:{PORT}//a.zip?xrdcl.unzip=stored.txt", out])
    assert r.returncode == 0 and Path(out).read_bytes() == STORED
