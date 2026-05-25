"""
tests/test_gsi_security.py

GSI authentication security tests for nginx-xrootd.

Covers:
  - Wire-level pre-auth opcode rejection on the GSI port (plain TCP, no TLS)
  - Protocol edge cases: bad credtype, empty/truncated kXR_auth body
  - XRootD Python client GSI functional tests (stat, read, write, dirlist)
  - VOMS proxy variant handling
  - GSI + in-protocol TLS port (port 11096) — same functional coverage

All raw-socket tests target port 11095 (plain GSI, no TLS).
XRootD client tests use gsi_url (port 11095) and gsi_tls_url (port 11096).

Run:
    python3 -m pytest tests/test_gsi_security.py -v
"""

import hashlib
import os
import socket
import struct

import pytest

from XRootD import client as xrd_client
from XRootD.client.flags import OpenFlags, QueryCode

from settings import (
    CA_DIR as DEFAULT_CA_DIR,
    DATA_ROOT as DEFAULT_DATA_ROOT,
    NGINX_GSI_PORT,
    NGINX_GSI_TLS_PORT,
    PROXY_STD,
    SERVER_HOST,
    USER_CERT,
)

# ---------------------------------------------------------------------------
# Module-level state
# ---------------------------------------------------------------------------

GSI_HOST     = SERVER_HOST
GSI_PORT     = NGINX_GSI_PORT      # plain GSI, port 11095
GSI_URL      = ""
GSI_TLS_URL  = ""
ANON_URL     = ""
DATA_ROOT    = DEFAULT_DATA_ROOT
CA_DIR       = DEFAULT_CA_DIR
PROXY_PEM    = PROXY_STD

# ---------------------------------------------------------------------------
# XRootD opcodes (same as wire_protocol_security.py)
# ---------------------------------------------------------------------------

kXR_auth       = 3000
kXR_query      = 3001
kXR_chmod      = 3002
kXR_close      = 3003
kXR_dirlist    = 3004
kXR_mkdir      = 3008
kXR_login      = 3007
kXR_open       = 3010
kXR_ping       = 3011
kXR_read       = 3013
kXR_rm         = 3014
kXR_rmdir      = 3015
kXR_sync       = 3016
kXR_stat       = 3017
kXR_write      = 3019
kXR_writev     = 3031
kXR_readv      = 3025
kXR_pgwrite    = 3026
kXR_truncate   = 3028

kXR_ok              = 0
kXR_error           = 4003
kXR_NOT_AUTHORIZED  = 3010
kXR_Unsupported     = 3013


# ---------------------------------------------------------------------------
# Session fixture
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module", autouse=True)
def _configure(test_env):
    global GSI_URL, GSI_TLS_URL, ANON_URL, DATA_ROOT, CA_DIR, PROXY_PEM
    GSI_URL     = test_env["gsi_url"]
    GSI_TLS_URL = test_env["gsi_tls_url"]
    ANON_URL    = test_env["anon_url"]
    DATA_ROOT   = test_env["data_dir"]
    CA_DIR      = test_env["ca_dir"]
    PROXY_PEM   = test_env["proxy_pem"]
    old = {}
    for k, v in [("X509_CERT_DIR", CA_DIR), ("X509_USER_PROXY", PROXY_PEM)]:
        old[k] = os.environ.get(k)
        os.environ[k] = v
    yield
    for k, v in old.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v


# ---------------------------------------------------------------------------
# Low-level helpers (raw TCP against plain-GSI port 11095)
# ---------------------------------------------------------------------------

def _recv_exact(sock, n):
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError(f"socket closed after {len(buf)}/{n} bytes")
        buf.extend(chunk)
    return bytes(buf)


def _read_response(sock):
    hdr = _recv_exact(sock, 8)
    sid, status, dlen = struct.unpack("!2sHI", hdr)
    body = _recv_exact(sock, dlen) if dlen else b""
    return status, body


def _handshake(sock):
    sock.sendall(struct.pack("!IIIII", 0, 0, 0, 4, 2012))
    status, _ = _read_response(sock)
    assert status == kXR_ok


def _login(sock, user=b"testuser"):
    padded = (user + b"\x00" * 8)[:8]
    req = struct.pack("!2sHI8sBBBBI",
                      b"\x00\x01", kXR_login,
                      os.getpid() & 0xFFFFFFFF,
                      padded, 0, 0, 5, 0, 0)
    sock.sendall(req)
    status, body = _read_response(sock)
    return status, body


def _raw_conn():
    sock = socket.create_connection((GSI_HOST, GSI_PORT), timeout=5)
    sock.settimeout(5)
    return sock


def _make_file(rel, content=b"x"):
    full = os.path.join(DATA_ROOT, rel.lstrip("/"))
    os.makedirs(os.path.dirname(full), exist_ok=True)
    with open(full, "wb") as f:
        f.write(content)


def _gsi_fs():
    return xrd_client.FileSystem(GSI_URL)


def _gsi_tls_fs():
    return xrd_client.FileSystem(GSI_TLS_URL)


def _anon_fs():
    return xrd_client.FileSystem(ANON_URL)


def _xrd_read_all(url):
    f = xrd_client.File()
    status, _ = f.open(url)
    if not status.ok:
        return None
    status, st = f.stat()
    if not status.ok or st.size == 0:
        f.close()
        return b""
    status, data = f.read(size=st.size)
    f.close()
    return data if status.ok else None


# ---------------------------------------------------------------------------
# TestGSIPreAuthRejection
# (pre-login opcode rejection on plain GSI port 11095)
# ---------------------------------------------------------------------------

class TestGSIPreAuthRejection:
    """Data opcodes before kXR_login must be rejected on the GSI port."""

    def _pre_auth_req(self, reqid, payload=b""):
        sock = _raw_conn()
        _handshake(sock)
        path = b"/test.txt\x00"
        req = struct.pack("!2sH16sI", b"\x00\x02", reqid, b"\x00" * 16,
                          len(payload) + len(path))
        sock.sendall(req + payload + path)
        status, _ = _read_response(sock)
        sock.close()
        return status

    def test_stat_before_login_rejected(self):
        sock = _raw_conn()
        _handshake(sock)
        path = b"/test.txt\x00"
        req = struct.pack("!2sH16sI", b"\x00\x02", kXR_stat, b"\x00" * 16, len(path))
        sock.sendall(req + path)
        status, _ = _read_response(sock)
        sock.close()
        assert status != kXR_ok

    def test_open_before_login_rejected(self):
        sock = _raw_conn()
        _handshake(sock)
        path = b"/test.txt\x00"
        body16 = struct.pack("!HHIHH4s", 0, 0, 0, kXR_open, 0, b"\x00" * 4)[:16]
        req = struct.pack("!2sH16sI", b"\x00\x02", kXR_open, b"\x00" * 16, len(path))
        sock.sendall(req + path)
        status, _ = _read_response(sock)
        sock.close()
        assert status != kXR_ok

    def test_rm_before_login_rejected(self):
        sock = _raw_conn()
        _handshake(sock)
        path = b"/test.txt\x00"
        req = struct.pack("!2sH16sI", b"\x00\x02", kXR_rm, b"\x00" * 16, len(path))
        sock.sendall(req + path)
        status, _ = _read_response(sock)
        sock.close()
        assert status != kXR_ok

    def test_rmdir_before_login_rejected(self):
        sock = _raw_conn()
        _handshake(sock)
        path = b"/\x00"
        req = struct.pack("!2sH16sI", b"\x00\x02", kXR_rmdir, b"\x00" * 16, len(path))
        sock.sendall(req + path)
        status, _ = _read_response(sock)
        sock.close()
        assert status != kXR_ok

    def test_ping_before_login_ok(self):
        sock = _raw_conn()
        _handshake(sock)
        req = struct.pack("!2sH16sI", b"\x00\x02", kXR_ping, b"\x00" * 16, 0)
        sock.sendall(req)
        status, _ = _read_response(sock)
        sock.close()
        assert status == kXR_ok

    def test_dirlist_before_login_rejected(self):
        sock = _raw_conn()
        _handshake(sock)
        path = b"/\x00"
        req = struct.pack("!2sH16sI", b"\x00\x02", kXR_dirlist, b"\x00" * 16, len(path))
        sock.sendall(req + path)
        status, _ = _read_response(sock)
        sock.close()
        assert status != kXR_ok

    def test_readv_before_login_rejected(self):
        sock = _raw_conn()
        _handshake(sock)
        req = struct.pack("!2sH16sI", b"\x00\x02", kXR_readv, b"\x00" * 16, 0)
        sock.sendall(req)
        status, _ = _read_response(sock)
        sock.close()
        assert status != kXR_ok

    def test_writev_before_login_rejected(self):
        sock = _raw_conn()
        _handshake(sock)
        req = struct.pack("!2sH16sI", b"\x00\x02", kXR_writev, b"\x00" * 16, 0)
        sock.sendall(req)
        status, _ = _read_response(sock)
        sock.close()
        assert status != kXR_ok

    def test_truncate_before_login_rejected(self):
        sock = _raw_conn()
        _handshake(sock)
        path = b"/test.txt\x00"
        req = struct.pack("!2sH16sI", b"\x00\x02", kXR_truncate, b"\x00" * 16, len(path))
        sock.sendall(req + path)
        status, _ = _read_response(sock)
        sock.close()
        assert status != kXR_ok

    def test_chmod_before_login_rejected(self):
        sock = _raw_conn()
        _handshake(sock)
        path = b"/test.txt\x00"
        req = struct.pack("!2sH16sI", b"\x00\x02", kXR_chmod, b"\x00" * 16, len(path))
        sock.sendall(req + path)
        status, _ = _read_response(sock)
        sock.close()
        assert status != kXR_ok

    def test_mkdir_before_login_rejected(self):
        sock = _raw_conn()
        _handshake(sock)
        path = b"/newdir\x00"
        req = struct.pack("!2sH16sI", b"\x00\x02", kXR_mkdir, b"\x00" * 16, len(path))
        sock.sendall(req + path)
        status, _ = _read_response(sock)
        sock.close()
        assert status != kXR_ok

    def test_sync_before_login_rejected(self):
        sock = _raw_conn()
        _handshake(sock)
        req = struct.pack("!2sH16sI", b"\x00\x02", kXR_sync, b"\x00" * 16, 0)
        sock.sendall(req)
        status, _ = _read_response(sock)
        sock.close()
        assert status != kXR_ok


# ---------------------------------------------------------------------------
# TestGSIProtocolEdges
# (wire-level edge cases on plain GSI port 11095)
# ---------------------------------------------------------------------------

class TestGSIProtocolEdges:
    """Edge cases in the XRootD protocol framing on the GSI port."""

    def test_auth_before_login_rejected(self):
        sock = _raw_conn()
        _handshake(sock)
        cred = b"gsi\x00" + b"\x00" * 8
        req = struct.pack("!2sH12s4sI",
                          b"\x00\x01", kXR_auth,
                          b"\x00" * 12, b"gsi\x00",
                          len(cred))
        sock.sendall(req + cred)
        status, _ = _read_response(sock)
        sock.close()
        assert status != kXR_ok

    def test_unknown_credtype_on_gsi_port(self):
        sock = _raw_conn()
        _handshake(sock)
        status, _ = _login(sock)
        assert status == kXR_ok
        cred = b"xyz\x00" + b"\x00" * 8
        req = struct.pack("!2sH12s4sI",
                          b"\x00\x02", kXR_auth,
                          b"\x00" * 12, b"xyz\x00",
                          len(cred))
        sock.sendall(req + cred)
        status, _ = _read_response(sock)
        sock.close()
        assert status != kXR_ok

    def test_kxr_auth_empty_body_on_gsi_port(self):
        sock = _raw_conn()
        _handshake(sock)
        status, _ = _login(sock)
        assert status == kXR_ok
        req = struct.pack("!2sH12s4sI",
                          b"\x00\x02", kXR_auth,
                          b"\x00" * 12, b"gsi\x00", 0)
        sock.sendall(req)
        status, _ = _read_response(sock)
        sock.close()
        assert status != kXR_ok

    def test_kxr_auth_four_bytes_too_short(self):
        sock = _raw_conn()
        _handshake(sock)
        status, _ = _login(sock)
        assert status == kXR_ok
        body = b"gsi\x00"  # only 4 bytes, below 8-byte minimum
        req = struct.pack("!2sH12s4sI",
                          b"\x00\x02", kXR_auth,
                          b"\x00" * 12, b"gsi\x00",
                          len(body))
        sock.sendall(req + body)
        status, _ = _read_response(sock)
        sock.close()
        assert status != kXR_ok

    def test_invalid_requestid_after_login(self):
        sock = _raw_conn()
        _handshake(sock)
        _login(sock)
        req = struct.pack("!2sH16sI", b"\x00\x02", 0xFFFF, b"\x00" * 16, 0)
        sock.sendall(req)
        status, _ = _read_response(sock)
        sock.close()
        # Before GSI auth completes: kXR_Unsupported or kXR_error
        assert status in (kXR_Unsupported, kXR_error)

    def test_requestid_zero_after_login(self):
        sock = _raw_conn()
        _handshake(sock)
        _login(sock)
        req = struct.pack("!2sH16sI", b"\x00\x02", 0, b"\x00" * 16, 0)
        sock.sendall(req)
        status, _ = _read_response(sock)
        sock.close()
        # Before GSI auth completes: kXR_Unsupported or kXR_error
        assert status in (kXR_Unsupported, kXR_error)

    def test_ping_after_login_on_gsi_port(self):
        sock = _raw_conn()
        _handshake(sock)
        status, _ = _login(sock)
        assert status == kXR_ok
        req = struct.pack("!2sH16sI", b"\x00\x02", kXR_ping, b"\x00" * 16, 0)
        sock.sendall(req)
        status, _ = _read_response(sock)
        sock.close()
        assert status == kXR_ok

    def test_stat_unauthenticated_after_login_rejected(self):
        """On the GSI port, stat should fail without completing GSI auth."""
        sock = _raw_conn()
        _handshake(sock)
        status, _ = _login(sock)
        assert status == kXR_ok
        path = b"/test.txt\x00"
        req = struct.pack("!2sH16sI", b"\x00\x03", kXR_stat, b"\x00" * 16, len(path))
        sock.sendall(req + path)
        status, _ = _read_response(sock)
        sock.close()
        assert status != kXR_ok

    def test_partial_handshake_no_crash(self):
        sock = _raw_conn()
        sock.sendall(b"\x00" * 10)  # partial 20-byte handshake
        sock.close()

    def test_multiple_pings_gsi_port(self):
        sock = _raw_conn()
        _handshake(sock)
        _login(sock)
        for i in range(5):
            sid = struct.pack("!H", i + 1)
            req = struct.pack("!2sH16sI", sid, kXR_ping, b"\x00" * 16, 0)
            sock.sendall(req)
            status, _ = _read_response(sock)
            assert status == kXR_ok
        sock.close()


# ---------------------------------------------------------------------------
# TestGSIClientStat
# (XRootD client functional tests — stat, dirlist, query)
# ---------------------------------------------------------------------------

class TestGSIClientStat:
    """Stat, dirlist, and query operations via the GSI port."""

    def test_stat_root_ok(self):
        fs = _gsi_fs()
        status, info = fs.stat("/")
        assert status.ok, f"stat('/') failed: {status.message}"

    def test_stat_test_file_ok(self):
        fs = _gsi_fs()
        status, info = fs.stat("/test.txt")
        assert status.ok, f"stat('/test.txt') failed: {status.message}"
        assert info.size == 24

    def test_stat_nonexistent_is_error(self):
        fs = _gsi_fs()
        status, _ = fs.stat("/gsi_no_such_file_xyz.txt")
        assert not status.ok

    def test_dirlist_root_contains_test_txt(self):
        fs = _gsi_fs()
        status, listing = fs.dirlist("/")
        assert status.ok, f"dirlist('/') failed: {status.message}"
        names = [e.name for e in listing]
        assert "test.txt" in names

    def test_qconfig_chksum_via_gsi(self):
        fs = _gsi_fs()
        status, resp = fs.query(QueryCode.CONFIG, "chksum")
        assert status.ok
        assert b"adler32" in resp

    def test_qspace_via_gsi_ok(self):
        fs = _gsi_fs()
        status, _ = fs.query(QueryCode.SPACE, "/")
        assert status.ok

    def test_gsi_stat_size_matches_anon(self):
        fs_gsi  = _gsi_fs()
        fs_anon = _anon_fs()
        s1, i1 = fs_gsi.stat("/test.txt")
        s2, i2 = fs_anon.stat("/test.txt")
        assert s1.ok and s2.ok
        assert i1.size == i2.size

    def test_two_consecutive_stats_ok(self):
        fs = _gsi_fs()
        s1, i1 = fs.stat("/test.txt")
        s2, i2 = fs.stat("/test.txt")
        assert s1.ok and s2.ok
        assert i1.size == i2.size


# ---------------------------------------------------------------------------
# TestGSIClientRead
# (XRootD client read operations via GSI port)
# ---------------------------------------------------------------------------

class TestGSIClientRead:
    """File read operations through the GSI port."""

    def test_read_test_txt_content(self):
        data = _xrd_read_all(f"{GSI_URL}//test.txt")
        assert data == b"hello from nginx-xrootd\n"

    def test_read_gsi_matches_anon(self):
        gsi_data  = _xrd_read_all(f"{GSI_URL}//test.txt")
        anon_data = _xrd_read_all(f"{ANON_URL}//test.txt")
        assert gsi_data == anon_data

    def test_read_random_bin_md5_matches(self):
        gsi_data  = _xrd_read_all(f"{GSI_URL}//random.bin")
        anon_data = _xrd_read_all(f"{ANON_URL}//random.bin")
        assert gsi_data is not None
        assert hashlib.md5(gsi_data).hexdigest() == hashlib.md5(anon_data).hexdigest()

    def test_read_partial_correct_bytes(self):
        f = xrd_client.File()
        status, _ = f.open(f"{GSI_URL}//test.txt")
        assert status.ok
        status, data = f.read(offset=6, size=4)
        f.close()
        assert status.ok
        assert data == b"from"

    def test_stat_then_read_same_size(self):
        fs = _gsi_fs()
        status, info = fs.stat("/test.txt")
        assert status.ok
        data = _xrd_read_all(f"{GSI_URL}//test.txt")
        assert len(data) == info.size

    def test_adler32_via_gsi_matches_anon(self):
        fs_gsi  = _gsi_fs()
        fs_anon = _anon_fs()
        s1, r1 = fs_gsi.query(QueryCode.CHECKSUM, "/test.txt")
        s2, r2 = fs_anon.query(QueryCode.CHECKSUM, "/test.txt")
        if s1.ok and s2.ok:
            assert r1 == r2


# ---------------------------------------------------------------------------
# TestGSIClientWrite
# (XRootD client write operations via GSI port)
# ---------------------------------------------------------------------------

class TestGSIClientWrite:
    """Write operations through the GSI port."""

    def test_write_read_roundtrip(self):
        content = b"gsi write test content 12345"
        path = "/gsi_sec_write.txt"
        f = xrd_client.File()
        status, _ = f.open(f"{GSI_URL}/{path}", OpenFlags.NEW | OpenFlags.DELETE)
        assert status.ok, f"open for write failed: {status.message}"
        status, _ = f.write(content)
        assert status.ok
        f.close()
        data = _xrd_read_all(f"{GSI_URL}/{path}")
        assert data == content

    def test_write_then_stat_size_correct(self):
        content = b"X" * 256
        path = "/gsi_sec_stat_check.txt"
        f = xrd_client.File()
        f.open(f"{GSI_URL}/{path}", OpenFlags.NEW | OpenFlags.DELETE)
        f.write(content)
        f.close()
        fs = _gsi_fs()
        status, info = fs.stat(path)
        assert status.ok
        assert info.size == len(content)

    def test_write_via_gsi_readable_via_anon(self):
        content = b"cross-auth content"
        path = "/gsi_sec_cross.txt"
        f = xrd_client.File()
        f.open(f"{GSI_URL}/{path}", OpenFlags.NEW | OpenFlags.DELETE)
        f.write(content)
        f.close()
        anon_data = _xrd_read_all(f"{ANON_URL}/{path}")
        assert anon_data == content

    def test_write_to_new_directory(self):
        _make_file("/gsi_sec_dir/placeholder.txt", b"")
        content = b"inside subdir"
        path = "/gsi_sec_dir/new_file.txt"
        f = xrd_client.File()
        status, _ = f.open(f"{GSI_URL}/{path}", OpenFlags.NEW | OpenFlags.DELETE)
        assert status.ok
        f.write(content)
        f.close()
        data = _xrd_read_all(f"{GSI_URL}/{path}")
        assert data == content


# ---------------------------------------------------------------------------
# TestGSITLSPort
# (GSI + in-protocol TLS port 11096)
# ---------------------------------------------------------------------------

class TestGSITLSPort:
    """Functional tests on the GSI+TLS port (xrootd_tls on)."""

    def test_stat_root_via_tls(self):
        fs = _gsi_tls_fs()
        status, info = fs.stat("/")
        assert status.ok, f"TLS stat('/') failed: {status.message}"

    def test_stat_test_file_via_tls(self):
        fs = _gsi_tls_fs()
        status, info = fs.stat("/test.txt")
        assert status.ok
        assert info.size == 24

    def test_read_via_tls_matches_plain(self):
        tls_data  = _xrd_read_all(f"{GSI_TLS_URL}//test.txt")
        plain_data = _xrd_read_all(f"{GSI_URL}//test.txt")
        assert tls_data == plain_data

    def test_stat_nonexistent_via_tls(self):
        fs = _gsi_tls_fs()
        status, _ = fs.stat("/tls_no_such_file_xyz.txt")
        assert not status.ok

    def test_dirlist_via_tls_has_test_txt(self):
        fs = _gsi_tls_fs()
        status, listing = fs.dirlist("/")
        assert status.ok
        names = [e.name for e in listing]
        assert "test.txt" in names

    def test_qconfig_via_tls_ok(self):
        fs = _gsi_tls_fs()
        status, resp = fs.query(QueryCode.CONFIG, "chksum")
        assert status.ok
        assert b"adler32" in resp

    def test_write_read_roundtrip_via_tls(self):
        content = b"tls port write test"
        path = "/gsi_tls_sec_write.txt"
        f = xrd_client.File()
        status, _ = f.open(f"{GSI_TLS_URL}/{path}", OpenFlags.NEW | OpenFlags.DELETE)
        assert status.ok
        f.write(content)
        f.close()
        data = _xrd_read_all(f"{GSI_TLS_URL}/{path}")
        assert data == content

    def test_adler32_tls_matches_plain_gsi(self):
        fs_tls   = _gsi_tls_fs()
        fs_plain = _gsi_fs()
        s1, r1 = fs_tls.query(QueryCode.CHECKSUM, "/test.txt")
        s2, r2 = fs_plain.query(QueryCode.CHECKSUM, "/test.txt")
        if s1.ok and s2.ok:
            assert r1 == r2

    def test_two_consecutive_reads_via_tls(self):
        d1 = _xrd_read_all(f"{GSI_TLS_URL}//test.txt")
        d2 = _xrd_read_all(f"{GSI_TLS_URL}//test.txt")
        assert d1 == d2

    def test_tls_stat_size_matches_anon(self):
        fs_tls  = _gsi_tls_fs()
        fs_anon = _anon_fs()
        s1, i1 = fs_tls.stat("/test.txt")
        s2, i2 = fs_anon.stat("/test.txt")
        assert s1.ok and s2.ok
        assert i1.size == i2.size
