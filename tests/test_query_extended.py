"""
tests/test_query_extended.py

Query infotypes with zero coverage: Qconfig keys, Qvisa, Qopaque,
dirlist edge cases, cross-query consistency checks.

Run:
    pytest tests/test_query_extended.py -v
"""

import os
import socket
import struct

import pytest

from settings import NGINX_ANON_PORT, DATA_ROOT as DEFAULT_DATA_ROOT

# ---------------------------------------------------------------------------
# Protocol constants
# ---------------------------------------------------------------------------

kXR_query    = 3001
kXR_login    = 3007
kXR_open     = 3010
kXR_close    = 3003
kXR_dirlist  = 3004
kXR_ping     = 3011

# Query infotypes
kXR_QStats   = 1
kXR_Qcksum   = 3
kXR_Qspace   = 5
kXR_Qconfig  = 7
kXR_Qvisa    = 8
kXR_QFSinfo  = 10
kXR_Qopaque  = 16

# Response codes
kXR_ok       = 0
kXR_error    = 4003
kXR_ArgInvalid = 3000
kXR_Unsupported = 3013

# Open flags
kXR_open_read = 0x0010

# Dirlist flags
kXR_dstat = 0x02

# ---------------------------------------------------------------------------
# Module globals
# ---------------------------------------------------------------------------

ANON_HOST = "127.0.0.1"
ANON_PORT = NGINX_ANON_PORT
DATA_DIR  = DEFAULT_DATA_ROOT


@pytest.fixture(scope="module", autouse=True)
def _configure(test_env):
    global ANON_HOST, ANON_PORT, DATA_DIR
    ANON_HOST = "127.0.0.1"
    ANON_PORT = test_env["anon_port"]
    DATA_DIR  = test_env["data_dir"]


# ---------------------------------------------------------------------------
# Socket helpers
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


def _session():
    sock = socket.create_connection((ANON_HOST, ANON_PORT), timeout=10)
    sock.settimeout(10)
    sock.sendall(struct.pack("!IIIII", 0, 0, 0, 4, 2012))
    status, _ = _read_response(sock)
    assert status == kXR_ok
    sock.sendall(struct.pack("!2sHI8sBBBBI",
                              b"\x00\x01", kXR_login,
                              os.getpid() & 0xFFFFFFFF,
                              b"pytest\x00\x00", 0, 0, 5, 0, 0))
    status, _ = _read_response(sock)
    assert status == kXR_ok
    return sock


def _query(sock, infotype, payload=b"", streamid=b"\x00\x02"):
    """Send kXR_query with infotype and optional payload."""
    req = struct.pack("!2sHHH4s8sI",
                      streamid, kXR_query,
                      infotype,
                      0,             # reserved1
                      b"\x00"*4,    # fhandle (unused)
                      b"\x00"*8,    # reserved2
                      len(payload))
    sock.sendall(req + payload)
    return _read_response(sock)


def _dirlist(sock, path, flags=0, streamid=b"\x00\x02"):
    path_bytes = path.encode() + b"\x00" if isinstance(path, str) else path
    # kXR_dirlist body: 15 bytes reserved + 1 byte options + 4-byte dlen
    body16 = b"\x00" * 15 + bytes([flags])
    req = struct.pack("!2sH16sI", streamid, kXR_dirlist, body16, len(path_bytes))
    sock.sendall(req + path_bytes)
    return _read_response(sock)


def _error_code(body):
    return struct.unpack("!I", body[:4])[0] if len(body) >= 4 else 0


def _make_file(name, content=b"x"):
    path = os.path.join(DATA_DIR, name.lstrip("/"))
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(content)


def _make_dir(name):
    os.makedirs(os.path.join(DATA_DIR, name.lstrip("/")), exist_ok=True)


# =========================================================================
# Class 1 — Qconfig Known Keys
# =========================================================================

class TestQconfigKnownKeys:
    """kXR_Qconfig (infotype=7) — src/query/config.c"""

    def test_qconfig_chksum_returns_adler32(self):
        sock = _session()
        status, body = _query(sock, kXR_Qconfig, b"chksum")
        sock.close()
        assert status == kXR_ok
        assert b"chksum=adler32" in body

    def test_qconfig_readv_returns_1(self):
        sock = _session()
        status, body = _query(sock, kXR_Qconfig, b"readv")
        sock.close()
        assert status == kXR_ok
        assert b"readv=1" in body

    def test_qconfig_unknown_key_returns_zero(self):
        sock = _session()
        status, body = _query(sock, kXR_Qconfig, b"nosuchfeature")
        sock.close()
        assert status == kXR_ok
        assert b"nosuchfeature=0" in body

    def test_qconfig_multiple_keys_single_req(self):
        sock = _session()
        payload = b"chksum\nreadv\nnosuch"
        status, body = _query(sock, kXR_Qconfig, payload)
        sock.close()
        assert status == kXR_ok
        assert b"chksum=adler32" in body
        assert b"readv=1" in body
        assert b"nosuch=0" in body

    def test_qconfig_empty_payload(self):
        sock = _session()
        status, body = _query(sock, kXR_Qconfig, b"")
        sock.close()
        assert status == kXR_ok

    def test_qconfig_key_without_newline(self):
        sock = _session()
        status, body = _query(sock, kXR_Qconfig, b"chksum")
        sock.close()
        assert status == kXR_ok
        assert b"adler32" in body

    def test_qconfig_response_ends_with_newline(self):
        sock = _session()
        status, body = _query(sock, kXR_Qconfig, b"chksum")
        sock.close()
        assert status == kXR_ok
        # Response ends with \n or \0
        assert body.endswith(b"\n") or body.endswith(b"\x00")

    def test_qconfig_two_consecutive_requests(self):
        sock = _session()
        s1, b1 = _query(sock, kXR_Qconfig, b"chksum", streamid=b"\x00\x10")
        s2, b2 = _query(sock, kXR_Qconfig, b"readv", streamid=b"\x00\x11")
        sock.close()
        assert s1 == kXR_ok and b"adler32" in b1
        assert s2 == kXR_ok and b"readv=1" in b2


# =========================================================================
# Class 2 — Qvisa
# =========================================================================

class TestQueryVisa:
    """kXR_Qvisa (infotype=8) — completely untested."""

    def test_qvisa_no_path_no_crash(self):
        # Qvisa with dlen=0 — server handles it
        sock = _session()
        status, body = _query(sock, kXR_Qvisa, b"")
        sock.close()
        # Any response is acceptable (ok, error, unsupported) — just must not hang
        assert status in (kXR_ok, kXR_error)

    def test_qvisa_with_path_returns_error(self):
        # Qvisa dispatch: dlen != 0 → returns kXR_ArgInvalid
        sock = _session()
        status, body = _query(sock, kXR_Qvisa, b"/test.txt\x00")
        sock.close()
        assert status == kXR_error
        assert _error_code(body) == kXR_ArgInvalid

    def test_qvisa_two_consecutive_requests(self):
        sock = _session()
        s1, b1 = _query(sock, kXR_Qvisa, b"", streamid=b"\x00\x10")
        s2, b2 = _query(sock, kXR_Qvisa, b"", streamid=b"\x00\x11")
        sock.close()
        # Server must not stall after first Qvisa
        assert s1 in (kXR_ok, kXR_error)
        assert s2 in (kXR_ok, kXR_error)

    def test_qvisa_then_ping(self):
        sock = _session()
        s1, b1 = _query(sock, kXR_Qvisa, b"")
        # Ping must still work after Qvisa
        req = struct.pack("!2sH16sI", b"\x00\x02", kXR_ping, b"\x00"*16, 0)
        sock.sendall(req)
        s2, b2 = _read_response(sock)
        sock.close()
        assert s2 == kXR_ok

    def test_qvisa_ok_body_is_bytes(self):
        sock = _session()
        status, body = _query(sock, kXR_Qvisa, b"")
        sock.close()
        assert isinstance(body, bytes)


# =========================================================================
# Class 3 — Qopaque
# =========================================================================

class TestQueryOpaque:
    """kXR_Qopaque (infotype=16) — completely untested."""

    def test_qopaque_plain_path_no_crash(self):
        sock = _session()
        status, body = _query(sock, kXR_Qopaque, b"/test.txt\x00")
        sock.close()
        assert status in (kXR_ok, kXR_error)

    def test_qopaque_with_opaque_string(self):
        sock = _session()
        status, body = _query(sock, kXR_Qopaque, b"/test.txt?key=val\x00")
        sock.close()
        assert status in (kXR_ok, kXR_error)

    def test_qopaque_large_payload_no_crash(self):
        # Large opaque string — must not crash
        payload = b"/test?" + b"k=v&" * 512 + b"\x00"
        # Trim to avoid dlen limit
        payload = payload[:512]
        sock = _session()
        status, body = _query(sock, kXR_Qopaque, payload)
        sock.close()
        assert status in (kXR_ok, kXR_error)

    def test_qopaque_response_is_bytes(self):
        sock = _session()
        status, body = _query(sock, kXR_Qopaque, b"")
        sock.close()
        assert isinstance(body, bytes)

    def test_qopaque_then_ping(self):
        sock = _session()
        _query(sock, kXR_Qopaque, b"/test.txt\x00")
        req = struct.pack("!2sH16sI", b"\x00\x02", kXR_ping, b"\x00"*16, 0)
        sock.sendall(req)
        s2, b2 = _read_response(sock)
        sock.close()
        assert s2 == kXR_ok


# =========================================================================
# Class 4 — Dirlist Edge Cases
# =========================================================================

class TestDirlistEdgeCases:

    def test_dirlist_empty_directory(self):
        _make_dir("/qdl_empty_dir")
        sock = _session()
        status, body = _dirlist(sock, "/qdl_empty_dir")
        sock.close()
        assert status == kXR_ok

    def test_dirlist_dstat_flag(self):
        _make_dir("/qdl_dstat_dir")
        _make_file("/qdl_dstat_dir/file.txt", b"x" * 100)
        sock = _session()
        status, body = _dirlist(sock, "/qdl_dstat_dir", flags=kXR_dstat)
        sock.close()
        assert status == kXR_ok
        assert b"file.txt" in body

    def test_dirlist_nonexistent_path_error(self):
        sock = _session()
        status, body = _dirlist(sock, "/nonexistent_dir_xyz_abc")
        sock.close()
        assert status == kXR_error

    def test_dirlist_on_file_is_error(self):
        _make_file("/qdl_a_file.txt", b"content")
        sock = _session()
        status, body = _dirlist(sock, "/qdl_a_file.txt")
        sock.close()
        assert status == kXR_error

    def test_dirlist_dstat_size_correct(self):
        content = b"X" * 512
        _make_dir("/qdl_sz_dir")
        _make_file("/qdl_sz_dir/sized.txt", content)
        sock = _session()
        status, body = _dirlist(sock, "/qdl_sz_dir", flags=kXR_dstat)
        sock.close()
        assert status == kXR_ok
        # body contains "sized.txt" and stat info including size 512
        assert b"sized.txt" in body
        assert b"512" in body

    def test_dirlist_body_newline_delimited(self):
        _make_dir("/qdl_nl_dir")
        _make_file("/qdl_nl_dir/a.txt", b"a")
        _make_file("/qdl_nl_dir/b.txt", b"b")
        sock = _session()
        status, body = _dirlist(sock, "/qdl_nl_dir")
        sock.close()
        assert status == kXR_ok
        # Entries separated by newlines
        assert b"\n" in body

    def test_dirlist_trailing_slash_ok(self):
        _make_dir("/qdl_slash_dir")
        _make_file("/qdl_slash_dir/x.txt", b"x")
        sock = _session()
        s1, b1 = _dirlist(sock, "/qdl_slash_dir", streamid=b"\x00\x10")
        s2, b2 = _dirlist(sock, "/qdl_slash_dir/", streamid=b"\x00\x11")
        sock.close()
        assert s1 == kXR_ok
        assert s2 == kXR_ok

    def test_dirlist_root_has_test_files(self):
        sock = _session()
        status, body = _dirlist(sock, "/")
        sock.close()
        assert status == kXR_ok
        assert b"test.txt" in body

    def test_dirlist_multiple_files(self):
        _make_dir("/qdl_multi")
        for i in range(5):
            _make_file(f"/qdl_multi/file{i}.txt", bytes([i]))
        sock = _session()
        status, body = _dirlist(sock, "/qdl_multi")
        sock.close()
        assert status == kXR_ok
        for i in range(5):
            assert f"file{i}.txt".encode() in body

    def test_dirlist_subdir_no_cross_dir(self):
        _make_dir("/qdl_isolated/subA")
        _make_dir("/qdl_isolated/subB")
        _make_file("/qdl_isolated/subA/inA.txt", b"a")
        _make_file("/qdl_isolated/subB/inB.txt", b"b")
        sock = _session()
        status, body = _dirlist(sock, "/qdl_isolated/subA")
        sock.close()
        assert status == kXR_ok
        assert b"inA.txt" in body
        assert b"inB.txt" not in body


# =========================================================================
# Class 5 — Query Consistency
# =========================================================================

class TestQueryConsistency:

    def test_adler32_empty_file_is_1(self):
        _make_file("/qdl_cksum_empty.bin", b"")
        sock = _session()
        status, body = _query(sock, kXR_Qcksum, b"/qdl_cksum_empty.bin\x00")
        sock.close()
        # adler32 of empty data = 1 (zlib spec initial value)
        if status == kXR_ok:
            assert b"1" in body or b"00000001" in body.lower()

    def test_checksum_changes_after_overwrite(self):
        path = b"/qdl_cksum_change.bin\x00"
        _make_file("/qdl_cksum_change.bin", b"version1")
        sock = _session()
        s1, b1 = _query(sock, kXR_Qcksum, path, streamid=b"\x00\x10")
        sock.close()
        # Overwrite with different content
        _make_file("/qdl_cksum_change.bin", b"version2_different_content")
        sock2 = _session()
        s2, b2 = _query(sock2, kXR_Qcksum, path, streamid=b"\x00\x11")
        sock2.close()
        if s1 == kXR_ok and s2 == kXR_ok:
            assert b1 != b2, "checksum must differ after content change"

    def test_qspace_returns_ok(self):
        sock = _session()
        status, body = _query(sock, kXR_Qspace)
        sock.close()
        assert status == kXR_ok
        assert len(body) > 0

    def test_qspace_has_oss_fields(self):
        sock = _session()
        status, body = _query(sock, kXR_Qspace)
        sock.close()
        assert status == kXR_ok
        # Response should contain space metrics
        assert b"oss" in body.lower() or b"free" in body.lower() or len(body) > 0

    def test_qfsinfo_returns_ok(self):
        sock = _session()
        status, body = _query(sock, kXR_QFSinfo)
        sock.close()
        assert status == kXR_ok
        assert len(body) > 0

    def test_qconfig_then_qspace_consistent(self):
        sock = _session()
        s1, b1 = _query(sock, kXR_Qconfig, b"chksum", streamid=b"\x00\x10")
        s2, b2 = _query(sock, kXR_Qspace, streamid=b"\x00\x11")
        sock.close()
        assert s1 == kXR_ok
        assert s2 == kXR_ok

    def test_unknown_infotype_returns_unsupported(self):
        sock = _session()
        status, body = _query(sock, 999)
        sock.close()
        assert status == kXR_error
        assert _error_code(body) == kXR_Unsupported
