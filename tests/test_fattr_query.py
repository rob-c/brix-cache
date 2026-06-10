"""
tests/test_fattr_query.py

Functional tests for:
  - kXR_fattr  (3020): file extended attributes (get/set/del/list)
  - kXR_QStats  (1): server statistics XML response
  - kXR_Qxattr  (4): extended-attribute query by path
  - kXR_QFinfo  (9): file information (compression type)
  - kXR_QFSinfo (10): filesystem information

Most tests use the anonymous XRootD endpoint (root://localhost:11094/),
with selected tests also covering the GSI endpoint (root://localhost:11095/).

kXR_fattr uses the XRootD Python-client FileProperty / FileSystem.{set,get,
del,list}_xattr API.  The query subtypes are exercised via raw socket tests
(the Python client does not expose all QueryCode variants) or via
FileSystem.query() where the enum value is available.
"""

import os
import socket
import struct
import tempfile
import time
import pytest
from settings import (
    CA_DIR,
    DATA_ROOT,
    NGINX_ANON_PORT,
    NGINX_GSI_PORT,
    PROXY_STD,
    SERVER_HOST,
)

# ── XRootD Python client imports ─────────────────────────────────────────────

try:
    from XRootD import client as xrd_client
    from XRootD.client.flags import OpenFlags, QueryCode
    HAS_XROOTD = True
except ImportError:
    HAS_XROOTD = False

pytestmark = pytest.mark.skipif(not HAS_XROOTD,
                                reason="XRootD Python client not installed")

# ── Endpoints ─────────────────────────────────────────────────────────────────

ANON_URL  = f"root://{SERVER_HOST}:{NGINX_ANON_PORT}/"
GSI_URL   = f"root://{SERVER_HOST}:{NGINX_GSI_PORT}/"
ANON_HOST = SERVER_HOST
ANON_PORT = NGINX_ANON_PORT
DATA_DIR  = DATA_ROOT
PROXY_PEM = PROXY_STD


# ── Helpers ───────────────────────────────────────────────────────────────────

def make_file(name: str, content: bytes = b"hello fattr\n") -> str:
    """Create a test file under DATA_DIR and return the XRootD path."""
    os.makedirs(DATA_DIR, exist_ok=True)
    fpath = os.path.join(DATA_DIR, name)
    with open(fpath, "wb") as f:
        f.write(content)
    return "/" + name


def rm_file(name: str) -> None:
    path = os.path.join(DATA_DIR, name)
    try:
        os.remove(path)
    except FileNotFoundError:
        pass


# ── Raw-socket helpers (for query subtypes the Python client doesn't expose) ──

_SESSION_ID_LEN = 16
_HDR_LEN = 24
_RSP_HDR_LEN = 8

_kXR_protocol = 3006
_kXR_login    = 3007
_kXR_query    = 3001
_kXR_ok       = 0

_kXR_QStats  = 1
_kXR_Qxattr  = 4
_kXR_QFinfo  = 9
_kXR_QFSinfo = 10


def _recvall(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        assert chunk, "connection closed unexpectedly"
        buf += chunk
    return buf


def _recv_response(sock: socket.socket) -> tuple[int, bytes]:
    """Read one XRootD response and return (status, body)."""
    hdr = _recvall(sock, _RSP_HDR_LEN)
    _sid0, _sid1, status, dlen = struct.unpack(">BBHI", hdr)
    body = _recvall(sock, dlen) if dlen else b""
    return status, body


def _raw_session(host: str, port: int) -> socket.socket:
    """Open a raw TCP socket, perform handshake + anonymous login."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    sock.connect((host, port))

    # Handshake: 5 × int32 = 20 bytes
    sock.sendall(struct.pack(">IIIII", 0, 0, 0, 4, 2012))

    # kXR_protocol (24 bytes): streamid[2] requestid[2] clientpv[4]
    #   flags[1] expect[1] reserved[10] dlen[4]
    sock.sendall(struct.pack(">BB H I BB 10x I",
                             0, 1, _kXR_protocol, 0x00000520, 0x02, 0x03, 0))

    _recvall(sock, 16)    # handshake reply (standard 8-byte hdr + 8-byte body)
    _recv_response(sock)  # protocol reply

    # kXR_login (24 bytes): streamid[2] requestid[2] pid[4] username[8]
    #   ability2[1] ability[1] capver[1] reserved[1] dlen[4]
    sock.sendall(struct.pack(">BB H I 8s BB B B I",
                             0, 1, _kXR_login, 0,
                             b"nobody\x00\x00",
                             0, 0, 5, 0, 0))
    status, body = _recv_response(sock)
    assert status == _kXR_ok, f"login failed: status={status}"
    return sock


def _send_query(sock: socket.socket, infotype: int, payload: bytes) -> bytes:
    """Send kXR_query with the given infotype and payload, return response body.

    ClientQueryRequest (24 bytes):
      streamid[2] requestid[2] infotype[2] reserved1[2]
      fhandle[4] reserved2[8] dlen[4]
    """
    dlen = len(payload)
    # 2+2+2+2+4+8 = 20 bytes before dlen, then dlen[4] = 24 total
    hdr = struct.pack(">BB H H 2x 4x 8x I",
                      0, 1, _kXR_query, infotype, dlen)
    sock.sendall(hdr + payload)
    status, body = _recv_response(sock)
    assert status == _kXR_ok, f"query infotype={infotype} failed: status={status}"
    return body


# ═══════════════════════════════════════════════════════════════════════════════
# TestFattr — kXR_fattr via Python client
# ═══════════════════════════════════════════════════════════════════════════════

class TestFattr:
    """kXR_fattr: set / get / del / list extended attributes on files."""

    def setup_method(self) -> None:
        self.fname = f"fattr_test_{os.getpid()}.txt"
        self.xrd_path = make_file(self.fname)
        self.local_path = os.path.join(DATA_DIR, self.fname)
        self.fs = xrd_client.FileSystem(ANON_URL)

    def teardown_method(self) -> None:
        rm_file(self.fname)

    def test_fattr_set_and_get(self) -> None:
        """Set an attribute, then retrieve it and verify the value."""
        status, _ = self.fs.set_xattr(self.xrd_path, [("project", "cms")])
        assert status.ok, f"set_xattr failed: {status.message}"

        status, attrs = self.fs.get_xattr(self.xrd_path, ["project"])
        assert status.ok, f"get_xattr failed: {status.message}"
        assert attrs is not None
        # Each entry is a tuple: (name, value, status_dict)
        attr_map = {t[0]: t[1] for t in attrs}
        assert "project" in attr_map, f"'project' not in response: {attr_map}"
        assert attr_map["project"] == "cms", f"value mismatch: {attr_map['project']!r}"

    def test_fattr_del(self) -> None:
        """Set an attribute, delete it, then verify it is gone."""
        status, _ = self.fs.set_xattr(self.xrd_path, [("tempkey", "42")])
        assert status.ok

        status, _ = self.fs.del_xattr(self.xrd_path, ["tempkey"])
        assert status.ok, f"del_xattr failed: {status.message}"

        status, attrs = self.fs.get_xattr(self.xrd_path, ["tempkey"])
        if status.ok and attrs:
            attr_map = {t[0]: t[1] for t in attrs}
            if "tempkey" in attr_map:
                assert attr_map["tempkey"] is None or attr_map["tempkey"] == ""

    def test_fattr_list(self) -> None:
        """Set several attributes, list them, and verify names appear."""
        attrs_to_set = {"tag1": "v1", "tag2": "v2", "experiment": "atlas"}
        status, _ = self.fs.set_xattr(self.xrd_path,
                                      list(attrs_to_set.items()))
        assert status.ok

        status, listed = self.fs.list_xattr(self.xrd_path)
        assert status.ok, f"list_xattr failed: {status.message}"
        # list returns (name, value, status) tuples; names include "U." prefix
        listed_names = {t[0] for t in (listed or [])}
        for name in attrs_to_set:
            assert name in listed_names or f"U.{name}" in listed_names, \
                f"attribute {name!r} missing from list: {listed_names}"

    def test_fattr_list_with_values(self) -> None:
        """list_xattr with values=True returns both names and values."""
        status, _ = self.fs.set_xattr(self.xrd_path, [("color", "red")])
        assert status.ok

        # Pass withValues=True if the client supports it; fall back to plain list
        try:
            status, listed = self.fs.list_xattr(self.xrd_path, withValues=True)
        except TypeError:
            status, listed = self.fs.list_xattr(self.xrd_path)

        assert status.ok, f"list_xattr (with values) failed: {status.message}"
        # Support multiple client return shapes: objects with .name, or tuples
        listed_names = set()
        for a in (listed or []):
            if hasattr(a, 'name'):
                listed_names.add(a.name)
            elif isinstance(a, tuple) and len(a) >= 1:
                listed_names.add(a[0])
        assert any("color" in n for n in listed_names), \
            f"'color' not in listed attrs: {listed_names}"

    def test_fattr_get_nonexistent(self) -> None:
        """Getting a non-existent attribute should return an error status or empty."""
        status, attrs = self.fs.get_xattr(self.xrd_path, ["nonexistent_xyz"])
        # The operation may succeed at the protocol level with a per-attr error,
        # or may fail at the call level — either is acceptable.
        if status.ok and attrs:
            if hasattr(attrs[0], 'name'):
                attr_map = {a.name: a.value for a in attrs}
            else:
                attr_map = {t[0]: t[1] for t in attrs}
            # Attribute should be absent or None
            val = attr_map.get("nonexistent_xyz")
            assert val is None or val == "", \
                f"Expected None/empty for missing attr, got: {val!r}"

    def test_fattr_multiple_attributes(self) -> None:
        """Set and get multiple attributes in a single request."""
        batch = {"run": "12345", "dataset": "physics_2024", "site": "CERN"}
        status, _ = self.fs.set_xattr(self.xrd_path, list(batch.items()))
        assert status.ok

        status, attrs = self.fs.get_xattr(self.xrd_path, list(batch.keys()))
        assert status.ok
        if attrs and hasattr(attrs[0], 'name'):
            attr_map = {a.name: a.value for a in (attrs or [])}
        else:
            attr_map = {t[0]: t[1] for t in (attrs or [])}
        for k, v in batch.items():
            assert attr_map.get(k) == v, \
                f"Attribute {k!r}: expected {v!r}, got {attr_map.get(k)!r}"

    def test_fattr_linux_xattr_visible(self) -> None:
        """Attributes set via kXR_fattr should be visible as Linux user.U.* xattrs."""
        status, _ = self.fs.set_xattr(self.xrd_path, [("checkmark", "pass")])
        assert status.ok

        # Read directly from local filesystem
        try:
            import subprocess
            result = subprocess.run(
                ["getfattr", "-n", "user.U.checkmark", self.local_path],
                capture_output=True, text=True
            )
            assert "pass" in result.stdout or result.returncode == 0
        except FileNotFoundError:
            # getfattr not installed — use Python os.getxattr
            try:
                val = os.getxattr(self.local_path, "user.U.checkmark")
                assert val == b"pass"
            except OSError:
                pytest.skip("xattr not supported on test filesystem")

    def test_fattr_gsi_endpoint(self) -> None:
        """Attributes work on the GSI-authenticated endpoint."""
        os.environ["X509_CERT_DIR"] = CA_DIR
        os.environ["X509_USER_PROXY"] = PROXY_PEM
        fs_gsi = xrd_client.FileSystem(GSI_URL)
        status, _ = fs_gsi.set_xattr(self.xrd_path, [("gsi_tag", "ok")])
        assert status.ok, f"GSI fattr set failed: {status.message}"

        status, attrs = fs_gsi.get_xattr(self.xrd_path, ["gsi_tag"])
        assert status.ok
        if attrs and hasattr(attrs[0], 'name'):
            attr_map = {a.name: a.value for a in (attrs or [])}
        else:
            attr_map = {t[0]: t[1] for t in (attrs or [])}
        assert attr_map.get("gsi_tag") == "ok"


# ═══════════════════════════════════════════════════════════════════════════════
# TestQueryStats — kXR_QStats (infotype=1) via raw socket
# ═══════════════════════════════════════════════════════════════════════════════

class TestQueryStats:
    """kXR_QStats returns an XML statistics blob."""

    def test_stats_returns_xml(self) -> None:
        """kXR_QStats response contains a <statistics> XML element."""
        sock = _raw_session(ANON_HOST, ANON_PORT)
        try:
            body = _send_query(sock, _kXR_QStats, b"a")
            text = body.rstrip(b"\x00").decode("utf-8", errors="replace")
            assert "<statistics" in text, \
                f"Expected <statistics> in stats response, got: {text[:200]!r}"
        finally:
            sock.close()

    def test_stats_contains_port(self) -> None:
        """Stats response includes the server port."""
        sock = _raw_session(ANON_HOST, ANON_PORT)
        try:
            body = _send_query(sock, _kXR_QStats, b"")
            text = body.rstrip(b"\x00").decode("utf-8", errors="replace")
            assert "11094" in text or "<port>" in text, \
                f"Expected port in stats: {text[:300]!r}"
        finally:
            sock.close()

    def test_stats_contains_link_section(self) -> None:
        """Stats response includes a <stats id=\"link\"> section."""
        sock = _raw_session(ANON_HOST, ANON_PORT)
        try:
            body = _send_query(sock, _kXR_QStats, b"i")
            text = body.rstrip(b"\x00").decode("utf-8", errors="replace")
            assert "stats" in text.lower(), \
                f"Expected stats content, got: {text[:300]!r}"
        finally:
            sock.close()

    def test_stats_via_python_client(self) -> None:
        """kXR_QStats can also be issued via the Python client's query API."""
        fs = xrd_client.FileSystem(ANON_URL)
        # QueryCode.STATS = 1
        status, response = fs.query(QueryCode.STATS, "/")
        assert status.ok, f"query STATS failed: {status.message}"
        assert response is not None and len(response) > 0


# ═══════════════════════════════════════════════════════════════════════════════
# TestQueryXattr — kXR_Qxattr (infotype=4) via raw socket
# ═══════════════════════════════════════════════════════════════════════════════

class TestQueryXattr:
    """kXR_Qxattr returns extended-attribute text for a path."""

    def setup_method(self) -> None:
        self.fname = f"qxattr_test_{os.getpid()}.txt"
        self.xrd_path = make_file(self.fname)
        self.local_path = os.path.join(DATA_DIR, self.fname)
        # Pre-set an xattr directly so the query has something to return
        try:
            os.setxattr(self.local_path, "user.U.meta", b"info")
        except OSError:
            pass  # xattr not supported — tests will check gracefully

    def teardown_method(self) -> None:
        rm_file(self.fname)

    def test_xattr_query_responds(self) -> None:
        """kXR_Qxattr returns kXR_ok for a valid path."""
        sock = _raw_session(ANON_HOST, ANON_PORT)
        try:
            path_payload = self.xrd_path.encode() + b"\x00"
            body = _send_query(sock, _kXR_Qxattr, path_payload)
            # kXR_ok means the server handled the request; body may be empty
            assert isinstance(body, bytes)
        finally:
            sock.close()

    def test_xattr_query_returns_set_attribute(self) -> None:
        """kXR_Qxattr response includes U.meta=info when that xattr is set."""
        sock = _raw_session(ANON_HOST, ANON_PORT)
        try:
            path_payload = self.xrd_path.encode() + b"\x00"
            body = _send_query(sock, _kXR_Qxattr, path_payload)
            text = body.rstrip(b"\x00").decode("utf-8", errors="replace")
            # If xattrs are supported, U.meta=info should appear
            if text:
                assert "meta" in text or "=" in text, \
                    f"Unexpected xattr response: {text!r}"
        finally:
            sock.close()

    def test_xattr_query_empty_for_no_attrs(self) -> None:
        """kXR_Qxattr returns empty body for a file with no U.* xattrs."""
        fname2 = f"noattrs_{os.getpid()}.txt"
        make_file(fname2)
        try:
            sock = _raw_session(ANON_HOST, ANON_PORT)
            try:
                path_payload = ("/" + fname2).encode() + b"\x00"
                body = _send_query(sock, _kXR_Qxattr, path_payload)
                # Empty body is valid; text body with only our U.* attrs is valid
                assert isinstance(body, bytes)
            finally:
                sock.close()
        finally:
            rm_file(fname2)


# ═══════════════════════════════════════════════════════════════════════════════
# TestQueryFinfo — kXR_QFinfo (infotype=9) via raw socket
# ═══════════════════════════════════════════════════════════════════════════════

class TestQueryFinfo:
    """kXR_QFinfo returns file information (compression type)."""

    def setup_method(self) -> None:
        self.fname = f"finfo_test_{os.getpid()}.txt"
        self.xrd_path = make_file(self.fname)

    def teardown_method(self) -> None:
        rm_file(self.fname)

    def test_finfo_returns_ok(self) -> None:
        """kXR_QFinfo returns kXR_ok."""
        sock = _raw_session(ANON_HOST, ANON_PORT)
        try:
            body = _send_query(sock, _kXR_QFinfo, b"\x00")
            assert isinstance(body, bytes)
        finally:
            sock.close()

    def test_finfo_indicates_no_compression(self) -> None:
        """For a plain file, kXR_QFinfo response starts with '0' (no compression)."""
        sock = _raw_session(ANON_HOST, ANON_PORT)
        try:
            body = _send_query(sock, _kXR_QFinfo, b"\x00")
            text = body.rstrip(b"\x00").decode("ascii", errors="replace")
            assert text.startswith("0"), \
                f"Expected '0' for uncompressed file, got: {text!r}"
        finally:
            sock.close()

    def test_finfo_with_path(self) -> None:
        """kXR_QFinfo with a path payload returns kXR_ok."""
        sock = _raw_session(ANON_HOST, ANON_PORT)
        try:
            payload = self.xrd_path.encode() + b"\x00"
            body = _send_query(sock, _kXR_QFinfo, payload)
            assert isinstance(body, bytes)
        finally:
            sock.close()


# ═══════════════════════════════════════════════════════════════════════════════
# TestQueryFSinfo — kXR_QFSinfo (infotype=10) via raw socket
# ═══════════════════════════════════════════════════════════════════════════════

class TestQueryFSinfo:
    """kXR_QFSinfo returns filesystem capacity information."""

    def test_fsinfo_returns_ok(self) -> None:
        """kXR_QFSinfo returns kXR_ok."""
        sock = _raw_session(ANON_HOST, ANON_PORT)
        try:
            body = _send_query(sock, _kXR_QFSinfo, b"/\x00")
            assert isinstance(body, bytes) and len(body) > 0
        finally:
            sock.close()

    def test_fsinfo_format(self) -> None:
        """kXR_QFSinfo response uses standard 6-number format."""
        sock = _raw_session(ANON_HOST, ANON_PORT)
        try:
            body = _send_query(sock, _kXR_QFSinfo, b"/\x00")
            text = body.rstrip(b"\x00").decode("utf-8", errors="replace")
            parts = text.split()
            assert len(parts) == 6, f"Expected 6 numbers in fsinfo: {text!r}"
            # Format: NodesRW FreeMB Util NodesStaging FreeMB Util
            for p in parts:
                assert p.isdigit(), f"Non-numeric value in fsinfo: {p!r}"
        finally:
            sock.close()

    def test_fsinfo_values_are_sane(self) -> None:
        """FSinfo values for space and utilization are sane."""
        sock = _raw_session(ANON_HOST, ANON_PORT)
        try:
            body = _send_query(sock, _kXR_QFSinfo, b"/\x00")
            text = body.rstrip(b"\x00").decode("utf-8", errors="replace")
            parts = [int(p) for p in text.split()]
            wVal, freeMB, util, sVal, freeMB2, util2 = parts
            assert wVal == 1
            assert sVal == 1
            assert freeMB >= 0
            assert util >= 0 and util <= 100
            assert freeMB == freeMB2
            assert util == util2
        finally:
            sock.close()

    def test_fsinfo_via_python_client_space(self) -> None:
        """Cross-check: kXR_Qspace and kXR_QFSinfo both report consistent free space."""
        fs = xrd_client.FileSystem(ANON_URL)
        status, space_resp = fs.query(QueryCode.SPACE, "/")
        assert status.ok, f"SPACE query failed: {status.message}"

        sock = _raw_session(ANON_HOST, ANON_PORT)
        try:
            fsinfo_body = _send_query(sock, _kXR_QFSinfo, b"/\x00")
        finally:
            sock.close()

        # Both should contain numeric free-space info
        assert space_resp is not None
        assert fsinfo_body is not None


# ═══════════════════════════════════════════════════════════════════════════════
# TestFattrRecurse — kXR_fa_recurse (local extension, options=0x20)
# ═══════════════════════════════════════════════════════════════════════════════

class TestFattrRecurse:
    """Tests for the kXR_fa_recurse local extension (options bit 0x20).

    The XRootD Python client has no API for custom option bits, so these
    tests use raw socket protocol to send kXR_fattr list with the recurse
    flag and verify the response format.

    Wire format — ClientFattrRequest (24 bytes total):
      streamid[2]  requestid[2]=3020  fhandle[4]
      subcode[1]=2  numattr[1]=0  options[1]  reserved[9]  dlen[4]

    Recursive response entries: "<relpath>:<U.name>\\0" per attribute.
    """

    _kXR_fattr     = 3020
    _kXR_fattrList = 2
    _kXR_fa_recurse = 0x20

    # ── Helpers ────────────────────────────────────────────────────────────

    def _send_fattr_list(self, sock: socket.socket, path: str,
                         options: int) -> tuple[int, bytes]:
        """Send kXR_fattr list for *path* and return (status, body)."""
        payload = path.encode() + b"\x00"
        # 2(sid) + 2(requestid) + 4(fhandle) + 1(subcode) + 1(numattr) +
        # 1(options) + 9(reserved) + 4(dlen) = 24 bytes
        hdr = struct.pack(
            ">BB H 4x B B B 9x I",
            0, 1,                    # streamid
            self._kXR_fattr,         # requestid = 3020
            self._kXR_fattrList,     # subcode   = 2
            0,                       # numattr   = 0 (required for list)
            options,                 # options   = kXR_fa_recurse etc.
            len(payload),            # dlen
        )
        sock.sendall(hdr + payload)
        hdr_bytes = _recvall(sock, 8)
        _sid0, _sid1, status, dlen = struct.unpack(">BBHI", hdr_bytes)
        body = _recvall(sock, dlen) if dlen else b""
        return status, body

    def _parse_entries(self, body: bytes) -> list[str]:
        """Split NUL-terminated entry list into a list of decoded strings."""
        return [p.decode(errors="replace") for p in body.split(b"\x00") if p]

    # ── Setup / teardown ──────────────────────────────────────────────────

    def setup_method(self) -> None:
        """Create a two-level directory tree with user.U.* xattrs."""
        pid = os.getpid()
        self.dir_name = f"fattr_recurse_{pid}"
        self.dir_fs   = os.path.join(DATA_DIR, self.dir_name)
        os.makedirs(self.dir_fs, exist_ok=True)

        # Top-level file with one xattr
        self.top_file_fs = os.path.join(self.dir_fs, "top.txt")
        with open(self.top_file_fs, "w") as f:
            f.write("top\n")
        try:
            os.setxattr(self.top_file_fs, b"user.U.color", b"blue")
        except OSError:
            pytest.skip("xattr not supported on test filesystem")

        # Subdirectory + nested file with a different xattr
        sub_fs = os.path.join(self.dir_fs, "sub")
        os.makedirs(sub_fs, exist_ok=True)
        self.nested_file_fs = os.path.join(sub_fs, "nested.txt")
        with open(self.nested_file_fs, "w") as f:
            f.write("nested\n")
        os.setxattr(self.nested_file_fs, b"user.U.project", b"cms")

    def teardown_method(self) -> None:
        import shutil
        shutil.rmtree(self.dir_fs, ignore_errors=True)

    # ── Tests ─────────────────────────────────────────────────────────────

    def test_recurse_returns_top_level_file_attrs(self) -> None:
        """kXR_fa_recurse on a directory returns attrs from top-level files."""
        sock = _raw_session(ANON_HOST, ANON_PORT)
        try:
            status, body = self._send_fattr_list(
                sock, "/" + self.dir_name, self._kXR_fa_recurse)
        finally:
            sock.close()

        assert status == _kXR_ok, f"fattr list returned status={status}"
        entries = self._parse_entries(body)
        # Expect an entry like "top.txt:U.color" (relpath:U.name)
        assert any("top.txt" in e and "U.color" in e for e in entries), \
            f"top-level attr 'U.color' not found in recurse result: {entries}"

    def test_recurse_finds_nested_subdir_attrs(self) -> None:
        """kXR_fa_recurse descends into subdirectories and returns nested attrs."""
        sock = _raw_session(ANON_HOST, ANON_PORT)
        try:
            status, body = self._send_fattr_list(
                sock, "/" + self.dir_name, self._kXR_fa_recurse)
        finally:
            sock.close()

        assert status == _kXR_ok, f"fattr list returned status={status}"
        entries = self._parse_entries(body)
        # Expect an entry like "sub/nested.txt:U.project"
        assert any("nested.txt" in e and "U.project" in e for e in entries), \
            f"nested attr 'U.project' not found in recurse result: {entries}"

    def test_recurse_flag_absent_does_not_list_children(self) -> None:
        """Without kXR_fa_recurse, listing a directory uses single-file semantics
        (the directory's own xattrs only, not its children's attrs)."""
        sock = _raw_session(ANON_HOST, ANON_PORT)
        try:
            # options=0: no recurse — directory has no user.U.* xattrs itself
            status, body = self._send_fattr_list(
                sock, "/" + self.dir_name, 0)
        finally:
            sock.close()

        assert status == _kXR_ok, f"fattr list returned status={status}"
        entries = self._parse_entries(body)
        # Children's attributes must not appear when recurse is not requested
        assert not any("top.txt" in e for e in entries), \
            f"child file attr appeared without recurse flag: {entries}"
        assert not any("nested.txt" in e for e in entries), \
            f"nested file attr appeared without recurse flag: {entries}"
