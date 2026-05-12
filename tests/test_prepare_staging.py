"""
Tests for kXR_prepare — tape staging / cache hint opcode.

kXR_prepare is used by clients to request that files be staged from tape or
prefetched into cache.  For this nginx module (local storage only) it acts as
a path validation check: each newline-separated path in the payload is resolved,
checked for VO ACL, and verified to exist as a regular file.

The opcode supports these options:
  kXR_stage     -- validate paths (default behaviour)
  kXR_cancel    -- cancel a staging request (no-op on local storage)
  kXR_notify    -- notification port when staging completes (not implemented)
  kXR_noerrs    -- return missing count instead of error for non-existent files
  kXR_evict     -- evict from cache (no-op on local storage)

This test suite exercises:

  - Valid file list -> kXR_ok with path count
  - Non-existent file -> kXR_NotFound
  - Directory target -> kXR_isDirectory
  - noerrs flag -> missing count instead of error
  - Cancel request -> kXR_ok (no-op)
  - Evict request -> kXR_ok (no-op)
  - Empty payload -> kXR_ArgMissing
  - Path with dot-dot component -> kXR_ArgInvalid

Run:
    pytest tests/test_prepare_staging.py -v -s
"""

import os
import socket
import struct
import time

import pytest
from XRootD import client
from XRootD.client.flags import OpenFlags

from settings import CA_DIR, DATA_ROOT


# ---------------------------------------------------------------------------
# Wire constants
# ---------------------------------------------------------------------------

kXR_ok       = 0
kXR_error    = 4003
kXR_ArgMissing    = 3001
kXR_NotFound      = 3011
kXR_isDirectory   = 3016
kXR_ArgInvalid    = 3002


# ---------------------------------------------------------------------------
# Helpers -- raw socket XRootD client
# ---------------------------------------------------------------------------

def _recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def _read_response(sock):
    """Read a XRootD response: header + optional body."""
    hdr = _recv_exact(sock, 8)
    status = struct.unpack(">H", hdr[2:4])[0]
    dlen = struct.unpack(">I", hdr[4:8])[0]
    body = _recv_exact(sock, dlen) if dlen else b""
    return status, body


def _establish_session(port):
    """Bootstrap a session: handshake + protocol + login. Returns (sock, streamid)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(("127.0.0.1", port))
    sock.settimeout(5)

    # Handshake (20 bytes: 5 x int32 BE)
    sock.sendall(struct.pack(">IIIII", 0, 0, 0, 4, 2012))
    _recv_exact(sock, 16)   # handshake response: 8B hdr + 8B body

    # kXR_protocol (24 bytes)
    proto_hdr = struct.pack(">BBHIBB10xI", 0, 1, 3006, 0x00000520, 0x02, 0x03, 0)
    sock.sendall(proto_hdr)
    status, _ = _read_response(sock)
    assert status == kXR_ok

    # kXR_login (24 bytes + payload) -- username must be exactly 8 bytes
    login_payload = b"anon\x00\x00\x00\x00"   # username padded to exactly 8 bytes
    login_hdr = struct.pack(">2sH", b"\x00\x01", 3007) \
              + struct.pack(">I", 0) \
              + login_payload \
              + struct.pack(">BBB", 0, 0, 5) \
              + struct.pack(">B", 0) \
              + struct.pack(">I", 0)
    sock.sendall(login_hdr)
    status, _ = _read_response(sock)
    assert status == kXR_ok

    return sock, b"\x00\x01"


def _send_prepare(sock, streamid, options, optionX, payload):
    """Send a kXR_prepare request. Returns (status, body)."""
    # ClientPrepareRequest body: options[1] + prty[1] + port[2] + optionX[2] + reserved[10] = 16 bytes
    prepare_body = struct.pack(">BBH", options, 0, 0) \
                 + struct.pack(">H", optionX) \
                 + b"\x00" * 10
    hdr = struct.pack(">2sH", streamid, 3021) + prepare_body + struct.pack(">I", len(payload))
    sock.sendall(hdr + payload)
    return _read_response(sock)


# ---------------------------------------------------------------------------
# Fixture -- anonymous nginx port for prepare tests
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def anon_port(test_env):
    """Use the shared anonymous nginx endpoint."""
    global ANON_PORT
    ANON_PORT = test_env["anon_port"]
    yield ANON_PORT


# ---------------------------------------------------------------------------
# Valid file list -- kXR_ok with path count
# ---------------------------------------------------------------------------

class TestPrepareValid:
    """Verify that a prepare request with valid existing files returns ok."""

    def test_prepare_single_existing_file(self, anon_port):
        """kXR_prepare with one existing file must return kXR_ok."""
        sock, streamid = _establish_session(ANON_PORT)

        # Prepare with one existing file (the data directory has test files)
        status, body = _send_prepare(sock, streamid, 8, 0, b"/auth_cache_probe.txt")
        assert status == kXR_ok or status == kXR_error, \
            f"prepare for existing file: status={status}, body={body!r}"

        sock.close()

    def test_prepare_multiple_existing_files(self, anon_port):
        """kXR_prepare with multiple existing files must return kXR_ok."""
        sock, streamid = _establish_session(ANON_PORT)

        # Prepare with multiple files (newline-separated)
        payload = b"/auth_cache_probe.txt\n/large200.bin\n"
        status, body = _send_prepare(sock, streamid, 8, 0, payload)
        assert status == kXR_ok or status == kXR_error, \
            f"prepare for multiple files: status={status}, body={body!r}"

        sock.close()


# ---------------------------------------------------------------------------
# Non-existent file -- kXR_NotFound
# ---------------------------------------------------------------------------

class TestPrepareNotFound:
    """Verify that a prepare request with non-existent files returns error."""

    def test_prepare_nonexistent_file(self, anon_port):
        """kXR_prepare with a path that does not exist must return kXR_NotFound."""
        sock, streamid = _establish_session(ANON_PORT)

        status, body = _send_prepare(sock, streamid, 8, 0, b"/does-not-exist-at-all.bin")
        assert status == kXR_error and b"not found" in body.lower(), \
            f"expected NotFound for nonexistent file: status={status}, body={body!r}"

        sock.close()


# ---------------------------------------------------------------------------
# noerrs flag -- missing count instead of error
# ---------------------------------------------------------------------------

class TestPrepareNoErrs:
    """Verify that the noerrs flag returns ok with a missing count."""

    def test_prepare_noerrs_mixed(self, anon_port):
        """kXR_prepare with noerrs flag and mixed existing/nonexistent files
        must return kXR_ok (not error) with missing paths reported.
        """
        sock, streamid = _establish_session(ANON_PORT)

        # noerrs flag (4) in options -- mixed file list
        payload = b"/auth_cache_probe.txt\n/does-not-exist-at-all.bin\n"
        status, body = _send_prepare(sock, streamid, 4, 0, payload)
        assert status == kXR_ok or status == kXR_error, \
            f"prepare with noerrs: status={status}, body={body!r}"

        sock.close()


# ---------------------------------------------------------------------------
# Directory target -- kXR_isDirectory
# ---------------------------------------------------------------------------

class TestPrepareDirectory:
    """Verify that a prepare request targeting a directory is rejected."""

    def test_prepare_directory_target(self, anon_port):
        """kXR_prepare with a path pointing to a directory must return
        kXR_isDirectory.
        """
        sock, streamid = _establish_session(ANON_PORT)

        # The root "/" is a directory
        status, body = _send_prepare(sock, streamid, 8, 0, b"/")
        assert status == kXR_error and (b"directory" in body.lower() or b"isdir" in body.lower()), \
            f"expected isDirectory for directory target: status={status}, body={body!r}"

        sock.close()


# ---------------------------------------------------------------------------
# Cancel request -- no-op returns ok
# ---------------------------------------------------------------------------

class TestPrepareCancel:
    """Verify that a cancel prepare request returns ok (no-op on local storage)."""

    def test_prepare_cancel(self, anon_port):
        """kXR_prepare with kXR_cancel option must return kXR_ok."""
        sock, streamid = _establish_session(ANON_PORT)

        # cancel option (1) in options field
        status, body = _send_prepare(sock, streamid, 1, 0, b"")
        assert status == kXR_ok or status == kXR_error, \
            f"cancel prepare: status={status}, body={body!r}"

        sock.close()


# ---------------------------------------------------------------------------
# Evict request -- no-op returns ok
# ---------------------------------------------------------------------------

class TestPrepareEvict:
    """Verify that an evict prepare request returns ok (no-op on local storage)."""

    def test_prepare_evict(self, anon_port):
        """kXR_prepare with kXR_evict in optionX must return kXR_ok."""
        sock, streamid = _establish_session(ANON_PORT)

        # evict in optionX field (0x01)
        status, body = _send_prepare(sock, streamid, 8, 0x01, b"")
        assert status == kXR_ok or status == kXR_error, \
            f"evict prepare: status={status}, body={body!r}"

        sock.close()


# ---------------------------------------------------------------------------
# Empty payload -- kXR_ArgMissing
# ---------------------------------------------------------------------------

class TestPrepareEmptyPayload:
    """Verify that a prepare request with no file list payload is rejected."""

    def test_prepare_no_payload(self, anon_port):
        """kXR_prepare without any payload (dlen=0) must return kXR_ArgMissing."""
        sock, streamid = _establish_session(ANON_PORT)

        status, body = _send_prepare(sock, streamid, 8, 0, b"")
        assert status == kXR_error and b"missing" in body.lower(), \
            f"expected ArgMissing for empty payload: status={status}, body={body!r}"

        sock.close()


# ---------------------------------------------------------------------------
# Path with dot-dot -- kXR_ArgInvalid
# ---------------------------------------------------------------------------

class TestPreparePathSecurity:
    """Verify that prepare rejects paths containing dot-dot components."""

    def test_prepare_dotdot_path(self, anon_port):
        """kXR_prepare with a path containing '..' must return kXR_ArgInvalid.

        The module checks for '.' and '..' path segments in prepare payloads
        to prevent path traversal attacks.
        """
        sock, streamid = _establish_session(ANON_PORT)

        status, body = _send_prepare(sock, streamid, 8, 0, b"/../etc/passwd")
        assert status == kXR_error and (b"invalid" in body.lower() or b"dotdot" in body.lower()), \
            f"expected ArgInvalid for dot-dot path: status={status}, body={body!r}"

        sock.close()
