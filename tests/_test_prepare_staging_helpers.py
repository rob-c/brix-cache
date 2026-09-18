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

from settings import (
    CA_DIR,
    DATA_ROOT,
    PREPARE_CMD_PORT,
    PREPARE_NOCMD_PORT,
    SERVER_HOST,
    TEST_ROOT,
)

ANON_HOST = SERVER_HOST
ANON_PORT = 0

PREPARE_CMD_DATA_DIR = os.path.join(TEST_ROOT, "data-prepare-command")
PREPARE_NOCMD_DATA_DIR = os.path.join(TEST_ROOT, "data-prepare-nocmd")
PREPARE_CMD_LOG = os.path.join(TEST_ROOT, "data-prepare-command", "staged.log")


def wait_for_prepare_log(path=PREPARE_CMD_LOG, seconds=3.0):
    """Wait for the prepare hook to write something, and say how long it got.

    The hook runs in a process the server forks, so how long it takes to
    appear is a property of the HOST, not of the code under test: a flat 3 s
    expired inside a lane on a busy machine while the same test passed
    standalone (2026-09-17). Scaling by TEST_BUDGET_SCALE keeps the CI
    reference at 3 s and gives a slower host the same number of chances.
    Returns the size seen, so a caller can assert on it and name the budget.
    """
    from lib_py.util import budget_scale   # noqa: PLC0415 — helper-module import
    budget = seconds * budget_scale()
    deadline = time.time() + budget
    size = 0
    while time.time() < deadline:
        size = os.path.getsize(path) if os.path.exists(path) else 0
        if size > 0:
            return size, budget
        time.sleep(0.1)
    return (os.path.getsize(path) if os.path.exists(path) else 0), budget


# ---------------------------------------------------------------------------
# Wire constants
# ---------------------------------------------------------------------------

kXR_ok       = 0
kXR_error    = 4003
kXR_ArgMissing    = 3001
kXR_NotFound      = 3011
kXR_isDirectory   = 3016
kXR_ArgInvalid    = 3000

kXR_query   = 3001
kXR_QPrep   = 2


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
    sock.connect((ANON_HOST, port))
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


def _send_query(sock, streamid, infotype, payload):
    """Send a kXR_query request. Returns (status, body)."""
    hdr = struct.pack(">2sHHH4s8sI",
                      streamid, kXR_query, infotype, 0,
                      b"\x00" * 4, b"\x00" * 8, len(payload))
    sock.sendall(hdr + payload)
    return _read_response(sock)


# ---------------------------------------------------------------------------
# Fixture -- anonymous nginx port for prepare tests
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def anon_port(test_env):
    """Use the shared anonymous nginx endpoint."""
    global ANON_HOST, ANON_PORT
    ANON_HOST = test_env["server_host"]
    ANON_PORT = test_env["anon_port"]
    data_dir = test_env["data_dir"]
    os.makedirs(data_dir, exist_ok=True)
    with open(os.path.join(data_dir, "auth_cache_probe.txt"), "wb") as fh:
        fh.write(b"prepare staging probe\n")
    with open(os.path.join(data_dir, "prepare_large_probe.bin"), "wb") as fh:
        fh.write(b"x" * 200)
    yield ANON_PORT


# ---------------------------------------------------------------------------
# Valid file list -- kXR_ok with path count
# ---------------------------------------------------------------------------
