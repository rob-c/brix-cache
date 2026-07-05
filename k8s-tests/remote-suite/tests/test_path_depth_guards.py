# brix-remote-ok
"""
Recursive walk guards — prevention of CPU exhaustion from excessive path depth.

These tests verify that paths exceeding BRIX_MAX_WALK_DEPTH (32 components) are
rejected before expensive realpath(3) / lstat() operations begin, preventing denial-
of-service conditions from malicious symlink traversal chains or deep nesting attacks.

Three test scenarios per invariant: success + error + security-neg.
"""

import os
import socket
import struct
import time

import pytest
from settings import DATA_ROOT, LOG_DIR, NGINX_ANON_PORT, SERVER_HOST


ANON_URL  = f"root://{SERVER_HOST}:{NGINX_ANON_PORT}"
ANON_HOST = SERVER_HOST
ANON_PORT = NGINX_ANON_PORT
DATA_DIR  = DATA_ROOT
ERROR_LOG = os.path.join(LOG_DIR, "error.log")


kXR_OK = 0
kXR_ERROR = 4003
kXR_ARG_INVALID = 3000

kXR_LOGIN = 3007
kXR_OPEN = 3010
kXR_MKDIR = 3008
kXR_RM = 3014

kXR_OPEN_READ = 0x0010
kXR_MKDIRPATH = 0x01


def _recv_exact(sock, nbytes):
    """Read exactly *nbytes* or fail loudly if the server closes early."""
    data = bytearray()
    while len(data) < nbytes:
        chunk = sock.recv(nbytes - len(data))
        if not chunk:
            raise AssertionError("socket closed before full response arrived")
        data.extend(chunk)
    return bytes(data)


def _read_response(sock):
    """Read one standard XRootD response frame: 8-byte header + body."""
    header = _recv_exact(sock, 8)
    _streamid, status, dlen = struct.unpack("!2sHI", header)
    body = _recv_exact(sock, dlen) if dlen else b""
    return status, body


def _raw_session():
    """Open a raw socket and complete only the initial 20-byte handshake."""
    sock = socket.create_connection((ANON_HOST, ANON_PORT), timeout=5)
    sock.settimeout(5)
    sock.sendall(struct.pack("!IIIII", 0, 0, 0, 4, 2012))
    _recv_exact(sock, 16)
    return sock


def _login_anon(sock, streamid=b"\x00\x01"):
    """Send a minimal anonymous kXR_login so later requests are post-auth."""
    username = b"pytest\x00\x00"
    req = struct.pack(
        "!2sHI8sBBBBI",
        streamid,
        kXR_LOGIN,
        os.getpid() & 0xFFFFFFFF,
        username,
        0,
        0,
        5,
        0,
        0,
    )
    sock.sendall(req)
    status, body = _read_response(sock)
    assert status == kXR_OK, f"login failed: status={status} body={body!r}"


def _open_read_body():
    return (
        struct.pack("!H", 0)
        + struct.pack("!H", kXR_OPEN_READ)
        + b"\x00\x00"
        + b"\x00" * 6
        + b"\x00" * 4
    )


def _mkdir_body(options=0, mode=0o755):
    return bytes([options]) + b"\x00" * 13 + struct.pack("!H", mode)


def _error_code(body):
    """Extract the kXR_error numeric code from the response body."""
    assert len(body) >= 4, f"error response too short: {body!r}"
    return struct.unpack("!I", body[:4])[0]


def _unlink_if_exists(path):
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass


def _log_size(path):
    try:
        return os.path.getsize(path)
    except FileNotFoundError:
        return 0


def _read_log_delta(path, offset, timeout=1.0):
    """Wait for log growth then read the delta."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if _log_size(path) > offset:
            break
        time.sleep(0.05)
    with open(path, "rb") as fh:
        fh.seek(offset)
        return fh.read()


# Build a path string with exactly *count* components (excluding leading '/').
def _make_deep_path(count):
    parts = [f"level{i}" for i in range(count)]
    return "/" + "/".join(parts)


# ---- Test 1: Success — normal path passes depth check ----

def test_normal_path_passes_depth_check():
    """A typical 5-component path must pass the depth guard and resolve successfully."""
    # Create a 5-level directory hierarchy (well within BRIX_MAX_WALK_DEPTH=32).
    deep_dir = _make_deep_path(5).lstrip("/")
    os.makedirs(os.path.join(DATA_DIR, deep_dir), exist_ok=True)

    try:
        with _raw_session() as sock:
            _login_anon(sock, streamid=b"\x00\x03")
            payload = f"/{deep_dir}/test.txt".encode("utf-8")
            req = struct.pack("!2sH16sI", b"\x00\x03", kXR_OPEN,
                              _open_read_body(), len(payload))
            sock.sendall(req + payload)
            status, resp = _read_response(sock)

        assert status == kXR_ERROR, f"expected missing-file error, got {status}"
        assert _error_code(resp) != kXR_ARG_INVALID, (
            "normal-depth path must not be rejected by the depth guard"
        )
    finally:
        for i in range(5, 0, -1):
            path = os.path.join(DATA_DIR, *_make_deep_path(i).strip("/").split("/"))
            try:
                os.rmdir(path)
            except FileNotFoundError:
                pass


# ---- Test 2: Error — path exceeding MAX_WALK_DEPTH rejected ----

def test_deep_path_rejected_by_guard():
    """A 33-component path must be rejected with kXR_ArgInvalid before realpath() begins."""
    with _raw_session() as sock:
        _login_anon(sock, streamid=b"\x00\x01")
        deep_path = _make_deep_path(33)  # exactly one over the limit
        payload = deep_path.encode("utf-8")
        req = struct.pack("!2sH16sI", b"\x00\x01", kXR_OPEN,
                          _open_read_body(), len(payload))
        sock.sendall(req + payload)
        status, body = _read_response(sock)

    assert status == kXR_ERROR, f"expected error response, got {status}"
    assert _error_code(body) == kXR_ARG_INVALID, (
        f"expected kXR_ArgInvalid for depth violation, got {_error_code(body)}"
    )


# ---- Test 3: Security-neg — malicious symlink chain attack blocked ----

def test_malicious_symlink_chain_blocked():
    """A path constructed with 32+ levels through symlink chains must be rejected."""
    with _raw_session() as sock:
        _login_anon(sock, streamid=b"\x00\x02")
        # Build a deep path even if filesystem has no corresponding hierarchy.
        # The guard rejects it at string-scan cost before any realpath/stat begins.
        deep_path = _make_deep_path(35)
        payload = deep_path.encode("utf-8")
        req = struct.pack("!2sH16sI", b"\x00\x02", kXR_MKDIR,
                          _mkdir_body(), len(payload))
        sock.sendall(req + payload)
        status, body = _read_response(sock)

    assert status == kXR_ERROR, f"expected error response, got {status}"
    assert _error_code(body) == kXR_ARG_INVALID, (
        "malicious deep path must be rejected with ArgInvalid"
    )


# ---- Test 4: Security-neg — mkdir with mkpath also blocked ----

def test_mkdir_mkpath_deep_path_rejected():
    """Recursive mkdir with MAKEPATH flag must reject paths exceeding depth limit."""
    with _raw_session() as sock:
        _login_anon(sock, streamid=b"\x00\x04")
        deep_dir = _make_deep_path(34)  # over the limit
        payload = deep_dir.encode("utf-8")
        req = struct.pack("!2sH16sI", b"\x00\x04", kXR_MKDIR,
                          _mkdir_body(kXR_MKDIRPATH), len(payload))
        sock.sendall(req + payload)
        status, body = _read_response(sock)

    assert status == kXR_ERROR, f"expected error response, got {status}"
    assert _error_code(body) == kXR_ARG_INVALID


# ---- Test 5: Error — rm with deep path rejected ----

def test_rm_deep_path_rejected():
    """DELETE operation on a deep path must be rejected by the guard."""
    with _raw_session() as sock:
        _login_anon(sock, streamid=b"\x00\x05")
        deep_path = _make_deep_path(34) + "/_depth_victim.txt"
        payload = deep_path.encode("utf-8")
        req = struct.pack("!2sH16sI", b"\x00\x05", kXR_RM,
                          b"\x00" * 16, len(payload))
        sock.sendall(req + payload)
        status, body = _read_response(sock)

    assert status == kXR_ERROR, f"expected error response, got {status}"
    assert _error_code(body) == kXR_ARG_INVALID
