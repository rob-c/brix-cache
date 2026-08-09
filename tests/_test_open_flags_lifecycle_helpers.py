"""
tests/test_open_flags_lifecycle.py — raw-wire conformance for kXR_open flags
and the open/close file-handle lifecycle.

This suite drives kXR_open at the wire level (the Python XRootD client
sanitises flags before they reach the wire, so we frame ClientOpenRequest by
hand exactly like tests/test_readv_security.py) to assert the documented
XRootD open semantics implemented in src/protocols/root/read/open_request.c and
src/protocols/root/read/open_resolved_file.c:

  * kXR_new on an existing path -> O_EXCL -> EEXIST -> kXR_ItExists
  * kXR_delete truncates an existing file to zero (O_CREAT|O_TRUNC)
  * kXR_open_apnd appends (O_WRONLY|O_APPEND)
  * kXR_mkpath creates missing parent directories
  * kXR_retstat returns the inline stat string appended to ServerOpenBody
  * an invalid flag combination (kXR_open_apnd|kXR_delete) is handled cleanly
  * kXR_posc on a clean close persists the staged file to its final name
  * kXR_posc on an aborted (disconnect) close leaves NO final file
  * opening more than BRIX_MAX_FILES (16) handles -> clean kXR_ServerError
  * closing an already-closed handle -> kXR_FileNotOpen
  * writing to a read-only handle -> kXR_NotAuthorized

Read/flag-only cases run against the shared anon fleet (root://localhost:11094)
and skip cleanly if it is unreachable.  Create/POSC/exhaustion cases need
writable storage, so they provision their OWN dedicated nginx-xrootd stream
server (brix_allow_write on) on a dedicated high port (>=12950) with its own
data root, pid and error log, and tear it down with `nginx -s stop`.  Every
hostile or edge request is followed by a sanity op (kXR_ping / kXR_open)
proving the session survived.

Run:
    TEST_SKIP_SERVER_SETUP=1 PYTHONPATH=tests pytest tests/test_open_flags_lifecycle.py -v
"""

import os
import shutil
import socket
import struct
import time

import pytest

from settings import (
    DATA_ROOT,
    NGINX_ANON_PORT,
    OPEN_FLAGS_LIFECYCLE_DATA_ROOT,
    OPEN_FLAGS_LIFECYCLE_NGINX_PORT,
    SERVER_HOST,
)


# ---------------------------------------------------------------------------
# Opcodes / status / error codes (XProtocol.hh)
# ---------------------------------------------------------------------------

kXR_login = 3007
kXR_open  = 3010
kXR_ping  = 3011
kXR_read  = 3013
kXR_write = 3019
kXR_close = 3003

kXR_ok    = 0
kXR_error = 4003

# XErrorCode (XProtocol.hh)
kXR_ArgInvalid    = 3000
kXR_FileLocked    = 3003
kXR_FileNotOpen   = 3004
kXR_IOError       = 3007
kXR_NotAuthorized = 3010
kXR_NotFound      = 3011
kXR_ServerError   = 3012
kXR_Unsupported   = 3013
kXR_ItExists      = 3018

# An exclusive-create over an existing file (EEXIST).  The canonical XRootD
# mapping (XProtocol::mapError) returns kXR_ItExists (3018); nginx-xrootd's
# open handler (src/protocols/root/read/open_resolved_file.c) currently maps EEXIST to
# kXR_FileLocked (3003) with message "file already exists".  Both communicate
# the same EEXIST semantic to the client, so we accept either to remain a
# conformance check rather than pinning an implementation detail.
_EEXIST_CODES = (kXR_ItExists, kXR_FileLocked)

# XOpenRequestOption (XProtocol.hh)
kXR_delete    = 0x0002
kXR_new       = 0x0008
kXR_open_read = 0x0010
kXR_open_updt = 0x0020
kXR_mkpath    = 0x0100
kXR_open_apnd = 0x0200
kXR_retstat   = 0x0400
kXR_posc      = 0x1000

# BRIX_MAX_FILES (src/core/types/tunables.h) — handles are a single wire byte.
BRIX_MAX_FILES = 16

# ServerOpenBody is fhandle[4] + cpsize[4] + cptype[4] = 12 bytes; with
# kXR_retstat a null-terminated stat string is appended after it.
OPEN_BODY_LEN = 12

ANON_HOST = SERVER_HOST
ANON_PORT = NGINX_ANON_PORT


# ---------------------------------------------------------------------------
# Raw socket helpers (mirror tests/test_readv_security.py exactly)
# ---------------------------------------------------------------------------

def _recv_exact(sock, nbytes):
    data = bytearray()
    while len(data) < nbytes:
        chunk = sock.recv(nbytes - len(data))
        if not chunk:
            raise ConnectionError(
                f"socket closed, {nbytes - len(data)} bytes remaining")
        data.extend(chunk)
    return bytes(data)


def _read_response(sock):
    header = _recv_exact(sock, 8)
    streamid, status, dlen = struct.unpack("!2sHI", header)
    body = _recv_exact(sock, dlen) if dlen else b""
    return streamid, status, body


def _handshake(host, port):
    sock = socket.create_connection((host, port), timeout=8)
    sock.settimeout(8)
    sock.sendall(struct.pack("!IIIII", 0, 0, 0, 4, 2012))
    _, status, _ = _read_response(sock)
    assert status == kXR_ok, "handshake rejected"
    return sock


def _login(sock, streamid=b"\x00\x01"):
    req = struct.pack("!2sHI8sBBBBI",
                      streamid, kXR_login,
                      os.getpid() & 0xFFFFFFFF,
                      b"pytest\x00\x00", 0, 0, 5, 0, 0)
    sock.sendall(req)
    return _read_response(sock)


def _session(host=ANON_HOST, port=ANON_PORT):
    sock = _handshake(host, port)
    _, status, _ = _login(sock)
    assert status == kXR_ok, "login rejected"
    return sock


def _open(sock, path, options=kXR_open_read, mode=0o644, streamid=b"\x00\x02"):
    """Frame ClientOpenRequest by hand: mode(u16) options(u16) optiont(u16)
    reserved[6] fhtemplt[4] dlen(i32), then the null-terminated path."""
    p = path.encode() + b"\x00" if isinstance(path, str) else path
    req = struct.pack("!2sHHH2s6s4sI",
                      streamid, kXR_open,
                      mode, options, b"\x00\x00", b"\x00" * 6, b"\x00" * 4,
                      len(p))
    sock.sendall(req + p)
    return _read_response(sock)


def _close(sock, fhandle, streamid=b"\x00\x0e"):
    req = struct.pack("!2sH4s12sI", streamid, kXR_close, fhandle,
                      b"\x00" * 12, 0)
    sock.sendall(req)
    return _read_response(sock)


def _write(sock, fhandle, offset, payload, streamid=b"\x00\x09"):
    """ClientWriteRequest: fhandle[4] offset(i64) pathid(1) reserved[3] dlen."""
    req = struct.pack("!2sH4sqB3sI", streamid, kXR_write, fhandle,
                      offset, 0, b"\x00\x00\x00", len(payload))
    sock.sendall(req + payload)
    return _read_response(sock)


def _read(sock, fhandle, offset, rlen, streamid=b"\x00\x06"):
    req = struct.pack("!2sH4sqiI", streamid, kXR_read, fhandle,
                      offset, rlen, 0)
    sock.sendall(req)
    return _read_response(sock)


def _ping(sock, streamid=b"\x00\x0f"):
    req = struct.pack("!2sH16sI", streamid, kXR_ping, b"\x00" * 16, 0)
    sock.sendall(req)
    return _read_response(sock)


def _error_code(body):
    return struct.unpack("!I", body[:4])[0] if len(body) >= 4 else 0


# ---------------------------------------------------------------------------
# Writable-server access — the server is a pre-started dedicated instance
# ---------------------------------------------------------------------------

H = SERVER_HOST

# The writable stream server is now a dedicated instance pre-started by
# manage_test_servers.sh start-all ("open-flags-lifecycle" on port 12980,
# serving data-open-flags-lifecycle); the wr_stack fixture just connects to it.
WR_NGINX_PORT = OPEN_FLAGS_LIFECYCLE_NGINX_PORT


def _reachable(host, port, timeout=1.0):
    try:
        socket.create_connection((host, port), timeout=timeout).close()
        return True
    except OSError:
        return False


# NOTE: the writable server is no longer spawned here — it is the pre-started
# "open-flags-lifecycle" dedicated instance (see manage_test_servers.sh
# start-all). The former _writable_nginx_conf/_start_nginx/_stop_nginx/_wait_port
# helpers were removed with that migration; wr_stack now just connects.


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def anon():
    """Require the shared anon stream fleet for read/flag-only cases; skip if
    unreachable, exactly like test_readv_security.py's _require_server."""
    if not _reachable(ANON_HOST, ANON_PORT, 3):
        pytest.skip(f"anon stream server {ANON_HOST}:{ANON_PORT} unreachable")
    return (ANON_HOST, ANON_PORT)


@pytest.fixture(scope="module")
def wr_stack():
    """Connect to the dedicated WRITABLE nginx xrootd server pre-started by
    manage_test_servers.sh start-all (the "open-flags-lifecycle" instance,
    brix_allow_write on, serving OPEN_FLAGS_LIFECYCLE_DATA_ROOT).  Used for
    create/truncate/append/mkpath/POSC/exhaustion cases.  Skips cleanly if that
    dedicated instance is not running.  The server and this test share the local
    filesystem, so files seeded into data_dir are visible to the server and the
    server's writes are visible to the test's assertions."""
    data_dir = OPEN_FLAGS_LIFECYCLE_DATA_ROOT
    os.makedirs(data_dir, exist_ok=True)
    if not _reachable(H, WR_NGINX_PORT, 3):
        pytest.skip(
            f"dedicated writable nginx not reachable on {H}:{WR_NGINX_PORT} — "
            f"run tests/manage_test_servers.sh start-all")
    return {"host": H, "port": WR_NGINX_PORT, "data_dir": data_dir}


@pytest.fixture(scope="module")
def ro_data(anon):
    """A known read-only data file under the shared anon data root."""
    name = "/test_open_flags_ro.bin"
    os.makedirs(DATA_ROOT, exist_ok=True)
    full = os.path.join(DATA_ROOT, name.lstrip("/"))
    with open(full, "wb") as f:
        f.write(b"OPEN-FLAGS-RO-" * 64)
    return name


def _wr_seed(wr_stack, rel, data):
    """Materialise a file directly under the writable server's data root."""
    full = os.path.join(wr_stack["data_dir"], rel.lstrip("/"))
    os.makedirs(os.path.dirname(full), exist_ok=True)
    with open(full, "wb") as f:
        f.write(data)
    return full


def _wr_full(wr_stack, rel):
    return os.path.join(wr_stack["data_dir"], rel.lstrip("/"))


def _wr_clear_staging(wr_stack, rel):
    """Idempotent cleanup for a POSC/create target on the persistent /tmp data
    root: remove the final file AND any staging siblings a prior *aborted* run
    left behind — the POSC temp ("<base>.xrd-tmp.*") and, crucially, the
    checkpoint-resume partial ("<base>.xrdresume.*.part"). A stale resume partial
    makes the server treat a fresh kXR_new (exclusive-create) POSC open as
    "already exists" (kXR_ItExists / 3018), so a carried-over partial from an
    earlier run would wedge this test forever."""
    final = _wr_full(wr_stack, rel)
    if os.path.exists(final):
        os.unlink(final)
    data_dir = wr_stack["data_dir"]
    base = os.path.basename(rel.lstrip("/"))
    for name in os.listdir(data_dir):
        if name.startswith(base + ".xrd"):
            try:
                os.unlink(os.path.join(data_dir, name))
            except OSError:
                pass


# ===========================================================================
# kXR_open flag semantics
# ===========================================================================
