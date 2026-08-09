"""
Data sub-streams (kXR_bind) as a PARALLEL DATA-TRANSFER mechanism.

`test_session_bind.py` proves the mechanics of a single bound secondary (pathid
assignment, one bound read, slot-hint cache, revocation).  This suite proves the
property the *client* relies on when it uses sub-streams for a transfer: several
bound secondary connections can read DISJOINT regions of one primary-published
handle in parallel and the concatenation reassembles the whole object byte-exact
— including under genuinely concurrent (threaded) in-flight reads.

The server default is `brix_data_substreams on`, so the shared anonymous endpoint
already accepts binds; no special server config is needed (that default is itself
asserted by `test_server_default_accepts_bind`).

Run:
    PYTHONPATH=tests pytest tests/test_data_substreams_parallel.py -v
"""

import os
import socket
import struct
import subprocess
import threading
import zlib

import pytest

from settings import DATA_ROOT

# The directory the target anon endpoint exports.  In the standard fleet the
# anonymous main-nginx exports DATA_ROOT, so that is the default and keeps this
# suite CI-correct.  A bespoke BriX endpoint (e.g. a hand-launched substreams-ON
# server on another port) can redirect writes here via BRIX_SUBS_EXPORT_DIR so
# the suite can be validated against it without touching the fleet.
EXPORT_DIR = os.environ.get("BRIX_SUBS_EXPORT_DIR", DATA_ROOT)

# Native-client binaries, defined in the SHARED helper so every split shard
# (test_data_substreams_parallel.py and its _b continuation) sees them via
# reexport — _server_checksum below and the _b shard's tests use them.
_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_XRDCP = os.path.join(_REPO, "client", "bin", "xrdcp")
_XRDFS = os.path.join(_REPO, "client", "bin", "xrdfs")

# ---------------------------------------------------------------------------
# Wire constants
# ---------------------------------------------------------------------------
kXR_ok        = 0
kXR_oksofar   = 4000
kXR_error     = 4003
kXR_protocol  = 3006
kXR_login     = 3007
kXR_open      = 3010
kXR_read      = 3013
kXR_bind      = 3024
kXR_close     = 3003
kXR_write     = 3019
kXR_open_read = 0x0010
kXR_open_updt = 0x0020  # open for update/write
kXR_new       = 0x0008  # create new
kXR_delete    = 0x0002  # delete/overwrite


# ---------------------------------------------------------------------------
# Raw-socket helpers (self-contained; host/port passed explicitly)
# ---------------------------------------------------------------------------
def _recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def _send_req(sock, streamid, reqid, body=b"", payload=b""):
    hdr = bytes(streamid[:2]) + struct.pack(">H", reqid)
    hdr += body.ljust(16, b"\x00")
    hdr += struct.pack(">I", len(payload))
    sock.sendall(hdr + payload)
    rsp_hdr = _recv_exact(sock, 8)
    assert rsp_hdr is not None, "no response header"
    status = struct.unpack(">H", rsp_hdr[2:4])[0]
    dlen = struct.unpack(">I", rsp_hdr[4:8])[0]
    data = _recv_exact(sock, dlen) if dlen else b""
    return status, data


def _handshake(sock):
    sock.sendall(struct.pack(">IIIII", 0, 0, 0, 4, 2012))
    _recv_exact(sock, 16)  # 8B hdr + 8B body


def _establish_primary(host, port):
    sock = socket.create_connection((host, port))
    _handshake(sock)
    status, _ = _send_req(sock, b"\x00\x01", kXR_protocol)
    assert status == kXR_ok, "protocol"
    status, sessid_body = _send_req(sock, b"\x00\x01", kXR_login,
                                    payload=b"anonymous\x00")
    assert status == kXR_ok and len(sessid_body) >= 16, "login"
    return sock, sessid_body[:16]


def _bind_secondary(host, port, sessid, streamid):
    sock = socket.create_connection((host, port))
    _handshake(sock)
    status, pathid_body = _send_req(sock, streamid, kXR_bind, body=sessid)
    assert status == kXR_ok, f"bind failed: status={status}"
    assert len(pathid_body) == 1, "pathid body must be 1 byte"
    return sock, pathid_body[0]


def _open_read(sock, streamid, path):
    open_body = struct.pack(">HH", 0o644, kXR_open_read) + b"\x00" * 12
    status, body = _send_req(sock, streamid, kXR_open, body=open_body,
                             payload=path.encode() + b"\x00")
    assert status == kXR_ok and len(body) >= 4, f"open failed: status={status}"
    return body[:4]


def _read_range(sock, streamid, fhandle, offset, length):
    """Read exactly `length` bytes from `offset`, looping over kXR_oksofar /
    server-side chunking.  Returns the assembled bytes (may be short only if the
    server signals EOF)."""
    out = b""
    pos = offset
    remaining = length
    while remaining > 0:
        body = fhandle + struct.pack(">q", pos) + struct.pack(">i", remaining)
        status, data = _send_req(sock, streamid, kXR_read, body=body)
        assert status in (kXR_ok, kXR_oksofar), f"read status {status}"
        if not data:
            break
        out += data
        pos += len(data)
        remaining -= len(data)
        if status == kXR_ok and len(data) < remaining + len(data):
            # a kXR_ok short read is EOF for this request window
            if len(data) < (length - (len(out) - len(data))):
                # nothing more expected once the server returned a final ok
                pass
    return out


def _write_data_file(name, content):
    os.makedirs(EXPORT_DIR, exist_ok=True)
    with open(os.path.join(EXPORT_DIR, name), "wb") as f:
        f.write(content)


def _rm_export_file(name):
    os.makedirs(EXPORT_DIR, exist_ok=True)
    try:
        os.remove(os.path.join(EXPORT_DIR, name))
    except FileNotFoundError:
        pass


def _read_export_file(name):
    with open(os.path.join(EXPORT_DIR, name), "rb") as f:
        return f.read()


def _open_write(sock, streamid, path):
    """Open a file for write (create/overwrite), returning its 4-byte fhandle."""
    opts = kXR_open_updt | kXR_new | kXR_delete
    open_body = struct.pack(">HH", 0o644, opts) + b"\x00" * 12
    status, body = _send_req(sock, streamid, kXR_open, body=open_body,
                             payload=path.encode() + b"\x00")
    assert status == kXR_ok and len(body) >= 4, f"write-open failed: status={status}"
    return body[:4]


def _write_range(sock, streamid, fhandle, offset, data, pathid=0):
    """Send one kXR_write (header + payload) on `sock`.  Returns the reply status.
    A bound secondary carries the WHOLE write inline (pathid 0) — the connection
    itself is the substream, mirroring the bound-read routing."""
    body = fhandle + struct.pack(">q", offset) + bytes([pathid]) + b"\x00" * 3
    status, _ = _send_req(sock, streamid, kXR_write, body=body, payload=data)
    return status


def _close_handle(sock, streamid, fhandle):
    body = fhandle + b"\x00" * 12
    status, _ = _send_req(sock, streamid, kXR_close, body=body)
    return status


def _det(n):
    """Deterministic period-251 content, tiled to n bytes."""
    p = bytes(i % 251 for i in range(251))
    full, rem = divmod(n, 251)
    return p * full + p[:rem]


# ---------------------------------------------------------------------------
# Fixture — shared anonymous (substreams-ON-by-default) endpoint
# ---------------------------------------------------------------------------
@pytest.fixture(scope="module")
def endpoint(test_env):
    return test_env["server_host"], test_env["anon_port"]

def _server_checksum(host, port, name):
    """Ask the server to compute the checksum of an already-stored file (kXR_query
    checksum via `brix-xrdfs query checksum`).  Returns (algo, hexdigest)."""
    res = subprocess.run(
        [_XRDFS, f"root://{host}:{port}/", "query", "checksum", f"/{name}"],
        capture_output=True, text=True, timeout=60)
    assert res.returncode == 0, f"xrdfs query checksum failed: {res.stderr}"
    parts = res.stdout.split()
    assert len(parts) >= 2, f"unexpected checksum reply: {res.stdout!r}"
    return parts[0], parts[1].lower()
