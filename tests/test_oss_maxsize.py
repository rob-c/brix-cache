"""brix_oss_maxsize — the oss.maxsize create-size cap (parity audit §3.9).

A data write whose END offset (offset + len) would push the file past the
configured cap is refused with kXR_overQuota, enforced on the whole root://
write plane (kXR_write / kXR_pgwrite / kXR_writev) so a client that omits or
understates the oss.asize hint is still stopped at the crossing byte. Default
0 = no cap (byte-identical to the pre-knob behaviour).

The probes drive the raw wire so the exact boundary and the kXR_overQuota code
are pinned, and xrdcp for an end-to-end integration check.

Coverage (the change-class trio):
  * success      — cap 64k: a 32 KiB xrdcp upload lands byte-exact; a raw
                   kXR_write ending exactly AT the cap is accepted.
  * error        — cap 64k: a raw kXR_write ending ONE byte past the cap is
                   refused kXR_overQuota, and a 128 KiB xrdcp upload fails
                   leaving no committed file.
  * security-neg — the default (no directive) accepts the same 128 KiB
                   upload — the cap must never apply unless configured; and a
                   writev whose LAST segment crosses the cap refuses the whole
                   vector, leaving nothing written.

Run:
    TEST_SKIP_SERVER_SETUP=1 PYTHONPATH=tests pytest tests/test_oss_maxsize.py -v
"""

import os
import shutil
import socket
import struct
import subprocess

import pytest

from settings import HOST, BIND_HOST, NGINX_BIN
from server_registry import NginxInstanceSpec

pytestmark = [pytest.mark.timeout(120), pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-oss-maxsize")]

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLIENT_DIR = os.path.join(REPO, "client")
XRDCP = os.path.join(CLIENT_DIR, "bin", "xrdcp")

CAP = 64 * 1024

# wire constants
kXR_protocol, kXR_login, kXR_open, kXR_write, kXR_writev, kXR_close = \
    3006, 3007, 3010, 3019, 3031, 3003
kXR_ok, kXR_error = 0, 4003
kXR_overQuota = 3021
kXR_open_updt, kXR_new, kXR_delete = 0x0020, 0x0008, 0x0002
WRITEV_SEGSIZE = 16


@pytest.fixture(scope="module")
def _client_built():
    if shutil.which("cc") is None and shutil.which("gcc") is None:
        pytest.skip("no C compiler")
    subprocess.run(["make", "-C", CLIENT_DIR, "xrdcp"],
                   capture_output=True, text=True, timeout=240)
    if not os.path.exists(XRDCP):
        pytest.skip("xrdcp build failed")


def _start(lifecycle, tmp_path, maxsize_line):
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx not executable: {NGINX_BIN}")
    data = tmp_path / "data"
    data.mkdir(exist_ok=True)
    ep = lifecycle.start(NginxInstanceSpec(
        name="lc-oss-maxsize",
        template="nginx_lc_oss_maxsize.conf",
        protocol="root",
        template_values={"BIND_HOST": BIND_HOST, "DATA_DIR": str(data),
                         "MAXSIZE_LINE": maxsize_line},
        reason="brix_oss_maxsize create-size cap postures"))
    return ep.port, data


# --------------------------------------------------------------------------- #
# raw-wire helpers
# --------------------------------------------------------------------------- #

def _recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def _resp(sock):
    hdr = _recv_exact(sock, 8)
    assert hdr is not None, "connection closed mid-response"
    status = struct.unpack(">H", hdr[2:4])[0]
    dlen = struct.unpack(">I", hdr[4:8])[0]
    return status, (_recv_exact(sock, dlen) or b"") if dlen else b""


def _send(sock, streamid, reqid, body=b"", payload=b""):
    hdr = bytes(streamid[:2]) + struct.pack(">H", reqid)
    hdr += body.ljust(16, b"\x00") + struct.pack(">I", len(payload))
    sock.sendall(hdr + payload)
    return _resp(sock)


def _connect(port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)
    sock.connect((HOST, port))
    sock.sendall(struct.pack(">IIIII", 0, 0, 0, 4, 2012))
    assert _recv_exact(sock, 16) is not None
    status, _ = _send(sock, b"\x00\x01", kXR_protocol)
    assert status == kXR_ok
    status, _ = _send(sock, b"\x00\x01", kXR_login, payload=b"anonymous\x00")
    assert status == kXR_ok
    return sock


def _open_write(sock, xrd_path):
    flags = kXR_open_updt | kXR_new | kXR_delete
    body = struct.pack(">HH", 0o644, flags) + b"\x00" * 12
    status, rbody = _send(sock, b"\x00\x01", kXR_open, body=body,
                          payload=xrd_path.encode() + b"\x00")
    assert status == kXR_ok, f"open failed: {status}"
    return rbody[:4]


def _write_at(sock, fh, offset, data):
    body = fh + struct.pack(">q", offset) + b"\x00" * 4
    return _send(sock, b"\x00\x02", kXR_write, body=body, payload=data)


def _writev(sock, segs):
    """segs = [(fh, offset, bytes)]; one kXR_writev. Stock framing: the request
    dlen frames ONLY the 16-byte descriptors; the segment data streams after
    the frame (the server's recv framing extends the read by sum(wlen))."""
    desc = b""
    data = b""
    for fh, off, payload in segs:
        desc += fh + struct.pack(">I", len(payload)) + struct.pack(">q", off)
        data += payload
    hdr = b"\x00\x03" + struct.pack(">H", kXR_writev)
    hdr += b"\x00" * 16 + struct.pack(">I", len(desc))
    sock.sendall(hdr + desc + data)
    return _resp(sock)


def _err_code(body):
    return struct.unpack(">I", body[:4])[0] if len(body) >= 4 else None


# --------------------------------------------------------------------------- #
# success
# --------------------------------------------------------------------------- #

def test_under_cap_upload_and_boundary_write(lifecycle, tmp_path,
                                             _client_built):
    """(success) a 32 KiB xrdcp upload lands byte-exact under a 64k cap, and a
    raw write ending exactly AT the cap is accepted."""
    port, data = _start(lifecycle, tmp_path, f"brix_oss_maxsize {CAP};")
    payload = os.urandom(32 * 1024)
    src = tmp_path / "src.bin"
    src.write_bytes(payload)
    proc = subprocess.run([XRDCP, "-f", str(src),
                           f"root://{HOST}:{port}//under.bin"],
                          capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, f"under-cap upload failed: {proc.stderr}"
    assert (data / "under.bin").read_bytes() == payload

    sock = _connect(port)
    try:
        fh = _open_write(sock, "/boundary.bin")
        # A single write of exactly CAP bytes at offset 0 ends AT the cap.
        status, _ = _write_at(sock, fh, 0, b"x" * CAP)
        assert status == kXR_ok, "write ending exactly at the cap was refused"
    finally:
        sock.close()


# --------------------------------------------------------------------------- #
# error
# --------------------------------------------------------------------------- #

def test_one_byte_over_cap_refused(lifecycle, tmp_path, _client_built):
    """(error) a raw write ending ONE byte past the cap is refused
    kXR_overQuota."""
    port, _data = _start(lifecycle, tmp_path, f"brix_oss_maxsize {CAP};")
    sock = _connect(port)
    try:
        fh = _open_write(sock, "/over.bin")
        status, body = _write_at(sock, fh, 0, b"x" * (CAP + 1))
        assert status == kXR_error, "over-cap write was not refused"
        assert _err_code(body) == kXR_overQuota, \
            f"expected kXR_overQuota(3021), got {_err_code(body)}"
    finally:
        sock.close()


def test_over_cap_upload_leaves_no_file(lifecycle, tmp_path, _client_built):
    """(error) a 128 KiB xrdcp upload against a 64k cap fails and commits no
    file at the destination."""
    port, data = _start(lifecycle, tmp_path, f"brix_oss_maxsize {CAP};")
    src = tmp_path / "big.bin"
    src.write_bytes(os.urandom(128 * 1024))
    proc = subprocess.run([XRDCP, "-f", str(src),
                           f"root://{HOST}:{port}//big.bin"],
                          capture_output=True, text=True, timeout=60)
    assert proc.returncode != 0, "over-cap upload unexpectedly succeeded"
    assert not (data / "big.bin").exists(), \
        "a refused over-cap upload left a committed file"


# --------------------------------------------------------------------------- #
# security-neg
# --------------------------------------------------------------------------- #

def test_default_is_uncapped(lifecycle, tmp_path, _client_built):
    """(security-neg for compatibility) no directive: the same 128 KiB upload
    succeeds — the cap must never apply unless explicitly configured."""
    port, data = _start(lifecycle, tmp_path, "")
    payload = os.urandom(128 * 1024)
    src = tmp_path / "big.bin"
    src.write_bytes(payload)
    proc = subprocess.run([XRDCP, "-f", str(src),
                           f"root://{HOST}:{port}//big.bin"],
                          capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, f"default posture grew a cap: {proc.stderr}"
    assert (data / "big.bin").read_bytes() == payload


def test_writev_crossing_segment_refuses_whole_vector(lifecycle, tmp_path,
                                                      _client_built):
    """(security-neg) a writev whose LAST segment crosses the cap refuses the
    ENTIRE vector — the earlier in-bounds segment must not be written either,
    so a partial vector can never leak past the limit."""
    port, data = _start(lifecycle, tmp_path, f"brix_oss_maxsize {CAP};")
    sock = _connect(port)
    try:
        fh = _open_write(sock, "/vec.bin")
        # seg0: 1 KiB at offset 0 (in bounds); seg1: 1 KiB ending 1 byte past.
        status, body = _writev(sock, [
            (fh, 0, b"a" * 1024),
            (fh, CAP - 1023, b"b" * 1024),   # ends at CAP+1
        ])
        assert status == kXR_error, "crossing writev was not refused"
        assert _err_code(body) == kXR_overQuota, \
            f"expected kXR_overQuota, got {_err_code(body)}"
    finally:
        sock.close()
    # Nothing committed from the refused vector: the file is either absent
    # (never committed) or present-but-empty — never carrying the in-bounds
    # segment's bytes.
    vec = data / "vec.bin"
    assert (not vec.exists()) or vec.stat().st_size == 0, \
        "a refused writev leaked its in-bounds segment to disk"
