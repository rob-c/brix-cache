"""brix_chkpnt_maxsz — the ofs.chkpnt maxsz analog (parity audit §1.11).

The kXR_chkpoint snapshot cap used to be hardwired to the protocol minimum
kXR_ckpMinMax (104857604); stock XRootD lets ``ofs.chkpnt maxsz`` raise it.
``brix_chkpnt_maxsz <size>`` now sets the cap: ckpBegin refuses larger files
with kXR_overQuota, ckpQuery reports the cap as maxCkpSize, and a configured
value BELOW the protocol minimum is silently raised to it at merge —
kXR_ckpMinMax is the "minimum maximum" every server must accept, so honoring
a lower cap would refuse checkpoints a spec-conforming client is entitled to.

Coverage (the change-class trio):
  * success      — with the cap raised to 200m a file over kXR_ckpMinMax
                   checkpoints (begin + rollback round-trip) and ckpQuery
                   reports maxCkpSize == 200m.
  * error        — with no directive the same file is refused kXR_overQuota,
                   and ckpQuery reports exactly kXR_ckpMinMax (stock default
                   posture unchanged).
  * security-neg — brix_chkpnt_maxsz 1m (below the protocol minimum) is
                   FLOORED: ckpQuery still reports kXR_ckpMinMax and a small
                   file still checkpoints — a misconfigured cap cannot refuse
                   what the spec entitles clients to.

Run:
    TEST_SKIP_SERVER_SETUP=1 PYTHONPATH=tests pytest tests/test_chkpnt_maxsz.py -v
"""

import os
import socket
import struct

import pytest

from settings import HOST, BIND_HOST, NGINX_BIN
from server_registry import NginxInstanceSpec

pytestmark = [pytest.mark.timeout(120), pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-chkpnt-maxsz")]

# wire constants (protocol/opcodes.h + flags.h)
kXR_ok, kXR_error = 0, 4003
kXR_protocol, kXR_login, kXR_open, kXR_chkpoint = 3006, 3007, 3010, 3012
kXR_overQuota = 3021
kXR_ckpBegin, kXR_ckpQuery, kXR_ckpRollback = 0, 2, 3
kXR_open_updt, kXR_new, kXR_delete = 0x0020, 0x0008, 0x0002
kXR_ckpMinMax = 104857604

OVER_MIN_SIZE = kXR_ckpMinMax + (1 << 20)     # > protocol minimum, < 200m


# --------------------------------------------------------------------------- #
# raw-socket client (framing per _test_chkpoint_stock_framing_helpers.py)
# --------------------------------------------------------------------------- #

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
    assert rsp_hdr is not None, "connection closed mid-response"
    status = struct.unpack(">H", rsp_hdr[2:4])[0]
    dlen = struct.unpack(">I", rsp_hdr[4:8])[0]
    return status, (_recv_exact(sock, dlen) or b"") if dlen else b""


def _connect(port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(15)
    sock.connect((HOST, port))
    sock.sendall(struct.pack(">IIIII", 0, 0, 0, 4, 2012))
    assert _recv_exact(sock, 16) is not None
    status, _ = _send_req(sock, b"\x00\x01", kXR_protocol)
    assert status == kXR_ok
    status, _ = _send_req(sock, b"\x00\x01", kXR_login,
                          payload=b"anonymous\x00")
    assert status == kXR_ok
    return sock


def _open_update(sock, xrd_path):
    open_body = struct.pack(">HH", 0o644, kXR_open_updt) + b"\x00" * 12
    status, body = _send_req(sock, b"\x00\x01", kXR_open, body=open_body,
                             payload=xrd_path.encode() + b"\x00")
    assert status == kXR_ok, f"open failed: {status}"
    return body[:4]


def _ckp(sock, fh, opcode):
    body = fh + b"\x00" * 11 + bytes([opcode])
    return _send_req(sock, b"\x00\x01", kXR_chkpoint, body=body)


def _err_code(body):
    return struct.unpack(">I", body[:4])[0] if len(body) >= 4 else None


# --------------------------------------------------------------------------- #
# fixture — one throwaway server per cap posture
# --------------------------------------------------------------------------- #

def _start(lifecycle, tmp_path, extra):
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx not executable: {NGINX_BIN}")
    data = tmp_path / "data"
    data.mkdir()
    ep = lifecycle.start(NginxInstanceSpec(
        name="lc-chkpnt-maxsz",
        template="nginx_lc_chkpnt_maxsz.conf",
        protocol="root",
        template_values={"BIND_HOST": BIND_HOST, "DATA_DIR": str(data),
                         "EXTRA_DIRECTIVES": extra},
        reason="brix_chkpnt_maxsz cap postures"))
    return ep.port, data


def _sparse(data_dir, name, size):
    """A sparse file: ckpBegin's copy_file_range snapshot stays cheap."""
    path = data_dir / name
    with open(path, "wb") as fh:
        fh.truncate(size)
    return f"/{name}"


# --------------------------------------------------------------------------- #
# tests
# --------------------------------------------------------------------------- #

def test_raised_cap_checkpoints_large_file_and_reports_it(lifecycle, tmp_path):
    """(success) cap 200m: a file over kXR_ckpMinMax checkpoints, and ckpQuery
    reports maxCkpSize == 200m."""
    port, data = _start(lifecycle, tmp_path, "brix_chkpnt_maxsz 200m;")
    xrd = _sparse(data, "big.bin", OVER_MIN_SIZE)

    sock = _connect(port)
    try:
        fh = _open_update(sock, xrd)
        status, body = _ckp(sock, fh, kXR_ckpQuery)
        assert status == kXR_ok, f"ckpQuery failed: {status}"
        max_ckp, _use = struct.unpack(">II", body[:8])
        assert max_ckp == 200 * 1024 * 1024, \
            f"maxCkpSize {max_ckp} != configured 200m"

        status, body = _ckp(sock, fh, kXR_ckpBegin)
        assert status == kXR_ok, \
            f"ckpBegin refused under a raised cap: {status} {body!r}"
        status, _ = _ckp(sock, fh, kXR_ckpRollback)
        assert status == kXR_ok, "rollback of the large checkpoint failed"
    finally:
        sock.close()


def test_default_cap_refuses_over_minimum(lifecycle, tmp_path):
    """(error) no directive: the same file is refused kXR_overQuota and
    ckpQuery reports exactly the protocol minimum — stock posture unchanged."""
    port, data = _start(lifecycle, tmp_path, "")
    xrd = _sparse(data, "big.bin", OVER_MIN_SIZE)

    sock = _connect(port)
    try:
        fh = _open_update(sock, xrd)
        status, body = _ckp(sock, fh, kXR_ckpQuery)
        assert status == kXR_ok
        max_ckp, _use = struct.unpack(">II", body[:8])
        assert max_ckp == kXR_ckpMinMax, \
            f"default maxCkpSize {max_ckp} != kXR_ckpMinMax"

        status, body = _ckp(sock, fh, kXR_ckpBegin)
        assert status == kXR_error, "over-minimum file checkpointed at default cap"
        assert _err_code(body) == kXR_overQuota, \
            f"expected kXR_overQuota, got {_err_code(body)}"
    finally:
        sock.close()


def test_below_minimum_cap_is_floored(lifecycle, tmp_path):
    """(security-neg) brix_chkpnt_maxsz 1m is raised to the protocol minimum:
    ckpQuery still reports kXR_ckpMinMax and a 2 MiB file (over the bogus 1m,
    under the real minimum) still checkpoints — a misconfigured cap cannot
    refuse what the spec entitles every client to."""
    port, data = _start(lifecycle, tmp_path, "brix_chkpnt_maxsz 1m;")
    xrd = _sparse(data, "small.bin", 2 * 1024 * 1024)

    sock = _connect(port)
    try:
        fh = _open_update(sock, xrd)
        status, body = _ckp(sock, fh, kXR_ckpQuery)
        assert status == kXR_ok
        max_ckp, _use = struct.unpack(">II", body[:8])
        assert max_ckp == kXR_ckpMinMax, \
            f"below-minimum cap not floored: maxCkpSize {max_ckp}"

        status, body = _ckp(sock, fh, kXR_ckpBegin)
        assert status == kXR_ok, \
            f"2 MiB checkpoint refused under a floored cap: {status} {body!r}"
        status, _ = _ckp(sock, fh, kXR_ckpRollback)
        assert status == kXR_ok
    finally:
        sock.close()
