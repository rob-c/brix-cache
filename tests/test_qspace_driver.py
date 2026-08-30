"""kXR_Qspace + kXR_QFSinfo driver-space seam + sd_xroot forwarding (audit §4.6).

BOTH filesystem-capacity reports — kXR_Qspace (detailed oss.* bytes) and
kXR_QFSinfo (the compact "wVal freeMB util sVal freeMB util" that CMS/kXR_locate
reads to pick a writable server) — reported the LOCAL export root's statvfs,
even for a backend whose real capacity lives elsewhere. Both now consult the
shared `query_space_probe` (the once-dormant `brix_vfs_space` seam) first, so:
  * a pblock export with a byte quota reports its QUOTA (not the host FS);
  * a proxy whose backend is a remote root:// origin forwards the query to the
    origin (sd_xroot `.space` slot → brix_cache_origin_query_space);
  * a plain POSIX export declines the seam and falls back to local statvfs —
    byte-for-byte the prior behaviour.

Because Qspace and QFSinfo now share one probe, they can never disagree about
which store's free space a proxy advertises — so each test asserts BOTH reports
against the same live backend.

The discriminator is a pblock quota: sd_pblock_space reports quota_bytes, a
value distinct from the host filesystem's (multi-GB) statvfs.

Coverage (the change-class trio, each ×{Qspace, QFSinfo}):
  * success      — pblock ?quota=150m: Qspace oss.space == 150 MiB and QFSinfo
                   freeMB is quota-bounded (<= 150) — the seam is consulted.
  * error/forward— proxy over a pblock-quota origin: both reports read the
                   origin's quota — forwarded, not the proxy's host-FS statvfs.
  * security-neg — plain posix export: both still report the host FS (>> the
                   150 MiB quota) — the statvfs fallback is intact.

Run:
    TEST_SKIP_SERVER_SETUP=1 PYTHONPATH=tests pytest tests/test_qspace_driver.py -v
"""

import os
import socket
import struct

import pytest

from settings import HOST, BIND_HOST, NGINX_BIN
from server_registry import NginxInstanceSpec

pytestmark = [pytest.mark.timeout(120), pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-qspace")]

kXR_login, kXR_query = 3007, 3001
kXR_Qspace = 5
kXR_QFSinfo = 10
kXR_ok = 0
QUOTA_BYTES = 150 * 1024 * 1024
QUOTA_MB = 150


def _start(lifecycle, name, backend):
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx not executable: {NGINX_BIN}")
    ep = lifecycle.start(NginxInstanceSpec(
        name=name,
        template="nginx_lc_qspace.conf",
        protocol="root",
        readiness="tcp",
        template_values={"BIND_HOST": BIND_HOST, "STORAGE_BACKEND": backend},
        reason="kXR_Qspace driver-space seam"))
    return ep.port


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
    status = struct.unpack("!H", hdr[2:4])[0]
    dlen = struct.unpack("!I", hdr[4:8])[0]
    return status, (_recv_exact(sock, dlen) or b"") if dlen else b""


def _query(port, infotype, path="/"):
    """Anon-login, then send one kXR_query of `infotype` for `path`; return the
    NUL-trimmed response body as text. Shared by the Qspace and QFSinfo probes so
    both exercise the identical wire path against the same live backend."""
    sock = socket.create_connection((HOST, port), timeout=15)
    try:
        sock.sendall(struct.pack("!IIIII", 0, 0, 0, 4, 2012))
        status, _ = _resp(sock)
        assert status == kXR_ok, "handshake failed"
        sock.sendall(struct.pack("!2sHI8sBBBBI", b"\x00\x01", kXR_login,
                                 0x7FFFFFFF & 12345, b"anon\x00\x00\x00\x00",
                                 0, 0, 0, 0, 0))
        status, _ = _resp(sock)
        assert status == kXR_ok, "anon login failed"
        arg = path.encode()
        sock.sendall(struct.pack("!2sHH14sI", b"\x00\x07", kXR_query,
                                 infotype, b"\x00" * 14, len(arg)) + arg)
        status, body = _resp(sock)
        assert status == kXR_ok, f"query infotype={infotype} not ok: {status}"
        return body.split(b"\x00", 1)[0].decode("latin-1")
    finally:
        sock.close()


def _qspace_report(port, path="/"):
    return _query(port, kXR_Qspace, path)


def _qfsinfo_report(port, path="/"):
    return _query(port, kXR_QFSinfo, path)


def _oss_total(report):
    for tok in report.split("&"):
        if tok.startswith("oss.space="):
            return int(tok[len("oss.space="):])
    raise AssertionError(f"no oss.space in report: {report}")


def _qfsinfo_free_mb(report):
    """Parse "wVal freeMB util sVal freeMB util"; return freeMB (field 1)."""
    fields = report.split()
    assert len(fields) == 6, f"unexpected QFSinfo report: {report!r}"
    return int(fields[1])


def test_pblock_quota_reported_via_seam(lifecycle, tmp_path):
    """(success) a pblock ?quota=150m export reports its quota through BOTH
    reports — Qspace oss.space == 150 MiB and QFSinfo freeMB quota-bounded —
    the driver-space seam is consulted instead of the host FS statvfs."""
    data = tmp_path / "pb"
    data.mkdir()
    port = _start(lifecycle, "lc-qspace-pblock",
                  f"pblock://{data}?quota=150m")
    assert _oss_total(_qspace_report(port)) == QUOTA_BYTES
    free_mb = _qfsinfo_free_mb(_qfsinfo_report(port))
    assert 0 < free_mb <= QUOTA_MB, \
        f"QFSinfo freeMB {free_mb} not bounded by the 150 MiB quota"


def test_proxy_forwards_qspace_to_origin(lifecycle, tmp_path):
    """(forward) a proxy whose backend is a remote pblock-quota origin reports
    the ORIGIN's quota in BOTH reports — Qspace and QFSinfo were forwarded via
    the sd_xroot .space slot, not answered from the proxy's host-FS statvfs."""
    odata = tmp_path / "origin"
    odata.mkdir()
    origin_port = _start(lifecycle, "lc-qspace-fwd-origin",
                         f"pblock://{odata}?quota=150m")
    proxy_port = _start(lifecycle, "lc-qspace-fwd-proxy",
                        f"root://{HOST}:{origin_port}")
    assert _oss_total(_qspace_report(proxy_port)) == QUOTA_BYTES
    free_mb = _qfsinfo_free_mb(_qfsinfo_report(proxy_port))
    assert 0 < free_mb <= QUOTA_MB, \
        f"proxy QFSinfo freeMB {free_mb} not forwarded from the quota origin"


def test_posix_falls_back_to_statvfs(lifecycle, tmp_path):
    """(security-neg/compat) a plain posix export declines the seam; BOTH
    reports show the host FS (>> the 150 MiB quota) — the statvfs fallback is
    intact, no behaviour change where no driver reports space."""
    data = tmp_path / "px"
    data.mkdir()
    port = _start(lifecycle, "lc-qspace-posix", f"posix:{data}")
    total = _oss_total(_qspace_report(port))
    assert total > QUOTA_BYTES, \
        f"posix export unexpectedly reported a small/quota-like total: {total}"
    free_mb = _qfsinfo_free_mb(_qfsinfo_report(port))
    assert free_mb > QUOTA_MB, \
        f"posix QFSinfo unexpectedly reported a small/quota-like freeMB: {free_mb}"
