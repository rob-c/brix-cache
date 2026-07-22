"""
GridFTP gateway — pinned passive-data-port range (brix_gridftp_pasv_port_range).

An FTP data connection lands on a *server*-chosen port that the peer must be able
to reach.  With an ephemeral (kernel-chosen) port that is un-firewallable: an
admin on a locked-down network cannot know which port to open, so every PASV/EPSV
transfer through a firewall breaks.  brix_gridftp_pasv_port_range pins those
listeners to an inclusive, pre-opened window (the equivalent of globus
GLOBUS_TCP_PORT_RANGE / vsftpd pasv_min_port..pasv_max_port).

This is the deployment knob half of the gsiftp hardening finding.  The repro that
motivates it: without the knob PASV hands out a random high port (asserted here so
a regression that silently ignores the range is caught), and a firewall that only
opens the configured window would drop every such transfer.

Covered:
  * PASV and EPSV data listeners land strictly inside the configured range
  * a real STOR + RETR actually completes over a pinned-range data channel
  * range exhaustion is refused with 425 (never a silent fall-back to a random,
    un-firewalled port)

Run:
    PYTHONPATH=tests python3 -m pytest tests/test_gridftp_pasv_range.py -v -p no:xdist
"""

import ftplib
import os
import re
import socket

import pytest

from settings import BIND_HOST, NGINX_BIN, SERVER_HOST
from server_launcher import LifecycleHarness
from server_registry import NginxInstanceSpec

pytestmark = [pytest.mark.serial, pytest.mark.timeout(180),
              pytest.mark.uses_lifecycle_harness]


def _require():
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx not executable: {NGINX_BIN}")


def _contiguous_free_range(n, host):
    """Find `n` consecutive free TCP ports on `host` and return (lo, hi).

    Binds the whole candidate block at once (holding every socket) so the run is
    genuinely contiguous and free, then releases — the gateway re-binds them."""
    for base in range(49200, 60000, n):
        socks = []
        try:
            ok = True
            for off in range(n):
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                try:
                    s.bind((host, base + off))
                except OSError:
                    s.close()
                    ok = False
                    break
                socks.append(s)
            if ok:
                return base, base + n - 1
        finally:
            for s in socks:
                s.close()
    pytest.skip("no contiguous free port range available")
    return None


class _Gateway:
    def __init__(self, harness, name, lo, hi):
        endpoint = harness.start(NginxInstanceSpec(
            name=name,
            template="nginx_gridftp_pasv_range.conf",
            protocol="root",
            readiness="tcp",
            template_values={
                "BIND_HOST": BIND_HOST,
                "PASV_LO": str(lo),
                "PASV_HI": str(hi),
            },
        ))
        self.harness = harness
        self.port = endpoint.port
        self.export = endpoint.data_root
        self.lo = lo
        self.hi = hi

    def close(self):
        self.harness.close()


def _connect(gw):
    ftp = ftplib.FTP()
    ftp.connect(SERVER_HOST, gw.port, timeout=30)
    ftp.login()
    return ftp


def _pasv_port(ftp):
    """Issue PASV and return the advertised data port (RFC 959 227)."""
    resp = ftp.sendcmd("PASV")
    m = re.search(r"\(([\d,]+)\)", resp)
    assert m, resp
    nums = [int(x) for x in m.group(1).split(",")]
    return (nums[4] << 8) | nums[5]


def _epsv_port(ftp):
    """Issue EPSV and return the advertised data port (RFC 2428 229)."""
    resp = ftp.sendcmd("EPSV")
    m = re.search(r"\(\|\|\|(\d+)\|\)", resp)
    assert m, resp
    return int(m.group(1))


def test_pasv_and_epsv_land_in_range(tmp_path):
    _require()
    lo, hi = _contiguous_free_range(8, BIND_HOST)
    gw = _Gateway(LifecycleHarness(), "gridftp-pasv-range", lo, hi)
    try:
        # Several fresh listeners; every one must fall inside the window.
        for _ in range(6):
            ftp = _connect(gw)
            try:
                p = _pasv_port(ftp)
                assert lo <= p <= hi, f"PASV port {p} outside [{lo},{hi}]"
                e = _epsv_port(ftp)
                assert lo <= e <= hi, f"EPSV port {e} outside [{lo},{hi}]"
            finally:
                ftp.quit()
    finally:
        gw.close()


def test_transfer_over_pinned_range(tmp_path):
    """A real STOR then RETR must complete when the data channel is confined to
    the pinned range — the knob narrows the port, it must not break the flow."""
    _require()
    lo, hi = _contiguous_free_range(8, BIND_HOST)
    gw = _Gateway(LifecycleHarness(), "gridftp-pasv-xfer", lo, hi)
    payload = os.urandom(6000)
    try:
        ftp = _connect(gw)
        try:
            up = tmp_path / "up.bin"
            up.write_bytes(payload)
            with open(up, "rb") as fh:
                ftp.storbinary("STOR pinned.bin", fh)
            got = []
            ftp.retrbinary("RETR pinned.bin", got.append)
            assert b"".join(got) == payload
        finally:
            ftp.quit()
    finally:
        gw.close()
    with open(os.path.join(gw.export, "pinned.bin"), "rb") as fh:
        assert fh.read() == payload


def test_range_exhaustion_refused(tmp_path):
    """When every port in the configured range is occupied, PASV must fail closed
    with 425 rather than silently binding a random, un-firewalled ephemeral port."""
    _require()
    lo, hi = _contiguous_free_range(2, BIND_HOST)
    gw = _Gateway(LifecycleHarness(), "gridftp-pasv-exhaust", lo, hi)
    holders = []
    try:
        # Occupy the whole window on the same address the data listener binds to,
        # so the gateway's bind() walk hits EADDRINUSE on every port.
        for p in range(lo, hi + 1):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.bind((BIND_HOST, p))
            s.listen(1)
            holders.append(s)

        ftp = _connect(gw)
        try:
            with pytest.raises(ftplib.error_temp) as e:   # 4xx transient
                ftp.sendcmd("PASV")
            assert e.value.args[0].startswith("425"), e.value.args[0]
        finally:
            ftp.quit()
    finally:
        for s in holders:
            s.close()
        gw.close()
