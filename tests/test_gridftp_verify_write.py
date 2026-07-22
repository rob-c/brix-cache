"""
GridFTP gateway with ``brix_gridftp_verify_write on`` (phase-82 P82.6).

When verify-write is enabled the gateway CRC-32s every byte it writes for a STOR,
then re-reads the object back through the storage driver and compares before
acknowledging the transfer: a 226 is proof the driver *persisted* what the client
sent, not merely that the write calls returned success. This is the
backend-agnostic integrity check the block/object backends (pblock, rados) need,
where there is no single kernel fd whose bytes are the file.

The read-back runs through ``brix_vfs_wverify_check`` → ``brix_cksum_u32_obj``, so
the same test exercises it over both the posix export and the pblock block store.

Covered:
  * STOR round-trips and is acknowledged (226) with verify on — posix + pblock
  * a MODE E out-of-order parallel STOR verifies and lands byte-identical
    (the accumulator coalesces extents by offset, not arrival order)
  * a zero-length STOR is accepted (empty object is a complete [0,0) write)

Run:
    PYTHONPATH=tests python3 -m pytest tests/test_gridftp_verify_write.py -v -p no:xdist
"""

import ftplib
import io
import os
import socket
import struct

import pytest

from settings import BIND_HOST, NGINX_BIN, SERVER_HOST
from server_launcher import LifecycleHarness
from server_registry import NginxInstanceSpec

pytestmark = [pytest.mark.serial, pytest.mark.timeout(180),
              pytest.mark.uses_lifecycle_harness]

EB_EOF = 0x40
EB_EOD = 0x08

# (fixture name, config template) for each backend under verify-write.
BACKENDS = {
    "posix": "nginx_gridftp_verify_posix.conf",
    "pblock": "nginx_gridftp_verify_pblock.conf",
}


def _require():
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx not executable: {NGINX_BIN}")


class _Gateway:
    def __init__(self, harness, name, template):
        endpoint = harness.start(NginxInstanceSpec(
            name=name,
            template=template,
            protocol="root",
            readiness="tcp",
            template_values={"BIND_HOST": BIND_HOST},
        ))
        self.harness = harness
        self.port = endpoint.port
        self.export = endpoint.data_root

    def close(self):
        self.harness.close()


@pytest.fixture(scope="module", params=list(BACKENDS), ids=list(BACKENDS))
def gateway(request):
    _require()
    gw = _Gateway(LifecycleHarness(), f"gridftp-verify-{request.param}",
                  BACKENDS[request.param])
    yield gw
    gw.close()


def _connect(gw):
    ftp = ftplib.FTP()
    ftp.connect(SERVER_HOST, gw.port, timeout=30)
    ftp.login()
    return ftp


def test_verified_stor_roundtrip(gateway):
    """With verify-write on, a good STOR is acknowledged and reads back intact:
    the 226 means the driver read-back matched the self-computed CRC."""
    payload = os.urandom(48000)
    ftp = _connect(gateway)
    try:
        # storbinary raises error_perm if the final reply is not 2xx, so reaching
        # here at all means the post-write verify passed (would be 550 otherwise).
        ftp.storbinary("STOR v.bin", io.BytesIO(payload))
        got = []
        ftp.retrbinary("RETR v.bin", got.append)
        assert b"".join(got) == payload
        assert ftp.size("v.bin") == len(payload)
    finally:
        ftp.quit()


def test_verified_empty_stor(gateway):
    """A zero-length STOR is a complete [0,0) write and must verify cleanly."""
    ftp = _connect(gateway)
    try:
        ftp.storbinary("STOR empty.bin", io.BytesIO(b""))
        assert ftp.size("empty.bin") == 0
    finally:
        ftp.quit()


def test_verified_mode_e_out_of_order(gateway):
    """A MODE E STOR whose blocks arrive out of offset order still verifies: the
    accumulator coalesces extents by offset, so the read-back CRC matches."""
    payload = os.urandom(40000)
    ftp = ftplib.FTP()
    ftp.connect(SERVER_HOST, gateway.port, timeout=30)
    ftp.login()
    try:
        ftp.sendcmd("TYPE I")
        ftp.sendcmd("MODE E")
        host, port = ftp.makepasv()
        data = socket.create_connection((host, port), timeout=30)
        try:
            ftp.putcmd("STOR ebv.bin")
            assert ftp.getresp().startswith("150")

            def _eb(desc, count, offset):
                return (struct.pack("!B", desc) + struct.pack("!Q", count)
                        + struct.pack("!Q", offset))

            # Second half first, then first half — out of order on purpose.
            data.sendall(_eb(0, 20000, 20000) + payload[20000:])
            data.sendall(_eb(0, 20000, 0) + payload[:20000])
            data.sendall(_eb(EB_EOF | EB_EOD, 0, 1))
            data.shutdown(socket.SHUT_WR)
            # 226 here means verify passed despite out-of-order arrival.
            assert ftp.getresp().startswith("226")
        finally:
            data.close()
        ftp.sendcmd("MODE S")
        got = []
        ftp.retrbinary("RETR ebv.bin", got.append)
        assert b"".join(got) == payload
    finally:
        ftp.quit()
