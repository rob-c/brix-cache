"""
GridFTP gateway over the pblock storage backend (phase-82 P82.6).

Proves that ``brix_gridftp_storage_backend pblock`` routes the gateway's data
plane through the block store rather than the posix export: the gateway itself
only ever touches storage through ``brix_vfs_*``, and ``ftp_vfs_ctx`` resolves the
export root to whatever backend the module registered at config time, so pblock
support needs no data-path change — only the registration.

The discriminating check is that a stored object round-trips through the gateway
but does NOT appear as a plain file under the export root: pblock keeps data in
its own catalog + block files, so a literal ``os.path.exists(export/name)`` being
false is direct evidence the backend engaged (a posix fallback would leave the
file right there).

Covered:
  * STOR then RETR round-trips byte-identical through pblock   (success)
  * a MODE E parallel STOR lands correctly on pblock too       (success, R4 path)
  * RETR of a missing object → 550                             (error)
  * a traversal argument stays confined                        (security-negative)

Run:
    PYTHONPATH=tests python3 -m pytest tests/test_gridftp_pblock.py -v -p no:xdist
"""

import ftplib
import hashlib
import os
import socket
import struct
import zlib

import pytest

from settings import BIND_HOST, NGINX_BIN
from server_launcher import LifecycleHarness
from server_registry import NginxInstanceSpec

pytestmark = [pytest.mark.serial, pytest.mark.timeout(180),
              pytest.mark.uses_lifecycle_harness]

EB_EOF = 0x40
EB_EOD = 0x08


def _require():
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx not executable: {NGINX_BIN}")


class _Gateway:
    def __init__(self, harness, name):
        endpoint = harness.start(NginxInstanceSpec(
            name=name,
            template="nginx_gridftp_pblock.conf",
            protocol="root",
            readiness="tcp",
            template_values={"BIND_HOST": BIND_HOST},
        ))
        self.harness = harness
        self.port = endpoint.port
        self.export = endpoint.data_root

    def close(self):
        self.harness.close()


@pytest.fixture(scope="module")
def gateway():
    _require()
    gw = _Gateway(LifecycleHarness(), "gridftp-pblock")
    yield gw
    gw.close()


def _connect(gw):
    ftp = ftplib.FTP()
    ftp.connect("localhost", gw.port, timeout=30)
    ftp.login()
    return ftp


def test_stor_retr_roundtrip_via_pblock(gateway, tmp_path):
    """A STOR/RETR round-trip lands in and comes back from the pblock store, and
    the object is not a plain posix file under the export (proof the backend
    engaged rather than falling through to posix)."""
    payload = os.urandom(48000)
    src = tmp_path / "up.bin"
    src.write_bytes(payload)
    ftp = _connect(gateway)
    try:
        with open(src, "rb") as fh:
            ftp.storbinary("STOR rt.bin", fh)
        got = []
        ftp.retrbinary("RETR rt.bin", got.append)
        assert b"".join(got) == payload, "pblock round-trip corrupted the object"
        assert ftp.size("rt.bin") == len(payload)
    finally:
        ftp.quit()
    # Backend really engaged: pblock does not store the logical name as a posix
    # file in the export tree.
    assert not os.path.exists(os.path.join(gateway.export, "rt.bin")), \
        "object present as a plain posix file — pblock backend did not engage"


def test_mode_e_stor_via_pblock(gateway):
    """A MODE E parallel STOR reassembles correctly onto the pblock backend,
    exercising the offset-addressed per-block write path against the block store
    rather than posix."""
    payload = os.urandom(40000)
    ftp = ftplib.FTP()
    ftp.connect("localhost", gateway.port, timeout=30)
    ftp.login()
    try:
        ftp.sendcmd("TYPE I")
        ftp.sendcmd("MODE E")
        host, port = ftp.makepasv()
        data = socket.create_connection((host, port), timeout=30)
        try:
            ftp.putcmd("STOR eb.bin")
            assert ftp.getresp().startswith("150")

            def _eb(desc, count, offset):
                return (struct.pack("!B", desc) + struct.pack("!Q", count)
                        + struct.pack("!Q", offset))

            data.sendall(_eb(0, 20000, 0) + payload[:20000])
            data.sendall(_eb(0, 20000, 20000) + payload[20000:])
            data.sendall(_eb(EB_EOF | EB_EOD, 0, 1))
            data.shutdown(socket.SHUT_WR)
            assert ftp.getresp().startswith("226")
        finally:
            data.close()
        # Read the object back in plain stream mode (MODE E would re-frame the
        # reply as extended blocks); a byte-identical read proves the parallel
        # STOR reassembled correctly onto pblock.
        ftp.sendcmd("MODE S")
        got = []
        ftp.retrbinary("RETR eb.bin", got.append)
        assert b"".join(got) == payload, "MODE E pblock reassembly corrupted"
    finally:
        ftp.quit()


def test_cksm_via_pblock_is_driver_routed(gateway, tmp_path):
    """CKSM over a pblock object is computed through the storage driver, so it
    reflects the whole stored object rather than a raw block-0 fd.

    STOR a payload, then ask the gateway for its MD5 (digest kernel) and CRC32
    (u32 kernel) and check both against locally-computed values. Because the
    object lives in the block store (not as a posix file), a correct answer is
    direct evidence CKSM read it back via ``brix_cksum_*_obj`` / the driver.
    (Multi-block striping across the 64 MiB granule is covered by pblock's own
    unit tests; this proves the gateway's driver-routed CKSM wiring.)"""
    payload = os.urandom(50000)
    src = tmp_path / "ck.bin"
    src.write_bytes(payload)
    ftp = _connect(gateway)
    try:
        with open(src, "rb") as fh:
            ftp.storbinary("STOR ck.bin", fh)

        md5 = ftp.sendcmd("CKSM MD5 0 -1 ck.bin")
        assert md5.startswith("213 ")
        assert md5[4:].strip().lower() == hashlib.md5(payload).hexdigest()

        crc = ftp.sendcmd("CKSM CRC32 0 -1 ck.bin")
        assert crc.startswith("213 ")
        assert int(crc[4:].strip(), 16) == (zlib.crc32(payload) & 0xFFFFFFFF)
    finally:
        ftp.quit()


def test_cksm_missing_object_is_550(gateway):
    """CKSM of an absent object is declined, not answered with a bogus digest."""
    ftp = _connect(gateway)
    try:
        with pytest.raises(ftplib.error_perm) as e:
            ftp.sendcmd("CKSM MD5 0 -1 nope.bin")
        assert e.value.args[0].startswith("550")
    finally:
        ftp.quit()


def test_cksm_traversal_confined_on_pblock(gateway):
    """A traversal path on CKSM cannot escape the export namespace (the resolve
    fails before any digest is attempted)."""
    ftp = _connect(gateway)
    try:
        with pytest.raises(ftplib.error_perm):
            ftp.sendcmd("CKSM MD5 0 -1 ../../../../etc/passwd")
    finally:
        ftp.quit()


def test_retr_missing_object_is_550(gateway):
    ftp = _connect(gateway)
    try:
        with pytest.raises(ftplib.error_perm) as e:
            ftp.retrbinary("RETR nope.bin", lambda _b: None)
        assert e.value.args[0].startswith("550")
    finally:
        ftp.quit()


def test_traversal_confined_on_pblock(gateway):
    """Confinement holds on the pblock backend exactly as on posix: a traversal
    argument cannot escape the export namespace."""
    ftp = _connect(gateway)
    try:
        with pytest.raises(ftplib.error_perm):
            ftp.sendcmd("MDTM ../../../../etc/passwd")
    finally:
        ftp.quit()
