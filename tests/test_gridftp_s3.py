"""
GridFTP gateway writing THROUGH an s3:// storage backend (phase-82).

The gateway's export is backed by ``brix_gridftp_storage_backend s3://...`` — an
object store, not a seekable filesystem. That exercises the *staged* arm of the
unified ``brix_vfs_writer``: a STOR is buffered into a temp/multipart upload and
atomically published on commit, then (verify-write on) read back through the
sd_remote driver and CRC-checked before the 226. There is no in-place fd whose
bytes are the object, so this is the backend where the common verified-write call
matters most.

The s3:// SigV4 keys reach sd_remote via a stream-scope ``brix_credential`` block
named by ``brix_gridftp_storage_credential``; the per-worker ``init_process``
replay (ftp_module.c) re-applies it after fork. A green STOR round-trip is
therefore also proof the credential survives worker spawn.

The object store itself is a second server in the same nginx: a ``brix_s3``
endpoint over a posix root (bucket ``testbucket``).

Covered:
  * STOR → RETR round-trips byte-for-byte through S3 (staged upload + verify)
  * CKSM (whole-object and a partial range) matches over the S3-backed object
  * a zero-length STOR publishes an empty object

Run:
    TEST_SKIP_SERVER_SETUP=1 PYTHONPATH=tests \
        python3 -m pytest tests/test_gridftp_s3.py -v -p no:xdist
"""

import ftplib
import io
import os
import socket
import time
import zlib

import pytest

from settings import HOST, BIND_HOST, NGINX_BIN
from server_launcher import LifecycleHarness
from server_registry import NginxInstanceSpec

pytestmark = [pytest.mark.serial, pytest.mark.timeout(180),
              pytest.mark.uses_lifecycle_harness]

S3_AK = "AKIDGRIDFTPS3TEST1"
S3_SK = "Z3JpZGZ0cC1zMy1zZWNyZXQta2V5LWZvci10ZXN0aW5n"


def _free_port():
    s = socket.socket()
    s.bind((BIND_HOST, 0))
    p = s.getsockname()[1]
    s.close()
    return p


def _port_up(host, port):
    try:
        with socket.create_connection((host, port), timeout=1):
            return True
    except OSError:
        return False


@pytest.fixture(scope="module")
def gateway(tmp_path_factory):
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx not executable: {NGINX_BIN}")

    # The S3 endpoint's posix root must exist (with the bucket dir) at parse.
    s3_dir = tmp_path_factory.mktemp("s3store")
    (s3_dir / "testbucket").mkdir()
    s3_port = _free_port()

    harness = LifecycleHarness()
    endpoint = harness.start(NginxInstanceSpec(
        name="gridftp-s3",
        template="nginx_gridftp_s3.conf",
        protocol="root",
        readiness="tcp",
        extra_ports={"S3_PORT": s3_port},
        template_values={"BIND_HOST": BIND_HOST,
                         "S3_DIR": str(s3_dir),
                         "S3_ACCESS_KEY": S3_AK,
                         "S3_SECRET_KEY": S3_SK},
    ))

    # Harness waits on the gridftp {PORT}; poll the S3 plane too.
    for _ in range(50):
        if _port_up(HOST, s3_port):
            break
        time.sleep(0.1)

    yield {"port": endpoint.port, "s3_port": s3_port}
    harness.close()


def _connect(gateway):
    ftp = ftplib.FTP()
    ftp.connect("localhost", gateway["port"], timeout=30)
    ftp.login()
    return ftp


def test_stor_retr_roundtrip_through_s3(gateway):
    """A STOR travels VFS → sd_remote → SigV4 PUT, verifies on read-back, and
    RETR returns the exact bytes from the object store."""
    payload = os.urandom(50000)
    ftp = _connect(gateway)
    try:
        # A verify mismatch (or an unsigned/failed upload) would make storbinary
        # raise error_perm; reaching the RETR means the S3 write committed clean.
        ftp.storbinary("STOR s3obj.bin", io.BytesIO(payload))
        assert ftp.size("s3obj.bin") == len(payload)
        got = []
        ftp.retrbinary("RETR s3obj.bin", got.append)
        assert b"".join(got) == payload
    finally:
        ftp.quit()


def test_cksm_over_s3_object(gateway):
    """CKSM (whole-object and a partial range) is computed by reading the object
    back through the sd_remote driver, so it matches the source bytes."""
    data = bytes(range(256)) * 40  # 10240 bytes, deterministic
    ftp = _connect(gateway)
    try:
        ftp.storbinary("STOR s3ck.bin", io.BytesIO(data))
        whole = ftp.sendcmd("CKSM CRC32 0 -1 s3ck.bin").split()[1]
        assert whole.lower() == f"{zlib.crc32(data) & 0xffffffff:08x}"
        part = ftp.sendcmd("CKSM CRC32 1000 2048 s3ck.bin").split()[1]
        assert part.lower() == f"{zlib.crc32(data[1000:3048]) & 0xffffffff:08x}"
    finally:
        ftp.quit()


def test_empty_stor_through_s3(gateway):
    """A zero-length STOR publishes an empty object (a complete [0,0) write)."""
    ftp = _connect(gateway)
    try:
        ftp.storbinary("STOR s3empty.bin", io.BytesIO(b""))
        assert ftp.size("s3empty.bin") == 0
    finally:
        ftp.quit()
