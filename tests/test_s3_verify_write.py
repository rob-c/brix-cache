"""S3 whole-object PUT under ``brix_verify_write on`` (writer-unification).

Every S3 write path now flows through the unified ``brix_vfs_writer`` session, and
with verify-on the commit re-reads the freshly published object through the storage
driver and CRC-compares it against the bytes the writer accumulated — a 200 is
proof the driver *persisted* what the client sent, not merely that the write calls
returned success.

This exercises the paths the writer migration reshaped, and pins the contract that
enabling verify does NOT falsely reject any of them:

  * a plain in-memory PUT round-trips and is acknowledged (200);
  * a large body nginx spools to a temp file round-trips — the writer ingests it
    via the fd path (write_fd bounce buffer), where the CRC accumulator must still
    see every byte;
  * a zero-length PUT is a complete [0,0) write and verifies cleanly (the writer
    skips the read-back when nothing was written — this must not error);
  * an aws-chunked streaming body de-frames and round-trips (the writer's raw-fd
    de-chunk path — verify is a no-op there and must not falsely fail);
  * an exclusive create (If-None-Match: *) still returns 412 on the losing race,
    proving the writer's commit_ex EEXIST mapping survived the migration.

Self-provisions a dedicated single-worker nginx with verify-write on (anonymous +
write), so the behaviour is observable without touching the shared fleet.

Run:
    PYTHONPATH=tests python3 -m pytest tests/test_s3_verify_write.py -v -p no:xdist
"""

import os
import uuid

import pytest
import requests

from settings import BIND_HOST, HOST as _HOST, NGINX_BIN  # noqa: F401  (NGINX_BIN: harness gate)
from server_launcher import LifecycleHarness
from server_registry import NginxInstanceSpec

pytestmark = [pytest.mark.serial, pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-s3-verify-write")]

BUCKET = "verifybucket"


@pytest.fixture(scope="module")
def s3(tmp_path_factory):
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx not executable: {NGINX_BIN}")
    data = tmp_path_factory.mktemp("s3-verify-data")
    harness = LifecycleHarness()
    ep = harness.start(NginxInstanceSpec(
        name="lc-s3-verify-write",
        template="nginx_lc_s3_verify_write.conf",
        protocol="s3",
        template_values={
            "BIND_HOST": BIND_HOST,
            "DATA_DIR": str(data),
            "BUCKET": BUCKET,
        },
        reason="s3 verify-on-write"))
    try:
        yield f"http://{_HOST}:{ep.port}"
    finally:
        harness.close()


def _key(url, name=None):
    return f"{url}/{BUCKET}/{name or uuid.uuid4().hex}"


def test_verified_put_roundtrip(s3):
    """A plain in-memory PUT verifies and reads back byte-identical."""
    payload = os.urandom(4000)
    key = _key(s3)
    r = requests.put(key, data=payload, timeout=15)
    assert r.status_code == 200, r.text
    assert requests.get(key, timeout=15).content == payload


def test_verified_spooled_put_roundtrip(s3):
    """A body large enough to spool (client_body_buffer_size 1k) round-trips:
    the writer ingests the nginx temp file via its fd path and the read-back CRC
    still matches, so verify saw every spooled byte."""
    payload = os.urandom((3 * 1024 * 1024) + 61)
    key = _key(s3)
    r = requests.put(key, data=payload, timeout=30)
    assert r.status_code == 200, r.text
    assert requests.get(key, timeout=30).content == payload


def test_verified_empty_put(s3):
    """A zero-length PUT is a complete write; verify skips the read-back for a
    zero-byte object and must still succeed (not a false mismatch)."""
    key = _key(s3)
    r = requests.put(key, data=b"", timeout=15)
    assert r.status_code == 200, r.text
    assert requests.get(key, timeout=15).content == b""


def _chunk(data):
    return b"%x\r\n%s\r\n" % (len(data), data)


def test_verified_aws_chunked_streaming(s3):
    """An aws-chunked streaming body de-frames to the object bytes and round-trips
    with verify on: the writer's raw-fd de-chunk path writes outside the CRC
    accumulator (verify is a no-op there), which must not falsely reject."""
    data = os.urandom(9000)
    body = _chunk(data) + b"0\r\n\r\n"
    key = _key(s3)
    r = requests.put(key, data=body, headers={
        "x-amz-content-sha256": "STREAMING-UNSIGNED-PAYLOAD-TRAILER",
        "x-amz-decoded-content-length": str(len(data)),
        "Content-Encoding": "aws-chunked",
        "Content-Length": str(len(body)),
    }, timeout=15)
    assert r.status_code == 200, r.text
    assert requests.get(key, timeout=15).content == data


def test_verified_exclusive_create_conflict(s3):
    """If-None-Match: * exclusive create still maps the losing race to 412 under
    the writer's commit_ex path — verify does not perturb the EEXIST mapping."""
    key = _key(s3)
    first = requests.put(key, data=os.urandom(2048),
                         headers={"If-None-Match": "*"}, timeout=15)
    assert first.status_code == 200, first.text
    second = requests.put(key, data=os.urandom(2048),
                          headers={"If-None-Match": "*"}, timeout=15)
    assert second.status_code == 412, second.text
