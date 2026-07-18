"""WebDAV whole-object PUT under ``brix_verify_write on`` (writer-unification).

Every WebDAV write path now flows through the unified ``brix_vfs_writer`` session,
and with verify-on the commit re-reads the freshly published object through the
storage driver and CRC-compares it against the bytes the writer accumulated — a
201/204 is proof the driver *persisted* what the client sent, not merely that the
write calls returned success.

This exercises the paths the writer migration reshaped, and pins the contract that
enabling verify does NOT falsely reject any of them:

  * a plain in-memory PUT round-trips and is acknowledged (201);
  * a large body nginx spools to a temp file round-trips — the writer ingests it
    via the fd path (write_fd bounce buffer), where the CRC accumulator must still
    see every byte;
  * a zero-length PUT is a complete [0,0) write and verifies cleanly (the writer
    skips the read-back when nothing was written — this must not error);
  * overwriting an existing object re-verifies and lands the new bytes (204).

Self-provisions a dedicated single-worker nginx with verify-write on (anonymous +
write), so the behaviour is observable without touching the shared fleet.

Run:
    PYTHONPATH=tests python3 -m pytest tests/test_webdav_verify_write.py -v -p no:xdist
"""

import os
import uuid

import pytest
import requests

from settings import BIND_HOST, HOST as _HOST, NGINX_BIN  # noqa: F401  (NGINX_BIN: harness gate)
from server_launcher import LifecycleHarness
from server_registry import NginxInstanceSpec

pytestmark = [pytest.mark.serial, pytest.mark.uses_lifecycle_harness]


@pytest.fixture(scope="module")
def dav(tmp_path_factory):
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx not executable: {NGINX_BIN}")
    data = tmp_path_factory.mktemp("dav-verify-data")
    harness = LifecycleHarness()
    ep = harness.start(NginxInstanceSpec(
        name="lc-webdav-verify-write",
        template="nginx_lc_webdav_verify_write.conf",
        protocol="webdav",
        template_values={
            "BIND_HOST": BIND_HOST,
            "DATA_DIR": str(data),
        },
        reason="webdav verify-on-write"))
    try:
        yield f"http://{_HOST}:{ep.port}", str(data)
    finally:
        harness.close()


def _url(base, name=None):
    return f"{base}/{name or uuid.uuid4().hex}.bin"


def test_verified_put_roundtrip(dav):
    """A plain in-memory PUT verifies and reads back byte-identical."""
    base, _ = dav
    payload = os.urandom(4000)
    url = _url(base)
    r = requests.put(url, data=payload, timeout=15)
    assert r.status_code in (201, 204), r.text
    assert requests.get(url, timeout=15).content == payload


def test_verified_spooled_put_roundtrip(dav):
    """A body large enough to spool (client_body_buffer_size 1k) round-trips:
    the writer ingests the nginx temp file via its fd path and the read-back CRC
    still matches, so verify saw every spooled byte."""
    base, _ = dav
    payload = os.urandom((3 * 1024 * 1024) + 61)
    url = _url(base)
    r = requests.put(url, data=payload, timeout=30)
    assert r.status_code in (201, 204), r.text
    assert requests.get(url, timeout=30).content == payload


def test_verified_empty_put(dav):
    """A zero-length PUT is a complete write; verify skips the read-back for a
    zero-byte object and must still succeed (not a false mismatch)."""
    base, _ = dav
    url = _url(base)
    r = requests.put(url, data=b"", timeout=15)
    assert r.status_code in (201, 204), r.text
    assert requests.get(url, timeout=15).content == b""


def test_verified_overwrite(dav):
    """An overwrite re-runs the verify read-back and publishes the new bytes,
    replying 204 (the object already existed) with the updated content."""
    base, _ = dav
    url = _url(base)
    first = requests.put(url, data=os.urandom(1500), timeout=15)
    assert first.status_code == 201, first.text
    payload = os.urandom(2500)
    second = requests.put(url, data=payload, timeout=15)
    assert second.status_code == 204, second.text
    assert requests.get(url, timeout=15).content == payload
