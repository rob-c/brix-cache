"""
tests/test_put_content_encoding.py

Coverage gap #4 (test-coverage-gap-audit): Content-Encoding gzip/deflate
decompress-on-store for PUT bodies (WebDAV src/protocols/webdav/put.c + S3 src/protocols/s3/put.c,
both via src/core/http/http_body.c::brix_http_body_inflate_to_fd).

No test exercised this at all.  The contract:
  * PUT with `Content-Encoding: gzip`    (window_bits 31) → stored = ORIGINAL bytes
  * PUT with `Content-Encoding: deflate` (window_bits 15) → stored = ORIGINAL bytes
  * PUT with a corrupt encoded stream    → error, and NO partial/empty object is
    left readable (a failed PUT must not create a half-decompressed object).

The corrupt-stream case is the data-integrity one: PUT opens the target with
O_CREAT|O_TRUNC and (before the fix) left the partial file on disk when inflate
failed, so a later GET returned a truncated/empty object as if the upload had
succeeded.
"""

import gzip
import os
import socket
import time
import uuid
import zlib

import pytest

try:
    import requests
    import urllib3
    urllib3.disable_warnings()
    _HAVE_REQUESTS = True
except Exception:                                # pragma: no cover
    _HAVE_REQUESTS = False

from settings import NGINX_BIN, HOST, BIND_HOST
from server_registry import NginxInstanceSpec

pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-put-content-encoding")]

BUCKET = "testbucket"

# Ports are assigned per-server by the lifecycle harness; _url() reads them here.
WEBDAV_PORT = None
S3_PORT = None

ORIGINAL = (b"the quick brown fox jumps over the lazy dog 0123456789\n" * 2000)


def _wait_port(port, timeout=10):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((HOST, port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.1)
    return False


@pytest.fixture()
def ce_server(lifecycle, tmp_path):
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx not executable: {NGINX_BIN}")
    if not _HAVE_REQUESTS:
        pytest.skip("requests not available")

    global WEBDAV_PORT, S3_PORT

    wroot = tmp_path / "wdata"
    wroot.mkdir()
    sroot = tmp_path / "sdata"
    sroot.mkdir()
    if os.geteuid() == 0:
        # nginx workers drop to `nobody` under the root harness; the root-owned
        # export trees are otherwise unwritable, so anonymous PUT fails at the
        # staged-open with EACCES (surfaced as 403). Make them world-writable.
        for d in (wroot, sroot):
            os.chmod(d, 0o777)
    ep = lifecycle.start(NginxInstanceSpec(
        name="lc-put-content-encoding",
        template="nginx_lc_put_content_encoding.conf",
        protocol="http",
        template_values={"BIND_HOST": BIND_HOST,
                         "WEBDAV_DIR": str(wroot),
                         "S3_DIR": str(sroot),
                         "BUCKET": BUCKET},
        reason="webdav+s3 PUT Content-Encoding decompress-on-store"))

    WEBDAV_PORT = ep.port
    S3_PORT = ep.extra_ports["S3_PORT"]

    # Harness waits on the WebDAV {PORT} only; poll the S3 port too.
    if not _wait_port(S3_PORT):
        pytest.skip("content-encoding S3 listener did not come up")
    yield


def _url(plane, key):
    if plane == "webdav":
        return f"http://{HOST}:{WEBDAV_PORT}/{key}"
    return f"http://{HOST}:{S3_PORT}/{BUCKET}/{key}"


def _put(plane, key, body, encoding):
    # requests must not re-encode: send raw bytes, set the header ourselves.
    return requests.put(_url(plane, key), data=body,
                        headers={"Content-Encoding": encoding}, timeout=20)


def _get(plane, key):
    # Accept-Encoding identity so requests doesn't try to decode the response.
    return requests.get(_url(plane, key),
                        headers={"Accept-Encoding": "identity"}, timeout=20)


@pytest.mark.parametrize("plane", ["webdav", "s3"])
def test_gzip_put_stored_decompressed(ce_server, plane):
    key = f"ce_gz_{uuid.uuid4().hex}.txt"
    r = _put(plane, key, gzip.compress(ORIGINAL), "gzip")
    assert r.status_code in (200, 201, 204), f"gzip PUT failed: {r.status_code}"
    g = _get(plane, key)
    assert g.status_code == 200, f"GET after gzip PUT: {g.status_code}"
    assert g.content == ORIGINAL, \
        f"{plane} gzip PUT must store the DECOMPRESSED bytes (got {len(g.content)} vs {len(ORIGINAL)})"


@pytest.mark.parametrize("plane", ["webdav", "s3"])
def test_deflate_put_stored_decompressed(ce_server, plane):
    key = f"ce_df_{uuid.uuid4().hex}.txt"
    r = _put(plane, key, zlib.compress(ORIGINAL), "deflate")
    assert r.status_code in (200, 201, 204), f"deflate PUT failed: {r.status_code}"
    g = _get(plane, key)
    assert g.status_code == 200, f"GET after deflate PUT: {g.status_code}"
    assert g.content == ORIGINAL, \
        f"{plane} deflate PUT must store the DECOMPRESSED bytes"


@pytest.mark.parametrize("plane", ["webdav", "s3"])
def test_corrupt_gzip_put_leaves_no_readable_object(ce_server, plane):
    key = f"ce_bad_{uuid.uuid4().hex}.txt"
    # Valid gzip magic then garbage → inflate starts, then fails mid-stream.
    corrupt = gzip.compress(ORIGINAL)[:40] + b"\x00\xff" * 200
    r = _put(plane, key, corrupt, "gzip")
    assert r.status_code >= 400, \
        f"corrupt gzip PUT must fail, got {r.status_code}"
    g = _get(plane, key)
    # A failed decompress-PUT must NOT leave a readable (partial/empty) object.
    assert g.status_code == 404, \
        (f"{plane}: failed gzip PUT left a readable object "
         f"(GET={g.status_code}, {len(g.content)} bytes) — partial-write not cleaned up")
