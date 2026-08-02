"""
tests/test_put_content_encoding_driver.py

Phase-92 open-work audit #3: Content-Encoding decode to a DRIVER-BACKED
(object) storage backend.

Before the fix, a `Content-Encoding: gzip/deflate` PUT whose storage backend is a
driver-backed object session — an s3:// (sd_remote) or ceph:// export that has NO
kernel fd — was rejected with 501: the decode engine could only stream plaintext
to a raw fd (`brix_http_body_decode_to_fd`), and `brix_vfs_writer_fd()` returns
NGX_INVALID_FILE for such a session.  The fix routes the decoded bytes through
`brix_http_body_decode_to_writer` -> `brix_vfs_writer_write`, which dispatches to
the driver's staged/object writer (and feeds the CRC accumulator), so:

  * PUT `Content-Encoding: gzip`    to a driver backend -> stored = ORIGINAL bytes
  * PUT `Content-Encoding: deflate` to a driver backend -> stored = ORIGINAL bytes
  * PUT with a corrupt encoded stream -> error, and NO partial/empty object is
    published to the origin (a failed decode aborts the staged writer before its
    single backend PUT, so a later GET 404s).

The topology (nginx_ce_driver_s3.conf) is a single nginx hosting a posix-backed
brix_s3 ORIGIN plus a WebDAV FRONT whose storage backend is that s3:// origin.
The client leg is anonymous; the front signs its OUTBOUND leg to the origin with
a configured credential.  The WebDAV `put_body.c` decode path and the S3
`put_stream.c` decode path call the identical `brix_http_body_decode_to_writer`
helper; the WebDAV front is used here because an S3 front over an s3:// backend
has a separate, pre-existing whole-object staged-open failure (it breaks a plain
identity PUT too), orthogonal to the #3 decode fix.  Sibling
test_put_content_encoding.py covers the POSIX (fd) path.
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

pytestmark = [pytest.mark.serial,
              pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-ce-driver-s3")]

BUCKET = "testbucket"
# Matched on both legs: the front signs its outbound PUT with these; the origin
# validates against the same key pair.
S3_AK = "AKIDCEDRIVERS3TEST1"
S3_SK = "Y2UtZHJpdmVyLXMzLWNvbnRlbnQtZW5jb2Rpbmctc2VjcmV0LXQ="

# Ports are assigned per-server by the lifecycle ledger; read back post-start.
WEBDAV_PORT = None
ORIGIN_PORT = None

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
def ce_driver_server(lifecycle, tmp_path):
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx not executable: {NGINX_BIN}")
    if not _HAVE_REQUESTS:
        pytest.skip("requests not available")

    global WEBDAV_PORT, ORIGIN_PORT

    # posix-backed brix_s3 origin stores objects FLAT under this root; the bucket
    # dir must exist at config-parse time.
    oroot = tmp_path / "origin"
    oroot.mkdir()
    (oroot / BUCKET).mkdir()
    if os.geteuid() == 0:
        # nginx workers drop to `nobody` under the root harness; make the
        # root-owned origin tree writable so the outbound PUT commit can land.
        os.chmod(oroot, 0o777)
        os.chmod(oroot / BUCKET, 0o777)

    ep = lifecycle.start(NginxInstanceSpec(
        name="lc-ce-driver-s3",
        template="nginx_ce_driver_s3.conf",
        protocol="http",
        template_values={"BIND_HOST": BIND_HOST,
                         "ORIGIN_DIR": str(oroot),
                         "S3_ACCESS_KEY": S3_AK,
                         "S3_SECRET_KEY": S3_SK},
        reason="Content-Encoding PUT to a driver-backed (s3://) object backend"))

    WEBDAV_PORT = ep.port
    ORIGIN_PORT = ep.extra_ports["ORIGIN_PORT"]

    # The harness waits on the WebDAV front {PORT}; poll the origin leg too.
    if not _wait_port(ORIGIN_PORT):
        pytest.skip("ce-driver s3 origin listener did not come up")
    yield


def _url(key):
    return f"http://{HOST}:{WEBDAV_PORT}/{key}"


def _put(key, body, encoding):
    # requests must not re-encode: send raw bytes, set the header ourselves.
    return requests.put(_url(key), data=body,
                        headers={"Content-Encoding": encoding}, timeout=30)


def _get(key):
    # Accept-Encoding identity so requests doesn't try to decode the response.
    return requests.get(_url(key),
                        headers={"Accept-Encoding": "identity"}, timeout=30)


def test_gzip_put_driver_backed_stored_decompressed(ce_driver_server):
    key = f"ced_gz_{uuid.uuid4().hex}.txt"
    r = _put(key, gzip.compress(ORIGINAL), "gzip")
    assert r.status_code in (200, 201, 204), \
        f"gzip PUT to driver backend failed: {r.status_code} " \
        f"(a 501 here means decode-to-driver never engaged)"
    g = _get(key)
    assert g.status_code == 200, f"GET after gzip PUT: {g.status_code}"
    assert g.content == ORIGINAL, \
        f"gzip PUT must store the DECOMPRESSED bytes through the driver " \
        f"(got {len(g.content)} vs {len(ORIGINAL)})"


def test_deflate_put_driver_backed_stored_decompressed(ce_driver_server):
    key = f"ced_df_{uuid.uuid4().hex}.txt"
    r = _put(key, zlib.compress(ORIGINAL), "deflate")
    assert r.status_code in (200, 201, 204), \
        f"deflate PUT to driver backend failed: {r.status_code}"
    g = _get(key)
    assert g.status_code == 200, f"GET after deflate PUT: {g.status_code}"
    assert g.content == ORIGINAL, \
        f"deflate PUT must store the DECOMPRESSED bytes through the driver"


def test_corrupt_gzip_put_driver_backed_publishes_nothing(ce_driver_server):
    # security-neg: a hostile/truncated coded body must not publish a partial
    # object to the origin — the staged writer aborts before its backend PUT.
    key = f"ced_bad_{uuid.uuid4().hex}.txt"
    corrupt = gzip.compress(ORIGINAL)[:40] + b"\x00\xff" * 200
    r = _put(key, corrupt, "gzip")
    assert r.status_code >= 400, \
        f"corrupt gzip PUT must fail, got {r.status_code}"
    g = _get(key)
    assert g.status_code == 404, \
        (f"failed gzip PUT published an object to the driver backend "
         f"(GET={g.status_code}, {len(g.content)} bytes) — abort not honoured")
