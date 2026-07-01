"""
tests/test_put_content_encoding.py

Coverage gap #4 (test-coverage-gap-audit): Content-Encoding gzip/deflate
decompress-on-store for PUT bodies (WebDAV src/webdav/put.c + S3 src/s3/put.c,
both via src/compat/http_body.c::xrootd_http_body_inflate_to_fd).

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
import subprocess
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

from settings import NGINX_BIN, free_port, HOST, BIND_HOST

WEBDAV_PORT = int(os.environ.get("TEST_CE_WEBDAV_PORT") or free_port())
S3_PORT = int(os.environ.get("TEST_CE_S3_PORT") or free_port())
BUCKET = "testbucket"

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


@pytest.fixture(scope="module")
def ce_server(tmp_path_factory):
    if not os.path.exists(NGINX_BIN):
        pytest.skip(f"nginx binary not found at {NGINX_BIN}")
    if not _HAVE_REQUESTS:
        pytest.skip("requests not available")

    d = tmp_path_factory.mktemp("ce")
    (d / "logs").mkdir()
    (d / "t").mkdir()
    wroot = d / "wdata"
    wroot.mkdir()
    sroot = d / "sdata"
    sroot.mkdir()

    conf = f"""
error_log {d}/logs/error.log error;
pid {d}/logs/nginx.pid;
events {{ worker_connections 64; }}
http {{
    client_body_temp_path {d}/t; proxy_temp_path {d}/t; fastcgi_temp_path {d}/t;
    uwsgi_temp_path {d}/t; scgi_temp_path {d}/t; access_log off;
    client_max_body_size 64m;
    server {{
        listen {BIND_HOST}:{WEBDAV_PORT};
        location / {{
            xrootd_webdav on;
            xrootd_webdav_storage_backend posix:{wroot};
            xrootd_webdav_auth none;
            xrootd_webdav_allow_write on;
        }}
    }}
    server {{
        listen {BIND_HOST}:{S3_PORT};
        location / {{
            xrootd_s3 on;
            xrootd_s3_storage_backend posix:{sroot};
            xrootd_s3_bucket {BUCKET};
            xrootd_s3_allow_write on;
        }}
    }}
}}
daemon off;
master_process off;
"""
    cp = d / "nginx.conf"
    cp.write_text(conf)
    proc = subprocess.Popen([NGINX_BIN, "-p", str(d), "-c", str(cp)],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if not (_wait_port(WEBDAV_PORT) and _wait_port(S3_PORT)):
        err = proc.stderr.read().decode(errors="replace") if proc.stderr else ""
        proc.terminate()
        pytest.skip(f"content-encoding server did not start: {err}")
    yield
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()


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
