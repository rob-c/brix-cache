"""
Phase-42 W2 — outbound (GET) response compression.

Attaches to the fleet's dedicated "compress" instance (WebDAV surface,
`brix_compress on`) started once by start_all_dedicated, rather than launching its
own nginx: a fixed-port self-start collides across pytest-xdist workers. The
shared harness's default WebDAV port cannot be reused here because enabling
compression globally would make every GET chunked and break unrelated
Content-Length assertions — hence a purpose-built fleet instance.

For every codec the server can emit (gzip, deflate, zstd, xz, brotli, bzip2): PUT
a compressible object uncompressed, GET it advertising ONLY that codec, and assert
the response carries `Content-Encoding: <token>` + `Vary` and that the raw
(undecoded) body decompresses byte-exact. Plus negotiation guards (no
Accept-Encoding / tiny file / Range -> identity).
"""

import bz2
import gzip
import lzma
import os
import shutil
import subprocess
import time
import uuid
import zlib

import pytest
import requests
import urllib3
from settings import HOST

urllib3.disable_warnings()

# Fixed port of the fleet "compress" instance WebDAV surface (see
# tests/lib/dedicated.sh -> start_all_dedicated + tests/configs/nginx_compress.conf).
COMPRESS_WEBDAV_PORT = int(os.environ.get("TEST_COMPRESS_WEBDAV_PORT", "12960"))
BASE_URL = f"http://{HOST}:{COMPRESS_WEBDAV_PORT}"
_POOL = urllib3.PoolManager()


def _wait_listen(url, tries=50):
    for _ in range(tries):
        try:
            requests.get(url, timeout=1)
            return True
        except Exception:
            time.sleep(0.1)
    return False


@pytest.fixture(scope="module")
def base():
    """Attach to the fleet "compress" WebDAV surface; skip cleanly if it is down.
    The tests PUT and GET their own uuid-named objects, so no seeding is needed —
    starting the server is the fleet's job, never the test's."""
    if not _wait_listen(BASE_URL):
        pytest.skip(
            f"fleet compress instance not listening on {COMPRESS_WEBDAV_PORT}")
    yield BASE_URL


def _decompress_cli(tool, args, data):
    path = shutil.which(tool)
    if path is None:
        pytest.skip(f"{tool} not available to decode test payload")
    p = subprocess.run([path, *args], input=data, stdout=subprocess.PIPE,
                       stderr=subprocess.DEVNULL, check=True)
    return p.stdout


def d_gzip(b):    return gzip.decompress(b)
def d_deflate(b): return zlib.decompress(b)
def d_xz(b):      return lzma.decompress(b)
def d_bzip2(b):   return bz2.decompress(b)


def d_zstd(b):
    try:
        import zstandard
        return zstandard.ZstdDecompressor().decompress(b)
    except Exception:
        return _decompress_cli("zstd", ["-d", "-q", "-c"], b)


def d_brotli(b):
    try:
        import brotli
        return brotli.decompress(b)
    except Exception:
        return _decompress_cli("brotli", ["-d", "-c"], b)


def d_lz4(b):
    # no python lz4 module in this env — decode via the lz4 CLI (LZ4 Frame)
    return _decompress_cli("lz4", ["-d", "-c"], b)


CODECS = {
    "gzip": d_gzip, "deflate": d_deflate, "zstd": d_zstd,
    "xz": d_xz, "br": d_brotli, "bzip2": d_bzip2, "lz4": d_lz4,
}

# zstd + lz4 are compile-gated OPTIONAL extensions (src/core/compat/codec_{zstd,lz4}.c,
# -DBRIX_HAVE_ZSTD / -DBRIX_HAVE_LZ4). A server built without libzstd/liblz4 dev
# headers registers them with available=0 and emits identity for those tokens. When
# that is the case we skip (not fail) the optional-codec case; mandatory codecs
# (gzip/deflate/xz/br/bzip2) are always asserted in full.
OPTIONAL_CODECS = {"zstd", "lz4"}


def _payload(n=200_000):
    return (b"the quick brown fox jumps over the lazy dog 0123456789\n"
            * (n // 54 + 1))[:n]


def _put(base, path, data):
    return requests.put(f"{base}{path}", data=data, timeout=60)


def _delete(base, path):
    try:
        requests.delete(f"{base}{path}", timeout=30)
    except Exception:
        pass


def _raw_get(base, path, headers):
    return _POOL.request("GET", f"{base}{path}", headers=headers,
                         decode_content=False, preload_content=True, retries=False)


@pytest.mark.parametrize("token", list(CODECS))
def test_get_compressed_roundtrip(base, token):
    decompress = CODECS[token]
    data = _payload()
    path = f"/out_{token.replace('/', '')}_{uuid.uuid4().hex}.bin"
    try:
        assert _put(base, path, data).status_code in (200, 201, 204)
        r = _raw_get(base, path, {"Accept-Encoding": token})
        assert r.status == 200, f"{token} GET status {r.status}"
        enc = r.headers.get("Content-Encoding", "")
        if not enc and token in OPTIONAL_CODECS:
            pytest.skip(
                f"server build lacks optional codec '{token}' "
                f"(returned identity for a compressible payload)")
        assert enc.lower() == token, f"{token}: Content-Encoding={enc!r}"
        raw = r.data
        assert len(raw) < len(data), f"{token}: not smaller ({len(raw)})"
        assert decompress(raw) == data, f"{token}: body mismatch"
        assert "accept-encoding" in r.headers.get("Vary", "").lower()
    finally:
        _delete(base, path)


def test_no_accept_encoding_is_identity(base):
    data = _payload()
    path = f"/out_none_{uuid.uuid4().hex}.bin"
    try:
        assert _put(base, path, data).status_code in (200, 201, 204)
        r = _raw_get(base, path, {})
        assert r.status == 200 and "Content-Encoding" not in r.headers
        assert r.data == data
    finally:
        _delete(base, path)


def test_small_file_not_compressed(base):
    data = b"tiny"
    path = f"/out_tiny_{uuid.uuid4().hex}.bin"
    try:
        assert _put(base, path, data).status_code in (200, 201, 204)
        r = _raw_get(base, path, {"Accept-Encoding": "gzip"})
        assert r.status == 200 and "Content-Encoding" not in r.headers
        assert r.data == data
    finally:
        _delete(base, path)


def test_range_request_not_compressed(base):
    data = _payload()
    path = f"/out_range_{uuid.uuid4().hex}.bin"
    try:
        assert _put(base, path, data).status_code in (200, 201, 204)
        r = _raw_get(base, path, {"Accept-Encoding": "gzip", "Range": "bytes=0-99"})
        assert r.status == 206, f"range status {r.status}"
        assert "Content-Encoding" not in r.headers
        assert r.data == data[:100]
    finally:
        _delete(base, path)
