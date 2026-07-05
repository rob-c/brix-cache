"""
Phase-42 W1 — inbound (PUT) decompression over the S3 REST gateway.

Sibling of test_compression_inbound.py (WebDAV plane); same idea, S3 surface.
For every codec the server may decode (gzip, deflate, zstd, xz, brotli, bzip2):
compress a payload client-side, PUT it to a unique key with the matching
Content-Encoding header, GET it back (plain), and assert the stored object is the
decompressed (original) bytes — i.e. the server decoded on ingest. Also:
  (a) an unsupported Content-Encoding ("snappy") is rejected with a 4xx (never a
      5xx, and never silently stored undecoded),
  (b) a gzip bomb is rejected (413 / at least 4xx) and leaves no partial object,
  (c) the Content-Encoding token is case-insensitive (uppercase "GZIP" works).

Targets the shared anonymous S3 server (allow_write) at
http://localhost:NGINX_S3_PORT — no auth, plain HTTP, no signing.
Codecs whose compressor is unavailable (no python module and no CLI) are skipped.
"""

import bz2
import gzip
import lzma
import os
import shutil
import subprocess
import uuid
import zlib

import pytest
import requests

from settings import NGINX_S3_PORT, S3_BUCKET

BASE = f"http://localhost:{NGINX_S3_PORT}"
BUCKET = S3_BUCKET


def _obj_url(key):
    return f"{BASE}/{BUCKET}/{key}"


# ---- client-side compressors: python stdlib where possible, else CLI ----

def _compress_cli(tool, args, data):
    path = shutil.which(tool)
    if path is None:
        pytest.skip(f"{tool} not available to produce test payload")
    p = subprocess.run([path, *args], input=data, stdout=subprocess.PIPE,
                       stderr=subprocess.DEVNULL, check=True)
    return p.stdout


def c_gzip(data):
    return gzip.compress(data)


def c_deflate(data):
    # raw zlib stream (zlib-wrapped deflate) == the "deflate" Content-Encoding
    # token; matches the server's deflate decode (windowBits 15).
    return zlib.compress(data)


def c_xz(data):
    return lzma.compress(data)            # .xz container


def c_bzip2(data):
    return bz2.compress(data)


def c_zstd(data):
    try:
        import zstandard
        return zstandard.ZstdCompressor().compress(data)
    except Exception:
        return _compress_cli("zstd", ["-q", "-c"], data)


def c_brotli(data):
    try:
        import brotli
        return brotli.compress(data)
    except Exception:
        return _compress_cli("brotli", ["-c"], data)


def c_lz4(data):
    # No python lz4 module in this env; the lz4 CLI is the only producer.
    return _compress_cli("lz4", ["-c"], data)


# codec name -> (Content-Encoding token, compressor)
CODECS = {
    "gzip":    ("gzip", c_gzip),
    "deflate": ("deflate", c_deflate),
    "zstd":    ("zstd", c_zstd),
    "xz":      ("xz", c_xz),
    "brotli":  ("br", c_brotli),
    "bzip2":   ("bzip2", c_bzip2),
    "lz4":     ("lz4", c_lz4),
}


def _payload(n=200_000):
    # Mixed structured + random so the codecs actually compress but the
    # round-trip is a strong byte-exact check.
    rnd = os.urandom(n // 2)
    structured = bytes((i & 0xff) for i in range(n - len(rnd)))
    return rnd + structured


def _put(key, data, headers=None):
    return requests.put(_obj_url(key), data=data, headers=headers or {},
                        timeout=60)


def _get(key):
    return requests.get(_obj_url(key), timeout=60)


def _delete(key):
    try:
        requests.delete(_obj_url(key), timeout=30)
    except Exception:
        pass


@pytest.fixture(scope="module", autouse=True)
def _require_server():
    try:
        # A HEAD on the bucket is enough to prove the S3 gateway is up; we do
        # not care about the exact status, only that the socket answers.
        requests.head(f"{BASE}/{BUCKET}/", timeout=5)
    except Exception:
        pytest.skip(f"S3 server not reachable at {BASE}")


@pytest.mark.parametrize("codec", list(CODECS))
def test_put_compressed_roundtrip(codec):
    token, compress = CODECS[codec]
    data = _payload()
    comp = compress(data)
    assert comp is not None and len(comp) > 0
    key = f"cmp_s3_in_{codec}_{uuid.uuid4().hex}.bin"
    try:
        r = _put(key, comp, {"Content-Encoding": token})
        assert r.status_code in (200, 201, 204), \
            f"{codec} PUT status {r.status_code}: {r.text[:200]}"
        g = _get(key)
        assert g.status_code == 200, f"{codec} GET status {g.status_code}"
        assert g.content == data, \
            f"{codec} stored object not byte-exact (got {len(g.content)} want {len(data)})"
    finally:
        _delete(key)


def test_unsupported_encoding_rejected_4xx():
    # "snappy" is a real codec name but one we deliberately do NOT support on
    # ingest. It must be rejected with a client error (4xx) — crucially NOT a
    # 5xx (that would mean the server tried and failed) and NOT stored as-is.
    data = _payload(1000)
    key = f"cmp_s3_in_unsupported_{uuid.uuid4().hex}.bin"
    try:
        r = _put(key, data, {"Content-Encoding": "snappy"})
        assert 400 <= r.status_code < 500, \
            f"unsupported encoding should be 4xx (not 5xx), got {r.status_code}"
        # And the object must not exist (never stored undecoded).
        assert _get(key).status_code in (403, 404), \
            "unsupported-encoding PUT must not leave a stored object"
    finally:
        _delete(key)


def test_decompression_bomb_rejected_413():
    # 8 MiB of zeros gzips to a few KiB: ratio >>1000:1 trips the codec guard.
    bomb = gzip.compress(b"\x00" * (8 * 1024 * 1024))
    key = f"cmp_s3_in_bomb_{uuid.uuid4().hex}.bin"
    try:
        r = _put(key, bomb, {"Content-Encoding": "gzip"})
        # Prefer the precise 413, but accept any 4xx rejection.
        assert r.status_code == 413 or 400 <= r.status_code < 500, \
            f"compression bomb should be 413 (or at least 4xx), got {r.status_code}"
        # No partial object may be persisted.
        assert _get(key).status_code in (403, 404), \
            "rejected bomb must not leave a partial object"
    finally:
        _delete(key)


def test_uppercase_encoding_token_accepted():
    # Content-Encoding is case-insensitive: "GZIP" must decode like "gzip".
    data = _payload(5000)
    key = f"cmp_s3_in_ci_{uuid.uuid4().hex}.bin"
    try:
        r = _put(key, gzip.compress(data), {"Content-Encoding": "GZIP"})
        assert r.status_code in (200, 201, 204), f"GZIP status {r.status_code}"
        g = _get(key)
        assert g.status_code == 200, f"GZIP GET status {g.status_code}"
        assert g.content == data, "uppercase-GZIP stored object not byte-exact"
    finally:
        _delete(key)
