"""
Phase-42 W1 — inbound (PUT) decompression over WebDAV.

For every codec the server may decode (gzip, deflate, zstd, xz, brotli, bzip2):
compress a payload client-side, PUT it with the matching Content-Encoding header,
GET it back, and assert the stored object is the decompressed (original) bytes.
Also: an unsupported Content-Encoding must be rejected 415, and a decompression
bomb must be rejected 413 (the codec-layer ratio guard), never written to disk.

Requires the WebDAV server (port 8443) built with phase-42 codec support.
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
import urllib3

from settings import NGINX_WEBDAV_PORT

urllib3.disable_warnings()

BASE = f"https://localhost:{NGINX_WEBDAV_PORT}"


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
    # zlib-wrapped deflate (matches the server's deflate decode = windowBits 15)
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
    # no python lz4 module in this env — compress via the lz4 CLI (LZ4 Frame),
    # which the server's LZ4F decoder accepts (cross-tool interop).
    return _compress_cli("lz4", ["-c"], data)


# codec name -> (Content-Encoding token, compressor)
CODECS = {
    "gzip":   ("gzip", c_gzip),
    "deflate": ("deflate", c_deflate),
    "zstd":   ("zstd", c_zstd),
    "xz":     ("xz", c_xz),
    "brotli": ("br", c_brotli),
    "bzip2":  ("bzip2", c_bzip2),
    "lz4":    ("lz4", c_lz4),
}

# zstd + lz4 are compile-gated OPTIONAL decoders (-DBRIX_HAVE_ZSTD / -DBRIX_HAVE_LZ4).
# A server built without libzstd/liblz4 dev headers rejects those Content-Encodings
# with 415 (exactly like the deliberately-unsupported "snappy" case below). Skip the
# optional case then; mandatory decoders (gzip/deflate/xz/br/bzip2) are always run.
OPTIONAL_CODECS = {"zstd", "lz4"}


def _payload(n=200_000):
    # Mixed structured + random so the codecs actually compress but the
    # round-trip is a strong byte-exact check.
    rnd = os.urandom(n // 2)
    structured = bytes((i & 0xff) for i in range(n - len(rnd)))
    return rnd + structured


def _put(path, data, headers=None):
    return requests.put(f"{BASE}{path}", data=data, headers=headers or {},
                        verify=False, timeout=60)


def _get(path):
    return requests.get(f"{BASE}{path}", verify=False, timeout=60)


def _delete(path):
    try:
        requests.delete(f"{BASE}{path}", verify=False, timeout=30)
    except Exception:
        pass


@pytest.fixture(scope="module", autouse=True)
def _require_server():
    try:
        requests.get(BASE, verify=False, timeout=5)
    except Exception:
        pytest.skip(f"WebDAV server not reachable at {BASE}")


@pytest.mark.parametrize("codec", list(CODECS))
def test_put_compressed_roundtrip(codec):
    token, compress = CODECS[codec]
    data = _payload()
    comp = compress(data)
    assert comp is not None and len(comp) > 0
    path = f"/cmp_in_{codec}_{uuid.uuid4().hex}.bin"
    try:
        r = _put(path, comp, {"Content-Encoding": token})
        if codec in OPTIONAL_CODECS and r.status_code == 415:
            pytest.skip(
                f"server build lacks inbound decoder for optional codec "
                f"'{codec}' (415 unsupported-encoding)")
        assert r.status_code in (200, 201, 204), \
            f"{codec} PUT status {r.status_code}: {r.text[:200]}"
        g = _get(path)
        assert g.status_code == 200, f"{codec} GET status {g.status_code}"
        assert g.content == data, \
            f"{codec} stored object not byte-exact (got {len(g.content)} want {len(data)})"
    finally:
        _delete(path)


def test_unsupported_encoding_415():
    data = _payload(1000)
    path = f"/cmp_in_unsupported_{uuid.uuid4().hex}.bin"
    try:
        # "snappy" is a real codec name but one we deliberately do NOT support.
        r = _put(path, data, {"Content-Encoding": "snappy"})
        assert r.status_code == 415, \
            f"unsupported encoding should be 415, got {r.status_code}"
        # And the object must not exist (never stored undecoded).
        assert _get(path).status_code in (404, 403)
    finally:
        _delete(path)


def test_decompression_bomb_rejected_413():
    # ~4 MiB of zeros gzips to a few KiB: ratio >1000:1 trips the codec guard.
    bomb = gzip.compress(b"\x00" * (4 * 1024 * 1024))
    path = f"/cmp_in_bomb_{uuid.uuid4().hex}.bin"
    try:
        r = _put(path, bomb, {"Content-Encoding": "gzip"})
        assert r.status_code == 413, \
            f"compression bomb should be 413, got {r.status_code}"
        assert _get(path).status_code in (404, 403)
    finally:
        _delete(path)


def test_uppercase_encoding_token_accepted():
    # Content-Encoding is case-insensitive.
    data = _payload(5000)
    path = f"/cmp_in_ci_{uuid.uuid4().hex}.bin"
    try:
        r = _put(path, gzip.compress(data), {"Content-Encoding": "GZIP"})
        assert r.status_code in (200, 201, 204), f"GZIP status {r.status_code}"
        assert _get(path).content == data
    finally:
        _delete(path)
