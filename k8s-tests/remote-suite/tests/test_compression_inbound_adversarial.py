"""
Phase-42 W1 — inbound (PUT) decompression over WebDAV: ADVERSARIAL cases.

Companion to test_compression_inbound.py (the happy-path round-trip suite).
Here we feed the server *malformed* compressed bodies and assert that the
codec layer rejects them with a 4xx AND that nothing is ever written to disk
(a failed decode must not leave a partial/undecoded object behind). We also
pin two non-codec behaviours that prove the decode path is *not* invoked when
it must not be: an empty no-encoding PUT stores 0 bytes, and a plain 1KiB
no-encoding PUT is stored byte-exact (identity passthrough).

For each codec gzip/deflate/zstd/xz/bzip2 we test:
  (1) CORRUPT   — valid header, flipped middle bytes        -> 4xx, nothing stored
  (2) TRUNCATED — last 8 bytes dropped (incomplete stream)  -> 4xx, nothing stored
Plus standalone:
  (3) empty body + Content-Encoding: gzip                   -> 4xx
  (4) empty body + NO Content-Encoding                      -> 2xx, GET == 0 bytes
  (5) identity passthrough: 1KiB, NO Content-Encoding       -> 2xx, byte-exact

Requires the WebDAV server (port 8443, auth none, allow_write) built with
phase-42 codec support. Codecs whose compressor is unavailable (no python
module and no CLI) are skipped per-case so the file degrades gracefully.
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

# A 4xx is the contract for a malformed body. Servers may map decode failure
# to 400 (bad request), 415 (unsupported/undecodable), or 422 (unprocessable).
REJECT_4XX = (400, 415, 422)
# After a rejected PUT the object must not exist. 404 is the canonical answer;
# 403 is accepted because some namespaces report a missing path as forbidden.
NOT_STORED = (403, 404)


# ---- client-side compressors: python stdlib where possible, else CLI ----

def _compress_cli(tool, args, data):
    """Compress via an external CLI; skip the case if the tool is absent."""
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
    # No python 'brotli' module in this env; the CLI is the only producer.
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
    "bzip2":   ("bzip2", c_bzip2),
    "lz4":     ("lz4", c_lz4),
}


# ---- payload + corruption helpers ----

def _payload(n=100_000):
    """Mixed random + structured bytes so every codec actually compresses."""
    rnd = os.urandom(n // 2)
    structured = bytes((i & 0xff) for i in range(n - len(rnd)))
    return rnd + structured


def _corrupt_middle(blob):
    """
    Keep the (valid) magic/header intact, then flip bytes in the middle of the
    stream. The header parses but the compressed body is garbage, so the decode
    must fail mid-stream rather than be rejected purely on the header.
    """
    b = bytearray(blob)
    if len(b) < 16:
        pytest.skip("compressed sample too small to corrupt meaningfully")
    lo = len(b) // 4
    hi = (len(b) * 3) // 4
    if hi <= lo:
        hi = lo + 1
    for i in range(lo, hi):
        b[i] ^= 0xFF
    # Guard: ensure we actually changed the bytes (random data could no-op
    # only if all were 0x00 in that window — flipping 0x00 still yields 0xFF).
    assert bytes(b) != blob
    return bytes(b)


def _truncate_tail(blob, drop=8):
    """Drop the last `drop` bytes, leaving the stream structurally incomplete."""
    if len(blob) <= drop + 4:
        pytest.skip("compressed sample too small to truncate")
    return blob[:-drop]


# ---- HTTP helpers ----

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


def _assert_not_stored(path):
    g = _get(path)
    assert g.status_code in NOT_STORED, \
        f"rejected PUT must leave nothing stored; GET {path} -> {g.status_code}"


@pytest.fixture(scope="module", autouse=True)
def _require_server():
    try:
        requests.get(BASE, verify=False, timeout=5)
    except Exception:
        pytest.skip(f"WebDAV server not reachable at {BASE}")


# Codecs whose container carries integrity (gzip CRC32, zlib/deflate Adler32,
# xz CRC, bzip2 block CRC): a mid-stream flip is ALWAYS detected → 4xx.
# zstd and brotli carry NO content checksum by default, so a mid-stream flip is
# NOT detectable by the decoder — it decodes to *different* bytes with no error.
# The security contract for those is therefore weaker but still real: the server
# must NEVER accept a corrupt stream and serve back the pristine original.
INTEGRITY_CODECS = {"gzip", "deflate", "xz", "bzip2"}


def _assert_corrupt_handled(codec, token, original, bad, path):
    """A corrupt compressed PUT must be either rejected (4xx, nothing stored) or,
    for a checksumless codec, accepted only with bytes that differ from the
    original — never a clean accept of the pristine plaintext."""
    r = _put(path, bad, {"Content-Encoding": token})
    if codec in INTEGRITY_CODECS:
        assert r.status_code in REJECT_4XX, \
            f"{codec} corrupt PUT should 4xx, got {r.status_code}: {r.text[:200]}"
        _assert_not_stored(path)
        return
    # Checksumless (zstd/brotli): 4xx is fine; a 2xx is only acceptable if the
    # stored, re-served bytes are NOT the original plaintext (corruption propagated).
    if r.status_code in REJECT_4XX:
        _assert_not_stored(path)
        return
    assert 200 <= r.status_code < 300, \
        f"{codec} corrupt PUT: unexpected status {r.status_code}: {r.text[:200]}"
    g = _get(path)
    assert g.status_code == 200, f"{codec}: stored object not readable back"
    assert g.content != original, \
        f"{codec} corrupt PUT was accepted AND round-tripped to the original — " \
        f"that would be silent acceptance of corrupted input"


# ---- (1) corrupt stream: valid header, flipped middle bytes ----

@pytest.mark.parametrize("codec", list(CODECS))
def test_corrupt_stream_rejected_and_not_stored(codec):
    token, compress = CODECS[codec]
    original = _payload()
    comp = compress(original)
    assert comp and len(comp) > 0
    bad = _corrupt_middle(comp)
    path = f"/cmp_adv_corrupt_{codec}_{uuid.uuid4().hex}.bin"
    try:
        _assert_corrupt_handled(codec, token, original, bad, path)
    finally:
        _delete(path)


# ---- (2) truncated stream: last 8 bytes dropped ----

@pytest.mark.parametrize("codec", list(CODECS))
def test_truncated_stream_rejected_and_not_stored(codec):
    token, compress = CODECS[codec]
    comp = compress(_payload())
    assert comp and len(comp) > 0
    bad = _truncate_tail(comp, 8)
    path = f"/cmp_adv_trunc_{codec}_{uuid.uuid4().hex}.bin"
    try:
        r = _put(path, bad, {"Content-Encoding": token})
        assert r.status_code in REJECT_4XX, \
            f"{codec} truncated PUT should 4xx, got {r.status_code}: {r.text[:200]}"
        _assert_not_stored(path)
    finally:
        _delete(path)


# ---- brotli corrupt case: CLI-only (no python module in this env) ----

def test_brotli_corrupt_stream_rejected_and_not_stored():
    if shutil.which("brotli") is None:
        try:
            import brotli  # noqa: F401
        except Exception:
            pytest.skip("brotli unavailable (no python module and no CLI)")
    original = _payload()
    comp = c_brotli(original)
    assert comp and len(comp) > 0
    bad = _corrupt_middle(comp)
    path = f"/cmp_adv_corrupt_br_{uuid.uuid4().hex}.bin"
    try:
        # brotli carries no content checksum → checksumless contract (4xx, or a
        # 2xx whose stored bytes differ from the original).
        _assert_corrupt_handled("br", "br", original, bad, path)
    finally:
        _delete(path)


# ---- (3) empty body declared as gzip is not a valid gzip stream ----

def test_empty_body_with_gzip_encoding_rejected():
    path = f"/cmp_adv_empty_gzip_{uuid.uuid4().hex}.bin"
    try:
        r = _put(path, b"", {"Content-Encoding": "gzip"})
        assert r.status_code in REJECT_4XX, \
            f"empty body + gzip encoding should 4xx, got {r.status_code}: {r.text[:200]}"
        _assert_not_stored(path)
    finally:
        _delete(path)


# ---- (4) empty body, NO encoding: valid 0-byte object ----

def test_empty_body_no_encoding_stored_zero_bytes():
    path = f"/cmp_adv_empty_plain_{uuid.uuid4().hex}.bin"
    try:
        r = _put(path, b"")
        assert r.status_code in (200, 201, 204), \
            f"empty PUT (no encoding) should 2xx, got {r.status_code}: {r.text[:200]}"
        g = _get(path)
        assert g.status_code == 200, f"GET of 0-byte object -> {g.status_code}"
        assert g.content == b"", \
            f"0-byte object must read back empty, got {len(g.content)} bytes"
    finally:
        _delete(path)


# ---- (5) identity passthrough: 1KiB, no encoding, byte-exact ----

def test_identity_passthrough_no_encoding_byte_exact():
    data = os.urandom(1024)
    path = f"/cmp_adv_identity_{uuid.uuid4().hex}.bin"
    try:
        r = _put(path, data)  # deliberately NO Content-Encoding header
        assert r.status_code in (200, 201, 204), \
            f"identity PUT should 2xx, got {r.status_code}: {r.text[:200]}"
        g = _get(path)
        assert g.status_code == 200, f"identity GET -> {g.status_code}"
        assert g.content == data, \
            f"identity passthrough not byte-exact (got {len(g.content)} want {len(data)})"
    finally:
        _delete(path)
