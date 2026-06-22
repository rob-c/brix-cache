"""
Phase-42 W1 — inbound (PUT) decompression GAPS: per-codec bomb guards,
trailing-garbage frame handling, and doubled Content-Encoding.

Companion to test_compression_inbound.py / test_compression_inbound_adversarial.py.
Those suites prove the happy-path round-trip + corrupt/truncated rejection. They
only ever test the *gzip* decompression-bomb path. This file closes three gaps on
the WebDAV PUT decode path (shared harness, port 8443):

  (1) BOMB-CODECS  — for EVERY codec the server decodes, PUT a decompression bomb
                     (several MiB of zeros, expansion ratio well over 1000:1) and
                     assert the codec-layer ratio guard fires with 413 and stores
                     nothing. Today only gzip's bomb path is exercised.
  (2) TRAILING     — PUT a VALID complete frame with 64 random garbage bytes
                     appended. The contract: the server must NOT silently store a
                     second concatenated frame's output. Either a 4xx (nothing
                     stored) OR a 2xx whose stored object equals EXACTLY the first
                     frame's plaintext. Tested for gzip (zlib drops trailing bytes)
                     and zstd + lz4 (both concatenated-frame capable) so the
                     codec-divergent behaviour is locked down.
  (3) DOUBLE-CE    — PUT with Content-Encoding "gzip, gzip" (comma list) AND with a
                     genuinely doubled header line. Assert deterministic behaviour:
                     either reject, or decode exactly once to a correct object —
                     NEVER a half-decoded object.

The server bomb guard (src/compat/codec_core.c + http_body.{c,h}) is an output cap
(XROOTD_DECODE_MAX_OUTPUT = 16 GiB) plus an expansion-ratio ceiling
(XROOTD_DECODE_MAX_RATIO = 1000:1, engaged once >= 64 KiB has been produced). LZ4
uses a lower codec-specific threshold because its frame format compresses zero
bombs below 1000:1.

Requires the WebDAV server (port 8443, auth none, allow_write) built with phase-42
codec support, the bomb guard, and local producer tooling for every codec case.
"""

import bz2
import gzip
import lzma
import os
import shutil
import socket
import ssl
import subprocess
import uuid
import zlib

import pytest
import requests
import urllib3

from settings import NGINX_WEBDAV_PORT, SERVER_HOST

urllib3.disable_warnings()

BASE = f"https://{SERVER_HOST}:{NGINX_WEBDAV_PORT}"

# A tripped bomb guard maps to 413 (request entity too large).
BOMB_413 = 413
# A rejected PUT must leave nothing stored. 404 is canonical; 403 is accepted
# because some namespaces report a missing path as forbidden.
NOT_STORED = (403, 404)
# Deterministic rejection statuses for malformed/ambiguous encodings.
REJECT_4XX = (400, 415, 422)
STORED_2XX = (200, 201, 204)


# ---- client-side compressors: python stdlib where possible, else CLI ----

def _compress_cli(tool, args, data):
    """Compress via an external CLI; fail the case if the tool is absent."""
    path = shutil.which(tool)
    if path is None:
        pytest.fail(f"{tool} not available to produce test payload")
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
    # No python lz4 module in this env; the lz4 CLI is the only producer
    # (LZ4 Frame format, which the server's LZ4F decoder accepts).
    return _compress_cli("lz4", ["-c"], data)


# codec name -> (Content-Encoding token, compressor)
CODECS = {
    "gzip":    ("gzip", c_gzip),
    "deflate": ("deflate", c_deflate),
    "zstd":    ("zstd", c_zstd),
    "xz":      ("xz", c_xz),
    "bzip2":   ("bzip2", c_bzip2),
    "brotli":  ("br", c_brotli),
    "lz4":     ("lz4", c_lz4),
}

# Codecs whose expansion on a zero bomb must trip the server's bomb guard. LZ4
# uses a lower codec-specific ceiling in untrusted HTTP decode because its frame
# format does not reach the generic 1000:1 threshold.
RATIO_GUARDED = ("gzip", "deflate", "zstd", "xz", "bzip2", "brotli", "lz4")


# ---- HTTP helpers ----

def _put(path, data, headers=None):
    return requests.put(f"{BASE}{path}", data=data, headers=headers or {},
                        verify=False, timeout=120)


def _get(path):
    return requests.get(f"{BASE}{path}", verify=False, timeout=120)


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


# ===========================================================================
# (1) BOMB-CODECS — every codec's decompression-bomb guard must fire.
# ===========================================================================

# 6 MiB of zeros: every ratio-guarded codec compresses this far past 1000:1, so
# the ratio ceiling trips once >= 64 KiB has been produced. Kept modest so the
# decode aborts almost immediately (the guard fires long before 6 MiB is written).
_BOMB_PLAIN = b"\x00" * (6 * 1024 * 1024)


@pytest.mark.parametrize("codec", list(RATIO_GUARDED))
def test_bomb_rejected_413_and_not_stored(codec):
    """A >1000:1 expansion bomb must be rejected 413 and never stored."""
    token, compress = CODECS[codec]
    bomb = compress(_BOMB_PLAIN)
    assert bomb and len(bomb) > 0
    # Sanity: the producer really achieved a bomb-grade ratio for this codec.
    ratio = len(_BOMB_PLAIN) // max(1, len(bomb))
    min_ratio = 200 if codec == "lz4" else 1000
    assert ratio > min_ratio, \
        f"{codec} producer only achieved {ratio}:1 — not above {min_ratio}:1"
    path = f"/cmp_bomb_{codec}_{uuid.uuid4().hex}.bin"
    try:
        r = _put(path, bomb, {"Content-Encoding": token})
        assert r.status_code == BOMB_413, \
            f"{codec} bomb should be 413, got {r.status_code}: {r.text[:200]}"
        _assert_not_stored(path)
    finally:
        _delete(path)


# ===========================================================================
# (2) TRAILING — valid frame + 64 garbage bytes: never a second frame's output.
# ===========================================================================

# Small + highly compressible so the whole frame lands in a single body buffer
# (so the codec hits end-of-stream and stops before the trailing garbage). The
# value is random-ish but reproducible per run via the frame's own bytes.
_TRAIL_PLAIN = (b"the-quick-brown-fox-jumps-over-the-lazy-dog-" * 64)


# Only codecs whose stream layout makes "valid frame then more bytes" meaningful:
# gzip (zlib stops cleanly at the gzip trailer and ignores the rest), and zstd +
# lz4 whose frame formats are explicitly concatenation-capable (multiple frames
# back-to-back are a single logical stream). If the server fed the garbage on as a
# second frame, the stored object would differ from the first frame's plaintext.
_TRAILING_CODECS = {
    "gzip": ("gzip", c_gzip),
    "zstd": ("zstd", c_zstd),
    "lz4":  ("lz4", c_lz4),
}


@pytest.mark.parametrize("codec", list(_TRAILING_CODECS))
def test_trailing_garbage_after_frame_is_deterministic(codec):
    """A valid frame + 64 trailing garbage bytes: the server must EITHER reject
    (4xx, nothing stored) OR store EXACTLY the first frame's plaintext — never a
    longer object that would imply a second concatenated frame was decoded."""
    token, compress = _TRAILING_CODECS[codec]
    frame = compress(_TRAIL_PLAIN)
    assert frame and len(frame) > 0
    blob = frame + os.urandom(64)
    path = f"/cmp_trail_{codec}_{uuid.uuid4().hex}.bin"
    try:
        r = _put(path, blob, {"Content-Encoding": token})
        if r.status_code in REJECT_4XX:
            _assert_not_stored(path)
            return
        assert r.status_code in STORED_2XX, \
            f"{codec} trailing PUT: unexpected status {r.status_code}: {r.text[:200]}"
        g = _get(path)
        assert g.status_code == 200, f"{codec} trailing GET -> {g.status_code}"
        assert g.content == _TRAIL_PLAIN, (
            f"{codec} trailing garbage changed the stored object: got "
            f"{len(g.content)} bytes, expected exactly the first frame's "
            f"{len(_TRAIL_PLAIN)}-byte plaintext (a second concatenated frame "
            f"must NOT be silently decoded/stored)"
        )
    finally:
        _delete(path)


# ===========================================================================
# (3) DOUBLE-CE — a doubled Content-Encoding must be deterministic, not half-done.
# ===========================================================================

_DCE_PLAIN = b"double-content-encoding-probe-" * 50


def test_double_ce_comma_list_is_deterministic():
    """Content-Encoding: "gzip, gzip" (comma list). The server must behave
    deterministically: reject (4xx, nothing stored), or decode to a correct,
    fully-decoded object — never a half-decoded object."""
    single = gzip.compress(_DCE_PLAIN)        # one gzip frame
    double = gzip.compress(single)            # gzip-of-gzip (true double-encode)
    path = f"/cmp_dce_comma_{uuid.uuid4().hex}.bin"
    try:
        # Body is the genuinely double-encoded bytes, matching the doubled token.
        r = _put(path, double, {"Content-Encoding": "gzip, gzip"})
        if r.status_code in REJECT_4XX:
            _assert_not_stored(path)
            return
        assert r.status_code in STORED_2XX, \
            f"comma-list PUT: unexpected status {r.status_code}: {r.text[:200]}"
        g = _get(path)
        assert g.status_code == 200, f"comma-list GET -> {g.status_code}"
        # A non-reject MUST be a clean, fully-decoded result. Acceptable outcomes:
        #   - decoded TWICE -> original plaintext
        #   - decoded ONCE  -> the inner single gzip frame (a valid, whole object)
        # Both are fully-decoded objects; a half-decoded/garbage object is not.
        assert g.content in (_DCE_PLAIN, single), (
            "comma-list double-CE produced a half-decoded object: stored "
            f"{len(g.content)} bytes that match neither the twice-decoded "
            f"plaintext ({len(_DCE_PLAIN)}) nor the once-decoded inner frame "
            f"({len(single)})"
        )
    finally:
        _delete(path)


def _raw_put_dup_header(path, body, ce_value, count=2):
    """PUT via a raw TLS socket with `count` separate identical Content-Encoding
    header LINES (requests would merge these into a comma list, so we go raw).
    Returns the HTTP status code."""
    ctx = ssl._create_unverified_context()
    with socket.create_connection((SERVER_HOST, NGINX_WEBDAV_PORT),
                                  timeout=30) as raw:
        with ctx.wrap_socket(raw, server_hostname=SERVER_HOST) as ss:
            head = (f"PUT {path} HTTP/1.1\r\nHost: {SERVER_HOST}\r\n"
                    + (f"Content-Encoding: {ce_value}\r\n" * count)
                    + f"Content-Length: {len(body)}\r\n"
                    + "Connection: close\r\n\r\n").encode()
            ss.sendall(head + body)
            data = b""
            while True:
                chunk = ss.recv(65536)
                if not chunk:
                    break
                data += chunk
    status_line = data.split(b"\r\n", 1)[0]
    return int(status_line.split(b" ")[1])


def test_double_ce_doubled_header_line_is_deterministic():
    """Two SEPARATE `Content-Encoding: gzip` header lines (not a comma list).
    The server must be deterministic and never store a half-decoded object: it
    either rejects, or applies a single well-defined decode producing a whole,
    fully-decoded object."""
    single = gzip.compress(_DCE_PLAIN)
    double = gzip.compress(single)
    path = f"/cmp_dce_dup_{uuid.uuid4().hex}.bin"
    try:
        status = _raw_put_dup_header(path, double, "gzip", count=2)
        if status in REJECT_4XX:
            _assert_not_stored(path)
            return
        assert status in STORED_2XX, \
            f"doubled-header PUT: unexpected status {status}"
        g = _get(path)
        assert g.status_code == 200, f"doubled-header GET -> {g.status_code}"
        # Whatever single decode the server chose, the result must be a whole,
        # fully-decoded object: either the once-decoded inner frame or the
        # twice-decoded plaintext — never a partial/garbage blob.
        assert g.content in (single, _DCE_PLAIN), (
            "doubled Content-Encoding header produced a half-decoded object: "
            f"stored {len(g.content)} bytes matching neither the once-decoded "
            f"inner frame ({len(single)}) nor the twice-decoded plaintext "
            f"({len(_DCE_PLAIN)})"
        )
    finally:
        _delete(path)
