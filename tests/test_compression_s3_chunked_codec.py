"""
GAP AWSCHUNK-CE — S3 aws-chunked upload that ALSO names an inner Content-Encoding.

Modern AWS SDKs/CLI stream uploads with an application-layer chunk framing carried
inside the HTTP body (``x-amz-content-sha256: STREAMING-*`` / ``Content-Encoding:
aws-chunked``).  The streaming de-chunker strips ONLY the chunk envelope.  If the
client *also* names an inner content-coding (e.g. ``Content-Encoding:
aws-chunked,gzip``) the payload was compressed THEN chunk-framed — de-chunking it
leaves the bytes still gzip-compressed, which would be committed as a silently
corrupt object.

The server was fixed (src/protocols/s3/put.c → ``s3_aws_chunked_has_inner_coding`` guard) to
REJECT such a request with 400 and abort the staged object so it is never committed,
mirroring the non-chunked path's 400 for an undecodable Content-Encoding.

These tests build the aws-chunked framing by hand (the test server is anonymous, so
per-chunk signatures need not be valid — we use ``STREAMING-UNSIGNED-PAYLOAD-TRAILER``
which needs no per-chunk sig).  They prove:
  (1) ``Content-Encoding: aws-chunked,gzip`` with a gzip-compressed inner payload is
      rejected (4xx) AND a subsequent GET/HEAD shows the object was never stored (404).
  (2) plain ``Content-Encoding: aws-chunked`` (no inner codec) still round-trips
      byte-exact (control — the fix did not break normal chunked uploads).

Attaches to the fleet's dedicated "compress" instance (S3 surface: anonymous +
allow_write) started once by start_all_dedicated, rather than launching its own
nginx: a fixed-port self-start collides across pytest-xdist workers. The inner
aws-chunked-codec guard lives on the PUT path, so the S3 surface having
`brix_compress on` (an outbound-GET directive) does not affect these cases.
"""

import gzip
import os
import time
import uuid

import pytest
import requests
from settings import HOST

BUCKET = "testbucket"
# Fixed port of the fleet "compress" instance S3 surface (see
# tests/lib/dedicated.sh -> start_all_dedicated + tests/configs/nginx_compress.conf).
COMPRESS_S3_PORT = int(os.environ.get("TEST_COMPRESS_S3_PORT", "12961"))
BASE_URL = f"http://{HOST}:{COMPRESS_S3_PORT}"


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
    """Attach to the fleet "compress" S3 surface; skip cleanly if it is down. The
    tests PUT and GET their own uuid-named objects, so no seeding is needed."""
    if not _wait_listen(BASE_URL):
        pytest.skip(
            f"fleet compress instance not listening on {COMPRESS_S3_PORT}")
    yield BASE_URL


# ---------------------------------------------------------------------------
# aws-chunked framing helpers (unsigned: no per-chunk signature required).
# ---------------------------------------------------------------------------
def _chunk(data):
    """One aws-chunked frame: '<hexlen>\\r\\n<bytes>\\r\\n'."""
    return b"%x\r\n%s\r\n" % (len(data), data)


def _framed(payload):
    """Wrap one payload body as a complete aws-chunked stream + final 0-chunk."""
    return _chunk(payload) + b"0\r\n\r\n"


def _key(base, tag):
    return f"{base}/{BUCKET}/awsce_{tag}_{uuid.uuid4().hex}.bin"


def _put_chunked(base, payload, decoded_len, content_encoding):
    """PUT an aws-chunked body using STREAMING-UNSIGNED-PAYLOAD-TRAILER.

    `payload` is the already-framed inner body bytes (the chunk envelope wraps
    whatever bytes the client streamed); `decoded_len` is what the client claims
    the de-chunked content length is (x-amz-decoded-content-length).
    """
    body = _framed(payload)
    headers = {
        "x-amz-content-sha256": "STREAMING-UNSIGNED-PAYLOAD-TRAILER",
        "x-amz-decoded-content-length": str(decoded_len),
        "Content-Length": str(len(body)),
        "Content-Encoding": content_encoding,
    }
    key = _key(base, content_encoding.replace(",", "_").replace(" ", ""))
    return key, requests.put(key, data=body, headers=headers, timeout=30)


def _exists(key):
    """True iff the object is committed (HEAD or GET sees a 200)."""
    h = requests.head(key, timeout=15)
    g = requests.get(key, timeout=15)
    return h.status_code, g.status_code


# ---------------------------------------------------------------------------
# (1) aws-chunked + inner codec is rejected AND never committed.
# ---------------------------------------------------------------------------
def test_aws_chunked_with_inner_gzip_rejected_and_not_stored(base):
    raw = b"the quick brown fox jumps over the lazy dog\n" * 200
    inner = gzip.compress(raw)              # compressed THEN chunk-framed
    # decoded length = the de-chunked (still-compressed) byte count the client
    # would claim; the server must reject before any of this matters.
    key, r = _put_chunked(base, inner, len(inner), "aws-chunked,gzip")
    assert r.status_code == 400, (
        f"aws-chunked,gzip must be rejected with 400, got {r.status_code}: "
        f"{r.text[:300]!r}"
    )
    # The corrupt object must never be committed.
    head, get = _exists(key)
    assert head == 404, f"object must not be stored (HEAD {head})"
    assert get == 404, f"object must not be stored (GET {get})"


@pytest.mark.parametrize("ce", ["aws-chunked, gzip", "gzip,aws-chunked", "aws-chunked,deflate"])
def test_aws_chunked_inner_codec_variants_rejected(base, ce):
    # Inner coding can be listed before/after aws-chunked, with whitespace, and
    # may name any non-identity codec — all must reject and never store.
    raw = b"payload variant " * 64
    inner = gzip.compress(raw) if "gzip" in ce else __import__("zlib").compress(raw)
    key, r = _put_chunked(base, inner, len(inner), ce)
    assert r.status_code == 400, f"{ce!r} expected 400, got {r.status_code}"
    head, get = _exists(key)
    assert head == 404 and get == 404, f"{ce!r}: object leaked (HEAD {head} GET {get})"


# ---------------------------------------------------------------------------
# (2) Control: plain aws-chunked (no inner codec) still works byte-exact.
# ---------------------------------------------------------------------------
def test_plain_aws_chunked_roundtrips(base):
    data = b"plain aws-chunked control payload " * 100
    key, r = _put_chunked(base, data, len(data), "aws-chunked")
    assert r.status_code in (200, 201, 204), (
        f"plain aws-chunked PUT failed: {r.status_code} {r.text[:300]!r}"
    )
    g = requests.get(key, timeout=15)
    assert g.status_code == 200
    assert g.content == data, "plain aws-chunked body must round-trip byte-exact"
    requests.delete(key, timeout=15)


def test_plain_aws_chunked_identity_token_roundtrips(base):
    # "aws-chunked,identity" carries no real inner coding — identity is a no-op,
    # so it must be accepted (the guard treats identity like aws-chunked).
    data = b"identity is a no-op coding " * 80
    key, r = _put_chunked(base, data, len(data), "aws-chunked,identity")
    assert r.status_code in (200, 201, 204), (
        f"aws-chunked,identity PUT failed: {r.status_code} {r.text[:300]!r}"
    )
    g = requests.get(key, timeout=15)
    assert g.status_code == 200 and g.content == data
    requests.delete(key, timeout=15)
