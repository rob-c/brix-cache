"""S3 aws-chunked streaming upload decode (phase-43 W0).

Modern AWS SDKs/CLI upload with an application-layer chunk framing carried inside
the HTTP body (x-amz-content-sha256: STREAMING-*).  Without decoding, that framing
is stored verbatim — corrupting every object.  These tests build the framing by
hand (the shared server is anonymous, so chunk signatures need not be valid) and
verify byte-exact decode, trailer-checksum verification, and the failure modes.

Uses the pre-started nginx_shared instance (port 9001), anonymous + write.
"""

import base64
import uuid
import zlib

import pytest
import requests

from settings import S3_BUCKET

BUCKET = S3_BUCKET


@pytest.fixture(scope="module")
def s3_url(test_env):
    return test_env["s3_url"]


def _put_chunked(s3_url, body, decoded_len, *, kind="STREAMING-UNSIGNED-PAYLOAD-TRAILER",
                 content_encoding="aws-chunked"):
    key = f"{s3_url}/{BUCKET}/stream_{uuid.uuid4().hex}"
    headers = {
        "x-amz-content-sha256": kind,
        "x-amz-decoded-content-length": str(decoded_len),
        "Content-Length": str(len(body)),
    }
    if content_encoding:
        headers["Content-Encoding"] = content_encoding
    return key, requests.put(key, data=body, headers=headers, timeout=15)


def _chunk(data, signature=None):
    if signature is not None:
        return b"%x;chunk-signature=%s\r\n%s\r\n" % (len(data), signature, data)
    return b"%x\r\n%s\r\n" % (len(data), data)


def test_unsigned_single_chunk(s3_url):
    data = b"hello streaming world"
    body = _chunk(data) + b"0\r\n\r\n"
    key, r = _put_chunked(s3_url, body, len(data))
    assert r.status_code == 200
    assert requests.get(key, timeout=15).content == data
    requests.delete(key, timeout=15)


def test_signed_multi_chunk(s3_url):
    d1, d2 = b"hello", b" signed world"
    body = (
        _chunk(d1, b"a" * 64)
        + _chunk(d2, b"b" * 64)
        + b"0;chunk-signature=%s\r\n\r\n" % (b"c" * 64)
    )
    key, r = _put_chunked(
        s3_url, body, len(d1) + len(d2), kind="STREAMING-AWS4-HMAC-SHA256-PAYLOAD"
    )
    assert r.status_code == 200
    assert requests.get(key, timeout=15).content == d1 + d2
    requests.delete(key, timeout=15)


def test_detect_via_sha256_without_content_encoding(s3_url):
    # Some clients omit Content-Encoding and signal streaming only via the
    # x-amz-content-sha256 header — decode must still trigger.
    data = b"detected by sha256 header"
    body = _chunk(data) + b"0\r\n\r\n"
    key, r = _put_chunked(s3_url, body, len(data), content_encoding=None)
    assert r.status_code == 200
    assert requests.get(key, timeout=15).content == data
    requests.delete(key, timeout=15)


def test_trailer_checksum_verified_and_echoed(s3_url):
    data = b"trailer checksum payload"
    crc = base64.b64encode((zlib.crc32(data) & 0xFFFFFFFF).to_bytes(4, "big")).decode()
    body = _chunk(data) + b"0\r\nx-amz-checksum-crc32:%s\r\n\r\n" % crc.encode()
    key, r = _put_chunked(s3_url, body, len(data))
    assert r.status_code == 200
    assert r.headers.get("x-amz-checksum-crc32") == crc
    requests.delete(key, timeout=15)


def test_trailer_checksum_mismatch_rejected(s3_url):
    data = b"trailer checksum payload"
    bad = base64.b64encode((0).to_bytes(4, "big")).decode()
    body = _chunk(data) + b"0\r\nx-amz-checksum-crc32:%s\r\n\r\n" % bad.encode()
    key, r = _put_chunked(s3_url, body, len(data))
    assert r.status_code == 400
    assert "BadDigest" in r.text
    assert requests.head(key, timeout=15).status_code == 404  # object not kept


def test_decoded_length_mismatch_rejected(s3_url):
    data = b"twenty-ish bytes here"
    body = _chunk(data) + b"0\r\n\r\n"
    key, r = _put_chunked(s3_url, body, len(data) + 5)  # lie about decoded length
    assert r.status_code == 400
    assert requests.head(key, timeout=15).status_code == 404


def test_missing_decoded_length_rejected(s3_url):
    data = b"no decoded length header"
    body = _chunk(data) + b"0\r\n\r\n"
    key = f"{s3_url}/{BUCKET}/stream_{uuid.uuid4().hex}"
    r = requests.put(
        key,
        data=body,
        headers={
            "x-amz-content-sha256": "STREAMING-UNSIGNED-PAYLOAD-TRAILER",
            "Content-Encoding": "aws-chunked",
            "Content-Length": str(len(body)),
        },
        timeout=15,
    )
    assert r.status_code == 400


def test_large_multichunk_byte_exact(s3_url):
    # Exercises the spooled-body 64 KiB windowed read path with many chunks.
    import hashlib

    blob = hashlib.sha256(b"seed").digest() * 8000  # 256 KiB
    parts, off, csz = [], 0, 7000
    while off < len(blob):
        parts.append(_chunk(blob[off:off + csz]))
        off += csz
    body = b"".join(parts) + b"0\r\n\r\n"
    key, r = _put_chunked(s3_url, body, len(blob))
    assert r.status_code == 200
    assert requests.get(key, timeout=15).content == blob
    requests.delete(key, timeout=15)
