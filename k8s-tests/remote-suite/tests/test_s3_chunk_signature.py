# brix-remote-skip
"""S3 aws-chunked per-chunk SigV4 signature verification (phase-47 W6a).

The dedicated *signed* S3 server (port 11183) runs with
`brix_s3_verify_chunk_signatures on`.  These tests build a real
STREAMING-AWS4-HMAC-SHA256-PAYLOAD upload, computing each chunk's signature with
the rolling-previous-signature chain, and assert:

  1. success      — correctly-signed chunks → 200, body byte-exact.
  2. error/sec     — one tampered chunk signature → 403 (SignatureDoesNotMatch).
  3. regression    — the anonymous server (port 9001, verify off) still accepts
                     garbage chunk signatures (decode-only, no verification).

The signing here mirrors the AWS streaming spec; the server must reconstruct the
identical seed signature and per-chunk string-to-sign, so any divergence fails.
"""

import datetime as dt
import hashlib
import hmac
import os
import uuid

import pytest
import requests

from settings import NGINX_S3_PORT, S3_PRESIGNED_PORT, S3_BUCKET, TEST_ROOT

# The signed server (11183) writes objects under this root (bucket stripped).
# It rejects unsigned GET/DELETE, so success/cleanup are checked on disk.
SIGNED_DATA_DIR = os.path.join(TEST_ROOT, "data-s3-presigned")

ACCESS_KEY = "test-access-key"
SECRET_KEY = "test-secret-key"
REGION = "us-east-1"
SERVICE = "s3"
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()
STREAMING = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD"


def _sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _hmac(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode(), hashlib.sha256).digest()


def _signing_key(date: str) -> bytes:
    k = _hmac(("AWS4" + SECRET_KEY).encode(), date)
    k = _hmac(k, REGION)
    k = _hmac(k, SERVICE)
    return _hmac(k, "aws4_request")


def _build_streaming_put(host, key, chunks, *, tamper_index=None):
    """Return (headers, body) for a signed aws-chunked PUT of `chunks` (a list
    of byte payloads).  If tamper_index is set, that chunk's signature is
    corrupted to exercise rejection."""
    now = dt.datetime.now(dt.timezone.utc)
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    date = now.strftime("%Y%m%d")
    scope = f"{date}/{REGION}/{SERVICE}/aws4_request"
    skey = _signing_key(date)

    decoded_len = sum(len(c) for c in chunks)
    uri = f"/{S3_BUCKET}/{key}"
    signed_headers = ("content-encoding;host;x-amz-content-sha256;"
                      "x-amz-date;x-amz-decoded-content-length")
    canonical_headers = (
        f"content-encoding:aws-chunked\n"
        f"host:{host}\n"
        f"x-amz-content-sha256:{STREAMING}\n"
        f"x-amz-date:{amz_date}\n"
        f"x-amz-decoded-content-length:{decoded_len}\n"
    )
    # The server canonicalizes the seed request with a hardcoded UNSIGNED-PAYLOAD
    # hashed-payload (XrdClS3 convention), regardless of x-amz-content-sha256.
    canonical_request = (
        f"PUT\n{uri}\n\n{canonical_headers}\n{signed_headers}\nUNSIGNED-PAYLOAD"
    )
    string_to_sign = (
        f"AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n"
        f"{_sha256(canonical_request.encode())}"
    )
    seed_sig = hmac.new(skey, string_to_sign.encode(), hashlib.sha256).hexdigest()

    # Roll the per-chunk signatures (each over its own payload), then the final
    # zero-length chunk over the empty payload.
    body = b""
    prev = seed_sig
    for i, payload in enumerate(chunks + [b""]):
        sts = (f"AWS4-HMAC-SHA256-PAYLOAD\n{amz_date}\n{scope}\n{prev}\n"
               f"{EMPTY_SHA256}\n{_sha256(payload)}")
        sig = hmac.new(skey, sts.encode(), hashlib.sha256).hexdigest()
        prev = sig
        if tamper_index is not None and i == tamper_index:
            sig = "0" * 64
        body += b"%x;chunk-signature=%s\r\n%s\r\n" % (
            len(payload), sig.encode(), payload)

    headers = {
        "Host": host,
        "x-amz-date": amz_date,
        "x-amz-content-sha256": STREAMING,
        "x-amz-decoded-content-length": str(decoded_len),
        "Content-Encoding": "aws-chunked",
        "Authorization": (
            f"AWS4-HMAC-SHA256 Credential={ACCESS_KEY}/{scope}, "
            f"SignedHeaders={signed_headers}, Signature={seed_sig}"
        ),
    }
    return headers, body


@pytest.fixture(scope="module")
def signed_host():
    return f"127.0.0.1:{S3_PRESIGNED_PORT}"


def _put(host, key, headers, body):
    return requests.put(f"http://{host}/{S3_BUCKET}/{key}", headers=headers,
                        data=body, timeout=15)


def test_valid_chunk_signatures_accepted(signed_host):
    key = f"chunksig_{uuid.uuid4().hex}"
    chunks = [b"hello ", b"streaming ", b"world"]
    headers, body = _build_streaming_put(signed_host, key, chunks)
    r = _put(signed_host, key, headers, body)
    assert r.status_code == 200, (r.status_code, r.text)

    # The signed server rejects unsigned GETs, so verify the commit on disk.
    path = os.path.join(SIGNED_DATA_DIR, key)
    try:
        with open(path, "rb") as f:
            assert f.read() == b"".join(chunks)
    finally:
        if os.path.exists(path):
            os.remove(path)


def test_tampered_chunk_signature_rejected(signed_host):
    key = f"chunksig_{uuid.uuid4().hex}"
    chunks = [b"hello ", b"streaming ", b"world"]
    headers, body = _build_streaming_put(signed_host, key, chunks, tamper_index=1)
    r = _put(signed_host, key, headers, body)
    assert r.status_code == 403, (r.status_code, r.text)
    assert b"SignatureDoesNotMatch" in r.content, r.text
    # The doomed object must not have been committed (no staged leak).
    assert not os.path.exists(os.path.join(SIGNED_DATA_DIR, key))


def test_anonymous_server_ignores_chunk_signatures():
    """Regression: the verify-off (anonymous) endpoint still decodes a streaming
    body whose chunk signatures are garbage — behaviour is unchanged there."""
    host = f"127.0.0.1:{NGINX_S3_PORT}"
    key = f"chunksig_{uuid.uuid4().hex}"
    payload = b"unverified-but-valid-framing"
    body = (b"%x;chunk-signature=%s\r\n%s\r\n" % (len(payload), b"a" * 64, payload)
            + b"0;chunk-signature=%s\r\n\r\n" % (b"b" * 64))
    headers = {
        "x-amz-content-sha256": STREAMING,
        "x-amz-decoded-content-length": str(len(payload)),
        "Content-Encoding": "aws-chunked",
    }
    r = _put(host, key, headers, body)
    assert r.status_code == 200, (r.status_code, r.text)
    got = requests.get(f"http://{host}/{S3_BUCKET}/{key}", timeout=10)
    assert got.content == payload
    requests.delete(f"http://{host}/{S3_BUCKET}/{key}", timeout=10)
