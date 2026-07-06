"""Minimal AWS SigV4 signer for S3 requests (hand-rolled HMAC-SHA256, matches
tests/test_s3_auth_oracle.py). No boto3 dependency."""
import datetime as _dt
import hashlib
import hmac
from urllib.parse import quote

REGION = "us-east-1"


def _signing_key(secret: str, date: str) -> bytes:
    k = hmac.new(f"AWS4{secret}".encode(), date.encode(), hashlib.sha256).digest()
    k = hmac.new(k, REGION.encode(), hashlib.sha256).digest()
    k = hmac.new(k, b"s3", hashlib.sha256).digest()
    return hmac.new(k, b"aws4_request", hashlib.sha256).digest()


def signed_headers(method: str, path: str, access_key: str, secret: str, *,
                   host: str, now: "_dt.datetime | None" = None) -> dict:
    """Return the SigV4 Authorization + x-amz-date headers for an UNSIGNED-PAYLOAD request.

    `host` is the netloc (e.g. "127.0.0.1:12105"); `path` is "/bucket/key". `now` is only
    injected by tests for determinism; production callers omit it.
    """
    now = now or _dt.datetime.now(_dt.timezone.utc)
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    date = now.strftime("%Y%m%d")
    canonical = (
        f"{method}\n"
        f"{quote(path, safe='/-_.~')}\n"
        "\n"
        f"host:{host}\n"
        f"x-amz-date:{amz_date}\n"
        "\n"
        "host;x-amz-date\n"
        "UNSIGNED-PAYLOAD"
    )
    sts = ("AWS4-HMAC-SHA256\n"
           f"{amz_date}\n"
           f"{date}/{REGION}/s3/aws4_request\n"
           f"{hashlib.sha256(canonical.encode()).hexdigest()}")
    sig = hmac.new(_signing_key(secret, date), sts.encode(), hashlib.sha256).hexdigest()
    cred = f"{access_key}/{date}/{REGION}/s3/aws4_request"
    return {
        "x-amz-date": amz_date,
        "x-amz-content-sha256": "UNSIGNED-PAYLOAD",
        "Authorization": (f"AWS4-HMAC-SHA256 Credential={cred}, "
                          f"SignedHeaders=host;x-amz-date, Signature={sig}"),
    }
