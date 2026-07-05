# brix-remote-ok
"""SigV4 authentication tests for S3 presigned URLs."""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import hmac
import json
import os
from pathlib import Path
from urllib.parse import quote, urlencode, urlparse

import pytest
import requests

from pathlib import Path
from settings import HOST, S3_PRESIGNED_PORT, S3_PRESIGNED_STS_PORT, TEST_ROOT


BUCKET = "testbucket"
ACCESS_KEY = "test-access-key"
SECRET_KEY = "test-secret-key"
REGION = "us-east-1"


@pytest.fixture(scope="module")
def s3_auth_instance():
    """Use the dedicated S3 presigned URL server."""
    import socket as _sock
    try:
        with _sock.create_connection((HOST, S3_PRESIGNED_PORT), timeout=5):
            pass
    except OSError:
        pytest.skip(f"S3 presigned server not reachable at port {S3_PRESIGNED_PORT}")
    data_dir = Path(TEST_ROOT) / "data-s3-presigned"
    data_dir.mkdir(parents=True, exist_ok=True)
    yield {
        "base": f"http://{HOST}:{S3_PRESIGNED_PORT}",
        "data_dir": data_dir,
    }


@pytest.fixture(scope="module")
def s3_auth_sts_instance():
    """Use the dedicated S3 presigned URL + STS server."""
    import socket as _sock
    try:
        with _sock.create_connection((HOST, S3_PRESIGNED_STS_PORT), timeout=5):
            pass
    except OSError:
        pytest.skip(f"S3 presigned STS server not reachable at port {S3_PRESIGNED_STS_PORT}")
    data_dir = Path(TEST_ROOT) / "data-s3-presigned-sts"
    data_dir.mkdir(parents=True, exist_ok=True)
    yield {
        "base": f"http://{HOST}:{S3_PRESIGNED_STS_PORT}",
        "data_dir": data_dir,
    }


def _put_object_file(instance, key: str, data: bytes) -> None:
    path = Path(instance["data_dir"]) / key
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def _signing_key(secret: str, date: str, region: str) -> bytes:
    k_date = hmac.new(f"AWS4{secret}".encode(), date.encode(), hashlib.sha256).digest()
    k_region = hmac.new(k_date, region.encode(), hashlib.sha256).digest()
    k_service = hmac.new(k_region, b"s3", hashlib.sha256).digest()
    return hmac.new(k_service, b"aws4_request", hashlib.sha256).digest()


def _canonical_query(params: dict[str, str]) -> str:
    parts = []
    for key, value in sorted(params.items()):
        parts.append(
            f"{quote(key, safe='-_.~')}={quote(value, safe='-_.~')}"
        )
    return "&".join(parts)


def _canonical_uri(path: str) -> str:
    return quote(path, safe="/-_.~")


def _string_to_sign(amz_date: str, date: str, canonical_request: str) -> str:
    digest = hashlib.sha256(canonical_request.encode()).hexdigest()
    return (
        "AWS4-HMAC-SHA256\n"
        f"{amz_date}\n"
        f"{date}/{REGION}/s3/aws4_request\n"
        f"{digest}"
    )


def _presigned_get_url(base: str, key: str, *, request_time: dt.datetime,
                       expires: int = 300,
                       session_token: str | None = None) -> str:
    parsed = urlparse(base)
    host = parsed.netloc
    path = f"/{BUCKET}/{key}"
    amz_date = request_time.strftime("%Y%m%dT%H%M%SZ")
    date = request_time.strftime("%Y%m%d")
    credential = f"{ACCESS_KEY}/{date}/{REGION}/s3/aws4_request"
    params = {
        "X-Amz-Algorithm": "AWS4-HMAC-SHA256",
        "X-Amz-Credential": credential,
        "X-Amz-Date": amz_date,
        "X-Amz-Expires": str(expires),
        "X-Amz-SignedHeaders": "host",
    }
    if session_token is not None:
        params["X-Amz-Security-Token"] = session_token
    canonical_request = (
        "GET\n"
        f"{_canonical_uri(path)}\n"
        f"{_canonical_query(params)}\n"
        f"host:{host}\n"
        "\n"
        "host\n"
        "UNSIGNED-PAYLOAD"
    )
    signature = hmac.new(
        _signing_key(SECRET_KEY, date, REGION),
        _string_to_sign(amz_date, date, canonical_request).encode(),
        hashlib.sha256,
    ).hexdigest()
    params["X-Amz-Signature"] = signature
    return f"{base}{path}?{urlencode(params, quote_via=quote, safe='-_.~')}"


def _header_auth(base: str, key: str, request_time: dt.datetime,
                 session_token: str | None = None) -> dict[str, str]:
    parsed = urlparse(base)
    host = parsed.netloc
    path = f"/{BUCKET}/{key}"
    amz_date = request_time.strftime("%Y%m%dT%H%M%SZ")
    date = request_time.strftime("%Y%m%d")
    signed_headers = "host;x-amz-date"
    token_header = ""
    if session_token is not None:
        signed_headers = "host;x-amz-date;x-amz-security-token"
        token_header = f"x-amz-security-token:{session_token}\n"
    canonical_request = (
        "GET\n"
        f"{_canonical_uri(path)}\n"
        "\n"
        f"host:{host}\n"
        f"x-amz-date:{amz_date}\n"
        f"{token_header}"
        "\n"
        f"{signed_headers}\n"
        "UNSIGNED-PAYLOAD"
    )
    signature = hmac.new(
        _signing_key(SECRET_KEY, date, REGION),
        _string_to_sign(amz_date, date, canonical_request).encode(),
        hashlib.sha256,
    ).hexdigest()
    credential = f"{ACCESS_KEY}/{date}/{REGION}/s3/aws4_request"
    headers = {
        "x-amz-date": amz_date,
        "Authorization": (
            "AWS4-HMAC-SHA256 "
            f"Credential={credential}, "
            f"SignedHeaders={signed_headers}, "
            f"Signature={signature}"
        ),
    }
    if session_token is not None:
        headers["x-amz-security-token"] = session_token
    return headers


def _post_policy_fields(key: str, data_len: int, *,
                        request_time: dt.datetime,
                        content_type: str | None = None,
                        policy_key: str | None = None,
                        signature_override: str | None = None) -> dict[str, str]:
    amz_date = request_time.strftime("%Y%m%dT%H%M%SZ")
    date = request_time.strftime("%Y%m%d")
    credential = f"{ACCESS_KEY}/{date}/{REGION}/s3/aws4_request"
    effective_policy_key = policy_key if policy_key is not None else key
    policy = {
        "expiration": (
            request_time + dt.timedelta(hours=1)
        ).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "conditions": [
            {"bucket": BUCKET},
            ["eq", "$key", effective_policy_key],
            {"x-amz-algorithm": "AWS4-HMAC-SHA256"},
            {"x-amz-credential": credential},
            {"x-amz-date": amz_date},
            ["content-length-range", 0, data_len + 16],
        ],
    }
    if content_type is not None:
        policy["conditions"].append(["eq", "$Content-Type", content_type])
    policy_b64 = base64.b64encode(
        json.dumps(policy, separators=(",", ":")).encode()
    ).decode()
    signature = hmac.new(
        _signing_key(SECRET_KEY, date, REGION),
        policy_b64.encode(),
        hashlib.sha256,
    ).hexdigest()
    if signature_override is not None:
        signature = signature_override
    fields = {
        "key": key,
        "policy": policy_b64,
        "x-amz-algorithm": "AWS4-HMAC-SHA256",
        "x-amz-credential": credential,
        "x-amz-date": amz_date,
        "x-amz-signature": signature,
        "success_action_status": "201",
    }
    if content_type is not None:
        fields["Content-Type"] = content_type
    return fields


def test_presigned_url_get_succeeds(s3_auth_instance):
    key = "presigned/success.txt"
    content = b"presigned-url-ok"
    _put_object_file(s3_auth_instance, key, content)

    now = dt.datetime.now(dt.UTC).replace(microsecond=0)
    url = _presigned_get_url(s3_auth_instance["base"], key, request_time=now)

    r = requests.get(url, timeout=10)
    assert r.status_code == 200
    assert r.content == content


def test_presigned_url_expired_returns_403(s3_auth_instance):
    key = "presigned/expired.txt"
    _put_object_file(s3_auth_instance, key, b"expired")

    old = dt.datetime.now(dt.UTC).replace(microsecond=0) - dt.timedelta(minutes=5)
    url = _presigned_get_url(
        s3_auth_instance["base"], key, request_time=old, expires=1
    )

    r = requests.get(url, timeout=10)
    assert r.status_code == 403


def test_presigned_url_future_skew_returns_403(s3_auth_instance):
    key = "presigned/future-skew.txt"
    _put_object_file(s3_auth_instance, key, b"future-skew")

    future = (
        dt.datetime.now(dt.UTC).replace(microsecond=0)
        + dt.timedelta(hours=1)
    )
    url = _presigned_get_url(s3_auth_instance["base"], key, request_time=future)

    r = requests.get(url, timeout=10)
    assert r.status_code == 403
    assert "RequestTimeTooSkewed" in r.text


def test_presigned_url_bad_signature_returns_403(s3_auth_instance):
    key = "presigned/bad-signature.txt"
    _put_object_file(s3_auth_instance, key, b"bad-signature")

    now = dt.datetime.now(dt.UTC).replace(microsecond=0)
    url = _presigned_get_url(s3_auth_instance["base"], key, request_time=now)
    url = url[:-1] + ("0" if url[-1] != "0" else "1")

    r = requests.get(url, timeout=10)
    assert r.status_code == 403


def test_sigv4_header_auth_still_works(s3_auth_instance):
    key = "presigned/header-auth.txt"
    content = b"header-auth-ok"
    _put_object_file(s3_auth_instance, key, content)

    now = dt.datetime.now(dt.UTC).replace(microsecond=0)
    url = f"{s3_auth_instance['base']}/{BUCKET}/{key}"
    r = requests.get(url, headers=_header_auth(s3_auth_instance["base"], key, now),
                     timeout=10)

    assert r.status_code == 200
    assert r.content == content


def test_sigv4_header_auth_future_skew_returns_403(s3_auth_instance):
    key = "presigned/header-future-skew.txt"
    _put_object_file(s3_auth_instance, key, b"header-future-skew")

    future = (
        dt.datetime.now(dt.UTC).replace(microsecond=0)
        + dt.timedelta(hours=1)
    )
    url = f"{s3_auth_instance['base']}/{BUCKET}/{key}"
    r = requests.get(
        url,
        headers=_header_auth(s3_auth_instance["base"], key, future),
        timeout=10,
    )

    assert r.status_code == 403
    assert "RequestTimeTooSkewed" in r.text


def test_post_object_signed_policy_succeeds(s3_auth_instance):
    key = "post-policy/success.txt"
    content = b"signed-post-policy-ok"
    now = dt.datetime.now(dt.UTC).replace(microsecond=0)

    r = requests.post(
        f"{s3_auth_instance['base']}/{BUCKET}/",
        data=_post_policy_fields(key, len(content), request_time=now),
        files={"file": ("upload.txt", content, "text/plain")},
        timeout=10,
    )
    assert r.status_code == 201, r.text

    r = requests.get(
        f"{s3_auth_instance['base']}/{BUCKET}/{key}",
        headers=_header_auth(s3_auth_instance["base"], key, now),
        timeout=10,
    )
    assert r.status_code == 200
    assert r.content == content


def test_post_object_signed_policy_content_type_field_succeeds(s3_auth_instance):
    key = "post-policy/content-type.txt"
    content = b"signed-post-content-type-ok"
    now = dt.datetime.now(dt.UTC).replace(microsecond=0)

    r = requests.post(
        f"{s3_auth_instance['base']}/{BUCKET}/",
        data=_post_policy_fields(
            key, len(content), request_time=now, content_type="text/plain"
        ),
        files={"file": ("upload.bin", content, "application/octet-stream")},
        timeout=10,
    )
    assert r.status_code == 201, r.text

    r = requests.get(
        f"{s3_auth_instance['base']}/{BUCKET}/{key}",
        headers=_header_auth(s3_auth_instance["base"], key, now),
        timeout=10,
    )
    assert r.status_code == 200
    assert r.content == content


def test_post_object_signed_policy_bad_signature_rejected(s3_auth_instance):
    key = "post-policy/bad-signature.txt"
    content = b"bad-signature"
    now = dt.datetime.now(dt.UTC).replace(microsecond=0)

    r = requests.post(
        f"{s3_auth_instance['base']}/{BUCKET}/",
        data=_post_policy_fields(
            key, len(content), request_time=now, signature_override="0" * 64
        ),
        files={"file": ("upload.txt", content, "text/plain")},
        timeout=10,
    )
    assert r.status_code == 403
    assert "SignatureDoesNotMatch" in r.text


def test_post_object_signed_policy_condition_rejected(s3_auth_instance):
    key = "post-policy/condition-target.txt"
    content = b"condition-mismatch"
    now = dt.datetime.now(dt.UTC).replace(microsecond=0)

    r = requests.post(
        f"{s3_auth_instance['base']}/{BUCKET}/",
        data=_post_policy_fields(
            key,
            len(content),
            request_time=now,
            policy_key="post-policy/other-key.txt",
        ),
        files={"file": ("upload.txt", content, "text/plain")},
        timeout=10,
    )
    assert r.status_code == 403
    assert "AccessDenied" in r.text


def test_session_token_rejected_by_default(s3_auth_instance):
    key = "sts/default-reject.txt"
    _put_object_file(s3_auth_instance, key, b"sts-default-reject")

    now = dt.datetime.now(dt.UTC).replace(microsecond=0)
    url = f"{s3_auth_instance['base']}/{BUCKET}/{key}"
    r = requests.get(
        url,
        headers=_header_auth(
            s3_auth_instance["base"],
            key,
            now,
            session_token="static-session-token",
        ),
        timeout=10,
    )

    assert r.status_code == 403


def test_session_token_header_allowed_with_static_secret(s3_auth_sts_instance):
    key = "sts/header-allowed.txt"
    content = b"sts-header-allowed"
    _put_object_file(s3_auth_sts_instance, key, content)

    now = dt.datetime.now(dt.UTC).replace(microsecond=0)
    url = f"{s3_auth_sts_instance['base']}/{BUCKET}/{key}"
    r = requests.get(
        url,
        headers=_header_auth(
            s3_auth_sts_instance["base"],
            key,
            now,
            session_token="static-session-token",
        ),
        timeout=10,
    )

    assert r.status_code == 200
    assert r.content == content


def test_session_token_presigned_allowed_with_static_secret(s3_auth_sts_instance):
    key = "sts/presigned-allowed.txt"
    content = b"sts-presigned-allowed"
    _put_object_file(s3_auth_sts_instance, key, content)

    now = dt.datetime.now(dt.UTC).replace(microsecond=0)
    url = _presigned_get_url(
        s3_auth_sts_instance["base"],
        key,
        request_time=now,
        session_token="static-session-token",
    )
    r = requests.get(url, timeout=10)

    assert r.status_code == 200
    assert r.content == content
